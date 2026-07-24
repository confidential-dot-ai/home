//go:build linux

package ratlsmesh

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeIptablesScript emulates just enough of iptables/ip6tables for the
// go-iptables client: version probing, chain create/flush/delete, rule
// append/insert/delete, -S listing, and -L -n -v -x stats. State lives in
// $FAKE_IPT_STATE/<binary-name>/<table>__<chain>, one rule per line, so
// assertions can inspect what was installed without a kernel.
const fakeIptablesScript = `#!/bin/bash
set -u
bin="$(basename "$0")"
state="${FAKE_IPT_STATE}/${bin}"
mkdir -p "$state"

if [ "${1:-}" = "--version" ]; then
  echo "iptables v1.8.9 (legacy)"
  exit 0
fi

args=("$@")
last=$(( ${#args[@]} - 1 ))
if [ "${args[$last]}" = "--wait" ]; then
  unset "args[$last]"
fi

table="${args[1]}"
op="${args[2]}"
chain="${args[3]:-}"
f="$state/${table}__${chain}"

builtin_chain() {
  case "$1" in OUTPUT|PREROUTING|FORWARD|INPUT|POSTROUTING) return 0;; *) return 1;; esac
}

case "$op" in
  -N)
    if [ -e "$f" ]; then echo "iptables: Chain already exists." >&2; exit 1; fi
    : > "$f" ;;
  -F)
    if [ ! -e "$f" ] && ! builtin_chain "$chain"; then
      echo "iptables: No chain/target/match by that name." >&2; exit 1
    fi
    : > "$f" ;;
  -X)
    if [ ! -e "$f" ]; then echo "iptables: No chain/target/match by that name." >&2; exit 1; fi
    rm -f "$f" ;;
  -A)
    if [ ! -e "$f" ] && ! builtin_chain "$chain"; then
      echo "iptables: No chain/target/match by that name." >&2; exit 1
    fi
    echo "${args[*]:4}" >> "$f" ;;
  -I)
    rule="${args[*]:5}"
    tmp="$f.tmp"
    { echo "$rule"; cat "$f" 2>/dev/null || true; } > "$tmp"
    mv "$tmp" "$f" ;;
  -D)
    rule="${args[*]:4}"
    if [ -e "$f" ] && grep -qxF -- "$rule" "$f"; then
      awk -v r="$rule" 'BEGIN{done=0} { if (!done && $0 == r) { done=1; next } print }' "$f" > "$f.tmp"
      mv "$f.tmp" "$f"
    else
      echo "iptables: Bad rule (does a matching rule exist in that chain?)." >&2
      exit 1
    fi ;;
  -S)
    if [ "${FAKE_IPT_LIST_FAIL:-}" = "1" ]; then
      echo "iptables: resource temporarily unavailable." >&2; exit 4
    fi
    if [ ! -e "$f" ]; then
      if builtin_chain "$chain"; then : > "$f"; else
        echo "iptables: No chain/target/match by that name." >&2; exit 1
      fi
    fi
    echo "-N $chain"
    while IFS= read -r line; do
      [ -n "$line" ] && echo "-A $chain $line"
    done < "$f" ;;
  -L)
    echo "Chain $chain (1 references)"
    echo "    pkts      bytes target     prot opt in     out     source               destination"
    if [ "$bin" = "ip6tables" ]; then
      echo "       7      420 DROP       all      *      *       ::/0                 ::/0                 match-set RATLS-MESH-CW-PODS6 dst"
    else
      echo "       7      420 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set RATLS-MESH-CW-PODS dst"
    fi ;;
esac
exit 0
`

// fakeIpsetScript emulates the ipset subcommands the package shells out to:
// `list -t NAME`, `destroy NAME`, and `restore` (stdin script). Each set is a
// file $FAKE_IPSET_STATE/<name> whose content is the set's maxelem.
const fakeIpsetScript = `#!/bin/bash
set -u
state="${FAKE_IPSET_STATE}"
mkdir -p "$state"

if [ "${FAKE_IPSET_FAIL:-}" = "1" ]; then
  echo "ipset v7.17: kernel says no" >&2
  exit 2
fi

cmd="${1:-}"
case "$cmd" in
  list)
    name="${3:-}"
    if [ -e "$state/$name" ]; then
      echo "Name: $name"
      echo "Type: hash:ip"
      echo "Header: family inet hashsize 1024 maxelem $(cat "$state/$name") bucketsize 12 initval 0x0"
    else
      echo "ipset v7.17: The set with the given name does not exist" >&2
      exit 1
    fi ;;
  destroy)
    name="${2:-}"
    if [ -e "$state/$name" ]; then
      rm -f "$state/$name"
    else
      echo "ipset v7.17: The set with the given name does not exist" >&2
      exit 1
    fi ;;
  restore)
    while read -r line; do
      set -- $line
      case "${1:-}" in
        create)
          n="$2"
          while [ $# -gt 1 ]; do
            if [ "$1" = "maxelem" ]; then echo "$2" > "$state/$n"; fi
            shift
          done ;;
        destroy)
          rm -f "$state/$2" ;;
      esac
    done ;;
esac
exit 0
`

// fakeNetfilterEnv holds the state directories backing the fake binaries.
type fakeNetfilterEnv struct {
	binDir     string
	iptState   string
	ipsetState string
}

// installFakeNetfilter puts fake iptables/ip6tables/ipset binaries at the
// front of PATH and points their state at temp dirs. Tests using it must not
// run in parallel (t.Setenv enforces this).
func installFakeNetfilter(t *testing.T) *fakeNetfilterEnv {
	t.Helper()
	binDir := t.TempDir()
	env := &fakeNetfilterEnv{
		binDir:     binDir,
		iptState:   t.TempDir(),
		ipsetState: t.TempDir(),
	}
	for _, name := range []string{"iptables", "ip6tables"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(fakeIptablesScript), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(binDir, "ipset"), []byte(fakeIpsetScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_IPT_STATE", env.iptState)
	t.Setenv("FAKE_IPSET_STATE", env.ipsetState)
	return env
}

// chainRules reads the fake-iptables rule lines for bin/table/chain.
// Returns nil when the chain does not exist.
func (e *fakeNetfilterEnv) chainRules(t *testing.T, bin, table, chain string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.iptState, bin, table+"__"+chain))
	if err != nil {
		return nil
	}
	return splitNonEmptyLines(string(raw))
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// seedIpset creates a fake live ipset with the given maxelem.
func (e *fakeNetfilterEnv) seedIpset(t *testing.T, name string, maxElem string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.ipsetState, name), []byte(maxElem+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *fakeNetfilterEnv) ipsetExists(name string) bool {
	_, err := os.Stat(filepath.Join(e.ipsetState, name))
	return err == nil
}
