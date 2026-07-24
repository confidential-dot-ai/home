#!/usr/bin/env bash
# coverage-gate.sh — compute and gate Go test coverage.
#
# Usage:
#   scripts/coverage-gate.sh run [profile]        run tests, write coverage profile
#   scripts/coverage-gate.sh total <profile>      print total coverage (e.g. "67.9")
#   scripts/coverage-gate.sh check <profile>      enforce the internal/ package floor
#
# Gates enforced by "check":
#   * every package under internal/ must have >= INTERNAL_FLOOR % statement
#     coverage (default 80). Packages with no statements are skipped.
#
# The profile is produced with -coverpkg=./... so packages without their own
# test files are still measured (a brand-new untested internal package counts
# as 0%, not "absent").
set -euo pipefail

MODULE="github.com/confidential-dot-ai/c8s"
INTERNAL_FLOOR="${INTERNAL_FLOOR:-80}"

cmd="${1:-}"
profile="${2:-coverage.out}"

percent() { # per-package coverage table from a coverprofile: "<pct> <stmts> <pkg>"
  awk -F'[ :]' '
    NR==1 {next}
    {
      key=$1":"$2; stmts[key]=$3; if ($4>0) covered[key]=1;
    }
    END {
      for (k in stmts) {
        file=k; sub(/:[^:]*$/, "", file);
        pkg=file; sub(/\/[^\/]*$/, "", pkg);
        tot[pkg]+=stmts[k]; if (covered[k]) cov[pkg]+=stmts[k];
        T+=stmts[k]; if (covered[k]) C+=stmts[k];
      }
      for (p in tot) printf "%.1f %d %s\n", 100*cov[p]/tot[p], tot[p], p;
      printf "%.1f %d TOTAL\n", (T ? 100*C/T : 0), T;
    }' "$1"
}

case "$cmd" in
run)
  go test ./... -count=1 -coverprofile="$profile" -coverpkg=./...
  ;;
total)
  percent "$profile" | awk '$3=="TOTAL" {print $1}'
  ;;
check)
  fail=0
  while read -r pct stmts pkg; do
    [ "$pkg" = TOTAL ] && continue
    case "$pkg" in
    "$MODULE"/internal/*)
      if awk -v p="$pct" -v f="$INTERNAL_FLOOR" 'BEGIN{exit !(p<f)}'; then
        printf 'FAIL %6s%% (< %s%%) %s\n' "$pct" "$INTERNAL_FLOOR" "$pkg"
        fail=1
      else
        printf 'ok   %6s%%          %s\n' "$pct" "$pkg"
      fi
      ;;
    esac
  done < <(percent "$profile" | sort -n)
  if [ "$fail" -ne 0 ]; then
    echo "coverage gate: packages under internal/ must have >= ${INTERNAL_FLOOR}% statement coverage" >&2
    exit 1
  fi
  echo "coverage gate: all internal/ packages meet the ${INTERNAL_FLOOR}% floor"
  ;;
*)
  echo "usage: $0 {run|total|check} [profile]" >&2
  exit 2
  ;;
esac
