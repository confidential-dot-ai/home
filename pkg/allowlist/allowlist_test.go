package allowlist

import (
	"bytes"
	"strings"
	"testing"
)

const digestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestParseJSON_Minimal(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"cds"}}`)
	if al.Digests[digestA] != "cds" {
		t.Fatalf("floor digest not parsed: %#v", al.Digests)
	}
}

func TestParseJSON_RejectsUnknownSchema(t *testing.T) {
	_, err := ParseJSON([]byte(`{"schema":"other","digests":{}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown schema") {
		t.Fatalf("expected unknown schema error, got %v", err)
	}
}

func TestParseJSON_RejectsUnknownFields(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","surprise":1}`)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestParseJSON_RejectsBadFloorDigest(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","digests":{"sha256:zz":"x"}}`)); err == nil {
		t.Fatal("expected invalid digest error")
	}
}

func TestParseJSON_AbsentPolicyDefaultsToDeny(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"`+digestA+`"}]}}}`)
	c := al.Workloads["w"].Containers[0]
	if c.Entrypoint.Policy != PolicyDeny || c.Cmd.Policy != PolicyDeny || c.Paths.Policy != PolicyDeny {
		t.Fatalf("absent policies should default to deny, got %#v", c)
	}
}

func TestParseJSON_ExactRequiresArgv(t *testing.T) {
	_, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","cmd":{"policy":"exact"}}]}}}`))
	if err == nil || !strings.Contains(err.Error(), "exact policy requires") {
		t.Fatalf("expected exact-needs-argv error, got %v", err)
	}
}

func TestParseJSON_DenyRejectsArgv(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","cmd":{"policy":"deny","argv":["x"]}}]}}}`)); err == nil {
		t.Fatal("expected deny-takes-no-argv error")
	}
}

func TestParseJSON_PathValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"relative", `"read":["etc/x"]`, false},
		{"dotdot", `"read":["/a/../b"]`, false},
		{"midglob", `"read":["/a/*/b"]`, false},
		{"subtree", `"read":["/a/**"]`, true},
		{"literal", `"write":["/secret"]`, true},
	} {
		body := `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` +
			digestA + `","paths":{"policy":"allow",` + tc.body + `}}]}}}`
		_, err := ParseJSON([]byte(body))
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestCanonicalDigest_OrderIndependent(t *testing.T) {
	a := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestB+`","cmd":{"policy":"any"}},
		{"digest":"`+digestA+`","cmd":{"policy":"any"}}]}}}`)
	b := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","cmd":{"policy":"any"}},
		{"digest":"`+digestB+`","cmd":{"policy":"any"}}]}}}`)
	da, _ := a.CanonicalDigest()
	db, _ := b.CanonicalDigest()
	if !bytes.Equal(da, db) {
		t.Fatal("canonical digest depends on container order")
	}
}

func TestCanonicalDigest_FormattingIndependent(t *testing.T) {
	compact := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"x"}}`)
	spaced := mustParse(t, "{\n  \"schema\": \"c8s.allowlist/v1\",\n  \"digests\": {\""+digestA+"\": \"x\"}\n}")
	dc, _ := compact.CanonicalDigest()
	ds, _ := spaced.CanonicalDigest()
	if !bytes.Equal(dc, ds) {
		t.Fatal("canonical digest depends on source formatting")
	}
}

func TestRoundTripCanonical(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"cds"},
		"workloads":{"w":{"label":"img","containers":[
		{"digest":"`+digestB+`","entrypoint":{"policy":"exact","argv":["/app"]},
		 "cmd":{"policy":"any"},"paths":{"policy":"allow","read":["/s/**"]}}]}}}`)
	canon, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseJSON(canon)
	if err != nil {
		t.Fatalf("re-parse canonical: %v", err)
	}
	c2, _ := again.Canonical()
	if !bytes.Equal(canon, c2) {
		t.Fatalf("canonical form not stable across round-trip:\n%s\n%s", canon, c2)
	}
}

func mustParse(t *testing.T, s string) *Allowlist {
	t.Helper()
	al, err := ParseJSON([]byte(s))
	if err != nil {
		t.Fatalf("ParseJSON: %v\n%s", err, s)
	}
	return al
}
