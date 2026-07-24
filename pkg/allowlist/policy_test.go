package allowlist

import "testing"

func TestIndex_FloorAdmitsAnyArgv(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"cds"}}`).BuildIndex()
	if !idx.AdmitsDigest(digestA) {
		t.Fatal("floor digest not admitted")
	}
	if !idx.AdmitsContainer(digestA, []string{"/anything", "--dynamic"}) {
		t.Fatal("floor digest must be admitted regardless of argv")
	}
}

func TestIndex_DenyRequiresEmptySegment(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","entrypoint":{"policy":"any"},"cmd":{"policy":"deny"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/app"}) {
		t.Fatal("cmd deny should admit an argv with no arguments")
	}
	if idx.AdmitsContainer(digestA, []string{"/app", "--exfil"}) {
		t.Fatal("cmd deny must reject any arguments")
	}
}

func TestIndex_ExactMatch(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","entrypoint":{"policy":"exact","argv":["/app"]},
		 "cmd":{"policy":"exact","argv":["--serve","--port=8080"]}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/app", "--serve", "--port=8080"}) {
		t.Fatal("exact argv should match")
	}
	if idx.AdmitsContainer(digestA, []string{"/bin/sh", "--serve", "--port=8080"}) {
		t.Fatal("a swapped entrypoint must be rejected")
	}
	if idx.AdmitsContainer(digestA, []string{"/app", "--serve"}) {
		t.Fatal("a truncated cmd must be rejected")
	}
}

// A shared digest may run under several argv policies; admission is the union.
func TestIndex_SharedDigestUnion(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"a":{"containers":[{"digest":"`+digestA+`","entrypoint":{"policy":"any"},"cmd":{"policy":"exact","argv":["sleep","1"]}}]},
		"b":{"containers":[{"digest":"`+digestA+`","entrypoint":{"policy":"any"},"cmd":{"policy":"exact","argv":["echo","hi"]}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"busybox", "sleep", "1"}) {
		t.Fatal("first entry's argv should be admitted")
	}
	if !idx.AdmitsContainer(digestA, []string{"busybox", "echo", "hi"}) {
		t.Fatal("second entry's argv should be admitted")
	}
	if idx.AdmitsContainer(digestA, []string{"busybox", "cat", "/etc/shadow"}) {
		t.Fatal("an argv no entry permits must be rejected")
	}
}

func TestIndex_UnknownDigestDenied(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"x"}}`).BuildIndex()
	if idx.AdmitsDigest(digestB) || idx.AdmitsContainer(digestB, nil) {
		t.Fatal("unknown digest must be denied")
	}
}
