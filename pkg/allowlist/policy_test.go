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

// A multi-token command is matched as an exact prefix; args:any leaves the rest
// free. This is the case an entrypoint like "/docker-entrypoint.sh nginx" needs.
func TestIndex_MultiTokenCommandPrefix(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/docker-entrypoint.sh","nginx"]},
		 "args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}) {
		t.Fatal("argv starting with the command prefix should be admitted")
	}
	if idx.AdmitsContainer(digestA, []string{"/docker-entrypoint.sh"}) {
		t.Fatal("argv shorter than the command prefix must be rejected")
	}
	if idx.AdmitsContainer(digestA, []string{"/bin/sh", "nginx", "-g"}) {
		t.Fatal("a different prefix must be rejected")
	}
}

func TestIndex_FullExact(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},
		 "args":{"policy":"exact","argv":["--serve","--port=8080"]}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/app", "--serve", "--port=8080"}) {
		t.Fatal("exact command+args should match the concatenation")
	}
	if idx.AdmitsContainer(digestA, []string{"/bin/sh", "--serve", "--port=8080"}) {
		t.Fatal("a swapped command must be rejected")
	}
	if idx.AdmitsContainer(digestA, []string{"/app", "--serve"}) {
		t.Fatal("truncated args must be rejected")
	}
}

func TestIndex_ArgsDenyMeansNoArgs(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/app"}) {
		t.Fatal("args:deny should admit the command with no extra args")
	}
	if idx.AdmitsContainer(digestA, []string{"/app", "--exfil"}) {
		t.Fatal("args:deny must reject any extra args")
	}
}

// A shared digest may run under several command/args policies; admission is the
// union across entries.
func TestIndex_SharedDigestUnion(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"a":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","sleep"]},"args":{"policy":"exact","argv":["1"]}}]},
		"b":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","echo"]},"args":{"policy":"any"}}]}}}`).BuildIndex()
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
