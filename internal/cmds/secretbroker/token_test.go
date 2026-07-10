package secretbroker

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTokenIssueLookup(t *testing.T) {
	st := newTokenStore(time.Hour)
	id := PeerIdentity{WorkloadID: "api"}
	tok, err := st.Issue(id, []string{"secret/data/api/*"}, "fp-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, tokenPrefix) {
		t.Errorf("token missing prefix: %q", tok)
	}

	sess, ok := st.Lookup(tok)
	if !ok {
		t.Fatal("freshly issued token not found")
	}
	if sess.identity.WorkloadID != "api" || len(sess.allow) != 1 {
		t.Errorf("session mismatch: %+v", sess)
	}

	if _, ok := st.Lookup("c8sb.bogus"); ok {
		t.Error("unknown token must not resolve")
	}
}

func TestTokenExpiry(t *testing.T) {
	st := newTokenStore(time.Hour)
	tok, _ := st.Issue(PeerIdentity{WorkloadID: "api"}, []string{"x"}, "fp-a")

	// Force the session past its expiry deterministically.
	st.byHash[hashToken(tok)].expiry = time.Now().Add(-time.Second)

	if _, ok := st.Lookup(tok); ok {
		t.Error("expired token must not resolve")
	}
	// Lookup should also have evicted it.
	if _, present := st.byHash[hashToken(tok)]; present {
		t.Error("expired token should be evicted on lookup")
	}
}

func TestTokenReap(t *testing.T) {
	st := newTokenStore(10 * time.Millisecond)
	tok, _ := st.Issue(PeerIdentity{WorkloadID: "api"}, []string{"x"}, "fp-a")
	st.byHash[hashToken(tok)].expiry = time.Now().Add(-time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.reap(ctx)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		st.mu.Lock()
		n := len(st.byHash)
		st.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("reaper did not evict expired token")
}

func TestTokensAreUnique(t *testing.T) {
	st := newTokenStore(time.Hour)
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := st.Issue(PeerIdentity{WorkloadID: "api"}, []string{"x"}, "fp-a")
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatal("duplicate token issued")
		}
		seen[tok] = true
	}
}
