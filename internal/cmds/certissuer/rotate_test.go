package certissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/issuer"
)

func TestRotateCAUsesConfiguredCommonName(t *testing.T) {
	iss, _ := testIssuer(t)
	rotator := testCARotator(t, iss, "Custom Mesh CA")

	cert, _, err := rotator.RotateCA()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "Custom Mesh CA" {
		t.Fatalf("rotated CA CN = %q, want %q", cert.Subject.CommonName, "Custom Mesh CA")
	}
	if got := iss.getBundle().caCert.Subject.CommonName; got != "Custom Mesh CA" {
		t.Fatalf("active CA CN = %q, want %q", got, "Custom Mesh CA")
	}
}

func TestRotateCASetsParentCertificateForContinuity(t *testing.T) {
	iss, _ := testIssuer(t)
	oldBundle := iss.getBundle()
	iss.bundle.Store(&certBundle{
		caCert:          oldBundle.caCert,
		caKey:           oldBundle.caKey,
		tokenSignerCert: oldBundle.tokenSignerCert,
		parentCert:      oldBundle.caCert,
	})
	rotator := testCARotator(t, iss, "c8s Mesh CA")

	if _, _, err := rotator.RotateCA(); err != nil {
		t.Fatal(err)
	}
	rotated := iss.getBundle()
	if parent := rotated.parentCert; parent == nil || !parent.Equal(oldBundle.caCert) {
		t.Fatalf("rotated CA parent = %v, want previous active CA", parent)
	}
	if err := rotated.caCert.CheckSignatureFrom(oldBundle.caCert); err != nil {
		t.Fatalf("rotated CA was not signed by previous CA: %v", err)
	}
}

func TestHandleSignCSRReturnsFullPublicBundleAfterMultipleRotations(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	rotator := testCARotator(t, iss, "c8s Mesh CA")

	for range 2 {
		if _, _, err := rotator.RotateCA(); err != nil {
			t.Fatal(err)
		}
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := generateCSR(t, csrKey, "ratls-mesh-10.0.0.1")
	signEAR := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})
	body, err := json.Marshal(newSignCSRRequest(signEAR, csr, "12h"))
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	iss.HandleSignCSR(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sign-csr status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp signCSRResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if got := len(resp.CACertificate.DERAll()); got != 3 {
		t.Fatalf("sign-csr CA bundle count = %d, want current + two retained parents", got)
	}
}

func testCARotator(t *testing.T, iss *Issuer, commonName string) *issuer.CARotator {
	t.Helper()
	bm := issuer.NewBundleManager(iss.MaxTTL, "", "default/mesh/ca-bundle", slog.Default())
	bm.SetInitial(iss.getBundle().caCert)
	iss.caBundle = bm
	r, err := issuer.NewCARotator(newCARotatorDeps(iss, bm, 365*24*time.Hour, commonName))
	if err != nil {
		t.Fatalf("new CA rotator: %v", err)
	}
	return r
}
