package assamclient

import (
	"net/http"
	"time"
)

// plainHTTPClient returns an *http.Client without RA-TLS. It is only safe for
// tests that talk to plain httptest.NewServer fakes. Production code MUST
// leave Config.HTTPClient nil so NewClient builds an RA-TLS-verifying
// transport.
func plainHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
