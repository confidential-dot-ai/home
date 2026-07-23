package ratls

import (
	"crypto/tls"
	"fmt"
)

// PeerConfigClaims returns the config-claims a verified TLS peer presented,
// parsed, or nil when the peer carried none. Read-only: the RA-TLS handshake
// already verified the binding, so this reads the leaf, it does not re-verify.
// For an HTTP server the connection state is on the request: PeerConfigClaims(r.TLS).
//
// INVARIANT: only call on a connection an RA-TLS verify callback accepted (the
// tls.Config from NewServerTLSConfig / NewClientTLSConfig). Acceptance is what
// authenticates the claims — the trust model, and its honest-workload ceiling,
// are in docs/ratls.md, "Reading a peer's claims".
func PeerConfigClaims(cs *tls.ConnectionState) (*ConfigClaims, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, fmt.Errorf("ratls: no peer certificate")
	}
	raw := ExtractConfigClaimsBytes(cs.PeerCertificates[0])
	if len(raw) == 0 {
		return nil, nil
	}
	return UnmarshalConfigClaims(raw)
}
