// Package cdsattest implements the tls-lb attestation + over-encryption sidecar:
// the *dynamic* browser-facing endpoints of the c8s-verify/v1 protocol. The
// tls-lb nginx front-end terminates public TLS, serves the static CDS/mesh-CA
// certs, and reverse-proxies the attestation challenge, the handshake, and the
// over-encrypted application paths to this sidecar on loopback. It lets an
// out-of-cluster JavaScript client verify that the LB is a genuine, CDS-issued,
// TEE-attested endpoint and then talk to it over a post-quantum over-encrypted
// channel that terminates inside the LB's enclave — independent of whatever TLS
// terminator sits in front of it. See c8s-verify-js/PROTOCOL.md.
package cdsattest

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/server"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const wellKnownPrefix = "/.well-known/c8s"

// minNonceBytes is the smallest client nonce accepted for the attestation
// challenge; below this the report_data freshness binding is not meaningful.
const minNonceBytes = 16

// Backend handles a decrypted application request and returns the response. The
// sidecar seals the response back to the client. Implementations forward the
// reconstructed request to the real backend (see backend.go).
type Backend interface {
	Forward(ctx context.Context, req types.TunnelRequest) (types.TunnelResponse, error)
}

// Config configures the sidecar server.
type Config struct {
	Logger     *slog.Logger
	Evidence   EvidenceProvider
	CDSCertPEM []byte // optional LB leaf + mesh CA chain, served at /cds-cert.pem
	// ServingCertFile is the path to the LB serving-leaf PEM (the cert nginx
	// presents on the wire). When set, GET .../attestation?pq=false binds
	// report_data to this leaf's SPKI instead of a per-session over-encryption
	// key. Empty disables the tls-cert binding.
	ServingCertFile string
	Backend         Backend // over-encrypted application backend (nil => EchoBackend)
	SessionTTL      time.Duration
	// NonceTTL bounds how long a pending handshake nonce stays valid between
	// the attestation fetch and the handshake POST. Defaults to SessionTTL.
	NonceTTL time.Duration
}

type pendingSession struct {
	key       *overenc.ServerKey
	createdAt time.Time
}

type establishedSession struct {
	channel  *overenc.Channel
	lastUsed time.Time
}

// Server serves the c8s-verify/v1 endpoints.
type Server struct {
	cfg     Config
	log     *slog.Logger
	backend Backend

	mu       sync.Mutex
	pending  map[string]pendingSession     // nonce(b64url) -> server key
	sessions map[string]establishedSession // session id -> channel
}

// NewServer constructs a Server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 5 * time.Minute
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = cfg.SessionTTL
	}
	backend := cfg.Backend
	if backend == nil {
		backend = EchoBackend{}
	}
	return &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		backend:  backend,
		pending:  make(map[string]pendingSession),
		sessions: make(map[string]establishedSession),
	}
}

// Handler returns the chi router for the LB endpoints.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// The tls-lb nginx front-end normally serves cds-cert.pem statically; only
	// expose it from the sidecar when a cert was explicitly supplied (dev/standalone).
	if len(s.cfg.CDSCertPEM) > 0 {
		r.Get(wellKnownPrefix+"/cds-cert.pem", s.handleCDSCert)
	}
	r.Get(wellKnownPrefix+"/attestation", s.handleAttestation)
	r.Post(wellKnownPrefix+"/handshake", s.handleHandshake)
	// Over-encrypted application traffic: a single tunnel endpoint. The real
	// method/path/headers/body are sealed inside the request envelope, so nginx
	// only needs to route this one fixed path to the sidecar.
	r.Post(wellKnownPrefix+"/tunnel", s.handleTunnel)
	return r
}

func (s *Server) handleCDSCert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.cfg.CDSCertPEM)
}

func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	nonceB64 := r.URL.Query().Get("nonce")
	if nonceB64 == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "missing nonce")
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "nonce must be base64url")
		return
	}
	// The freshness guarantee rests on a high-entropy, client-chosen nonce bound
	// into report_data; reject anything too short to carry it.
	if len(nonce) < minNonceBytes {
		writeErr(w, http.StatusBadRequest, "invalid_request", "nonce too short")
		return
	}

	// pq=false selects the tls-cert binding: report_data commits to the LB's
	// serving-leaf SPKI instead of a per-session over-encryption key. It is for
	// clients that ride the validated upstream TLS (e.g. TEErminator Flow B)
	// rather than the post-quantum tunnel. pq=true (or absent) is the default.
	if r.URL.Query().Get("pq") == "false" {
		s.handleAttestationTLSCert(w, r, nonceB64, nonce)
		return
	}

	key, err := overenc.GenerateServerKey()
	if err != nil {
		s.log.Error("generate session key", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal", "key generation failed")
		return
	}
	pub := key.Public()

	// report_data = SHA-384(x25519 || mlkem768 || nonce): binds the session key
	// and the client nonce into the hardware report the verifier checks.
	reportData := reportDataFor(pub, nonce)

	evidence, platform, generation, err := s.cfg.Evidence.Evidence(r.Context(), reportData)
	if err != nil {
		s.log.Error("evidence provider failed", "error", err)
		writeErr(w, http.StatusBadGateway, "attestation_unavailable", "could not obtain attestation evidence")
		return
	}

	s.sweep()
	s.mu.Lock()
	s.pending[nonceB64] = pendingSession{key: key, createdAt: time.Now()}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, types.AttestationBundle{
		Version:    "c8s-verify/v1",
		Platform:   platform,
		Generation: generation,
		Nonce:      nonceB64,
		Evidence:   evidence,
		CDSCertPEM: string(s.cfg.CDSCertPEM),
		Binding:    types.BindingOverEncryption,
		SessionPubKey: &types.SessionPublicKey{
			X25519:   base64.RawURLEncoding.EncodeToString(pub.X25519),
			MLKEM768: base64.RawURLEncoding.EncodeToString(pub.MLKEM768),
		},
	})
}

// handleAttestationTLSCert serves the tls-cert binding: report_data =
// SHA-384(serving_leaf_spki || nonce). No over-encryption keypair is minted and
// no pending session is stored — the client verifies the binding against the LB
// leaf it already sees on the connection, then rides that TLS.
func (s *Server) handleAttestationTLSCert(w http.ResponseWriter, r *http.Request, nonceB64 string, nonce []byte) {
	spki, err := s.servingLeafSPKI()
	if err != nil {
		s.log.Error("tls-cert binding unavailable", "error", err)
		writeErr(w, http.StatusNotImplemented, "binding_unavailable",
			"tls-cert binding is not configured on this LB (set --serving-cert-file)")
		return
	}

	// report_data = SHA-384(serving_leaf_spki || nonce): binds the LB's TLS
	// identity and the client nonce into the hardware report.
	reportData := reportDataForCert(spki, nonce)

	evidence, platform, generation, err := s.cfg.Evidence.Evidence(r.Context(), reportData)
	if err != nil {
		s.log.Error("evidence provider failed", "error", err)
		writeErr(w, http.StatusBadGateway, "attestation_unavailable", "could not obtain attestation evidence")
		return
	}

	writeJSON(w, http.StatusOK, types.AttestationBundle{
		Version:    "c8s-verify/v1",
		Platform:   platform,
		Generation: generation,
		Nonce:      nonceB64,
		Evidence:   evidence,
		CDSCertPEM: string(s.cfg.CDSCertPEM),
		Binding:    types.BindingTLSCert,
	})
}

// servingLeafSPKI reads the LB serving-leaf PEM and returns its
// SubjectPublicKeyInfo (DER). It is read per request so a get-cert renewal
// (which SIGHUPs nginx to a new leaf) is picked up without restarting the
// sidecar.
func (s *Server) servingLeafSPKI() ([]byte, error) {
	if s.cfg.ServingCertFile == "" {
		return nil, fmt.Errorf("no --serving-cert-file configured")
	}
	pemBytes, err := os.ReadFile(s.cfg.ServingCertFile)
	if err != nil {
		return nil, fmt.Errorf("read serving cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("serving cert %q is not a PEM certificate", s.cfg.ServingCertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse serving cert: %w", err)
	}
	return cert.RawSubjectPublicKeyInfo, nil
}

func (s *Server) handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req types.HandshakeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}

	s.sweep()
	now := time.Now()
	s.mu.Lock()
	entry, ok := s.pending[req.Nonce]
	if ok {
		delete(s.pending, req.Nonce)
	}
	s.mu.Unlock()
	if !ok || now.Sub(entry.createdAt) > s.cfg.NonceTTL {
		writeErr(w, http.StatusBadRequest, "invalid_request", "unknown or expired nonce")
		return
	}

	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "nonce must be base64url")
		return
	}
	clientX, err1 := base64.RawURLEncoding.DecodeString(req.ClientX25519)
	ct, err2 := base64.RawURLEncoding.DecodeString(req.MLKEMCt)
	if err1 != nil || err2 != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "handshake fields must be base64url")
		return
	}

	channel, err := entry.key.Agree(overenc.Handshake{ClientX25519: clientX, MLKEMCiphertext: ct}, nonce)
	if err != nil {
		s.log.Warn("handshake agree failed", "error", err)
		writeErr(w, http.StatusBadRequest, "channel_error", "key agreement failed")
		return
	}

	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		s.log.Error("generate session id", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal", "session id generation failed")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	s.mu.Lock()
	s.sessions[id] = establishedSession{channel: channel, lastUsed: time.Now()}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, types.HandshakeResponse{SessionID: id})
}

// handleTunnel terminates the over-encryption: it opens the sealed request
// envelope, forwards the reconstructed request to the backend (plaintext; the
// cluster raTLS mesh wraps that hop), and seals the response back to the client.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-C8s-Session")
	s.sweep()

	s.mu.Lock()
	now := time.Now()
	session, ok := s.sessions[id]
	switch {
	case ok && now.Sub(session.lastUsed) > s.cfg.SessionTTL:
		delete(s.sessions, id)
		session = establishedSession{} // expired => treat as no session
	case ok:
		session.lastUsed = now
		s.sessions[id] = session
	default: // case !ok
		session = establishedSession{}
	}
	s.mu.Unlock()

	if session.channel == nil {
		writeErr(w, http.StatusUnauthorized, "channel_error", "no over-encryption session")
		return
	}

	recBytes, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "channel_error", "read record")
		return
	}
	var rec overenc.Record
	if err := cbor.Unmarshal(recBytes, &rec); err != nil {
		writeErr(w, http.StatusBadRequest, "channel_error", "invalid record")
		return
	}
	plaintext, err := session.channel.Open(rec, overenc.RequestAAD())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "channel_error", "decrypt failed")
		return
	}

	var env types.TunnelRequest
	if err := cbor.Unmarshal(plaintext, &env); err != nil {
		writeErr(w, http.StatusBadRequest, "channel_error", "invalid request envelope")
		return
	}

	resp, err := s.backend.Forward(r.Context(), env)
	if err != nil {
		s.log.Warn("backend forward failed", "method", env.Method, "path", env.Path, "error", err)
		resp = types.TunnelResponse{Status: http.StatusBadGateway, Body: []byte("backend error")}
	}

	respCBOR, err := cbor.Marshal(resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "marshal response envelope")
		return
	}
	out, err := session.channel.Seal(respCBOR, overenc.ResponseAAD())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "seal failed")
		return
	}
	writeCBOR(w, http.StatusOK, out)
}

// sweep evicts expired pending handshakes and idle established sessions.
func (s *Server) sweep() {
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.pending {
		if now.Sub(v.createdAt) > s.cfg.NonceTTL {
			delete(s.pending, k)
		}
	}
	for k, v := range s.sessions {
		if now.Sub(v.lastUsed) > s.cfg.SessionTTL {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
}

func reportDataFor(pub overenc.PublicKey, nonce []byte) []byte {
	buf := make([]byte, 0, len(pub.X25519)+len(pub.MLKEM768)+len(nonce))
	buf = append(buf, pub.X25519...)
	buf = append(buf, pub.MLKEM768...)
	buf = append(buf, nonce...)
	sum := sha512.Sum384(buf)
	return sum[:]
}

// reportDataForCert is the tls-cert binding: SHA-384(serving_leaf_spki || nonce).
// A client recomputes it from the SPKI of the certificate it sees on the wire.
func reportDataForCert(spkiDER, nonce []byte) []byte {
	buf := make([]byte, 0, len(spkiDER)+len(nonce))
	buf = append(buf, spkiDER...)
	buf = append(buf, nonce...)
	sum := sha512.Sum384(buf)
	return sum[:]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeCBOR(w http.ResponseWriter, status int, v any) {
	b, err := cbor.Marshal(v)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "marshal failed")
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	w.Write(b)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, types.ErrorResponse{Error: code, Message: msg})
}
