// Package certutil provides common helper functions shared across the ratls
// project: serial number generation, fingerprinting, PEM encoding, and more.
package certutil

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

// serialNumberLimit is 2^128, the upper bound for X.509 serial numbers.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// OIDAttestationDigest marks issued certificates with a SHA-256 of the
// attestation evidence that authorized issuance — an audit-trail extension
// shared between the CDS HTTP signer and the in-process issuer.
var OIDAttestationDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 2}

// GenerateSerial returns a cryptographically random 128-bit serial number
// suitable for X.509 certificates.
func GenerateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, serialNumberLimit)
}

// CertFingerprint returns the lowercase hex SHA-256 fingerprint of raw
// certificate bytes (DER or x509.Certificate.Raw).
func CertFingerprint(raw []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// EncodeCertPEM encodes DER certificate bytes as a PEM block.
func EncodeCertPEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// MarshalECKeyPEM marshals an EC private key to PKCS#8 PEM format.
// PKCS#8 ("PRIVATE KEY" header) is what CDS and the rest of the stack
// expect; SEC 1 ("EC PRIVATE KEY") fails to parse with x509.ParsePKCS8PrivateKey.
func MarshalECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// ParseECPrivateKey parses a PEM-encoded EC private key, trying PKCS8 first
// then SEC 1 (EC) format.
func ParseECPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first (openssl genpkey), then EC (openssl ecparam).
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ec, ok := key.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("pkcs8 key is not ECDSA")
	}
	ec, err2 := x509.ParseECPrivateKey(block.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("parse key: PKCS8: %w; EC: %w", err, err2)
	}
	return ec, nil
}

// LoadECPrivateKeyFile reads a PEM file and parses the EC private key.
func LoadECPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseECPrivateKey(data)
}

// ParseCertificatePEM parses a PEM-encoded certificate, returning the first
// CERTIFICATE block found. Use [LoadCertificateFile] for file-based loading.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadCertificateFile reads a PEM file and parses the first certificate.
func LoadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseCertificatePEM(data)
}

// NewJSONLogger creates a JSON [slog.Logger] writing to stdout at the given
// level string. An empty string selects info; any other value must be one of
// debug, info, warn, error (case-insensitive) or an error is returned, so a
// typo fails at startup rather than silently logging at info.
func NewJSONLogger(levelStr string) (*slog.Logger, error) {
	level := slog.LevelInfo
	if levelStr != "" {
		// Delegate parsing/validation to the stdlib instead of maintaining a
		// level table here.
		if err := level.UnmarshalText([]byte(levelStr)); err != nil {
			return nil, err
		}
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})), nil
}

// ParsePEMCertificates parses all CERTIFICATE PEM blocks from data and returns
// the parsed certificates. It returns an error if no certificate blocks are found.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found")
	}
	return certs, nil
}

// TrimExpiredCABundle returns the subset of certs whose NotAfter is after
// cutoff. The dropped certs are returned in dropped — callers typically log
// their fingerprints. Order is preserved relative to the input.
func TrimExpiredCABundle(certs []*x509.Certificate, cutoff time.Time) (kept, dropped []*x509.Certificate) {
	for _, cert := range certs {
		if cert.NotAfter.Before(cutoff) {
			dropped = append(dropped, cert)
			continue
		}
		kept = append(kept, cert)
	}
	return kept, dropped
}

// LoadPEMCertificatesFile reads a PEM file and parses all CERTIFICATE blocks.
func LoadPEMCertificatesFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParsePEMCertificates(data)
}

// NewCATemplate returns an x509.Certificate template for a self-signed CA
// with the given serial number, subject common name, and expiry time.
func NewCATemplate(serial *big.Int, commonName string, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// NewLeafTemplate returns the canonical x509 leaf-certificate template used
// by the c8s issuers: digital-signature key usage and Server+Client
// extended key usage, anchored at time.Now() with the given TTL. Callers
// populate DNSNames / IPAddresses on the returned template themselves so
// SAN policy stays at the call site.
func NewLeafTemplate(commonName string, ttl time.Duration) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}, nil
}

// AppendAttestationDigest stamps an OIDAttestationDigest extension carrying
// the given digest onto tmpl. No-op when digest is empty.
func AppendAttestationDigest(tmpl *x509.Certificate, digest []byte) error {
	if len(digest) == 0 {
		return nil
	}
	ext, err := asn1.Marshal(digest)
	if err != nil {
		return fmt.Errorf("marshal attestation digest: %w", err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    OIDAttestationDigest,
		Value: ext,
	})
	return nil
}
