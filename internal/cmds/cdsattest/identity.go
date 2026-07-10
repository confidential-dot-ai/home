package cdsattest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type meshIdentity struct {
	leaf      *x509.Certificate
	ca        *x509.Certificate
	private   *ecdsa.PrivateKey
	bundlePEM []byte
}

// loadMeshIdentity reads all three files for every v2 attestation request so a
// get-cert rotation is observed without restarting the sidecar. X509KeyPair
// verifies that the private key matches the leaf. A transient rotation mismatch
// fails this request closed; the next request can retry after the three files
// converge on one credential generation.
func loadMeshIdentity(certFile, keyFile, caFile string) (*meshIdentity, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, fmt.Errorf("mesh identity cert, key, and CA files are required")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read mesh identity cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read mesh identity key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read mesh identity CA: %w", err)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load mesh identity keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("mesh identity certificate file has no leaf")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse mesh identity leaf: %w", err)
	}
	private, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mesh identity private key must be ECDSA, got %T", pair.PrivateKey)
	}

	caCerts, err := certutil.ParsePEMCertificates(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse mesh identity CA bundle: %w", err)
	}
	var issuer *x509.Certificate
	for _, candidate := range caCerts {
		if leaf.CheckSignatureFrom(candidate) == nil {
			issuer = candidate
			break
		}
	}
	if issuer == nil {
		return nil, fmt.Errorf("mesh identity leaf is not signed by any configured mesh CA")
	}

	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	return &meshIdentity{leaf: leaf, ca: issuer, private: private, bundlePEM: bundle}, nil
}

func (m *meshIdentity) bind(pub overenc.PublicKey, nonce []byte) ([]byte, *types.MeshIdentityProof, error) {
	transcriptHash, err := overenc.IdentityTranscriptHash(pub, nonce, m.leaf.Raw, m.ca.Raw)
	if err != nil {
		return nil, nil, err
	}
	message, err := overenc.IdentityProofMessage(transcriptHash)
	if err != nil {
		return nil, nil, err
	}
	digest := sha512.Sum384(message)
	signature, err := ecdsa.SignASN1(rand.Reader, m.private, digest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("sign mesh identity proof: %w", err)
	}
	leafHash := sha256.Sum256(m.leaf.Raw)
	caHash := sha256.Sum256(m.ca.Raw)
	return transcriptHash, &types.MeshIdentityProof{
		Algorithm:    types.MeshIdentityProofECDSASHA384,
		LeafSHA256:   base64.RawURLEncoding.EncodeToString(leafHash[:]),
		MeshCASHA256: base64.RawURLEncoding.EncodeToString(caHash[:]),
		Signature:    base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}
