package overenc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

const (
	identityTranscriptDomain = "c8s-verify/pq-mesh-identity/v2"
	identityProofDomain      = "c8s-verify/pq-mesh-identity-proof/v2"
	identityNonceBytes       = 32
)

// IdentityTranscriptHash commits the hybrid server key, client nonce, exact
// mesh leaf, and issuing mesh CA to one SHA-384 value suitable for TEE
// report_data. Every variable-length field is length-prefixed to make the
// transcript unambiguous across the Go and browser implementations.
func IdentityTranscriptHash(pub PublicKey, nonce, leafDER, caDER []byte) ([]byte, error) {
	if len(pub.X25519) != X25519PubBytes {
		return nil, fmt.Errorf("overenc: identity transcript X25519 key must be %d bytes, got %d", X25519PubBytes, len(pub.X25519))
	}
	if len(pub.MLKEM768) != MLKEM768EKBytes {
		return nil, fmt.Errorf("overenc: identity transcript ML-KEM key must be %d bytes, got %d", MLKEM768EKBytes, len(pub.MLKEM768))
	}
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: identity transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(leafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: identity transcript requires leaf and CA certificates")
	}

	leafHash := sha256.Sum256(leafDER)
	caHash := sha256.Sum256(caDER)
	h := sha512.New384()
	for _, field := range [][]byte{
		[]byte(identityTranscriptDomain),
		pub.X25519,
		pub.MLKEM768,
		nonce,
		leafHash[:],
		caHash[:],
	} {
		if err := writeTranscriptField(h, field); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// IdentityProofMessage returns the domain-separated message signed by the
// mesh leaf. The TEE report authenticates transcriptHash; this signature proves
// possession of the private key for the exact leaf committed by that report.
func IdentityProofMessage(transcriptHash []byte) ([]byte, error) {
	if len(transcriptHash) != sha512.Size384 {
		return nil, fmt.Errorf("overenc: identity transcript hash must be %d bytes, got %d", sha512.Size384, len(transcriptHash))
	}
	message := make([]byte, 0, 8+len(identityProofDomain)+len(transcriptHash))
	message = appendLengthPrefixed(message, []byte(identityProofDomain))
	message = appendLengthPrefixed(message, transcriptHash)
	return message, nil
}

type transcriptWriter interface {
	Write([]byte) (int, error)
}

func writeTranscriptField(w transcriptWriter, field []byte) error {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return fmt.Errorf("overenc: identity transcript field is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	if _, err := w.Write(size[:]); err != nil {
		return fmt.Errorf("overenc: hash identity transcript length: %w", err)
	}
	if _, err := w.Write(field); err != nil {
		return fmt.Errorf("overenc: hash identity transcript field: %w", err)
	}
	return nil
}

func appendLengthPrefixed(dst, field []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	dst = append(dst, size[:]...)
	return append(dst, field...)
}
