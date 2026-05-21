package attestclient

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// hclReportMagic is the first four bytes of an AKS HCL envelope.
const hclReportMagic = "HCLA"

// azureHeader is the 32-byte little-endian header that AKS prepends to the
// raw hardware attestation report when it serves az-snp / az-tdx evidence.
// Field names and ordering match Fraunhofer-AISEC/cmc verifier/azure.go.
// PayloadSize observed on real AKS az-snp evidence is the byte length of the
// post-header payload (hw_report + AzureRuntimeData), not the hw_report size
// alone, so the only field used for routing here is Signature; downstream
// SNP signature verification is the trust gate.
type azureHeader struct {
	Signature   [4]byte
	Version     uint32
	PayloadSize uint32
	RequestType uint32
	Status      [4]byte
	Reserved    [12]byte
}

// snpReportEnvelope holds the fields we care about inside the inner evidence
// blob returned by the attestation service. Bare-metal SNP carries the raw
// report under attestation_report (standard base64); vTPM (az-snp, az-tdx)
// carries it inside hcl_report (URL-safe base64, no padding).
type snpReportEnvelope struct {
	AttestationReport string `json:"attestation_report"`
	HCLReport         string `json:"hcl_report"`
}

// ExtractSNPReport returns the raw SNP report bytes (as a string) from the
// attestation service's evidence envelope, picking the right field and
// base64 alphabet for the platform. Callers feed this into raTLS as the
// per-connection self-attestation payload.
func ExtractSNPReport(resp types.AttestResponse) (string, error) {
	var envelope snpReportEnvelope
	if err := json.Unmarshal(resp.Evidence, &envelope); err != nil {
		return "", fmt.Errorf("parse attestation evidence: %w", err)
	}

	switch {
	case envelope.AttestationReport != "":
		raw, err := base64.StdEncoding.DecodeString(envelope.AttestationReport)
		if err != nil {
			return "", fmt.Errorf("decode attestation_report: %w", err)
		}
		return string(raw), nil
	case envelope.HCLReport != "":
		raw, err := base64.RawURLEncoding.DecodeString(envelope.HCLReport)
		if err != nil {
			return "", fmt.Errorf("decode hcl_report: %w", err)
		}
		raw, err = unwrapHCLReport(raw)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	default:
		return "", fmt.Errorf("attestation evidence contains neither attestation_report nor hcl_report (platform: %s)", resp.Platform)
	}
}

func unwrapHCLReport(raw []byte) ([]byte, error) {
	if len(raw) == ratls.SNPReportSize {
		return raw, nil
	}
	var hdr azureHeader
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("hcl_report is %d bytes, too short for HCL envelope: %w", len(raw), err)
	}
	if !bytes.Equal(hdr.Signature[:], []byte(hclReportMagic)) {
		return nil, fmt.Errorf("hcl_report missing %q signature", hclReportMagic)
	}
	headerSize := binary.Size(hdr)
	end := headerSize + ratls.SNPReportSize
	if len(raw) < end {
		return nil, fmt.Errorf("hcl_report is %d bytes, need at least %d", len(raw), end)
	}
	return raw[headerSize:end], nil
}
