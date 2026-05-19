package earclaims

import (
	"encoding/json"
	"fmt"
)

func LaunchDigestFromSubmods(raw json.RawMessage) (string, error) {
	var attester json.RawMessage
	if err := UnmarshalObject(raw, Bind(SubmodAttester, &attester)); err != nil {
		return "", fmt.Errorf("parse %s: %w", Submods, err)
	}
	if len(attester) == 0 {
		return "", fmt.Errorf("missing %s in EAR %s", SubmodAttester, Submods)
	}

	var launchDigest string
	if err := UnmarshalObject(attester, Bind(LaunchDigest, &launchDigest)); err != nil {
		return "", err
	}
	if launchDigest == "" {
		return "", fmt.Errorf("missing %s in EAR %s", LaunchDigest, Submods)
	}

	return launchDigest, nil
}
