package earclaims

import (
	"encoding/json"
	"fmt"
)

type Binding struct {
	Name   string
	Target any
}

func Bind(name string, target any) Binding {
	return Binding{Name: name, Target: target}
}

func UnmarshalObject(raw []byte, bindings ...Binding) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	for _, binding := range bindings {
		rawClaim, ok := object[binding.Name]
		if !ok || len(rawClaim) == 0 {
			continue
		}
		if err := json.Unmarshal(rawClaim, binding.Target); err != nil {
			return fmt.Errorf("parse %s claim: %w", binding.Name, err)
		}
	}
	return nil
}
