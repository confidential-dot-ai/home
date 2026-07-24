package luks

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Flag validation shared by every subcommand. workload/name/namespace feed KV
// paths, kubectl argv, and device names, so each must be a DNS-1123 label —
// no separators, no dots, no leading '-'.

func validateWorkload(workload string) error {
	if workload == "" {
		return errors.New("--workload is required")
	}
	if errs := validation.IsDNS1123Label(workload); len(errs) > 0 {
		return fmt.Errorf("--workload %q must be a DNS-1123 label: %v", workload, errs)
	}
	return nil
}

func validateWorkloadName(workload, name string) error {
	if workload == "" || name == "" {
		return errors.New("--workload and --name are required")
	}
	if err := validateWorkload(workload); err != nil {
		return err
	}
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("--name %q must be a DNS-1123 label: %v", name, errs)
	}
	return nil
}

func validateNamespace(ns string) error {
	if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
		return fmt.Errorf("--namespace %q must be a DNS-1123 label: %v", ns, errs)
	}
	return nil
}
