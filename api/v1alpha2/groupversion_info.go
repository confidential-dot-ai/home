// Package v1alpha2 contains the confidential.ai/v1alpha2 CRD types.
//
// The cluster runs without these CRDs installed. They exist as a UX overlay
// for `kubectl get td` / `kubectl get cwl` and to mirror per-pod attestation
// state into a status surface. Sidecar injection, cert issuance, and image
// policy enforcement do not consult these types — the webhook keys off pod
// annotations and CDS / the NRI plugin hold the actual gates.
//
// +kubebuilder:object:generate=true
// +groupName=confidential.ai
package v1alpha2

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion = schema.GroupVersion{Group: "confidential.ai", Version: "v1alpha2"}

	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	AddToScheme = SchemeBuilder.AddToScheme
)
