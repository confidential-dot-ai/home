package ratlsmesh

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

var defaultMeshExcludedSourceNamespaces = []string{
	"kube-system",
}

func defaultMeshExcludedSourceNamespacesCSV() string {
	return strings.Join(defaultMeshExcludedSourceNamespaces, ",")
}

func parseExcludedNamespaces(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		ns := strings.TrimSpace(part)
		if ns == "" {
			continue
		}
		out[ns] = struct{}{}
	}
	return out
}

func podEligibleForMeshEndpoint(pod *corev1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed
}

func podEligibleForMeshSource(pod *corev1.Pod, excludedNamespaces map[string]struct{}) bool {
	if !podEligibleForMeshEndpoint(pod) {
		return false
	}
	_, excluded := excludedNamespaces[pod.Namespace]
	return !excluded
}
