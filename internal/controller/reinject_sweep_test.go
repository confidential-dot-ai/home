package controller

import (
	"context"
	"slices"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/lunal-dev/c8s/internal/webhook"
)

// pod builds a test pod. ownerKind == "" means a bare (unowned) pod.
func pod(name, ns, ownerKind string, ann map[string]string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann},
	}
	if ownerKind != "" {
		controller := true
		p.OwnerReferences = []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: ownerKind, Name: name + "-owner", UID: types.UID("uid-" + name), Controller: &controller},
		}
	}
	return p
}

func TestReinjectSweepDeletesOnlyOwnedUninjectedWorkloadPods(t *testing.T) {
	cw := map[string]string{webhook.AnnotationWorkload: "wl"}
	cwInjected := map[string]string{webhook.AnnotationWorkload: "wl", webhook.AnnotationInjected: "true"}

	pods := []client.Object{
		// Deleted: owned, cw, never injected, covered namespace.
		pod("needs", "tenant", "ReplicaSet", cw),
		pod("needs-sts", "tenant", "StatefulSet", cw),
		// Kept: already injected.
		pod("injected", "tenant", "ReplicaSet", cwInjected),
		// Kept: no cw annotation (not opted in).
		pod("no-cw", "tenant", "ReplicaSet", nil),
		// Kept: bare pod (no controller would recreate it).
		pod("bare", "tenant", "", cw),
		// Kept: excluded namespace (webhook never injects there).
		pod("in-release", "c8s-system", "ReplicaSet", cw),
		pod("in-kube", "kube-system", "ReplicaSet", cw),
		pod("in-extra", "skip-me", "ReplicaSet", cw),
	}

	c := fake.NewClientBuilder().WithObjects(pods...).Build()
	excluded := excludedNamespaceSet("c8s-system", []string{"skip-me"})

	if err := reinjectSweep(context.Background(), c, excluded); err != nil {
		t.Fatalf("reinjectSweep: %v", err)
	}

	var remaining corev1.PodList
	if err := c.List(context.Background(), &remaining); err != nil {
		t.Fatalf("list: %v", err)
	}
	got := make([]string, 0, len(remaining.Items))
	for _, p := range remaining.Items {
		got = append(got, p.Name)
	}
	sort.Strings(got)

	want := []string{"bare", "in-extra", "in-kube", "in-release", "injected", "no-cw"}
	if !slices.Equal(got, want) {
		t.Fatalf("surviving pods = %v, want %v", got, want)
	}
}

func TestNeedsReinject(t *testing.T) {
	excluded := excludedNamespaceSet("c8s-system", nil)
	cw := map[string]string{webhook.AnnotationWorkload: "wl"}

	tests := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"opted-in uninjected", pod("a", "tenant", "ReplicaSet", cw), true},
		{"no cw", pod("b", "tenant", "ReplicaSet", nil), false},
		{"already injected", pod("c", "tenant", "ReplicaSet", map[string]string{
			webhook.AnnotationWorkload: "wl", webhook.AnnotationInjected: "true",
		}), false},
		{"excluded namespace", pod("d", "c8s-system", "ReplicaSet", cw), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsReinject(tc.pod, excluded); got != tc.want {
				t.Fatalf("needsReinject = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNeedsReinjectSkipsTerminatingPod(t *testing.T) {
	excluded := excludedNamespaceSet("c8s-system", nil)
	p := pod("term", "tenant", "ReplicaSet", map[string]string{webhook.AnnotationWorkload: "wl"})
	now := metav1.Now()
	p.DeletionTimestamp = &now
	if needsReinject(p, excluded) {
		t.Fatal("terminating pod should not be swept")
	}
}
