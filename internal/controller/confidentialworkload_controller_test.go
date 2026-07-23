package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha2 "github.com/confidential-dot-ai/c8s/api/v1alpha2"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// cwPod builds a pod carrying the cw workload annotation; ready toggles the
// PodReady=True condition that isPodReady keys on.
func cwPod(name, ns, cwName string, ready bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: map[string]string{webhook.AnnotationWorkload: cwName},
		},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}
	} else {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionFalse},
		}
	}
	return p
}

func confidentialWorkload(ns, name string, generation int64) *v1alpha2.ConfidentialWorkload {
	return &v1alpha2.ConfidentialWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: generation},
		Spec: v1alpha2.ConfidentialWorkloadSpec{
			WorkloadRef: v1alpha2.WorkloadRef{Kind: v1alpha2.WorkloadKindDeployment, Name: name},
		},
	}
}

func cwReconcilerFor(objs ...client.Object) *ConfidentialWorkloadReconciler {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha2.ConfidentialWorkload{}).
		Build()
	return &ConfidentialWorkloadReconciler{Client: c}
}

func cwReconcile(t *testing.T, r *ConfidentialWorkloadReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return res
}

func getCW(t *testing.T, c client.Client, ns, name string) *v1alpha2.ConfidentialWorkload {
	t.Helper()
	var cw v1alpha2.ConfidentialWorkload
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &cw); err != nil {
		t.Fatalf("get ConfidentialWorkload %s/%s: %v", ns, name, err)
	}
	return &cw
}

func TestConfidentialWorkloadResolvesWorkloadRefCWID(t *testing.T) {
	const ns = "tenant"
	// The referenced workload's pods carry cw id "api-id", which differs from
	// the CW object's own name "cw-name". Matching on cw.Name (the pre-fix
	// behavior) would count the wrong pod; resolving spec.workloadRef finds the
	// real member pods (M-09).
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api-deploy", Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{webhook.AnnotationWorkload: "api-id"},
				},
			},
		},
	}
	cw := &v1alpha2.ConfidentialWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "cw-name", Namespace: ns, Generation: 1},
		Spec: v1alpha2.ConfidentialWorkloadSpec{
			WorkloadRef: v1alpha2.WorkloadRef{Kind: v1alpha2.WorkloadKindDeployment, Name: "api-deploy"},
		},
	}
	// Two member pods carry the workload's cw id; a decoy pod carries the CW
	// object name and must NOT be counted.
	p1 := cwPod("p1", ns, "api-id", true)
	p2 := cwPod("p2", ns, "api-id", false)
	decoy := cwPod("decoy", ns, "cw-name", true)

	r := cwReconcilerFor(cw, dep, p1, p2, decoy)
	cwReconcile(t, r, ns, "cw-name")

	sum := getCW(t, r.Client, ns, "cw-name").Status.AttestationSummary
	if sum == nil || sum.Total != 2 || sum.Attested != 1 {
		t.Fatalf("summary = %#v, want Total=2 Attested=1 (matched via workloadRef cw id, decoy excluded)", sum)
	}
}

func TestConfidentialWorkloadReconcileNotFoundIsNoOp(t *testing.T) {
	r := cwReconcilerFor()
	res := cwReconcile(t, r, "tenant", "missing")
	// IgnoreNotFound: no error, no requeue scheduled.
	if res.RequeueAfter != 0 {
		t.Fatalf("requeue = %v, want 0 for a missing CW", res.RequeueAfter)
	}
}

func TestConfidentialWorkloadReconcileNoPods(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 3)
	r := cwReconcilerFor(cw)

	res := cwReconcile(t, r, "tenant", "wl")
	if res.RequeueAfter != statusMirrorRequeue {
		t.Fatalf("requeue = %v, want %v", res.RequeueAfter, statusMirrorRequeue)
	}

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary == nil ||
		got.Status.AttestationSummary.Total != 0 || got.Status.AttestationSummary.Attested != 0 {
		t.Fatalf("summary = %#v, want 0/0", got.Status.AttestationSummary)
	}
	if got.Status.ObservedGeneration != 3 {
		t.Fatalf("observedGeneration = %d, want 3", got.Status.ObservedGeneration)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha2.ConditionAttested)
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "NoPods" {
		t.Fatalf("condition = %#v, want Unknown/NoPods", cond)
	}
}

func TestConfidentialWorkloadReconcileAllAttested(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(
		cw,
		cwPod("p1", "tenant", "wl", true),
		cwPod("p2", "tenant", "wl", true),
		// Different workload in the same namespace: must not be counted.
		cwPod("other", "tenant", "elsewhere", true),
		// No cw annotation: ignored.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "tenant"}},
	)

	cwReconcile(t, r, "tenant", "wl")

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary.Total != 2 || got.Status.AttestationSummary.Attested != 2 {
		t.Fatalf("summary = %#v, want 2/2", got.Status.AttestationSummary)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha2.ConditionAttested)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "AllAttested" {
		t.Fatalf("condition = %#v, want True/AllAttested", cond)
	}
}

func TestConfidentialWorkloadReconcilePartialAttestation(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(
		cw,
		cwPod("ready", "tenant", "wl", true),
		cwPod("pending", "tenant", "wl", false),
	)

	cwReconcile(t, r, "tenant", "wl")

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary.Total != 2 || got.Status.AttestationSummary.Attested != 1 {
		t.Fatalf("summary = %#v, want 1/2", got.Status.AttestationSummary)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha2.ConditionAttested)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "PendingAttestation" {
		t.Fatalf("condition = %#v, want False/PendingAttestation", cond)
	}
}

func TestConfidentialWorkloadReconcileIgnoresOtherNamespace(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(
		cw,
		// Same cw name but a different namespace: List is namespace-scoped, so
		// this pod must not be counted.
		cwPod("foreign", "other", "wl", true),
	)

	cwReconcile(t, r, "tenant", "wl")

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary.Total != 0 {
		t.Fatalf("total = %d, want 0 (pod is in another namespace)", got.Status.AttestationSummary.Total)
	}
}

func TestConfidentialWorkloadReconcileIsIdempotent(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(cw, cwPod("p1", "tenant", "wl", true))

	cwReconcile(t, r, "tenant", "wl")
	first := getCW(t, r.Client, "tenant", "wl")
	firstRV := first.ResourceVersion

	// A second reconcile with unchanged state must short-circuit on the
	// DeepEqual guard and not bump the resourceVersion via a status update.
	res := cwReconcile(t, r, "tenant", "wl")
	if res.RequeueAfter != statusMirrorRequeue {
		t.Fatalf("requeue = %v, want %v", res.RequeueAfter, statusMirrorRequeue)
	}
	second := getCW(t, r.Client, "tenant", "wl")
	if second.ResourceVersion != firstRV {
		t.Fatalf("resourceVersion changed on no-op reconcile: %q -> %q", firstRV, second.ResourceVersion)
	}
}

func TestIsPodReady(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"ready", cwPod("a", "ns", "wl", true), true},
		{"not ready", cwPod("b", "ns", "wl", false), false},
		{"no conditions", &corev1.Pod{}, false},
		{
			name: "other condition true only",
			pod: &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
				{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
			}}},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPodReady(tc.pod); got != tc.want {
				t.Fatalf("isPodReady = %v, want %v", got, tc.want)
			}
		})
	}
}
