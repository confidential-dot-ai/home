package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha2 "github.com/lunal-dev/c8s/api/v1alpha2"
	"github.com/lunal-dev/c8s/internal/webhook"
)

// statusMirrorRequeue keeps the per-pod summary loosely current without
// hammering the API server. The reconciler watches CW only (not pods), so
// pod-readiness transitions are picked up at this cadence.
const statusMirrorRequeue = 30 * time.Second

// ConfidentialWorkloadReconciler is a status-mirror controller. It lists
// pods carrying confidential.ai/cw=<cwName> in the CW's namespace and
// aggregates a Total / Attested summary into status. No security gates
// live here.
type ConfidentialWorkloadReconciler struct {
	client.Client
}

func (r *ConfidentialWorkloadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("cwl", req.NamespacedName)

	var cw v1alpha2.ConfidentialWorkload
	if err := r.Get(ctx, req.NamespacedName, &cw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	previous := cw.Status.DeepCopy()

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(cw.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pods: %w", err)
	}

	summary := v1alpha2.AttestationSummary{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Annotations[webhook.AnnotationWorkload] != cw.Name {
			continue
		}
		summary.Total++
		if isPodReady(pod) {
			summary.Attested++
		}
	}
	cw.Status.AttestationSummary = &summary
	cw.Status.ObservedGeneration = cw.Generation

	cond := metav1.Condition{
		Type:               v1alpha2.ConditionAttested,
		ObservedGeneration: cw.Generation,
	}
	switch {
	case summary.Total == 0:
		cond.Status = metav1.ConditionUnknown
		cond.Reason = "NoPods"
		cond.Message = "no pods carry the confidential.ai/cw annotation"
	case summary.Attested == summary.Total:
		cond.Status = metav1.ConditionTrue
		cond.Reason = "AllAttested"
		cond.Message = fmt.Sprintf("%d/%d pods attested", summary.Attested, summary.Total)
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "PendingAttestation"
		cond.Message = fmt.Sprintf("%d/%d pods attested", summary.Attested, summary.Total)
	}
	meta.SetStatusCondition(&cw.Status.Conditions, cond)

	if equality.Semantic.DeepEqual(previous, &cw.Status) {
		return ctrl.Result{RequeueAfter: statusMirrorRequeue}, nil
	}
	if err := r.Status().Update(ctx, &cw); err != nil {
		return ctrl.Result{}, fmt.Errorf("status update: %w", err)
	}

	l.V(1).Info("status mirrored", "total", summary.Total, "attested", summary.Attested)
	return ctrl.Result{RequeueAfter: statusMirrorRequeue}, nil
}

// isPodReady is the heuristic for "this pod has attested": the kubelet has
// reported PodReady, which means c8s-init-cert (the init container) exited
// 0 — and that only happens after a successful attestation round-trip with
// CDS.
func isPodReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (r *ConfidentialWorkloadReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.ConfidentialWorkload{}).
		Named("confidentialworkload-status-mirror").
		Complete(r)
}
