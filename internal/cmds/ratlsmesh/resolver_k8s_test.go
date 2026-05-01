package ratlsmesh

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestK8sResolverLocal(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: map[string]podEntry{
			"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-local"},  // local pod
			"10.244.1.5": {nodeIP: "10.0.0.2", uid: "uid-remote"}, // remote pod
		},
	}

	tests := []struct {
		podIP     string
		wantNode  string
		wantLocal bool
	}{
		{"10.0.0.1", "10.0.0.1", true},    // node IP = local
		{"127.0.0.1", "10.0.0.1", true},   // loopback = local
		{"::1", "10.0.0.1", true},         // IPv6 loopback = local
		{"10.244.0.5", "10.0.0.1", true},  // local pod from cache
		{"10.244.1.5", "10.0.0.2", false}, // remote pod from cache
		{"10.99.0.1", "10.99.0.1", false}, // unknown = direct fallthrough
	}

	for _, tt := range tests {
		nodeIP, local, err := r.Resolve(tt.podIP)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", tt.podIP, err)
			continue
		}
		if nodeIP != tt.wantNode || local != tt.wantLocal {
			t.Errorf("Resolve(%q) = (%q, %v), want (%q, %v)",
				tt.podIP, nodeIP, local, tt.wantNode, tt.wantLocal)
		}
	}
}

func TestK8sResolverPodEvents(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-1"},
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}, {IP: "fd00::5"}},
		},
	}

	// Add pod.
	r.onPod(pod)

	if got := r.podMap["10.244.0.5"]; got.nodeIP != "10.0.0.1" {
		t.Errorf("after add: podMap[10.244.0.5].nodeIP = %q, want 10.0.0.1", got.nodeIP)
	}
	if got := r.podMap["fd00::5"]; got.nodeIP != "10.0.0.1" {
		t.Errorf("after add: podMap[fd00::5].nodeIP = %q, want 10.0.0.1", got.nodeIP)
	}

	// Delete pod.
	r.onDeletePod(pod)

	if _, ok := r.podMap["10.244.0.5"]; ok {
		t.Error("after delete: podMap still contains 10.244.0.5")
	}
	if _, ok := r.podMap["fd00::5"]; ok {
		t.Error("after delete: podMap still contains fd00::5")
	}
}

func TestK8sResolverTombstone(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-tomb"}},
	}

	tombstone := cache.DeletedFinalStateUnknown{
		Obj: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{UID: "uid-tomb"},
			Status: corev1.PodStatus{
				PodIP:  "10.244.0.5",
				HostIP: "10.0.0.1",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
			},
		},
	}

	r.onDeletePod(tombstone)

	if _, ok := r.podMap["10.244.0.5"]; ok {
		t.Error("tombstone delete did not remove entry")
	}
}

func TestK8sResolverSkipsEmptyHostIP(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
	}

	// Pod without HostIP yet (still scheduling).
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "",
		},
	}

	r.onPod(pod)

	if _, ok := r.podMap["10.244.0.5"]; ok {
		t.Error("pod with empty HostIP should not be added to cache")
	}
}

func TestK8sResolverInformer(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "default", UID: "uid-a"},
			Status: corev1.PodStatus{
				PodIP:  "10.244.0.10",
				HostIP: "10.0.0.1",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "default", UID: "uid-b"},
			Status: corev1.PodStatus{
				PodIP:  "10.244.1.10",
				HostIP: "10.0.0.2",
				PodIPs: []corev1.PodIP{{IP: "10.244.1.10"}},
			},
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r, err := newK8sResolver(ctx, clientset, "10.0.0.1", testLogger())
	if err != nil {
		t.Fatal(err)
	}

	// pod-a is on our node → local.
	nodeIP, local, err := r.Resolve("10.244.0.10")
	if err != nil {
		t.Fatal(err)
	}
	if nodeIP != "10.0.0.1" || !local {
		t.Errorf("pod-a: got (%q, %v), want (10.0.0.1, true)", nodeIP, local)
	}

	// pod-b is on a different node → remote.
	nodeIP, local, err = r.Resolve("10.244.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if nodeIP != "10.0.0.2" || local {
		t.Errorf("pod-b: got (%q, %v), want (10.0.0.2, false)", nodeIP, local)
	}
}

func TestK8sResolverLastEventTime(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
	}

	if got := r.LastEventTime(); got != 0 {
		t.Errorf("initial LastEventTime = %d, want 0", got)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-evt"},
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}

	r.onPod(pod)

	if got := r.LastEventTime(); got <= 0 {
		t.Errorf("LastEventTime after onPod = %d, want > 0", got)
	}

	r.onDeletePod(pod)

	if got := r.LastEventTime(); got <= 0 {
		t.Errorf("LastEventTime after onDeletePod = %d, want > 0", got)
	}
}

func TestK8sResolverDeleteGuardsIPReuse(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
	}

	// Pod A gets IP 10.244.0.5.
	podA := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-a"},
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	r.onPod(podA)

	// Pod B gets the same IP (reuse) on the same node.
	podB := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-b"},
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	r.onPod(podB)

	// Late delete for Pod A arrives — must NOT remove Pod B's entry.
	r.onDeletePod(podA)

	entry, ok := r.podMap["10.244.0.5"]
	if !ok {
		t.Fatal("late delete for Pod A incorrectly removed Pod B's cache entry")
	}
	if entry.uid != types.UID("uid-b") {
		t.Errorf("entry.uid = %q, want uid-b", entry.uid)
	}

	// Delete for Pod B should remove it.
	r.onDeletePod(podB)
	if _, ok := r.podMap["10.244.0.5"]; ok {
		t.Error("delete for Pod B should have removed the entry")
	}
}
