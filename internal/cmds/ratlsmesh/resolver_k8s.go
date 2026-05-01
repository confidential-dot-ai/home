package ratlsmesh

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// podEntry stores the node IP and pod UID for a cache entry. The UID guards
// against stale delete events removing a newer pod's entry after IP reuse.
type podEntry struct {
	nodeIP string
	uid    types.UID
}

// k8sResolver watches K8s Pods and maps podIP → nodeIP (hostIP).
// Trust model: the API server provides routing hints; RA-TLS attestation
// is the actual trust boundary. A compromised control plane can cause DoS
// (handshake failure to non-TEE node) but never data leakage.
type k8sResolver struct {
	nodeIP string
	logger *slog.Logger

	mu            sync.RWMutex
	podMap        map[string]podEntry // podIP → {hostIP, podUID}
	lastEventTime atomic.Int64        // Unix timestamp of last successful informer event
}

// newK8sResolver creates a resolver backed by a K8s Pod informer.
// It blocks until the initial cache sync completes.
func newK8sResolver(ctx context.Context, clientset kubernetes.Interface, nodeIP string, logger *slog.Logger) (*k8sResolver, error) {
	r := &k8sResolver{
		nodeIP: nodeIP,
		logger: logger,
		podMap: make(map[string]podEntry),
	}

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { r.onPod(obj) },
		UpdateFunc: func(_, obj interface{}) { r.onPod(obj) },
		DeleteFunc: func(obj interface{}) { r.onDeletePod(obj) },
	}); err != nil {
		return nil, fmt.Errorf("k8s resolver: add event handler: %w", err)
	}

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return nil, fmt.Errorf("k8s resolver: cache sync failed")
	}

	r.lastEventTime.Store(time.Now().Unix())

	r.mu.RLock()
	count := len(r.podMap)
	r.mu.RUnlock()
	logger.Info("k8s resolver ready", "pods", count)

	return r, nil
}

func (r *k8sResolver) onPod(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	hostIP := pod.Status.HostIP
	if hostIP == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry := podEntry{nodeIP: hostIP, uid: pod.UID}
	if pod.Status.PodIP != "" {
		r.podMap[pod.Status.PodIP] = entry
	}
	for _, pip := range pod.Status.PodIPs {
		if pip.IP != "" {
			r.podMap[pip.IP] = entry
		}
	}

	r.lastEventTime.Store(time.Now().Unix())
}

func (r *k8sResolver) onDeletePod(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Only delete if the cached entry's UID matches this pod. A late delete
	// event must not remove a newer pod's entry after IP reuse — comparing
	// UIDs (not just hostIP) handles same-node IP reuse correctly.
	if e, ok := r.podMap[pod.Status.PodIP]; ok && e.uid == pod.UID {
		delete(r.podMap, pod.Status.PodIP)
	}
	for _, pip := range pod.Status.PodIPs {
		if e, ok := r.podMap[pip.IP]; ok && e.uid == pod.UID {
			delete(r.podMap, pip.IP)
		}
	}

	r.lastEventTime.Store(time.Now().Unix())
}

// LastEventTime returns the Unix timestamp of the last successful informer event.
// Returns 0 if no events have been processed yet.
func (r *k8sResolver) LastEventTime() int64 {
	return r.lastEventTime.Load()
}

// CacheSize returns the number of pod→node mappings in the cache.
func (r *k8sResolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.podMap)
}

// ValidateLocalDest returns true if ip is a pod running on this node
// (or loopback/nodeIP). Used to prevent the inbound listener from being
// used as an open relay to arbitrary destinations.
func (r *k8sResolver) ValidateLocalDest(ip string) bool {
	if ip == "127.0.0.1" || ip == "::1" || ip == r.nodeIP {
		return true
	}
	r.mu.RLock()
	entry, found := r.podMap[ip]
	r.mu.RUnlock()
	return found && entry.nodeIP == r.nodeIP
}

// Resolve maps a pod IP to its node IP. Loopback and the local node IP are
// always treated as local. Unknown IPs (service VIPs, external) fall through
// as remote with the original IP used as the dial target.
func (r *k8sResolver) Resolve(podIP string) (string, bool, error) {
	if podIP == "127.0.0.1" || podIP == "::1" || podIP == r.nodeIP {
		return r.nodeIP, true, nil
	}

	r.mu.RLock()
	entry, found := r.podMap[podIP]
	r.mu.RUnlock()

	if !found {
		r.logger.Debug("pod IP not in cache, treating as direct", "podIP", podIP)
		return podIP, false, nil
	}

	return entry.nodeIP, entry.nodeIP == r.nodeIP, nil
}
