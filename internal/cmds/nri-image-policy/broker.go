package nriimagepolicy

import (
	"fmt"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// workloadBroker answers "which admitted, non-injected container image digests
// belong to the pod of the calling process" for the node-CVM workload-claims
// flow (docs/ratls.md). It is fed from the same CreateContainer /
// Synchronize events that drive enforcement, so what it vouches for is exactly
// what was admitted. Caller identity comes from the kernel (SO_PEERCRED →
// cgroup → container), never from the request.
type workloadBroker struct {
	mu         sync.RWMutex
	containers map[string]ctrRec // containerID -> record
	procRoot   string
}

type ctrRec struct {
	sandboxID string
	name      string
	digest    string   // canonical sha256:<hex>; "" when unresolved
	args      []string // NRI's merged entrypoint+cmd argv (docs/ratls.md)
}

func newWorkloadBroker(procRoot string) *workloadBroker {
	return &workloadBroker{
		containers: map[string]ctrRec{},
		procRoot:   procRoot,
	}
}

// record notes an admitted container. Injected containers (the get-cert
// sidecar and its wait gate) are recorded too but excluded at query time by
// name (workloadclaims.IsInjectedContainer) — the sidecar attests the app's
// images, not its own. args is NRI's merged argv the runtime will exec,
// which the (image, argv) commitment folds in (docs/ratls.md).
func (b *workloadBroker) record(containerID, sandboxID, name, digest string, args []string) {
	if containerID == "" || sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Copy args: NRI reuses its slice across events, and the broker holds this
	// value until eviction — a later mutation upstream must not race the answer.
	argsCopy := append([]string(nil), args...)
	b.containers[containerID] = ctrRec{sandboxID: sandboxID, name: name, digest: digest, args: argsCopy}
}

// remove evicts a container that stopped, so its digest can't linger in a
// later pod's answer (container IDs are unique, but eviction keeps the map
// bounded and correct across pod churn).
func (b *workloadBroker) remove(containerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.containers, containerID)
}

// ContainersForPeer resolves the calling process to its pod and returns that
// pod's admitted, non-injected containers (name + digest). peerPID 0 is
// rejected: on node-CVM the broker MUST bind the caller via kernel credentials.
func (b *workloadBroker) ContainersForPeer(peerPID int) ([]workloadclaims.Container, error) {
	if peerPID <= 0 {
		return nil, fmt.Errorf("no peer credentials on the broker connection")
	}
	candidates, err := workloadclaims.ContainerIDCandidatesForPID(b.procRoot, peerPID)
	if err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Resolve the shallowest candidate that is a tracked container: the
	// caller's own runtime-assigned scope is always an ancestor of any cgroup
	// it could nest, so this defeats a caller that names a child cgroup with a
	// victim's container ID (see ContainerIDCandidatesForPID).
	var caller ctrRec
	found := false
	for _, id := range candidates {
		if rec, ok := b.containers[id]; ok {
			caller = rec
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("caller cgroup names no tracked container")
	}

	var out []workloadclaims.Container
	for _, rec := range b.containers {
		if rec.sandboxID != caller.sandboxID || rec.digest == "" {
			continue
		}
		if workloadclaims.IsInjectedContainer(rec.name) {
			continue
		}
		out = append(out, workloadclaims.Container{Name: rec.name, Digest: rec.digest, Args: rec.args})
	}
	return out, nil
}
