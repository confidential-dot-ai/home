package policymonitor

import (
	"context"
	"log/slog"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// containerNameAnnotations are the CRI annotation keys carrying a container's
// name, used to exclude the webhook-injected sidecars from the workload digest.
var containerNameAnnotations = []string{
	"io.kubernetes.cri.container-name",  // containerd CRI
	"io.kubernetes.cri-o.ContainerName", // CRI-O
}

// workloadBroker serves the kata-guest workload-claims flow
// (docs/ratls.md). A kata guest holds exactly one pod, so there is
// no caller to disambiguate: the broker returns that pod's admitted,
// non-injected container digests, fed from the same admission decisions
// policy-monitor already makes. It listens on a Unix socket inside the
// measured guest — the same transport nri-image-policy uses on node-CVM,
// bind-mounted into the pod — so no host-reachable socket and no
// peer-credential check are needed; the guest boundary is the isolation.
type workloadBroker struct {
	mu         sync.RWMutex
	containers map[string]workloadclaims.Container // container id -> name+digest
}

func newWorkloadBroker() *workloadBroker {
	return &workloadBroker{containers: map[string]workloadclaims.Container{}}
}

// record notes an admitted container's name, digest, and argv. Injected
// containers (the get-cert sidecar and its wait gate) are skipped by name so
// the workload digest covers only the app's own images. args is the merged
// argv from the container's OCI process.args — what kata-agent will exec —
// which the (image, argv) commitment folds in
// (docs/ratls.md).
func (b *workloadBroker) record(cid, name, digest string, args []string) {
	if workloadclaims.IsInjectedContainer(name) || digest == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	argsCopy := append([]string(nil), args...)
	b.containers[cid] = workloadclaims.Container{Name: name, Digest: digest, Args: argsCopy}
}

// ContainersForPeer returns every admitted, non-injected container in the
// guest's single pod. The peer PID is ignored: the guest boundary is the
// isolation, so there is nothing to bind the caller to.
func (b *workloadBroker) ContainersForPeer(_ int) ([]workloadclaims.Container, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]workloadclaims.Container, 0, len(b.containers))
	for _, c := range b.containers {
		out = append(out, c)
	}
	return out, nil
}

// containerName extracts a container's name from its OCI annotations, or ""
// when absent (then it is treated as a non-injected app container).
func containerName(annotations map[string]string) string {
	for _, key := range containerNameAnnotations {
		if v := annotations[key]; v != "" {
			return v
		}
	}
	return ""
}

// startWorkloadClaimsBroker serves the broker on a Unix socket the guest
// bind-mounts into the pod's containers, the same transport nri-image-policy
// uses on node-CVM (docs/ratls.md). The shared socket path lets get-cert dial
// one compiled endpoint in both shapes.
func startWorkloadClaimsBroker(ctx context.Context, logger *slog.Logger, broker *workloadBroker, socketPath string) error {
	l, err := workloadclaims.ListenUnix(socketPath, workloadclaims.BrokerSocketGID)
	if err != nil {
		return err
	}
	go func() {
		logger.Info("starting workload-claims broker", "socket", socketPath)
		if err := workloadclaims.Serve(ctx, l, broker); err != nil {
			logger.Error("workload-claims broker error", "error", err)
		}
	}()
	return nil
}
