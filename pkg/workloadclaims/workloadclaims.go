// Package workloadclaims implements the workload-digest layer of the RA-TLS
// config-claims (docs/ratls.md): the canonical hash over a pod's
// admitted container image digests, and the node-local broker protocol
// get-cert uses to learn its own pod's digests from the component that
// admitted them (nri-image-policy on node-CVM, policy-monitor in a kata
// guest). The broker binds the answer to the calling pod via kernel peer
// credentials, never via anything the caller sends.
package workloadclaims

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ReservedInjectedNames are the container names the c8s webhook injects into a
// workload pod (the get-cert sidecar and its wait gate). Brokers exclude them
// from the workload digest: injected infrastructure is vouched by the node
// measurement or the measured guest image, and self-assertion by the asserter
// adds nothing (docs/ratls.md). The webhook rejects user pods that
// define a container with one of these names, so exclusion-by-name cannot be
// abused to hide a workload image.
var ReservedInjectedNames = []string{"c8s-cert", "c8s-cert-wait"}

// IsInjectedContainer reports whether name is a c8s-injected container to
// exclude from the workload digest.
func IsInjectedContainer(name string) bool {
	for _, n := range ReservedInjectedNames {
		if name == n {
			return true
		}
	}
	return false
}

// DigestsPath is the broker's single route.
const DigestsPath = "/v1/workload-digests"

// SocketName is the fixed filename of the broker's Unix socket, and
// SidecarSocketDir is where the socket directory is presented inside the
// c8s-cert sidecar. Both are compiled constants, not deployment values:
// get-cert dials BrokerEndpoint (built from them) as a baked path, so the
// control plane cannot redirect the fetch to a rogue broker
// (docs/getcert-workload-binding.md Corner 5). The broker (nri-image-policy on
// node-CVM, policy-monitor in the kata guest) creates its socket as SocketName
// under its configured directory; the platform maps that directory to
// SidecarSocketDir in the pod (a webhook hostPath mount on node-CVM, a guest
// bind-mount under kata).
const (
	SocketName       = "workload-claims.sock"
	SidecarSocketDir = "/run/c8s/workload-claims"
)

// BrokerEndpoint is get-cert's compiled broker endpoint: the in-sidecar Unix
// socket path, fixed at build time so it is not control-plane-supplied. Both
// deployment shapes present the socket here.
func BrokerEndpoint() string {
	return "unix://" + SidecarSocketDir + "/" + SocketName
}

// BrokerSocketGID owns the broker's Unix socket. The broker runs as root, but
// get-cert connects as the non-root c8s UID/GID over a read-only mount; a
// root:root 0660 socket is unreachable by that caller (connect needs write
// permission on the socket node), so the connect would fail closed and issuance
// would hang. The broker chgrps the socket to this group and the webhook
// injects it as a supplemental group on the get-cert sidecar
// (pod_mutator.go, ensureSupplementalGroup) — together they let the non-root
// caller connect. Reuses the c8s distroless nonroot GID, so a default get-cert
// (RunAsGroup 65532) also reaches it via its primary group. Connecting to a
// socket is exempt from the read-only-mount write block (sockets are not
// regular files), so the RO mount still prevents a socket-file swap without
// blocking the connect. See docs/pitfalls.md.
const BrokerSocketGID = 65532

// ListenUnix binds a broker's Unix socket at socketPath: it removes a stale
// socket file first (so a broker restart does not fail with EADDRINUSE), chmods
// the socket to 0660, and (when gid > 0) chgrps it to gid so a non-root caller
// in that group can connect. Caller binding is by kernel peer credentials, so
// the mode and group gate reachability only, not authorization.
func ListenUnix(socketPath string, gid int) (net.Listener, error) {
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod %s: %w", socketPath, err)
	}
	if gid > 0 {
		if err := os.Chown(socketPath, -1, gid); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("chgrp %s to gid %d: %w", socketPath, gid, err)
		}
	}
	return l, nil
}

// maxResponseBytes bounds a broker response; a pod has a handful of
// containers, each digest 71 bytes.
const maxResponseBytes = 1 << 20

// Container is one admitted, non-injected container of the calling pod: its
// name (so get-cert can split it into the init/main role its pod spec
// declares), its resolved image digest, and the merged argv the runtime will
// exec (image-config entrypoint+cmd overlaid with pod-spec command+args, as
// NRI's api.Container.Args or an OCI process.args reports it). Args feeds the
// per-container leaf in WorkloadArgsDigest (docs/ratls.md);
// nil is treated as an empty list, never as a "don't bind" sentinel — a
// missing argv is a bug in the broker path, not a wildcard.
type Container struct {
	Name   string   `json:"name"`
	Digest string   `json:"digest"`
	Args   []string `json:"args"`
}

// Response is the broker's answer: the admitted, non-injected containers of
// the calling pod.
type Response struct {
	Containers []Container `json:"containers"`
}

// roleInit / roleMain label the two container-role partitions in the workload
// digest preimage (docs/ratls.md). A digest cannot contain these
// bytes (it is sha256:<hex>), so the labels unambiguously separate the sets.
const (
	roleInit = "init\n"
	roleMain = "main\n"
)

// Domain-separation prefixes for the (image, argv) commitment
// (docs/ratls.md). The container-leaf and role-hash
// prefixes are disjoint from the image-only WorkloadDigest transcript, and
// from each other, so no cross-format substring can collide.
const (
	containerLeafDomain = "c8s/workload/container/v1\n"
	argsDigestDomain    = "c8s/workload/args/v1\n"
)

// Digest returns the canonical workload digest (docs/ratls.md):
// SHA-256 over the init image set then the main image set, each sorted,
// deduplicated, canonicalized and role-labeled. Order-independent WITHIN a
// role (restart churn does not move it) but role-distinguishing ACROSS roles,
// so {init:A, main:B} and {init:B, main:A} differ. Both sets empty is an
// error: a pod runs at least one non-injected container, so an empty claim
// can only be a bug and must fail closed rather than attest an empty workload.
func Digest(initImages, mainImages []string) ([]byte, error) {
	if len(initImages) == 0 && len(mainImages) == 0 {
		return nil, fmt.Errorf("workloadclaims: no container digests to hash")
	}
	h := sha256.New()
	for _, part := range []struct {
		role   string
		images []string
	}{{roleInit, initImages}, {roleMain, mainImages}} {
		h.Write([]byte(part.role))
		if err := writeImageSet(h, part.images); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// writeImageSet writes the sorted, deduplicated, canonical sha256:<hex>
// strings of images into h, each terminated by '\n'.
func writeImageSet(h hash.Hash, images []string) error {
	canonical := make([]string, 0, len(images))
	for _, d := range images {
		parsed, err := types.ParseDigest(d)
		if err != nil {
			return fmt.Errorf("workloadclaims: %w", err)
		}
		canonical = append(canonical, parsed.String())
	}
	sort.Strings(canonical)
	prev := ""
	for _, d := range canonical {
		if d == prev {
			continue
		}
		h.Write([]byte(d))
		h.Write([]byte{'\n'})
		prev = d
	}
	return nil
}

// containerLeaf returns the length-framed identity commitment for one
// admitted container (docs/ratls.md):
//
//	SHA-256(
//	    "c8s/workload/container/v1\n"
//	    "image\n" || canonical(sha256:HEX) || "\n"
//	    "argv\n"  || uint32-BE(len(argv))
//	            || (uint32-BE(len(argv[i])) || argv[i])*
//	            || "\n"
//	)
//
// Length framing at every level makes the preimage unambiguous regardless of
// what bytes an argv element contains, so no separator-lookalike inside argv
// can collide with a distinct (image, argv) pair.
func containerLeaf(imageDigest string, args []string) ([]byte, error) {
	parsed, err := types.ParseDigest(imageDigest)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(containerLeafDomain))
	h.Write([]byte("image\n"))
	h.Write([]byte(parsed.String()))
	h.Write([]byte{'\n'})
	h.Write([]byte("argv\n"))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(args)))
	h.Write(lenBuf[:])
	for _, a := range args {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(a)))
		h.Write(lenBuf[:])
		h.Write([]byte(a))
	}
	h.Write([]byte{'\n'})
	return h.Sum(nil), nil
}

// ArgsDigest returns the role-partitioned (image, argv) commitment
// (docs/ratls.md). Preserves the same order-independent-
// within-a-role / role-distinguishing-across-roles / whole-set-per-role
// properties as Digest, but distinguishes two containers that share an image
// digest and differ only in argv — the busybox motivator. Both sets empty is
// an error for the same reason it is on Digest.
func ArgsDigest(initContainers, mainContainers []Container) ([]byte, error) {
	if len(initContainers) == 0 && len(mainContainers) == 0 {
		return nil, fmt.Errorf("workloadclaims: no containers to hash")
	}
	h := sha256.New()
	h.Write([]byte(argsDigestDomain))
	for _, part := range []struct {
		role       string
		containers []Container
	}{{roleInit, initContainers}, {roleMain, mainContainers}} {
		h.Write([]byte(part.role))
		leaves := make([][]byte, 0, len(part.containers))
		for _, c := range part.containers {
			leaf, err := containerLeaf(c.Digest, c.Args)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, leaf)
		}
		sort.Slice(leaves, func(i, j int) bool { return bytes.Compare(leaves[i], leaves[j]) < 0 })
		var prev []byte
		for _, leaf := range leaves {
			if bytes.Equal(leaf, prev) {
				continue
			}
			h.Write(leaf)
			h.Write([]byte{'\n'})
			prev = leaf
		}
	}
	return h.Sum(nil), nil
}

// imagesOf projects containers to their image digests, for feeding the
// image-only Digest alongside ArgsDigest.
func imagesOf(cs []Container) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Digest)
	}
	return out
}

// BuildConfigClaims builds the RA-TLS config-claims for a workload from its
// admitted init and main containers (docs/ratls.md,
// docs/ratls.md): operator-keys and seed are the unset
// sentinel (a workload does not attest allowlist governance); WorkloadDigest
// is the image-only role hash; WorkloadArgsDigest is the (image, argv)
// per-container role hash. Both are always set together on a workload cert.
func BuildConfigClaims(initContainers, mainContainers []Container) (*ratls.ConfigClaims, error) {
	wd, err := Digest(imagesOf(initContainers), imagesOf(mainContainers))
	if err != nil {
		return nil, err
	}
	ad, err := ArgsDigest(initContainers, mainContainers)
	if err != nil {
		return nil, err
	}
	return &ratls.ConfigClaims{
		OperatorKeysDigest: ratls.UnsetDigest(),
		SeedDigest:         ratls.UnsetDigest(),
		WorkloadDigest:     wd,
		WorkloadArgsDigest: ad,
	}, nil
}

// VerifyWorkloadDigests reparses claimsDER and confirms that both stamped
// digests match the given per-role container tuples: WorkloadDigest against
// the image-only role hash, WorkloadArgsDigest against the (image, argv)
// role hash (docs/ratls.md). It is the CDS-side check
// that the (untrusted) tuples a requester sent are exactly what its
// evidence-bound claims committed to — so CDS can safely allowlist-check the
// images. It does NOT check allowlist membership (the caller holds the
// store). Returns the parsed claims on success.
func VerifyWorkloadDigests(claimsDER []byte, initContainers, mainContainers []Container) (*ratls.ConfigClaims, error) {
	claims, err := ratls.UnmarshalConfigClaims(claimsDER)
	if err != nil {
		return nil, err
	}
	if !claims.HasWorkload() {
		return nil, fmt.Errorf("workloadclaims: claims carry no workload digest")
	}
	if !claims.HasWorkloadArgs() {
		return nil, fmt.Errorf("workloadclaims: claims carry no workload-args digest")
	}
	// A workload attests only its own images, never allowlist governance
	// (docs/ratls.md). Reject non-sentinel operator/seed fields so
	// a CDS-issued leaf can never carry forged governance claims.
	if claims.HasSeed() || !bytes.Equal(claims.OperatorKeysDigest, ratls.UnsetDigest()) {
		return nil, fmt.Errorf("workloadclaims: workload claims must not carry operator-keys or seed digests")
	}
	wantImages, err := Digest(imagesOf(initContainers), imagesOf(mainContainers))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(claims.WorkloadDigest, wantImages) {
		return nil, fmt.Errorf("workloadclaims: container images do not match the attested workload digest")
	}
	wantArgs, err := ArgsDigest(initContainers, mainContainers)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(claims.WorkloadArgsDigest, wantArgs) {
		return nil, fmt.Errorf("workloadclaims: (image, argv) tuples do not match the attested workload-args digest")
	}
	return claims, nil
}

// Resolver answers "which admitted, non-injected containers belong to the pod
// of the calling process". peerPID is the kernel-reported PID of the caller
// (SO_PEERCRED) — the caller never names its own pod. The node-CVM resolver
// binds peerPID to a pod; the kata resolver ignores it, since the guest holds
// exactly one pod and no disambiguation is needed.
type Resolver interface {
	ContainersForPeer(peerPID int) ([]Container, error)
}

// connKey carries the accepted net.Conn through the request context so the
// handler can read kernel peer credentials from it.
type connKey struct{}

// Serve runs the broker on l (a unix listener in both deployment shapes) until
// ctx is done. Errors from the resolver are returned to the caller as 500s —
// get-cert fails closed on them.
func Serve(ctx context.Context, l net.Listener, resolver Resolver) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DigestsPath, func(w http.ResponseWriter, r *http.Request) {
		conn, _ := r.Context().Value(connKey{}).(net.Conn)
		containers, err := resolver.ContainersForPeer(peerPID(conn))
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve caller pod: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Response{Containers: containers})
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Fetch queries the broker at endpoint and returns the caller pod's
// containers. In both deployment shapes endpoint is a "unix:///path/to.sock"
// socket (node-CVM: peer credentials bind the caller; kata: one pod per guest,
// see docs/getcert-workload-binding.md "Why a unix socket"). A plain
// "http://host:port" endpoint is also accepted but carries no peer credentials
// and is used only by tests.
func Fetch(ctx context.Context, endpoint string, timeout time.Duration) ([]Container, error) {
	client := &http.Client{Timeout: timeout}
	url := endpoint + DigestsPath
	if path, ok := strings.CutPrefix(endpoint, "unix://"); ok {
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		}
		url = "http://workload-claims" + DigestsPath
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: fetch %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("workloadclaims: broker returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("workloadclaims: decode broker response: %w", err)
	}
	return out.Containers, nil
}

// Partition splits a pod's containers into (init, main) by name, using
// initNames as the set of container names the pod spec declares as init
// containers. A container not in initNames is treated as main. The webhook
// supplies initNames (it knows the pod spec); get-cert does the split so both
// broker shapes stay role-agnostic. The Container struct is preserved
// intact — argv rides along with the image digest through the split.
func Partition(containers []Container, initNames map[string]struct{}) (initContainers, mainContainers []Container) {
	for _, c := range containers {
		if _, isInit := initNames[c.Name]; isInit {
			initContainers = append(initContainers, c)
		} else {
			mainContainers = append(mainContainers, c)
		}
	}
	return initContainers, mainContainers
}
