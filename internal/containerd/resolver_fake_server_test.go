package containerd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	tasktypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	testNamespace = "k8s.io"
	testDigest    = "sha256:df85a2c1d7c4ec9a3ff6f4e5023d1b8f47a6a5406b0e14a4a91b1bfe7e5c3b1a"
)

// fakeImages is a minimal in-process containerd images service. It knows a
// single image and can be told to fail the next N calls with Unavailable to
// exercise the reconnect path.
type fakeImages struct {
	imagesapi.UnimplementedImagesServer

	mu            sync.Mutex
	knownName     string
	unavailable   int      // fail this many Get calls with codes.Unavailable
	requested     []string // image names seen
	lastNamespace string   // containerd-namespace header of the last call
}

func (f *fakeImages) Get(ctx context.Context, req *imagesapi.GetImageRequest) (*imagesapi.GetImageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ns := md.Get(namespaces.GRPCHeader); len(ns) > 0 {
			f.lastNamespace = ns[0]
		}
	}
	f.requested = append(f.requested, req.Name)

	if f.unavailable > 0 {
		f.unavailable--
		return nil, status.Error(codes.Unavailable, "containerd is down")
	}
	if req.Name != f.knownName {
		return nil, status.Errorf(codes.NotFound, "image %q: not found", req.Name)
	}
	return &imagesapi.GetImageResponse{
		Image: &imagesapi.Image{
			Name: req.Name,
			Target: &types.Descriptor{
				MediaType: "application/vnd.oci.image.index.v1+json",
				Digest:    testDigest,
				Size:      1234,
			},
		},
	}, nil
}

// fakeContainers is a minimal containers service knowing a single container ID.
type fakeContainers struct {
	containersapi.UnimplementedContainersServer

	knownID string
}

func (f *fakeContainers) Get(_ context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	if req.ID != f.knownID {
		return nil, status.Errorf(codes.NotFound, "container %q: not found", req.ID)
	}
	return &containersapi.GetContainerResponse{
		Container: &containersapi.Container{
			ID:      req.ID,
			Runtime: &containersapi.Container_Runtime{Name: "io.containerd.runc.v2"},
		},
	}, nil
}

// fakeTasks is a minimal tasks service whose Get/Kill behavior is scriptable.
type fakeTasks struct {
	tasksapi.UnimplementedTasksServer

	mu         sync.Mutex
	getErr     error
	killErr    error
	killed     []uint32 // signals received
	containers map[string]uint32
}

func (f *fakeTasks) Get(_ context.Context, req *tasksapi.GetRequest) (*tasksapi.GetResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	pid, ok := f.containers[req.ContainerID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "task %q: not found", req.ContainerID)
	}
	return &tasksapi.GetResponse{
		Process: &tasktypes.Process{
			ID:     req.ContainerID,
			Pid:    pid,
			Status: tasktypes.Status_RUNNING,
		},
	}, nil
}

func (f *fakeTasks) Kill(_ context.Context, req *tasksapi.KillRequest) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.killErr != nil {
		return nil, f.killErr
	}
	if _, ok := f.containers[req.ContainerID]; !ok {
		return nil, status.Errorf(codes.NotFound, "task %q: not found", req.ContainerID)
	}
	f.killed = append(f.killed, req.Signal)
	return &emptypb.Empty{}, nil
}

// tempSocketPath returns a path short enough for a unix socket (the kernel
// caps sun_path at ~108 bytes, which deep TMPDIRs can exceed).
func tempSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "c8s-ctrd-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	if sock := filepath.Join(dir, "c.sock"); len(sock) < 100 {
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return sock
	}
	_ = os.RemoveAll(dir)
	dir, err = os.MkdirTemp("/tmp", "c8s-ctrd-")
	if err != nil {
		t.Fatalf("MkdirTemp(/tmp): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// startFakeContainerd serves the fake services on a unix socket and returns
// the socket path.
func startFakeContainerd(t *testing.T, images *fakeImages, containers *fakeContainers, tasks *fakeTasks) string {
	t.Helper()
	socket := tempSocketPath(t)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on %s: %v", socket, err)
	}
	srv := grpc.NewServer()
	if images != nil {
		imagesapi.RegisterImagesServer(srv, images)
	}
	if containers != nil {
		containersapi.RegisterContainersServer(srv, containers)
	}
	if tasks != nil {
		tasksapi.RegisterTasksServer(srv, tasks)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return socket
}

func newTestResolver(t *testing.T, socket string) *Resolver {
	t.Helper()
	r, err := NewResolver(socket, testNamespace)
	if err != nil {
		t.Fatalf("NewResolver(%s): %v", socket, err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestNewResolverError(t *testing.T) {
	// An empty address gives the containerd client neither a connection nor
	// preconfigured services, so construction fails without any dialing.
	r, err := NewResolver("", testNamespace)
	if err == nil {
		_ = r.Close()
		t.Fatal("NewResolver(\"\") succeeded, want error")
	}
	if want := "connect to containerd at"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func TestResolve(t *testing.T) {
	images := &fakeImages{knownName: "docker.io/library/nginx:1.27"}
	socket := startFakeContainerd(t, images, nil, nil)
	r := newTestResolver(t, socket)

	t.Run("short ref is normalized before lookup", func(t *testing.T) {
		digest, err := r.Resolve(context.Background(), "nginx:1.27")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if digest != testDigest {
			t.Fatalf("digest = %q, want %q", digest, testDigest)
		}
		images.mu.Lock()
		defer images.mu.Unlock()
		if got := images.requested[len(images.requested)-1]; got != "docker.io/library/nginx:1.27" {
			t.Fatalf("server saw name %q, want normalized docker.io/library/nginx:1.27", got)
		}
		if images.lastNamespace != testNamespace {
			t.Fatalf("server saw namespace %q, want %q", images.lastNamespace, testNamespace)
		}
	})

	t.Run("fully qualified ref resolves as-is", func(t *testing.T) {
		digest, err := r.Resolve(context.Background(), "docker.io/library/nginx:1.27")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if digest != testDigest {
			t.Fatalf("digest = %q, want %q", digest, testDigest)
		}
	})

	t.Run("missing image returns a not-found error without reconnecting", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), "ghcr.io/acme/absent:v1")
		if err == nil {
			t.Fatal("Resolve succeeded for an absent image")
		}
		if want := "image not found in containerd store"; !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	})

	t.Run("unparseable ref is passed through verbatim", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), "not a valid ref!!")
		if err == nil {
			t.Fatal("Resolve succeeded for an unparseable ref")
		}
		images.mu.Lock()
		defer images.mu.Unlock()
		if got := images.requested[len(images.requested)-1]; got != "not a valid ref!!" {
			t.Fatalf("server saw name %q, want the verbatim ref", got)
		}
	})
}

func TestResolveReconnects(t *testing.T) {
	images := &fakeImages{knownName: "docker.io/library/nginx:1.27"}
	socket := startFakeContainerd(t, images, nil, nil)
	r := newTestResolver(t, socket)

	// First call fails with Unavailable; the resolver must re-dial and retry.
	images.mu.Lock()
	images.unavailable = 1
	images.mu.Unlock()

	digest, err := r.Resolve(context.Background(), "nginx:1.27")
	if err != nil {
		t.Fatalf("Resolve after transient outage: %v", err)
	}
	if digest != testDigest {
		t.Fatalf("digest = %q, want %q", digest, testDigest)
	}
	images.mu.Lock()
	calls := len(images.requested)
	images.mu.Unlock()
	if calls != 2 {
		t.Fatalf("server saw %d Get calls, want 2 (original + post-reconnect retry)", calls)
	}

	// A second outage inside the throttle window skips the re-dial but still
	// retries the operation on the shared connection.
	images.mu.Lock()
	images.unavailable = 1
	images.mu.Unlock()

	if _, err := r.Resolve(context.Background(), "nginx:1.27"); err != nil {
		t.Fatalf("Resolve during throttled reconnect: %v", err)
	}
	images.mu.Lock()
	calls = len(images.requested)
	images.mu.Unlock()
	if calls != 4 {
		t.Fatalf("server saw %d Get calls, want 4", calls)
	}
}

func TestStopContainer(t *testing.T) {
	const containerID = "abc123"

	newFakes := func() (*fakeContainers, *fakeTasks) {
		return &fakeContainers{knownID: containerID},
			&fakeTasks{containers: map[string]uint32{containerID: 42}}
	}

	t.Run("kills the running task with SIGKILL", func(t *testing.T) {
		containers, tasks := newFakes()
		socket := startFakeContainerd(t, nil, containers, tasks)
		r := newTestResolver(t, socket)

		if err := r.StopContainer(context.Background(), containerID); err != nil {
			t.Fatalf("StopContainer: %v", err)
		}
		tasks.mu.Lock()
		defer tasks.mu.Unlock()
		if len(tasks.killed) != 1 || tasks.killed[0] != 9 {
			t.Fatalf("kill signals = %v, want [9] (SIGKILL)", tasks.killed)
		}
	})

	t.Run("unknown container fails at load", func(t *testing.T) {
		containers, tasks := newFakes()
		socket := startFakeContainerd(t, nil, containers, tasks)
		r := newTestResolver(t, socket)

		err := r.StopContainer(context.Background(), "no-such-id")
		if err == nil {
			t.Fatal("StopContainer succeeded for an unknown container")
		}
		if want := "load container no-such-id"; !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	})

	t.Run("missing task fails at task lookup", func(t *testing.T) {
		containers, tasks := newFakes()
		tasks.getErr = status.Error(codes.NotFound, "no running task")
		socket := startFakeContainerd(t, nil, containers, tasks)
		r := newTestResolver(t, socket)

		err := r.StopContainer(context.Background(), containerID)
		if err == nil {
			t.Fatal("StopContainer succeeded without a task")
		}
		if want := "get task for " + containerID; !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	})

	t.Run("kill failure is surfaced", func(t *testing.T) {
		containers, tasks := newFakes()
		tasks.killErr = status.Error(codes.Internal, "shim exploded")
		socket := startFakeContainerd(t, nil, containers, tasks)
		r := newTestResolver(t, socket)

		err := r.StopContainer(context.Background(), containerID)
		if err == nil {
			t.Fatal("StopContainer succeeded despite a failing Kill")
		}
		if want := "kill task for " + containerID; !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	})
}
