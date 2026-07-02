package containerd

import (
	"errors"
	"testing"

	"github.com/containerd/errdefs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"grpc unavailable", status.Error(codes.Unavailable, "connection refused"), true},
		{"errdefs unavailable", errdefs.ErrUnavailable, true},
		{"grpc not found", status.Error(codes.NotFound, "no such image"), false},
		{"errdefs not found", errdefs.ErrNotFound, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionError(tt.err); got != tt.want {
				t.Fatalf("isConnectionError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestWithReconnect(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "containerd down")
	notFound := status.Error(codes.NotFound, "no such image")

	t.Run("success on first try does not reconnect", func(t *testing.T) {
		var ops, reconnects int
		err := withReconnect(
			func() error { ops++; return nil },
			func() error { reconnects++; return nil },
			isConnectionError,
		)
		if err != nil || ops != 1 || reconnects != 0 {
			t.Fatalf("err=%v ops=%d reconnects=%d, want nil/1/0", err, ops, reconnects)
		}
	})

	t.Run("non-connection error is returned without reconnect", func(t *testing.T) {
		var ops, reconnects int
		err := withReconnect(
			func() error { ops++; return notFound },
			func() error { reconnects++; return nil },
			isConnectionError,
		)
		if !errors.Is(err, notFound) || ops != 1 || reconnects != 0 {
			t.Fatalf("err=%v ops=%d reconnects=%d, want notFound/1/0", err, ops, reconnects)
		}
	})

	t.Run("connection error reconnects and retries once", func(t *testing.T) {
		var ops, reconnects int
		err := withReconnect(
			func() error {
				ops++
				if ops == 1 {
					return unavailable // first attempt fails on a dead connection
				}
				return nil // retry after reconnect succeeds
			},
			func() error { reconnects++; return nil },
			isConnectionError,
		)
		if err != nil || ops != 2 || reconnects != 1 {
			t.Fatalf("err=%v ops=%d reconnects=%d, want nil/2/1", err, ops, reconnects)
		}
	})

	t.Run("reconnect failure surfaces the original op error", func(t *testing.T) {
		var ops, reconnects int
		reconnectErr := errors.New("re-dial failed")
		err := withReconnect(
			func() error { ops++; return unavailable },
			func() error { reconnects++; return reconnectErr },
			isConnectionError,
		)
		if !errors.Is(err, unavailable) || errors.Is(err, reconnectErr) {
			t.Fatalf("err=%v, want the original unavailable error, not the reconnect error", err)
		}
		if ops != 1 || reconnects != 1 {
			t.Fatalf("ops=%d reconnects=%d, want 1/1 (no retry when reconnect fails)", ops, reconnects)
		}
	})

	t.Run("still failing after reconnect returns the retry error", func(t *testing.T) {
		var ops int
		err := withReconnect(
			func() error { ops++; return unavailable }, // stays down across the retry
			func() error { return nil },
			isConnectionError,
		)
		if !errors.Is(err, unavailable) || ops != 2 {
			t.Fatalf("err=%v ops=%d, want unavailable/2", err, ops)
		}
	})
}
