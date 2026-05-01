package ratlsmesh

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lunal-dev/c8s/pkg/ratls"
)

// healthServer exposes /live, /ready, and /metrics on a dedicated admin port.
type healthServer struct {
	ready                atomic.Bool
	metrics              *metrics
	mux                  *http.ServeMux
	serverCertMgr        *ratls.CertManager
	clientCertMgr        *ratls.CertManager // nil if no mTLS
	acceptErrorThreshold int64
	readTimeout          time.Duration
	writeTimeout         time.Duration
}

func newHealthServer(m *metrics, serverCertMgr, clientCertMgr *ratls.CertManager, acceptErrorThreshold int64, readTimeout, writeTimeout time.Duration) *healthServer {
	h := &healthServer{
		metrics:              m,
		serverCertMgr:        serverCertMgr,
		clientCertMgr:        clientCertMgr,
		acceptErrorThreshold: acceptErrorThreshold,
		readTimeout:          readTimeout,
		writeTimeout:         writeTimeout,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", h.handleLive)
	mux.HandleFunc("GET /ready", h.handleReady)
	mux.HandleFunc("GET /metrics", h.handleMetrics)
	h.mux = mux
	return h
}

func (h *healthServer) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func (h *healthServer) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !h.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	// Gate on cert provisioning: don't accept traffic until we can serve TLS.
	if h.serverCertMgr != nil && !h.serverCertMgr.CertReady() {
		http.Error(w, "server cert not provisioned", http.StatusServiceUnavailable)
		return
	}
	if h.clientCertMgr != nil && !h.clientCertMgr.CertReady() {
		http.Error(w, "client cert not provisioned", http.StatusServiceUnavailable)
		return
	}
	// Degrade readiness if either accept loop is in sustained failure.
	if h.metrics.acceptConsecutiveInbound.Load() >= h.acceptErrorThreshold ||
		h.metrics.acceptConsecutiveOutbound.Load() >= h.acceptErrorThreshold {
		http.Error(w, "accept loop degraded", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready\n"))
}

func (h *healthServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	h.metrics.writePrometheus(w)
}

func (h *healthServer) serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Handler:      h.mux,
		ReadTimeout:  durOrDefault(h.readTimeout, 5*time.Second),
		WriteTimeout: durOrDefault(h.writeTimeout, 10*time.Second),
		IdleTimeout:  60 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}
