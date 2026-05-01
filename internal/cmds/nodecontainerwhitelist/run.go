// Package nodecontainerwhitelist fetches the NRI image whitelist from a
// whitelist API and serves it as a JSON HTTP endpoint, periodically
// refreshing the whitelist in the background.
package nodecontainerwhitelist

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/version"
	"github.com/lunal-dev/c8s/pkg/whitelist"
	"github.com/lunal-dev/c8s/pkg/whitelistclient"
)

// server holds the cached whitelist and serves HTTP.
type server struct {
	mu sync.RWMutex
	wl *whitelist.Whitelist
}

func (s *server) get() *whitelist.Whitelist {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.wl
}

func (s *server) set(wl *whitelist.Whitelist) {
	s.mu.Lock()
	s.wl = wl
	s.mu.Unlock()
}

// replace atomically swaps the cached whitelist if the new version differs
// from the current one. Returns true if anything changed, so callers can
// emit a "refreshed" log line only when something actually rotated.
func (s *server) replace(wl *whitelist.Whitelist) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wl != nil && s.wl.Version == wl.Version && len(s.wl.Digests) == len(wl.Digests) {
		return false
	}
	s.wl = wl
	return true
}

func fetchWithRetries(ctx context.Context, client whitelistclient.Client, retries int, delay, timeout time.Duration) (*whitelist.Whitelist, error) {
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		wl, err := client.FetchWhitelist(fetchCtx)
		cancel()
		if err == nil {
			return wl, nil
		}
		lastErr = err
		slog.Warn("fetch attempt failed", "attempt", attempt, "max", retries, "error", err)
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return nil, fmt.Errorf("failed after %d attempts: %w", retries, lastErr)
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// Run executes the node-container-whitelist binary's main loop. args is
// the slice of CLI args after the program name.
func Run(args []string) error {
	fs := flag.NewFlagSet("node-container-whitelist", flag.ContinueOnError)
	port := fs.Int("port", 8000, "HTTP listen port")
	whitelistURL := fs.String("whitelist-url", "", "whitelist API base URL")
	refreshInterval := fs.Duration("refresh-interval", 300*time.Second, "whitelist refresh interval")
	maxRetries := fs.Int("max-retries", 60, "max fetch retries on startup")
	retryDelay := fs.Duration("retry-delay", 5*time.Second, "delay between startup retries")
	readTimeout := fs.Duration("read-timeout", 5*time.Second, "HTTP server read timeout")
	writeTimeout := fs.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	fetchTimeout := fs.Duration("fetch-timeout", 30*time.Second, "per-request timeout for whitelist fetches")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	if *whitelistURL == "" {
		return fmt.Errorf("--whitelist-url is required")
	}

	slog.Info("initializing whitelist client", "url", *whitelistURL, "version", version.Version)

	client := whitelistclient.NewClientWithHTTP(*whitelistURL, &http.Client{
		Timeout: *fetchTimeout,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("fetching whitelist")
	wl, err := fetchWithRetries(ctx, client, *maxRetries, *retryDelay, *fetchTimeout)
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	slog.Info("whitelist loaded", "digests", len(wl.Digests))

	srv := &server{wl: wl}

	go func() {
		ticker := time.NewTicker(*refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchCtx, fetchCancel := context.WithTimeout(ctx, *fetchTimeout)
				refreshed, err := client.FetchWhitelist(fetchCtx)
				fetchCancel()
				if err != nil {
					slog.Error("refresh failed (serving cached)", "error", err)
					continue
				}
				if srv.replace(refreshed) {
					slog.Info("refreshed whitelist", "digests", len(refreshed.Digests))
				}
			}
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if srv.get() != nil {
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		} else {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		}
	})

	mux.HandleFunc("GET /digests", func(w http.ResponseWriter, r *http.Request) {
		wl := srv.get()
		if wl == nil {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "whitelist not loaded"})
			return
		}
		respondJSON(w, http.StatusOK, wl)
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/whitelist" {
			respondJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		wl := srv.get()
		if wl == nil {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "whitelist not loaded"})
			return
		}
		respondJSON(w, http.StatusOK, wl)
	})

	addr := fmt.Sprintf(":%d", *port)
	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: *readTimeout, WriteTimeout: *writeTimeout}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "error", err)
		}
	}()

	slog.Info("listening", "addr", addr, "refresh_interval", *refreshInterval)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
