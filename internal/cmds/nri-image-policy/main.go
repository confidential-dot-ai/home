// Package nriimagepolicy is an NRI plugin that validates container images
// against a digest whitelist. The whitelist is sourced either from a remote
// CDS service (pull mode) or from an operator-pushed payload on the local
// unix socket (push mode), with a bootstrap file on disk as the cold-boot
// baseline in both modes.
package nriimagepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lunal-dev/c8s/internal/audit"
	"github.com/lunal-dev/c8s/internal/cache"
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	ctrdresolver "github.com/lunal-dev/c8s/internal/containerd"
	"github.com/lunal-dev/c8s/internal/fileutil"
	"github.com/lunal-dev/c8s/internal/httputil"
	"github.com/lunal-dev/c8s/internal/version"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
	"github.com/lunal-dev/c8s/pkg/whitelist"
	"github.com/lunal-dev/c8s/pkg/whitelistclient"
)

// Pull-startup retry parameters. Declared as vars so tests can shrink
// the backoff without exposing test-only knobs on the public surface.
var (
	whitelistApiMaxRetries   = 5
	whitelistApiInitialDelay = 2 * time.Second
)

var (
	errInitialWhitelistNotModified = errors.New("initial whitelist fetch returned not modified without a cached CDS whitelist")
	errInitialWhitelistNil         = errors.New("initial whitelist fetch returned nil whitelist")
	errPushHandlerRequiresUnixAddr = errors.New("push mode requires plugin.health_addr to use unix://")
	errPluginDied                  = errors.New("NRI plugin died during whitelist init")
)

// pushBodyLimit caps PUT /whitelist payloads. Push mode carries a
// single digest entry so this is intentionally tight.
const pushBodyLimit = 16 * 1024

func startupSourceMode(cfg *config) string {
	if cfg.PullEnabled() {
		return "pull"
	}
	if cfg.PushEnabled() {
		return "push"
	}

	sources := make([]string, 0, 2)
	if len(cfg.Whitelist.AlwaysAllow) > 0 {
		sources = append(sources, "always_allow")
	}
	if len(cfg.Policy.LabelRules) > 0 {
		sources = append(sources, "label_rules")
	}
	if len(sources) == 0 {
		return "none"
	}
	return strings.Join(sources, "+")
}

// Run executes the nri-image-policy binary. args is the slice of CLI args
// after the program name.
func Run(args []string) error {
	fs := flag.NewFlagSet("nri-image-policy", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/nri/conf.d/image-policy.yaml", "path to config file")
	healthAddr := fs.String("health-addr", ":8080", "health check listen address")
	readTimeout := fs.Duration("read-timeout", 5*time.Second, "HTTP server read timeout")
	writeTimeout := fs.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}

	logger, err := certutil.NewJSONLogger(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	slog.SetDefault(logger)

	logger.Info("starting nri-image-policy",
		"version", version.Version,
		"config", *configPath,
		"mode", startupSourceMode(cfg),
	)

	logger.Debug("initializing containerd resolver",
		"socket", cfg.Containerd.Socket,
		"namespace", cfg.Containerd.Namespace,
	)
	resolver, err := ctrdresolver.NewResolver(cfg.Containerd.Socket, cfg.Containerd.Namespace)
	if err != nil {
		return fmt.Errorf("create containerd resolver: %w", err)
	}
	defer resolver.Close()

	policyCache := cache.NewPolicyCache()
	auditLogger := audit.NewLogger()

	var wlClient whitelistclient.Client
	if cfg.PullEnabled() {
		logger.Info("initializing whitelist client", "url", cfg.Whitelist.Pull.URL)
		httpClient, err := whitelistPullHTTPClient(cfg.Whitelist.Pull)
		if err != nil {
			return fmt.Errorf("create whitelist client: %w", err)
		}
		wlClient = whitelistclient.NewClientWithHTTP(cfg.Whitelist.Pull.URL, httpClient)
	}

	plugin, err := newPlugin(cfg, resolver, policyCache, auditLogger, logger)
	if err != nil {
		return fmt.Errorf("create plugin: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	bootstrap := alwaysAllowWhitelist(cfg.Whitelist.AlwaysAllow)

	var pushed *whitelist.Whitelist
	if cfg.PushEnabled() && cfg.Whitelist.Push.PersistPath != "" {
		pushed, err = loadWhitelistFile(cfg.Whitelist.Push.PersistPath, "pushed", logger)
		if err != nil {
			return fmt.Errorf("load pushed %q: %w", cfg.Whitelist.Push.PersistPath, err)
		}
	}

	seed := mergeWhitelists(bootstrap, pushed)
	policyCache.SetWhitelist(seed)
	logger.Info("cache seeded",
		"always_allow_entries", entriesOf(bootstrap),
		"pushed_entries", entriesOf(pushed),
	)

	var pushH *pushHandler
	if cfg.PushEnabled() {
		pushH, err = newPushHandler(policyCache, bootstrap, cfg.Whitelist.Push.PersistPath, logger)
		if err != nil {
			return fmt.Errorf("create push handler: %w", err)
		}
	}

	addr := *healthAddr
	if cfg.Plugin.HealthAddr != "" {
		addr = cfg.Plugin.HealthAddr
	}
	if err := startHealthServer(ctx, healthServerConfig{
		logger:       logger,
		plugin:       plugin,
		addr:         addr,
		readTimeout:  *readTimeout,
		writeTimeout: *writeTimeout,
		pushHandler:  pushH,
	}); err != nil {
		return fmt.Errorf("start health server on %q: %w", addr, err)
	}

	pluginErrCh := make(chan error, 1)
	go func() {
		pluginErrCh <- plugin.Run(ctx)
	}()

	var initialETag string
	if cfg.PullEnabled() {
		initialETag, err = pullInitial(ctx, pullArgs{
			client:      wlClient,
			cache:       policyCache,
			bootstrap:   bootstrap,
			timeout:     cfg.Whitelist.Pull.Timeout,
			pluginErrCh: pluginErrCh,
			logger:      logger,
		})
		if err != nil {
			switch {
			case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
				logger.Info("shutdown before plugin became ready")
				if perr := <-pluginErrCh; perr != nil {
					logger.Error("plugin error during shutdown", "error", perr)
				}
				return nil
			case errors.Is(err, errPluginDied):
				return err
			default:
				// The cache already holds the bootstrap floor (always_allow), so
				// stay up serving it rather than crash-loop the plugin and block
				// container creation node-wide. runPullLoop keeps retrying.
				logger.Warn("initial whitelist pull failed; serving bootstrap floor and retrying in background", "error", err)
			}
		}
	}

	plugin.SetReady()
	logger.Info("plugin ready")

	if cfg.PullEnabled() {
		go runPullLoop(ctx, pullLoopArgs{
			client:    wlClient,
			cache:     policyCache,
			bootstrap: bootstrap,
			interval:  cfg.Whitelist.Pull.Interval,
			timeout:   cfg.Whitelist.Pull.Timeout,
			etag:      initialETag,
			logger:    logger,
		})
	}

	plugin.RunDeferredSweep(ctx)

	select {
	case err := <-pluginErrCh:
		if err != nil {
			return fmt.Errorf("plugin: %w", err)
		}
	case <-ctx.Done():
		if err := <-pluginErrCh; err != nil {
			logger.Error("plugin error during shutdown", "error", err)
		}
	}
	logger.Info("nri-image-policy stopped")
	return nil
}

// whitelistPullHTTPClient builds the RA-TLS client for the CDS pull. The pull
// URL is always https (enforced by config.Validate), so this always verifies
// the CDS attestation handshake.
func whitelistPullHTTPClient(cfg pullConfig) (*http.Client, error) {
	measurements, err := ratls.ParseHexMeasurementsList(cfg.CDSMeasurements)
	if err != nil {
		return nil, fmt.Errorf("parse CDS measurements: %w", err)
	}
	if len(measurements) == 0 {
		slog.Warn("whitelist.pull.cds_measurements not set; nri-image-policy accepts any RA-TLS-attested CDS measurement")
	}
	client, err := ratls.NewVerifyingHTTPClient(measurements, cfg.AttestationServiceURL)
	if err != nil {
		return nil, fmt.Errorf("CDS RA-TLS client: %w", err)
	}
	client.Timeout = cfg.Timeout
	return client, nil
}

// alwaysAllowWhitelist builds an in-memory Whitelist from the config's
// AlwaysAllow map. Used to seed the cache at startup with chart-managed
// entries (typically the installer image so chart upgrades can roll).
func alwaysAllowWhitelist(entries map[string]string) *whitelist.Whitelist {
	wl := &whitelist.Whitelist{Digests: make(map[string]string, len(entries))}
	for d, image := range entries {
		wl.Digests[d] = image
	}
	return wl
}

// loadWhitelistFile reads a YAML/JSON whitelist from disk. Missing file
// returns (nil, nil); parse errors fail closed.
func loadWhitelistFile(path, kind string, logger *slog.Logger) (*whitelist.Whitelist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Info("whitelist file absent", "kind", kind, "path", path)
			return nil, nil
		}
		return nil, fmt.Errorf("read: %w", err)
	}
	return parseWhitelistFile(data, path)
}

// parseWhitelistFile decodes YAML/JSON whitelist content. Digest keys
// are validated via the typed wire shape; empty digest maps are allowed.
func parseWhitelistFile(data []byte, path string) (*whitelist.Whitelist, error) {
	var raw types.WhitelistListResponse
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	out := &whitelist.Whitelist{
		Version: raw.Version,
		Digests: make(map[string]string, len(raw.Digests)),
	}
	for d, image := range raw.Digests {
		out.Digests[d.String()] = image
	}
	return out, nil
}

func entriesOf(wl *whitelist.Whitelist) int {
	if wl == nil {
		return 0
	}
	return len(wl.Digests)
}

// mergeWhitelists overlays b onto a. Entries in b win on conflict; b's
// version is preferred when set. Either argument may be nil. Bootstrap
// entries (a) cannot be removed by overlay — they're the static floor.
func mergeWhitelists(a, b *whitelist.Whitelist) *whitelist.Whitelist {
	out := &whitelist.Whitelist{Digests: map[string]string{}}
	if a != nil {
		out.Version = a.Version
		for k, v := range a.Digests {
			out.Digests[k] = v
		}
	}
	if b != nil {
		if b.Version != "" {
			out.Version = b.Version
		}
		for k, v := range b.Digests {
			out.Digests[k] = v
		}
	}
	return out
}

type pullArgs struct {
	client      whitelistclient.Client
	cache       *cache.PolicyCache
	bootstrap   *whitelist.Whitelist
	timeout     time.Duration
	pluginErrCh <-chan error
	logger      *slog.Logger
}

// pullInitial fetches the startup whitelist with bounded retries and
// returns the response ETag for the steady-state poll loop.
//
// INVARIANT: a nil error return means args.cache holds bootstrap ∪ pulled.
// Context cancellation surfaces as ctx.Err(); callers must not mark the
// plugin ready on that path.
func pullInitial(ctx context.Context, args pullArgs) (string, error) {
	delay := whitelistApiInitialDelay
	for attempt := 1; attempt <= whitelistApiMaxRetries; attempt++ {
		select {
		case err := <-args.pluginErrCh:
			return "", fmt.Errorf("%w: %w", errPluginDied, err)
		case <-ctx.Done():
			args.logger.Info("shutdown requested during whitelist init")
			return "", ctx.Err()
		default:
		}

		reqCtx, reqCancel := context.WithTimeout(ctx, args.timeout)
		args.logger.Info("fetching initial whitelist from CDS", "attempt", attempt)
		wl, etag, notModified, err := args.client.FetchWhitelistConditional(reqCtx, "")
		reqCancel()
		if err == nil {
			if notModified {
				err = errInitialWhitelistNotModified
			} else if wl == nil {
				err = errInitialWhitelistNil
			} else {
				merged := mergeWhitelists(args.bootstrap, wl)
				args.cache.SetWhitelist(merged)
				args.logger.Info("initial whitelist pulled from CDS",
					"pulled_entries", len(wl.Digests),
					"merged_entries", len(merged.Digests),
					"etag", etag,
				)
				return etag, nil
			}
		}

		args.logger.Error("whitelist fetch failed", "attempt", attempt, "error", err)
		if attempt >= whitelistApiMaxRetries {
			return "", fmt.Errorf("whitelist fetch failed after %d attempts: %w", whitelistApiMaxRetries, err)
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			args.logger.Info("shutdown requested during whitelist init")
			return "", ctx.Err()
		}
		delay *= 2
	}
	return "", nil
}

type pullLoopArgs struct {
	client    whitelistclient.Client
	cache     *cache.PolicyCache
	bootstrap *whitelist.Whitelist
	interval  time.Duration
	timeout   time.Duration
	etag      string
	logger    *slog.Logger
}

// runPullLoop polls CDS with If-None-Match. 200 swaps the cache to
// bootstrap ∪ pulled; 304 and errors leave it untouched.
func runPullLoop(ctx context.Context, args pullLoopArgs) {
	ticker := time.NewTicker(args.interval)
	defer ticker.Stop()

	etag := args.etag
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		reqCtx, cancel := context.WithTimeout(ctx, args.timeout)
		wl, newETag, notModified, err := args.client.FetchWhitelistConditional(reqCtx, etag)
		cancel()
		if err != nil {
			args.logger.Warn("pull loop fetch failed", "error", err)
			continue
		}
		if notModified {
			args.logger.Debug("pull loop: not modified", "etag", etag)
			continue
		}
		if wl == nil {
			args.logger.Warn("pull loop fetch returned nil whitelist")
			continue
		}
		merged := mergeWhitelists(args.bootstrap, wl)
		args.cache.SetWhitelist(merged)
		etag = newETag
		args.logger.Info("pull loop: whitelist refreshed",
			"pulled_entries", len(wl.Digests),
			"merged_entries", len(merged.Digests),
			"etag", etag,
		)
	}
}

// pushHandler implements PUT /whitelist for push-mode nodes.
//
// INVARIANT: pushedPath is non-empty (enforced by newPushHandler).
// Persistence to disk is part of the contract; restarting must re-load
// the last pushed payload, so silent skip-on-empty-path would defeat
// the design.
type pushHandler struct {
	mu         sync.Mutex
	cache      *cache.PolicyCache
	bootstrap  *whitelist.Whitelist
	pushedPath string
	logger     *slog.Logger
}

// newPushHandler returns a handler that persists to pushedPath and
// applies bootstrap ∪ pushed to cache. pushedPath must be non-empty.
func newPushHandler(c *cache.PolicyCache, bootstrap *whitelist.Whitelist, pushedPath string, logger *slog.Logger) (*pushHandler, error) {
	if pushedPath == "" {
		return nil, fmt.Errorf("pushedPath must be non-empty")
	}
	return &pushHandler{
		cache:      c,
		bootstrap:  bootstrap,
		pushedPath: pushedPath,
		logger:     logger,
	}, nil
}

// Body must be a single-entry WhitelistListResponse. pushed.json is
// written atomically before the cache is updated.
func (h *pushHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, ok := httputil.ReadCappedBody(w, r, pushBodyLimit)
	if !ok {
		return
	}
	pushed, err := whitelist.ParseJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(pushed.Digests) != 1 {
		http.Error(w, "push mode accepts exactly one digest entry", http.StatusUnprocessableEntity)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	persisted, err := json.Marshal(pushed)
	if err != nil {
		h.logger.Error("failed to marshal pushed payload", "error", err)
		http.Error(w, "marshal push payload", http.StatusInternalServerError)
		return
	}
	if err := fileutil.WriteAtomic(h.pushedPath, persisted, 0o600); err != nil {
		h.logger.Error("failed to persist pushed.json", "path", h.pushedPath, "error", err)
		http.Error(w, "persist push payload", http.StatusInternalServerError)
		return
	}

	merged := mergeWhitelists(h.bootstrap, pushed)
	h.cache.SetWhitelist(merged)
	h.logger.Info("push applied",
		"pushed_entries", len(pushed.Digests),
		"merged_entries", len(merged.Digests),
	)
	w.WriteHeader(http.StatusNoContent)
}

type healthServerConfig struct {
	logger       *slog.Logger
	plugin       *plugin
	addr         string
	readTimeout  time.Duration
	writeTimeout time.Duration
	pushHandler  *pushHandler // nil disables PUT /whitelist
}

// startHealthServer starts an HTTP server for readiness/liveness probes.
// addr accepts plain `host:port` for TCP or `unix:///path/to.sock` for a
// Unix socket. PUT /whitelist is registered only when pushHandler is
// non-nil and addr is unix://. Shuts down gracefully when ctx is cancelled.
func startHealthServer(ctx context.Context, cfg healthServerConfig) error {
	if cfg.pushHandler != nil && !isUnixSocketAddr(cfg.addr) {
		return fmt.Errorf("%w, got %q", errPushHandlerRequiresUnixAddr, cfg.addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.plugin.Ready() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not ready")
		}
	})
	if cfg.pushHandler != nil {
		mux.Handle("/whitelist", cfg.pushHandler)
	}

	listener, err := healthListener(cfg.addr)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: mux, ReadTimeout: cfg.readTimeout, WriteTimeout: cfg.writeTimeout}
	go func() {
		cfg.logger.Info("starting health server", "addr", cfg.addr, "push_enabled", cfg.pushHandler != nil)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			cfg.logger.Error("health server error", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			cfg.logger.Error("health server shutdown error", "error", err)
		}
	}()
	return nil
}

// healthListener returns a TCP listener for `host:port` or a Unix socket
// listener for `unix:///abs/path`. Stale socket files are removed before
// bind so plugin restarts don't fail with EADDRINUSE; the file is chmod'd
// to 0660.
func healthListener(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("listen unix %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o660); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("chmod unix socket %s: %w", path, err)
		}
		return l, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	return l, nil
}

func isUnixSocketAddr(addr string) bool {
	_, ok := strings.CutPrefix(addr, "unix://")
	return ok
}
