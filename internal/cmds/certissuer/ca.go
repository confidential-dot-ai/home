package certissuer

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/lunal-dev/c8s/internal/issuer"
)

func handlePublicCA(bm *bundleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bm == nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(bm.bundlePEM())
	}
}

func recordTokenValidationFailure(err error) {
	var tve *issuer.TokenValidationError
	if errors.As(err, &tve) {
		tokenValidationFailuresTotal.WithLabelValues(string(tve.Reason)).Inc()
		return
	}
	slog.Warn("token validation failed without typed reason", "error", err)
}
