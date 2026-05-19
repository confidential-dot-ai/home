package certissuer

import (
	"errors"
	"net/http"
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
	var tve *tokenValidationError
	if errors.As(err, &tve) {
		tokenValidationFailuresTotal.WithLabelValues(tve.Reason).Inc()
	}
}
