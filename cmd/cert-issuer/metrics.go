package main

import (
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// updateCACertFingerprint resets the fingerprint info gauge and sets the new
// value. Returns the hex fingerprint for logging.
func updateCACertFingerprint(raw []byte) string {
	fp := certutil.CertFingerprint(raw)
	caCertFingerprintInfo.Reset()
	caCertFingerprintInfo.WithLabelValues(fp).Set(1)
	return fp
}

var (
	signRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_issuer_sign_requests_total",
		Help: "Total sign-csr requests by result.",
	}, []string{"result"})

	signLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "cert_issuer_sign_latency_seconds",
		Help:    "Signing request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	certificatesIssuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_certificates_issued_total",
		Help: "Total certificates successfully issued.",
	})

	tokenValidationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_issuer_token_validation_failures_total",
		Help: "Token validation failures by reason.",
	}, []string{"reason"})

	activeRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_active_requests",
		Help: "Number of in-flight sign-csr requests.",
	})

	caCertExpirySeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_ca_cert_expiry_seconds",
		Help: "Seconds until CA certificate expires.",
	})

	tokenCertExpirySeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_token_cert_expiry_seconds",
		Help: "Seconds until token-signer certificate expires.",
	})

	rateLimitRejectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_rate_limit_rejections_total",
		Help: "Total requests rejected by rate limiter.",
	})

	certReloadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_cert_reloads_total",
		Help: "Total successful certificate reloads.",
	})

	certReloadFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_cert_reload_failures_total",
		Help: "Total certificate reload failures.",
	})

	caCertFingerprintInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cert_issuer_ca_cert_fingerprint_info",
		Help: "Info metric exposing the active CA certificate SHA-256 fingerprint.",
	}, []string{"fingerprint"})

	sanValidationFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_san_validation_failures_total",
		Help: "Total CSR SAN validation failures (IP SAN mismatch with source).",
	})

	dnsSanValidationFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_dns_san_validation_failures_total",
		Help: "Total CSR DNS SAN validation failures.",
	})

	rateLimiterEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_rate_limiter_entries",
		Help: "Current number of entries in the per-IP rate limiter.",
	})

	activeNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_active_nodes",
		Help: "Number of distinct node IPs that received certificates within the TTL window.",
	})

	oldestActiveCertExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_oldest_active_cert_expiry_seconds",
		Help: "Seconds until the oldest active node certificate expires.",
	})

	rotateRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_issuer_rotate_requests_total",
		Help: "Total rotate-ca requests by result.",
	}, []string{"result"})

	measurementDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_issuer_measurement_denied_total",
		Help: "Requests denied due to measurement mismatch.",
	}, []string{"endpoint"})
)
