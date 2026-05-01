# tls-lb

TLS-terminating reverse proxy with TEE-attested certificate provisioning.

## What it does

This chart deploys an nginx reverse proxy that terminates TLS in front of a backend service. The TLS certificate is provisioned automatically at pod startup via a TEE (Trusted Execution Environment) attestation flow - no manual cert management or cert-manager required.

### How it works

1. An init container (`get-cert`) contacts the **assam** key broker service, proving the pod is running inside a genuine TEE via a local attestation service.
2. Assam issues a TLS certificate for the configured SAN (subject alternative name).
3. The cert and key are written to an in-memory volume shared with the nginx container.
4. Nginx starts and serves HTTPS, proxying all traffic to the configured upstream backend.

The cert and key are shared between the init container and nginx via an `emptyDir` volume with `medium: Memory` - backed by tmpfs, so private keys are held in RAM only and never written to disk. Each replica gets a fresh, attested certificate on startup.

## Usage
```bash
helm install my-lb charts/tls-lb \
  --set san=api.example.com \
  --set assamURL=http://assam:8080 \
  --set attestationServiceURL=http://attestation-service:8400 \
  --set upstream.address=my-backend:8080
```

## Values

| Key | Default | Description |
|-----|---------|-------------|
| `san` | `""` | SAN for the TLS certificate (IP or hostname) |
| `assamURL` | `http://assam:8080` | URL of the assam key broker |
| `attestationServiceURL` | `http://attestation-service:8400` | URL of the local attestation service |
| `upstream.address` | `backend:8080` | Host:port of the upstream service |
| `upstream.protocol` | `http` | Protocol for upstream connection (`http` or `https`) |
| `nginx.replicas` | `1` | Number of nginx replicas |
| `nginx.httpsPort` | `443` | HTTPS listen port |
| `nginx.extraConfig` | `""` | Extra nginx config injected into the server block |
| `nginx.resources` | `{}` | Resource requests/limits for the nginx container |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `443` | Service port |
| `initContainer.verbose` | `false` | Enable debug logging for cert provisioning |
| `tlsMountPath` | `/tls` | Mount path for the shared cert volume |
