# tls-lb

TLS-terminating reverse proxy with TEE-attested certificate provisioning.

## What it does

This chart deploys an nginx reverse proxy that terminates TLS in front of a
backend service. The chart owns nginx, the in-memory CDS certificate volume,
public TLS Secret mounts, discovery storage, and mesh CA mounts. The c8s
admission webhook owns certificate lifecycle by injecting get-cert containers
from the c8s operator image.

For public edge deployments, the chart can instead present a normal WebPKI
certificate from a Kubernetes TLS Secret while still generating and exposing a
CDS-issued certificate for client preflight/discovery.

### How it works

1. The chart annotates the nginx pod template with `confidential.ai/cw=<san>`
   and the tls-lb cert provisioning settings.
2. The c8s admission webhook injects `c8s-init-cert` and `c8s-renew-cert`.
3. The init container contacts the CDS trust root configured on the c8s
   operator, proving the pod is running inside a genuine TEE via the local
   attestation service.
4. CDS issues a TLS certificate for the configured SAN (subject alternative name).
5. The CDS cert and key are written to the chart-owned in-memory `tls-certs` volume shared with nginx.
6. The native get-cert sidecar reuses that key, renews the CDS cert, and SIGHUPs nginx after each successful renewal.
7. If `publicTLS.secretName` is set, nginx presents that Secret's WebPKI cert
   to clients and the get-cert sidecar reloads nginx when Kubernetes rotates
   the mounted Secret. Otherwise nginx presents the CDS cert for backwards
   compatibility.
8. If `discovery.enabled=true`, get-cert writes JSON discovery metadata with
   the issued CDS certificate and attestation evidence, and nginx serves it at
   `discovery.path`.
9. Nginx serves any configured `routes` first, then proxies all other traffic
   to the configured upstream backend. If `upstream.protocol=https`, it can
   present the CDS cert as its upstream client certificate and optionally verify
   the upstream with the mesh CA bundle.

The CDS cert and key are shared between the injected init container, injected
renewal sidecar, and nginx via an `emptyDir` volume with `medium: Memory` -
backed by tmpfs, so private keys are held in RAM only and never written to
disk. Each replica gets a fresh, attested key on startup and reuses it for
certificate renewal.

The supported deployment shape is the c8s umbrella chart, or an equivalent
install with the c8s admission webhook already running. Without the webhook,
tls-lb renders the PKI volumes and nginx config but no get-cert containers are
injected.

When switching the chart-managed `tee-proxy` upstream to HTTPS, also set
`upstream.address` to its HTTPS service port, for example `c8s-tee-proxy:443`.
The default umbrella-chart address uses the HTTP port.

### Trust Notes

`publicTLS.secretName` only controls nginx's public edge cert. It does not replace the CDS cert/key, discovery evidence, or CDS upstream client cert. A swapped WebPKI Secret can affect browser transport identity, but CDS-aware clients must validate the CDS cert and evidence.

`upstream.tls.verifyDepth` maps to nginx `proxy_ssl_verify_depth`: max upstream server certificate chain depth when `upstream.tls.verify=true`.

## Usage
```bash
helm install my-lb charts/tls-lb \
  --set san=api.example.com \
  --set upstream.address=my-backend:8080
```

## Values

| Key | Default | Description |
|-----|---------|-------------|
| `san` | `""` | SAN for the CDS certificate. Empty defaults to the chart-managed Service DNS name. |
| `upstream.address` | `backend:8080` | Host:port of the upstream service |
| `upstream.protocol` | `http` | Protocol for upstream connection (`http` or `https`) |
| `upstream.tls.useCDSClientCert` | `true` | Present the CDS cert to HTTPS upstreams |
| `upstream.tls.verify` | `false` | Verify HTTPS upstream certificates |
| `upstream.tls.verifyDepth` | `2` | Maximum upstream server certificate chain depth nginx verifies when `upstream.tls.verify=true` |
| `upstream.tls.serverName` | `""` | Optional SNI/verification name for HTTPS upstreams |
| `upstream.tls.trustedCAPath` | `""` | Optional upstream CA path. Empty uses `<meshCA.mountPath>/<meshCA.key>`; custom paths must be provided by the image or another mount. |
| `routes` | `[]` | Additional path routes proxied before the default upstream backend. Each entry has `path`, optional `match` (`exact` or `prefix`, default `prefix`), and `backend`. |
| `routes[].backend.address` | _(required)_ | Host:port backend address for a typed route. Do not include a URL scheme. |
| `routes[].backend.protocol` | `http` | Typed route backend protocol (`http` or `https`). |
| `routes[].backend.tls.useCDSClientCert` | `false` | Present the CDS cert to this HTTPS route backend. |
| `routes[].backend.tls.verify` | `false` | Verify this HTTPS route backend certificate. |
| `routes[].backend.tls.verifyDepth` | `2` | Maximum route backend server certificate chain depth nginx verifies when `verify=true`. |
| `routes[].backend.tls.serverName` | `""` | Optional SNI/verification name for this HTTPS route backend. Empty derives the host from `address`. |
| `routes[].backend.tls.trustedCAPath` | `""` | Optional route backend CA path. Empty uses `<meshCA.mountPath>/<meshCA.key>`, mounting the mesh CA when `verify=true`. |
| `publicTLS.secretName` | `""` | Kubernetes TLS Secret for public client TLS. Empty means present the CDS cert. |
| `publicTLS.certKey` | `tls.crt` | Secret key containing the public certificate chain |
| `publicTLS.keyKey` | `tls.key` | Secret key containing the public private key |
| `discovery.enabled` | `false` | Serve preflight discovery JSON and CDS/mesh PEM endpoints |
| `discovery.path` | `/v1/discovery` | JSON discovery endpoint |
| `discovery.cdsCertPath` | `/.well-known/cds-cert.pem` | Endpoint serving the CDS-issued cert PEM |
| `discovery.meshCAPath` | `/.well-known/mesh-ca.pem` | Endpoint serving the mesh CA PEM |
| `meshCA.expose` | `true` | Serve and advertise the mesh CA PEM when discovery is enabled. |
| `meshCA.configMapName` | `""` | Mesh CA ConfigMap name. Empty defaults to `<release>-cds-mesh-ca`. |
| `meshCA.optional` | `true` | Tolerate a missing mesh CA ConfigMap at pod start. Set to `false` when the ConfigMap is pre-created and missing data should fail fast. |
| `nginx.replicas` | `1` | Number of nginx replicas |
| `nginx.httpsPort` | `443` | HTTPS listen port |
| `nginx.resources` | `{}` | Resource requests/limits for the nginx container |
| `nginx.runAsUser` | `101` | UID used by nginx and the injected get-cert containers |
| `nginx.runAsGroup` | `101` | GID used by nginx and the injected get-cert containers |
| `nginx.runAsNonRoot` | `true` | Run nginx and injected get-cert containers as non-root |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `443` | Service port |
| `certProvisioning.verbose` | `false` | Enable debug logging for webhook-injected cert provisioning |
| `certProvisioning.renewInterval` | `1h` | Renewal interval passed to the webhook-injected get-cert sidecar |
| `tlsMountPath` | `/tls` | Mount path for the shared cert volume |
