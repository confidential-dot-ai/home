# nri-image-policy

Installs the c8s NRI image-policy plugin onto every node as a
containerd-managed host process, then pushes the deployment-specific CDS image
digest to the CDS-node plugin so it can admit the CDS container.

This is a transitional chart. Once node images bake the plugin binary,
containerd registration, and boot configs, the operator disables this chart at
the umbrella level (`nri-image-policy.enabled: false`) and a future chart
handles digest delivery.

## What gets deployed

- Copies `/usr/local/bin/nri-image-policy` from the install image to the host
  plugin directory.
- Writes `image-policy.yaml` under the configured host config directory.
- Registers the NRI plugin and `default_validator.required_plugins` in
  containerd: patched into `config.toml` in place on `k8s`, or written as a
  schema-versioned drop-in on `rke2`.
- Restarts containerd, or the RKE2 supervisor, so the change takes effect.

| Resource | When | Where |
| --- | --- | --- |
| Worker installer DS | Always | Every node except the CDS node |
| CDS installer DS | Always | The CDS node only (matches `cds.node.selector`) |
| Push hook Job | `post-install,post-upgrade` | The CDS node only |
| Uninstall hook DS | `pre-delete` (if `uninstall.enabled`) | All nodes |

Each installer DaemonSet init container writes a boot config, copies the plugin
binary, updates containerd NRI registration, restarts containerd if anything
changed, and waits for the plugin's unix-socket health probe.

The push hook Job lands only on the CDS node, mounts the plugin's unix socket
from the host, and `PUT`s a single-entry whitelist payload:

```json
{"version":"1","digests":{"<cds.image.digest>":"<cds.image.reference>"}}
```

The plugin validates the digest, persists the payload to
`/var/lib/nri-image-policy/pushed.json`, and updates its in-memory cache. A
plugin or containerd restart re-loads the pushed payload from disk.

## Push vs pull boot config

The two installer DaemonSets write different boot configs:

| Boot field | Worker DS | CDS DS |
| --- | --- | --- |
| `whitelist.pull.url` | `cds.url` | unset |
| `whitelist.pull.interval` | `refresh.interval` | unset |
| `whitelist.push.persist_path` | unset | `/var/lib/nri-image-policy/pushed.json` |
| `whitelist.always_allow` | `image.digest` (auto) + `bootstrapWhitelist.digests` | same as worker |

Everything else (containerd socket, `policy.mode`, exempt namespaces, label
rules) is identical across archetypes.

## Required values

```yaml
image:
  tag: "<release-tag>"        # or use image.digest
  digest: "sha256:<64 hex>"   # required for chart self-allow
cds:
  image:
    digest: "sha256:<64 hex>"
    reference: "ghcr.io/<owner>/cds:<tag>"
  url: "http://c8s-cds.c8s-system.svc:8080"
  node:
    selector:
      role: cds-node
```

`cds.node.selector` must be exactly one key/value pair. The chart uses it for
CDS-installer affinity, worker-installer anti-affinity, and the push hook
nodeSelector.

## CDS digest rotation

```bash
helm upgrade <release> <chart> \
  --set cds.image.digest=sha256:<new> \
  --set cds.image.reference=ghcr.io/<owner>/cds:<new>
```

The `post-upgrade` hook re-fires and pushes the new digest. The CDS-node
plugin's `pushed.json` is rewritten atomically. No containerd restart is needed
for that digest rotation.

If workers also need the new digest, push it to CDS via its EAR-authenticated
`POST /whitelist` API. Workers pick it up on their next ETag-aware poll.

## Uninstall

`helm uninstall` triggers the pre-delete uninstall DaemonSet, which lands on
every node, removes the containerd-managed block or drop-in, deletes host
artifacts, and restarts containerd.

To skip cleanup for debugging:

```bash
helm uninstall --no-hooks <release>
```

## Node distro compatibility

`distro` selects the containerd config layout the installer targets:

- `k8s` (default): vanilla/kubeadm. The NRI block is patched into
  `/etc/containerd/config.toml` in place, between sentinel markers. Restart:
  `systemctl restart containerd`.
- `rke2`: RKE2 regenerates its containerd config from a template on every
  supervisor restart, so an in-place patch would not survive. The installer
  writes a standalone `config-v3.toml.d/nri-image-policy.toml` drop-in instead
  (or `config.toml.d` on the legacy v2 schema). The `containerd-prep`
  initContainer adds the required drop-in import before `install` runs.
  Restart: `systemctl restart rke2-agent`.

`c8s install --distro <k8s|rke2>` sets this; it also drives kata-deploy.

For a distro neither value covers, pick the `distro` whose patch strategy fits
and override the path specifics: `containerd.configDir`, `containerd.socket`,
and `containerd.restartCommand`. For k3s, use `distro: rke2`,
`containerd.configDir: /var/lib/rancher/k3s/agent/etc/containerd`, and
`containerd.restartCommand: systemctl restart k3s`.

Verify on a non-production node before rolling the chart fleet-wide.

## Trust boundary caveat

Before the installer DaemonSets run on a brand-new node, NRI is not yet gating
container creation. Closing that gap requires TEE-attested node images that
enforce a host-side allowlist before kubelet pulls privileged installer images.

## Smoke testing

```bash
helm lint . -f ci/test-values.yaml --set image.tag=dev
helm template test . -f ci/test-values.yaml --set image.tag=dev
```
