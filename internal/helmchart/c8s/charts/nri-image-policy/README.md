# nri-image-policy

Installs the c8s NRI image policy plugin as a containerd-managed host process.
The chart writes the plugin binary and config files onto each node, patches
containerd's NRI settings, restarts containerd, and keeps a pre-delete cleanup
hook available for uninstall.

## What it does

- Copies `/usr/local/bin/nri-image-policy` from the install image to the host
  plugin directory.
- Writes runtime policy and bootstrap whitelist files under the configured host
  config directory.
- Registers the NRI plugin and `default_validator.required_plugins` in
  containerd's config — patched into `config.toml` in place on `k8s`, or
  written as a `config-v3.toml.d/` drop-in on `rke2` (see Node distro
  compatibility).
- Restarts containerd (or the RKE2 supervisor) so the change takes effect.

## Install verification

Check that the installer DaemonSet rolled out:

```bash
kubectl -n <namespace> rollout status ds/<release>-nri-image-policy --timeout=5m
```

Confirm the host plugin artifacts exist on a node:

```bash
NODE=$(kubectl -n <namespace> get pod \
  -l app.kubernetes.io/instance=<release> \
  -o jsonpath='{.items[0].spec.nodeName}')

kubectl debug node/$NODE -it --image=busybox -- \
  ls -la /host/opt/nri/plugins /host/etc/nri/conf.d
```

## Upgrade ordering

Image bumps for this chart, or for any image in `bootstrapWhitelist`, require
coordinated whitelist updates before Helm rolls the install DaemonSet. With
`required_plugins` active, kubelet cannot start the new install pod unless its
image digest is already allowed.

Use this order:

1. Resolve the new digest in CI, update Assam through its EAR-authorized
   `/whitelist` API, and add it to `bootstrapWhitelist.digests` in the
   per-cluster HelmRelease values. Operators should not manually edit the
   node-level runtime whitelist; Assam owns that state.
2. Let Flux or Helm reconcile the values. Existing install pods pick up the new
   `bootstrap.yaml` on the next reconcile and write it to disk.
3. Bump `image.tag`. New install pods can start because the image is present in
   either the bootstrap allowlist or assam's runtime whitelist.

Skipping the digest update and going straight to the image bump can wedge the
cluster. Recovery requires SSH access to the node and a manual edit of
`/etc/containerd/config.toml` to remove the managed block.

## Uninstall

`helm uninstall` triggers the pre-delete uninstall DaemonSet named
`<release>-nri-image-policy-uninstall`. Helm waits for it to become Ready on
every node, which means each node has reverted the containerd config block,
restarted containerd, and removed host artifacts such as the binary, configs,
and cache.

Expect roughly 30 seconds to 2 minutes per fleet, dominated by the containerd
restart on each node. `RollingUpdate` with `maxUnavailable=1` processes nodes
one at a time, so larger fleets scale linearly. The Helm CLI blocks until the
DaemonSet reports Ready on every node.

To skip cleanup for debugging or forensics:

```bash
helm uninstall --no-hooks <release>
```

## First-install trust boundary

Before the install DaemonSet runs on a brand-new node, NRI is not yet gating
container creation. The untrusted Kubernetes control plane can schedule any
image as the install pod and run it with privileged, hostPID, and hostPath
access to `/etc/containerd/config.toml`.

This is a known chart-level threat-model gap. Closing it requires the
TEE-attested node image to enforce a host-side allowlist on the install image
digest before kubelet ever pulls it. That enforcement does not live in this
chart.

## Chart and plugin-source contract

Several security guarantees are enforced by the plugin source code, not by
chart logic:

- stale-cache TTL
- bootstrap and cache union semantics
- signature verification in Phase 2
- plugin registration name
- Unix-socket health binding

The chart writes config fields; the plugin must honor them. The plugin source
lives in the c8s monorepo, so chart and plugin changes must roll together.
Bumping `image.tag` without a matching plugin change can silently regress
behavior.

The install image must ship these tools on `PATH`:

- the host plugin binary at `/usr/local/bin/nri-image-policy`
- `curl` with `--unix-socket` support, not busybox curl
- `nsenter`
- `awk`
- `cmp`
- `install`

## Node distro compatibility

`distro` selects the containerd config layout the installer targets:

- **`k8s`** (default) — vanilla / kubeadm. The NRI block is patched into
  `/etc/containerd/config.toml` in place, between sentinel markers.
  Restart: `systemctl restart containerd`.
- **`rke2`** — RKE2 regenerates its containerd config from a template on
  every supervisor restart, so an in-place patch would not survive. The
  installer writes a standalone `config-v3.toml.d/nri-image-policy.toml`
  drop-in instead (the directory tracks the containerd config schema
  version, `config.toml.d` on the legacy v2 schema — the same directory
  kata-deploy uses). A drop-in loads only if the config `imports` that
  directory; neither RKE2 nor kata-deploy adds the import, so the DaemonSet's
  `containerd-prep` initContainer adds it — to both the rendered config and
  the RKE2 template — before `install` runs. Restart:
  `systemctl restart rke2-agent`.

`c8s install --distro <k8s|rke2>` sets this; it also drives kata-deploy.

For a distro neither value covers, pick the `distro` whose patch strategy
fits — `k8s` for in-place, `rke2` for a drop-in — and override the path
specifics: `containerd.configDir`, `containerd.socket`,
`containerd.restartCommand`. E.g. k3s: `distro: rke2`,
`containerd.configDir: /var/lib/rancher/k3s/agent/etc/containerd`,
`containerd.restartCommand: systemctl restart k3s`.

Verify on a non-production node before rolling the chart fleet-wide.
