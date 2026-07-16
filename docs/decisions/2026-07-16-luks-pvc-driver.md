# 2026-07-16 — `c8s luks --driver pvc`: webhook-attached raw-block claims, no controller

Implements the `pvc` driver stubbed by
[2026-07-10-luks-cli.md](2026-07-10-luks-cli.md), resolving its "PVC
first-bind format controller" follow-up in favor of the alternative it named:
fold first-boot formatting into the pod's own init sequence.

## Shape

- `c8s luks create --driver pvc` writes the passphrase to openbao (unchanged)
  and creates a raw-block PVC `c8s-luks-<workload>-<name>` (`volumeMode:
  Block`, RWO, `--namespace`, optional `--storage-class`) by shelling out to
  `kubectl apply` — the same auth path `c8s install` uses; no client-go in the
  CLI, no new dependency.
- The emitted annotation leads with `pvc=<claim>` instead of `dev=<path>`, and
  **always** `mode=format-if-empty`: nothing can `luksFormat` an unbound
  claim, so the pod's `c8s-luks-open` init container formats the empty device
  on first boot — inside the TEE boundary, so the passphrase is only ever used
  by the workload that owns the volume.
- The **webhook** consumes `pvc=` (XOR with `dev=`): it declares the claim as
  a pod-scope volume and maps it as a raw `volumeDevices` entry on the
  `c8s-luks-open` init container at `/c8s-dev/<name>`. The device path is NOT
  under `/dev` — that mount IS the host's `/dev` (hostPath), and a device node
  created inside it would race the bind mount. App containers are unchanged
  (decrypted fs via the shared emptyDir subPath) and never see the raw device.
- Operators paste **only annotations** — no volume snippet, no nodeSelector.
  The CSI driver attaches the volume wherever the pod schedules, so the pvc
  driver is also the first multi-node-safe path.
- `destroy --driver pvc` refuses (without `--force`) while any pod in the
  namespace mounts the claim; the in-use pre-check for BOTH drivers now runs
  **before** the KV delete — a refused destroy leaves the passphrase intact
  (deleting it under a live volume would orphan the data at the next open).

## Rejected

- **First-bind format controller** (the 2026-07-10 sketch): a new reconcile
  loop + RBAC surface to do what an init container the webhook already
  injects does for free. Nothing watches PVCs now; nothing needs to.
- **client-go in the CLI**: kubeconfig semantics would have to be kept
  bit-identical with the `kubectl`/`helm` shell-outs install already does;
  shelling out keeps one auth path.
- **`--driver csi`** stays a stub: a named-StorageClass variant of `pvc` with
  vendor parameters; add when a concrete vendor need shows up.

## Constraints

- The StorageClass must support `volumeMode: Block` (cloud CSI drivers do;
  rancher local-path does NOT — dev clusters without a block-capable
  provisioner can bind the claim to a static `local` PV over a loop device).
- `kubectl` + cluster access at create/destroy time. List/show stay
  openbao-only.
