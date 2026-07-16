# 2026-07-16 — `c8s install --kms`: chart-managed dev OpenBao

`--kms` sets `kms.enabled=true` + `secretBroker.enabled=true`: the chart
renders a dev-mode OpenBao (Deployment + Service `<release>-openbao` + a
`<release>-openbao-dev-cred` root-token Secret) and defaults the broker's
unset `secretBroker.openbao.*` values to it (in-release address, unattested,
dev-cred token). `c8s uninstall` removes it with the release.

Why chart-managed instead of the hand-applied Deployment the KMS demo runbook
used: a `kubectl apply` of a Service over a previous, differently-labeled
`c8s-openbao` **merges** selectors (maps merge key-wise under client-side
apply) into one that matches no pods — apply reports success, the Service
silently has no endpoints (bitten on the Azure demo cluster). Helm instead
fails fast on ownership conflicts, and release-owned resources can't drift.

Guards (validations.yaml): `kms.enabled` without the broker is refused
(`kms_without_broker` — a root-token store nothing fronts), as is combining it
with an explicit `secretBroker.openbao.address` (`kms_conflicting_store`).

Dev/demo only, stated everywhere it renders: in-memory storage, no seal, root
token in a plain Secret. Production points the broker at an external —
eventually attested (`openbao.attested=true`) — store and never sets `--kms`.

The store runs the already digest-pinned `secretAgent.image` (same openbao
image), so the derived NRI allowlist covers it with no new entry.
