# The c8s image ships every subcommand the operator + injected init
# containers need. Historically distroless/static:nonroot, but the LUKS
# path (`c8s luks-open`, injected by the pod-mutator webhook) shells out
# to `cryptsetup` + `mkfs.<fs>` + `mount`, none of which distroless
# carries. Debian-slim gives us all three plus a stable libc and a
# nonroot user, at ~35 MB compressed vs distroless's ~2 MB — the trade
# is deliberate: the c8s binary itself is static, but bundling cryptsetup
# as a subprocess is the simplest correct answer for now (a purpose-built
# luks-open image is tracked in docs/decisions/2026-07-10-openbao-luks.md
# under "Follow-ups").
FROM debian:12-slim

# cryptsetup: LUKS format/open/close for c8s luks-open.
# util-linux: mount(8), blkid, losetup.
# e2fsprogs: mkfs.ext4 for the format-if-empty path (Stage 5 default fs).
# xfsprogs: mkfs.xfs when fstype=xfs.
# ca-certificates: TLS to CDS + broker from every c8s subcommand.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       cryptsetup \
       util-linux \
       e2fsprogs \
       xfsprogs \
       ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Nonroot user matching the distroless UID/GID we historically used, so
# the chart's runAsUser:65532 continues to work for get-cert / broker /
# every non-LUKS subcommand. luks-open itself runs privileged via the
# webhook (host-dev mount + cryptsetup requires it), so 65532 doesn't
# apply there.
RUN groupadd --system --gid 65532 nonroot \
  && useradd  --system --uid 65532 --gid 65532 --home /nonexistent \
              --shell /usr/sbin/nologin nonroot

# The `/c8s` binary path is hardcoded in the c8s-cert-wait gate command
# (internal/helmchart/c8s/templates/_helpers.tpl "c8s.getCertContainers" and
# internal/webhook/pod_mutator.go "certWaitContainer") because command bypasses
# the ENTRYPOINT. If you move the COPY target or change the ENTRYPOINT, update
# that command too.
COPY build/c8s /c8s

# NUMERIC uid:gid so kubelet's runAsNonRoot check can verify without a
# name→uid lookup. `USER nonroot` (the symbolic form) is rejected with
# "image has non-numeric user, cannot verify user is non-root".
USER 65532:65532
ENTRYPOINT ["/c8s"]
