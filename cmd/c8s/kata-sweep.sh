# c8s kata host sweep — run by `c8s uninstall` as a privileged init container
# on every node kata-deploy targeted (a short-lived kubectl-applied DaemonSet;
# see cmd/c8s/uninstall.go).
#
# `helm uninstall` already drives the supported kata cleanup: deleting the
# kata-deploy DaemonSet runs `kata-deploy cleanup` in its preStop hook, which
# removes /opt/kata, deregisters the containerd drop-in, restarts the runtime,
# and unlabels the node. That hook is best-effort — it is bounded by the pod's
# termination grace period, and the runtime restart it triggers can kill the
# pod mid-cleanup — and it knows nothing about the c8s-side artifacts (the
# pulled kata-guest-base image, the RKE2 containerd-prep template). This sweep
# is the idempotent last word: it removes whatever is still present and
# restarts the runtime only if it had to deregister kata itself.
#
# Env (all required; set by `c8s uninstall` from the release's computed
# values):
#   HOST_CONTAINERD_DIR — host containerd config directory (distro-specific)
#   GUEST_IMAGE_DIR     — host dir the kata-image-puller pulled kata-guest-base
#                         into (kata.guestImage.hostPath)
#   RKE2_PREP           — "true" when the install ran the RKE2 containerd-prep
#                         initContainer whose template/lock this sweep owns
#   RESTART_COMMAND     — host runtime restart, run via nsenter into PID 1
set -eu

echo "==> c8s kata sweep starting"

CONTAINERD_DIR="/host${HOST_CONTAINERD_DIR}"
config_changed=0

# 1. kata-deploy's containerd runtime drop-in. Still present only when the
#    preStop cleanup was cut short — remove it from whichever schema-versioned
#    drop-in dir it landed in; the restart below deregisters the runtimes.
#    The `imports` line referencing the drop-in dir is left alone: with no
#    matching files the glob is inert, kata-deploy owns that edit on k8s, and
#    on RKE2 the next config regen drops it once the managed template (step 4)
#    is gone.
for d in config-v3.toml.d config.toml.d; do
  f="${CONTAINERD_DIR}/${d}/kata-deploy.toml"
  if [ -f "$f" ]; then
    rm -f "$f"
    config_changed=1
    echo "containerd drop-in removed: $f"
  fi
done
[ "$config_changed" = "1" ] || echo "containerd drop-in already absent"

# 2. The kata-static payload (runtime, shim, QEMU/CLH, guest kernel + images)
#    and the per-shim symlinks kata-deploy installs beside it. /opt/kata also
#    carries the image-puller's <cfg>.upstream snapshot, so that goes too.
if [ -d /host/opt/kata ]; then
  rm -rf /host/opt/kata
  echo "/opt/kata removed"
else
  echo "/opt/kata already absent"
fi
rm -f /host/usr/local/bin/containerd-shim-kata-*-v2

# 3. The kata-guest-base artifact the image-puller pulled (hardened kernel +
#    dm-verity rootfs, multi-GB). Nothing else cleans this up — kata-deploy
#    never knew about it, and the puller has no uninstall path.
if [ -d "/host${GUEST_IMAGE_DIR}" ]; then
  rm -rf "/host${GUEST_IMAGE_DIR}"
  echo "guest image dir removed: ${GUEST_IMAGE_DIR}"
else
  echo "guest image dir already absent: ${GUEST_IMAGE_DIR}"
fi

# 4. RKE2 containerd-prep leftovers: the sentinel-marked managed template
#    (which would re-add the drop-in import on every RKE2 config regen) and
#    the prep lock file. Only a sentinel-marked template is removed — an
#    operator-owned template is never touched, and a legacy pre-sentinel
#    template is left for the prep's own next-install self-repair rather than
#    deleted on content guesswork.
if [ "${RKE2_PREP}" = "true" ]; then
  SENTINEL='c8s-containerd-prep:managed-template'
  for t in config-v3.toml.tmpl config.toml.tmpl; do
    f="${CONTAINERD_DIR}/${t}"
    [ -f "$f" ] || continue
    if grep -qF "$SENTINEL" "$f"; then
      rm -f "$f"
      echo "managed containerd template removed: $f"
    else
      echo "leaving ${t}: not the c8s-managed template"
    fi
  done
  rm -f "${CONTAINERD_DIR}/.c8s-containerd-prep.lock"
fi

# 5. Restart the runtime only if step 1 deregistered kata. On the clean
#    preStop path the restart already happened, and a second restart would
#    blip the node for nothing.
if [ "$config_changed" = "1" ]; then
  echo "restarting containerd: ${RESTART_COMMAND}"
  nsenter -t 1 -m -u -i -n -p -- sh -c "${RESTART_COMMAND}"
fi

echo "==> c8s kata sweep finished"
