# c8s kata-agent boot policy — baked into the kata-guest-base guest
# rootfs at /etc/kata-opa/default-policy.rego. This is the file
# kata-agent loads at startup (POLICY_DEFAULT_FILE in upstream
# src/agent/policy/src/policy.rs).
#
# Role in the c8s design:
#
#   kata-agent's OPA policy gates kata-agent's own ttRPC RPCs (e.g.
#   "is the host allowed to call SetPolicy?"). It is permissive on the
#   container-*creation* RPCs by design: per-image-digest allowlisting
#   is enforced by the in-VM policy-monitor daemon (see kata-guest-base/
#   extra/etc/systemd/system/policy-monitor.service and c8s/docs/kata-
#   image-policy.md), NOT here. The split exists because regorus
#   (kata-agent's OPA engine) lacks the crypto builtins needed to verify
#   a signed allowlist update, and the operator workflow we've landed on
#   is "guest-image tag = pinned allowlist", which policy-monitor
#   implements by reading a baked JSON seed at boot.
#
#   It is NOT permissive on the RPCs that let the host reach into a
#   running container (Exec/ReadStream/WriteStream) — those are
#   denied below, since policy-monitor only gates the image, not runtime
#   host access. See the block comment on those rules. CopyFile is the
#   exception: the runtime needs it to seed a shared_fs="none" sandbox,
#   so it stays allowed (see the DEVIATION note on that rule).
#
#   The primary load-bearing rule is `SetPolicyRequest := false`, which
#   stops the host (which has vsock reach to kata-agent's ttRPC) from
#   replacing this baked policy with a permissive one at runtime. The
#   policy is self-protecting: it lives on the dm-verity root, so the
#   only way to change it is to rebuild the guest image (which changes
#   the kernel-hashes SNP launch measurement).
#
# How updates work:
#
#   This policy is FIXED for the lifetime of the guest image. To change
#   it (e.g. to add a non-permissive default to some RPC), the operator
#   rebuilds the guest image and rolls kata-qemu-snp pods to pick up the
#   new kata-guest-base tag by setting `kata.guestImage.tag` in a values
#   file (`c8s install --kata -f values.yaml`).
#
# Historical note:
#
#   An earlier version of this file was symlinked into a tmpfs render
#   from an in-VM service (`guest-policy-agent`) that fetched a
#   allowlist from CDS over RA-TLS. That design created a CDS
#   bootstrap deadlock (kata-agent waited on the render, the render
#   dialed CDS, CDS was the workload kata-agent was supposed to
#   start) and didn't actually enforce per-image-digest gating
#   (kata-agent's Rego didn't carry the c8s-specific rule). It's been
#   replaced by the baked file + policy-monitor combination. See
#   c8s/docs/kata-image-policy.md for the discussion.

package agent_policy

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default GetDiagnosticDataRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true

# Load-bearing override. See header comment.
default SetPolicyRequest := false

# Host-as-adversary RPCs. policy-monitor gates *which image* runs, but these
# ttRPCs let the host reach *into a running container* over vsock — regardless
# of the image digest — so they are denied at the policy layer too. Nothing in
# the c8s in-guest flow needs them: workloads are driven by kubelet→kata-agent
# CreateContainer, not by host-side exec/stream/copy. This intentionally breaks
# `kubectl exec` into a kata-snp pod — the host node is outside the trust
# boundary, so an in-guest shell/stream/file-copy would be a host-readable side
# channel. Flip one back to `true` only with a one-line note on why it must stay.
default ExecProcessRequest := false
default ReadStreamRequest := false
default WriteStreamRequest := false

# DEVIATION (PR #117 set this to false; that broke kata-qemu-snp boot).
# With shared_fs="none" + experimental_force_guest_pull there is no
# virtio-fs share, so the kata runtime seeds the sandbox into the guest
# over CopyFile: resolv.conf, hostname, /etc/hosts, the serviceaccount
# token, and every configmap/secret/projected mount. Denying it makes
# EVERY kata-qemu-snp sandbox fail at CreateContainer with
# "CopyFileRequest is blocked by policy". A static baked policy cannot
# enumerate the per-pod destination paths the way kata's genpolicy does,
# so a blanket deny is not viable here. Allow it for now; the host can
# inject files into the guest fs, but Exec/ReadStream/WriteStream (live
# host access to a running container) stay denied and SetPolicy stays
# denied. Follow-up: a path-scoped rule limiting dest to /run/kata-
# containers/ (tracked in docs/pitfalls.md).
default CopyFileRequest := true

default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
