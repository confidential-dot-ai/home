# Kettle: Attested Builds from a TEE

**Today we're open-sourcing Kettle, a tool for building and verifying attested builds.**

Attested builds are packages that include cryptographically signed SLSA provenance, certifying exactly what source code, dependencies, and toolchain produced a binary. Anyone can verify it. No trust required.

## The problem

You ship a binary. Someone has to trust it.

They can audit your source code. They can review your dependencies. But there's a gap they can't close: did the binary they're running actually come from the code they reviewed?

Traditional build systems can't answer that question. They ask users to trust that CI didn't tamper, that sysadmins didn't interfere, that the hypervisor behaved. That's a lot of trust.

Attested builds close the gap.

## How Kettle works

Kettle runs inside a TEE (Trusted Execution Environment). It generates a SLSA-compliant `provenance.json` covering your source, dependencies, and toolchain, then applies a hardware signature to everything via the TEE's attestation mechanism.

The hardware signature is verified against certificates published by the hardware manufacturer. That chain links your binary directly to its source inputs, cryptographically, without requiring trust in any intermediate party.

Two commands:

```bash
# Build and apply a hardware signature from inside a TEE
kettle attest <project>

# Verify the signed evidence and binary checksum
kettle verify <project>/kettle-build
```

Output: a `provenance.json`, an `evidence.json`, and your binaries. Anyone with Kettle can verify them.

## Why TEE-backed attestation matters

GitHub's artifact attestations ask you to trust GitHub's word that their cloud VMs didn't tamper with your build.

Kettle's attestation asks you to trust only the hardware manufacturer and the physical custodians of the build machine. No sysadmins. No hypervisor authors. No image maintainers. The TEE's memory is encrypted even against the hypervisor, so nothing running outside the enclave can observe or modify the build as it runs.

That's a dramatically smaller trust surface.

## Who needs this

**A customer deploying your service** wants to know it's running the code you claim, built from the source they audited.

**A compliance team** wants evidence that a binary was built with specific dependency versions, not newer ones with unknown changes.

**A security auditor** wants to verify that the toolchain used to compile a release matches the one specified in your security documentation.

**A regulated enterprise** wants proof that sensitive data will be processed only by code that passed their review, not by a modified version.

**A package consumer** wants to ensure the binary they downloaded corresponds to the source and dependencies they reviewed, not a tampered version.

## Getting started

Kettle is open source and installs via Cargo:

```bash
# From GitHub Releases
curl -LO https://github.com/confidential-dot-ai/kettle/releases/latest/download/kettle

# From source
cargo install --git https://github.com/confidential-dot-ai/kettle

# Inside a TEE (enables hardware attestation)
apt-get install -y libtss2-dev
cargo install --features attest --git https://github.com/confidential-dot-ai/kettle
```

Rust, Nix, JavaScript, and TypeScript (via pnpm) projects are supported today. Python and Go support is coming.

Full documentation, architecture, and threat model: [github.com/confidential-dot-ai/kettle](https://github.com/confidential-dot-ai/kettle)

---

Kettle is part of Confidential's broader infrastructure for confidential computing. If you're building systems where the integrity of code matters, this is the foundation.
