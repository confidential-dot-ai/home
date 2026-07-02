# Measurement Strategies

This document explains the measurement problem and how we approach it at Confidential. The gap between what hardware measures at launch and what you actually run is fundamental to confidential computing—and bridging that gap is core to what we do.

After reading this, you'll understand the measurement gap, two common approaches to bridge it (initramfs and dm-verity), and how SVSM can provide isolated services like a vTPM for key sealing. This assumes familiarity with [Document 5: Attestation](05-attestation.md), particularly how launch measurements work and what LAUNCH_DIGEST contains.

## The Problem: Your Code Isn't in the Measurement

The launch digest covers what's loaded at VM startup: OVMF firmware, the kernel, and the initial boot filesystem. Your application code? Probably not measured.

Consider a typical deployment: you have a Python service with dependencies. At launch, the PSP measures the kernel and initial boot image. Then the kernel boots, mounts a disk, and runs your code from that disk. The disk contents were never measured by the PSP. A malicious hypervisor could swap your disk image for a modified one, and the attestation report would look identical.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          The Measurement Gap                             │
│                                                                          │
│   What the PSP measures at launch:                                       │
│   ┌────────────────────────────────────────────────────────────────────┐ │
│   │  OVMF (UEFI firmware)                                              │ │
│   │  vmlinuz (Linux kernel)                                            │ │
│   │  initramfs (initial boot filesystem)                               │ │
│   │  cmdline (kernel parameters)                                       │ │
│   └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│   What you actually want to attest:                                      │
│   ┌────────────────────────────────────────────────────────────────────┐ │
│   │  Your application code                                             │ │
│   │  Python interpreter                                                │ │
│   │  Dependencies and libraries                                        │ │
│   │  Configuration files                                               │ │
│   │  Model weights                                                     │ │
│   └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│   The gap: application code loads from disk AFTER the measurement.       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

This isn't a flaw in SEV-SNP. The hardware can only measure what's in memory at launch. It has no way to measure a disk image that will be mounted later. The question is: how do you extend trust from the PSP measurement to your runtime code?

This is the measurement gap we bridge. When you deploy on Confidential, your application code becomes part of an attestable measurement chain—you don't need to manage IGVM files, initramfs builds, or dm-verity setup yourself.

## Background: Key Concepts

Before diving into the strategies, let's define some terms that will come up repeatedly.

### initramfs (Initial RAM Filesystem)

When a Linux system boots, it faces a chicken-and-egg problem: the kernel needs drivers to access the disk, but those drivers might be on the disk. The solution is initramfs, a small filesystem that gets loaded into RAM alongside the kernel.

The initramfs is a compressed archive (cpio format, gzipped) containing a minimal Linux environment. The kernel unpacks it into a RAM-based filesystem and runs /init from there. Typically, initramfs contains just enough to mount the real root filesystem: disk drivers, filesystem tools, and a small init script. Once the real root is mounted, the system pivots to it and discards the initramfs.

For confidential computing, initramfs has a special property: it's loaded at launch time, so the PSP measures it. Whatever is in the initramfs is part of the LAUNCH_DIGEST.

### dm-verity (Device Mapper Verity)

dm-verity is a Linux kernel feature that provides integrity verification for block devices. It's used by Android, Chrome OS, and other systems that need verified boot.

The idea is simple: before deployment, you compute a hash tree (Merkle tree) over your filesystem image. The root of this tree, a 32-byte hash, commits to the entire filesystem contents. At runtime, the kernel verifies each block as it's read by checking it against the hash tree. If any block has been modified, the verification fails and the kernel returns an I/O error.

The critical insight for confidential computing: the root hash is tiny (32 bytes). You can embed it in the initramfs. The PSP measures the initramfs (including the root hash), and the kernel uses that hash to verify everything else.

### TPM (Trusted Platform Module) and vTPM

A TPM is a dedicated security chip that provides several capabilities: secure key storage, random number generation, and platform measurement. The key feature for confidential computing is key sealing: the ability to encrypt data such that it can only be decrypted when the system is in a specific state.

TPMs have Platform Configuration Registers (PCRs), which are special hash accumulators. You can "extend" a PCR by mixing in new data: new_value = hash(old_value || new_data). Critically, you cannot set a PCR to an arbitrary value or reset it (except by rebooting). This creates a tamper-evident log of what has happened on the system. You can seal keys to specific PCR values, meaning the key can only be unsealed if the PCRs match the expected state.

A vTPM (virtual TPM) brings these capabilities to virtual machines. For confidential computing, the vTPM runs inside the SVSM at VMPL0, isolated from the guest kernel by hardware. The kernel can request TPM operations through a defined interface, but cannot directly access the vTPM's state. This isolation is what makes the vTPM trustworthy: even a compromised kernel cannot unseal keys that were sealed to different PCR values.

## Computing Expected Measurements with IGVM

Before examining the strategies, we need to address a practical problem: how do you know what measurement to expect?

The PSP computes the LAUNCH_DIGEST by hashing each page of initial memory along with its address and metadata. To verify an attestation report, you need to perform the same computation on your build machine and compare results.

We use IGVM (Independent Guest Virtual Machine) format to solve this. IGVM is a standardized file format that packages everything needed to launch a confidential VM: firmware, kernel, initramfs, and metadata about how to lay out memory. The IGVM file specifies exactly which bytes go at which addresses, eliminating ambiguity.

When you build your VM image, you produce an IGVM file. A measurement tool can parse this file and compute the expected LAUNCH_DIGEST deterministically. Because the IGVM format fully specifies the memory layout, the measurement is reproducible: same IGVM file always produces the same expected measurement.

This matters because the PSP's measurement depends not just on file contents, but on where each page is placed in guest physical memory. Without a standardized format, different hypervisors might lay out memory differently, producing different measurements for the same logical content. IGVM eliminates this problem.

We use IGVM to ensure attestable measurements. When you push code, we build an IGVM file that captures the complete memory layout, making the resulting measurement deterministic and verifiable.

## Two Common Approaches

There are various ways to extend trust to your application code. Here we cover two common, straightforward approaches:

| Approach  | What's Measured                        | Who Does the Measuring | Key Tradeoff         |
| --------- | -------------------------------------- | ---------------------- | -------------------- |
| initramfs | Everything at launch                   | PSP (hardware)         | Size limited to RAM  |
| dm-verity | Root hash at launch, blocks at runtime | PSP + kernel           | Read-only filesystem |

These aren't the only options, but they represent the most common patterns. Both can be combined with SVSM to demote the kernel and enable isolated services like a vTPM for key sealing.

## Option 1: Pack Everything Into initramfs

The simplest approach: put your application code directly in the initramfs. The PSP measures it at launch.

### How It Works

Normally, initramfs contains just enough to boot: a small init script, busybox for basic utilities, and drivers. But you can pack anything into it: your application code, the Python interpreter, all your dependencies, configuration files.

The structure would include: an init script (the first process that runs), basic utilities, your language runtime, its standard library, your application code, and any shared libraries needed. All of this gets packed together into the cpio archive.

The init script mounts the necessary virtual filesystems (proc, sysfs, devtmpfs) and then executes your application directly. There's no disk mounting, no package managers, no systemd. Just your code running.

To build the initramfs, you create a cpio archive of the directory structure and compress it. The result is a single file that gets included in your IGVM image.

### The Trust Chain

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         initramfs Trust Chain                            │
│                                                                          │
│   AMD PSP                                                                │
│     │ measures                                                           │
│     ▼                                                                    │
│   OVMF + kernel + initramfs (contains your code)                         │
│     │                                                                    │
│     │ the measurement is: SHA-384(page contents || GPA || ...)           │
│     ▼                                                                    │
│   LAUNCH_DIGEST in attestation report                                    │
│     │                                                                    │
│     │ verifier compares to expected value                                │
│     ▼                                                                    │
│   If match: entire initramfs contents are trusted, including your app    │
│                                                                          │
│   Trust basis: PSP hardware measurement                                  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

The PSP directly measures your application code. No software intermediary is trusted for integrity of the initial load.

### Practical Workflow

The workflow is straightforward: copy your latest application code into the initramfs directory structure, rebuild the cpio archive, regenerate your IGVM file, and compute the new expected measurement from the IGVM. The measurement value is what your verifier should expect.

Every time you change your code, you rebuild the initramfs, which changes the IGVM, which changes the expected measurement.

We automate this workflow. Push your code, and we build the initramfs, generate the IGVM, and record the expected measurement. All this is tied to your specific git commit.

### Tradeoffs

**Strengths:**
- Simplest verification (just compare LAUNCH_DIGEST)
- No runtime verification overhead for initial code
- Minimal software in the trust chain for initial load

**Limitations:**
- Size constrained by available RAM (initramfs unpacks into tmpfs)
- Every code change requires new initramfs and new expected measurement
- Large dependencies (ML frameworks, model weights) may not fit
- Filesystem is in memory, so writes consume RAM
- No runtime measurement: once booted, the kernel is trusted to behave correctly

**When to use:** When your total runtime footprint (code + deps + data) fits comfortably in memory. Good for small services, microservices, or situations where you want minimal complexity in the boot process.

## Option 2: dm-verity for Filesystem Verification

When your application is too large for initramfs, use dm-verity to extend trust to a disk-based filesystem.

### How It Works

You compute a Merkle tree (hash tree) over your filesystem image. The tree structure looks like this:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          dm-verity Merkle Tree                           │
│                                                                          │
│                             Root Hash                                    │
│                            (32 bytes)                                    │
│                           /          \                                   │
│                      Hash01           Hash23                             │
│                     /      \         /      \                            │
│                 Hash0     Hash1   Hash2     Hash3                        │
│                   │         │       │         │                          │
│                Block0   Block1   Block2    Block3                        │
│                 4KB      4KB      4KB       4KB                          │
│                                                                          │
│   The root hash commits to the entire filesystem.                        │
│   Verifying a block = hash it, walk up the tree, check against root.     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

The critical insight: the root hash is only 32 bytes. You embed this in your initramfs. The PSP measures the initramfs (including the root hash). At runtime, the kernel verifies disk blocks against this hash.

### The Trust Chain

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          dm-verity Trust Chain                           │
│                                                                          │
│   AMD PSP                                                                │
│     │ measures                                                           │
│     ▼                                                                    │
│   OVMF + kernel + initramfs                                              │
│                      │                                                   │
│                      │ initramfs contains: root hash = 7f3b2c9e...       │
│                      ▼                                                   │
│   LAUNCH_DIGEST commits to this root hash                                │
│                      │                                                   │
│                      │ at boot, initramfs sets up dm-verity              │
│                      ▼                                                   │
│   Kernel creates verified block device                                   │
│                      │                                                   │
│                      │ every block read is verified against root hash    │
│                      ▼                                                   │
│   Your rootfs (contains Python, your app, etc.)                          │
│                                                                          │
│   Trust basis: PSP measures root hash, kernel verifies blocks            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

Let's trace why an attack would fail:

**Attacker modifies rootfs.img:** The hash of the modified blocks won't match the Merkle tree. The kernel returns I/O error. Attack detected.

**Attacker modifies the hash tree:** The root of the modified tree won't match the root hash in initramfs. Block verification fails. Attack detected.

**Attacker modifies initramfs to use different root hash:** LAUNCH_DIGEST changes. Attestation verification fails. Attack detected.

### Setup: Build Time

On your trusted build machine, you create your root filesystem with everything you need: the Python interpreter, your application, all dependencies, configuration files, and any other runtime components. You then create a filesystem image from this directory.

Next, you compute the Merkle tree over the filesystem image. This produces two things: the hash tree (stored in a separate file) and the root hash (a 32-byte value). The root hash is what you'll embed in your initramfs.

### Setup: Boot Time

The initramfs init script has the root hash baked into it. At boot, after mounting the standard virtual filesystems, the init script creates a dm-verity device. This takes the rootfs image, the hash tree image, and the root hash. If the root hash doesn't match the hash tree, device creation fails.

Once the verified device is created, the init script mounts it read-only as the new root. It sets up tmpfs mounts for directories that need to be writable (like /tmp and /var), then pivots to the verified filesystem and starts the real init system.

### Who Verifies What

This is a common point of confusion. Let's be explicit:

| Component                | Who Measures/Verifies    | Where                |
| ------------------------ | ------------------------ | -------------------- |
| OVMF, kernel, initramfs  | AMD PSP                  | Hardware, at launch  |
| Root hash (in initramfs) | AMD PSP                  | Hardware, at launch  |
| Filesystem blocks        | Linux kernel (dm-verity) | Software, at runtime |

The kernel is trusted because it was measured by the PSP. If the kernel is modified, the measurement changes, attestation fails. A correct kernel will correctly verify dm-verity. So the chain holds.

The kernel was always in your TCB anyway. You can't run userspace without trusting the kernel. dm-verity doesn't add to the TCB, it just leverages the kernel you already trust.

### Handling Writes

dm-verity is read-only. If you modify a block, verification fails on the next read. For runtime state, use overlayfs: mount a tmpfs for the "upper" layer, with the verified filesystem as the "lower" layer. The combined view appears writable. Reads come from the verified lower layer; writes go to the RAM-backed upper layer.

This is how Android and Chrome OS work. The OS is read-only and verified. User data goes to a separate writable partition.

### Practical Workflow

When you update your application code, the workflow has several steps. First, copy your new code into the rootfs directory. Second, rebuild the filesystem image. Third, compute a new hash tree and root hash. Fourth, update your initramfs init script with the new root hash. Fifth, rebuild the initramfs archive. Finally, regenerate your IGVM file and compute the new expected measurement.

The kernel and OVMF typically stay the same across updates. Only the initramfs changes (because it contains the new root hash), which means the LAUNCH_DIGEST changes.

We automate this entire workflow. When you deploy, we build the filesystem image, compute the Merkle tree, embed the root hash in the initramfs, and generate the IGVM—all in a single pipeline tied to your git commit.

### Tradeoffs

**Strengths:**
- Full filesystem, no RAM constraints on size
- Can include large dependencies, ML frameworks, model weights
- Read verification is fast (microseconds per block, parallelizable)
- Familiar filesystem semantics
- Continuous verification: every block read is checked

**Limitations:**
- Filesystem is read-only (need overlayfs for writes)
- Kernel is in TCB for verification (but it was anyway)
- No runtime measurement of dynamic content

**When to use:** When your runtime is too large for initramfs. Good for applications with large dependencies, or when you want a "normal" Linux environment.

## Adding SVSM: Kernel Demotion and Isolated Services

Both initramfs and dm-verity solve the problem of getting trusted code into your VM. But in both cases, the kernel runs at VMPL0, the most privileged level. If you want to run services that are isolated from the kernel (like a vTPM for key sealing), you need to demote the kernel to a lower privilege level. That's what SVSM does.

### What SVSM Does

The SVSM (Secure VM Service Module) runs at VMPL0, the most privileged level inside the guest. It's measured by the PSP at launch along with everything else. The key change is that the guest kernel now runs at VMPL2, a lower privilege level. This means:

- The kernel cannot access SVSM memory (hardware enforced)
- The SVSM can run services that the kernel cannot tamper with
- Even a compromised kernel cannot access VMPL0 resources

The SVSM provides a place to run isolated services. The most common is a vTPM for key sealing.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           SVSM Architecture                              │
│                                                                          │
│   ┌────────────────────────────────────────────────────────────────────┐ │
│   │  VMPL 0 (most privileged)                                          │ │
│   │  ┌──────────────────────────────────────────────────────────────┐  │ │
│   │  │  SVSM + isolated services (e.g., vTPM)                       │  │ │
│   │  │  • Measured by PSP at launch                                 │  │ │
│   │  │  • Kernel CANNOT access this memory                          │  │ │
│   │  │  • Can provide vTPM, attestation proxy, other services       │  │ │
│   │  └──────────────────────────────────────────────────────────────┘  │ │
│   └────────────────────────────────────────────────────────────────────┘ │
│   ┌────────────────────────────────────────────────────────────────────┐ │
│   │  VMPL 2 (less privileged, where kernel now runs)                   │ │
│   │  ┌──────────────────────────────────────────────────────────────┐  │ │
│   │  │  Guest kernel + your application                             │  │ │
│   │  │  • Calls SVSM for vTPM operations                            │  │ │
│   │  │  • Cannot directly access vTPM state or keys                 │  │ │
│   │  │  • Cannot unseal keys sealed to different PCR values         │  │ │
│   │  └──────────────────────────────────────────────────────────────┘  │ │
│   └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### vTPM and Key Sealing

The primary use of the vTPM in this context is key sealing: encrypting keys so they can only be decrypted when PCRs have specific values. This binds secrets to a particular system state.

PCRs are hash accumulators. You extend them by mixing in new data:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                             PCR Extension                                │
│                                                                          │
│   Initial state: PCR[14] = 0x000...000                                   │
│                                                                          │
│   Extend with hash of /app/main.py:                                      │
│     PCR[14] = SHA-256(PCR[14] || SHA-256(/app/main.py))                  │
│                                                                          │
│   Extend with hash of config.json:                                       │
│     PCR[14] = SHA-256(PCR[14] || SHA-256(config.json))                   │
│                                                                          │
│   The final PCR value depends on all extended data, in order.            │
│   Cannot be "undone" or reset to an intermediate value.                  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

You can seal a key to PCR[14]. Later, the key can only be unsealed if PCR[14] has the exact same value. If the kernel were compromised and ran different code, the PCR would be different, and the sealed key would remain inaccessible.

Note that you could measure things into PCRs without a vTPM (the kernel can maintain its own measurement log). The vTPM adds two things: (1) the measurement state is isolated from the kernel, so a compromised kernel can't forge it, and (2) you get standard TPM APIs for key sealing.

### The Combined Trust Chain

With SVSM added to either base approach:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Combined Trust Chain                            │
│                                                                          │
│   AMD PSP                                                                │
│     │ measures                                                           │
│     ▼                                                                    │
│   SVSM (at VMPL0)                                                        │
│     │                                                                    │
│     │ also measured:                                                     │
│     ▼                                                                    │
│   OVMF + kernel + initramfs (with dm-verity root hash, if using)         │
│     │                                                                    │
│     │ LAUNCH_DIGEST covers all of this                                   │
│     ▼                                                                    │
│   Guest boots, kernel runs at VMPL2 (demoted)                            │
│     │                                                                    │
│     │ kernel uses SVSM services (vTPM, etc.)                             │
│     ▼                                                                    │
│   Keys sealed to PCR values can only be unsealed if PCRs match           │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### When to Add SVSM

SVSM is useful when:

- You need key sealing (binding secrets to specific PCR/system states)
- You want services isolated from the kernel (vTPM, attestation proxy)
- You want defense in depth: even if the kernel is compromised, sealed keys remain protected
- You have multiple parties and want isolation between different components

It adds complexity: you're adding another component to your TCB (the SVSM), and the kernel runs at a lower privilege level which may affect some operations. But for scenarios where you need isolated services or key sealing, this complexity is justified.

## PSP Communication: VMPCKs and Guest Messages

Before closing, let's cover how the guest talks to the PSP for attestation requests. This applies to all approaches.

### The VMPCK Protocol

The guest communicates with the PSP through an encrypted channel using VMPCKs (VM Platform Communication Keys). There are four keys, one per VMPL:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       VMPCKs in the Secrets Page                         │
│                                                                          │
│   Offset 0x020: VMPCK0 (32 bytes) - for VMPL0 (SVSM, if present)         │
│   Offset 0x040: VMPCK1 (32 bytes) - for VMPL1                            │
│   Offset 0x060: VMPCK2 (32 bytes) - for VMPL2 (guest kernel, typically)  │
│   Offset 0x080: VMPCK3 (32 bytes) - for VMPL3                            │
│                                                                          │
│   These are AES-256 keys for AES-256-GCM encryption.                     │
│   The PSP has copies; the guest has copies in the secrets page.          │
│   The hypervisor never sees them (secrets page is encrypted).            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

When the guest wants an attestation report, it:

1. Constructs the request (MSG_REPORT_REQ with REPORT_DATA)
2. Encrypts with AES-256-GCM using its VMPCK
3. Sends through shared memory via VMGEXIT
4. Hypervisor forwards to PSP (can't decrypt it)
5. PSP decrypts, processes, encrypts response
6. Guest decrypts response

Sequence numbers prevent replay attacks. If the hypervisor tries to replay an old message, the sequence number is wrong and the PSP rejects it.

### VMPCK0 Zeroing

When an SVSM is present, it zeros VMPCK0 in the secrets page after reading it. This means:

- The guest kernel (at VMPL2/3) cannot communicate as VMPL0
- Only the SVSM can request VMPL0 attestation
- The guest kernel uses VMPCK2 or VMPCK3

If there's no SVSM and the guest kernel runs at VMPL0, it has VMPCK0 and can use it directly.

## Practical Recommendations

1. **Start with dm-verity for most workloads.** It handles arbitrary sizes, gives you a real filesystem, and the trust chain is solid. The read-only constraint is manageable with overlayfs.

2. **Use initramfs for simple, small workloads.** If you can fit everything in RAM and want minimal complexity, initramfs is straightforward.

3. **Add SVSM when you need isolated services or key sealing.** If you need to seal keys to PCR values, or want services that the kernel can't tamper with, add the SVSM layer to demote the kernel.

4. **Use IGVM for reproducible measurements.** Whatever approach you choose, IGVM ensures your expected measurements are deterministic and portable.

## How We Handle Measurement

We abstract the measurement workflow so you don't need to manage IGVM files, initramfs builds, or dm-verity setup yourself.

**Attested builds:** When you push code to your connected GitHub repo, we build an attestable image. The build process is recorded, and the resulting measurement is tied to your git commit hash.

**The measurement chain:**
```
Your git commit
    │
    ▼
Our build pipeline (recorded, auditable)
    │
    ▼
IGVM file with deterministic memory layout
    │
    ▼
Expected LAUNCH_DIGEST (tied to your commit)
    │
    ▼
Attestation report (signed by hardware)
```

**Verifying a deployment:** Every deployment on Confidential can produce an attestation report. That report contains the LAUNCH_DIGEST, which you can trace back to the git commit that produced it. If you want to verify that a deployment matches your source code, you can:

1. Get the attestation report from the running deployment
2. Check that the MEASUREMENT matches the expected value for your commit
3. Verify the certificate chain to confirm the hardware signature

We provide SDKs that handle this verification, but the underlying data is standard—you can verify independently with AMD's tools or your own implementation.

**What this means in practice:** You push code. We build it into an attestable image. Every request to that deployment can include cryptographic proof that your code (identified by git commit) is running on genuine TEE hardware. The measurement gap is bridged automatically.

## Further Reading

- [Document 5: Attestation & Verification](05-attestation.md) for how measurements end up in reports
- [Document 4: Privilege & Communication](04-privilege-and-communication.md) for VMPLs and SVSM details
