# Attested Builds

Cryptographic proof of what was built and from which source. Uses [Kettle](https://github.com/confidential-dot-ai/kettle), our open-source attested build tool, to run your build process inside a TEE and emit a signed [attested build](/docs/attested-builds/) linking the git commit to the final artifact, no deterministic compilers required.

Every build produces a verifiable, tamper-evident chain of custody: signed attestation of the build environment, provenance for every input, and a hardware-rooted measurement of the output. Downstream consumers can verify the artifact came from the claimed source, built with the claimed toolchain, without needing to trust anyone.

Hardware enforcement of the build pipeline: MAC policies, seccomp filters, and process isolation keep the build environment unchanged between source checkout and artifact emission. Achieves SLSA Build L3.

Connects to your GitHub repo. On every commit: checkout, build inside TEE, signed provenance.

See [build pricing](/pricing.md#attested-builds) for per-minute rates.
