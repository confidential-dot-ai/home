# Contributing to c8s

Thanks for your interest in contributing. c8s is confidential computing
infrastructure for Kubernetes, and we welcome contributions from anyone —
bug reports, fixes, features, and documentation.

This document and the repository license are still evolving; see
[Policy changes](#policy-changes) before opening a PR.

## Terms

- **Anyone may contribute; maintainers decide.** Contributions are accepted
  or declined at the maintainers' sole discretion. We may rework, partially
  adopt, or decline a change for any reason.
- **Contributing grants no governance rights.** Having a contribution merged
  does not give you decision-making power, maintainership, or any say in the
  project's direction.
- **Your contribution becomes the project's code.** By submitting a
  contribution you grant the project the right to use, modify, relicense,
  and redistribute it for any purpose. In practice: once you commit and
  push, it is the project's code, not yours.

## LLM-assisted contributions

Using LLMs to write code is accepted and encouraged, with three conditions:

1. **You are responsible for what it writes.** We hold contributors
   accountable for their submissions, regardless of what tool produced them.
2. **Review before you submit.** You must have read and reviewed all
   LLM-generated code yourself before asking others to approve it.
3. **Understand what you're proposing.** You should be able to explain the
   change — what it does, why it does it, and why it fits into the vision of
   c8s — without the LLM's help.

If you can't meet all three for a given change, it isn't ready to submit.

## Developer Certificate of Origin

Every commit must be signed off, certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This adds a `Signed-off-by:` trailer stating you have the right to submit
the work under the repository license. PRs containing unsigned commits will
not be merged.

## Development setup

You need Go 1.26 or later (the toolchain version is derived from `go.mod`).

```sh
make build   # build all binaries
make test    # unit tests
make lint    # gofmt + go vet
```

Make sure `make lint` and `make test` pass locally before opening a PR. CI
additionally runs golangci-lint, a CRD/chart consistency check
(`make check-crd-chart`), and vulnerability scanning.

## Pull requests

- **Discuss large changes first.** Open an issue before starting anything
  substantial so we can agree on the approach — especially changes touching
  attestation flows, trust boundaries, or the
  [threat model](docs/THREAT_MODEL.md).
- **Keep PRs small and focused.** One logical change per PR.
- **Use conventional commit style** for commits and PR titles:
  `feat(ratls-mesh): ...`, `fix(chart): ...`, `docs: ...`, `test(e2e): ...`.
- **CI must be green** before requesting review.
- Maintainers review and merge at their discretion; expect requests for
  changes.

## Security issues

Do **not** report vulnerabilities through public issues or PRs. See
[SECURITY.md](SECURITY.md) — in short, email **security@confidential.ai**.

## Policy changes

This document and the repository license are likely to change during the
project's early stages. Check both regularly, and re-read them before
raising a PR — the terms in effect when you submit are the ones that apply.
