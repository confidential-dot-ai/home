# 2026-07-16 — RA-TLS on-cert evidence binds the bare key, embedded by the client

## Problem

`secretBroker.peerVerify=ratls` rejected every CDS-issued workload cert at the
TLS handshake with `report_data mismatch` (first seen on the Azure node-as-CVM
demo cluster; deterministic on every platform).

Root cause: CDS's `/attest` handler verified the client's evidence bound to
`SHA-384(csrPubKey || challenge)` and then embedded **that same challenge-bound
evidence** into the issued leaf's OID `.1.1` extension. The broker (and any
other downstream verifier) re-verifies with `ratls.VerifyCert(cert, policy,
nil)` — a nil nonce, i.e. expected REPORTDATA `SHA-384(pubKey)`. The two can
never match: the challenge is single-use and consumed at issuance, so evidence
bound to it is unverifiable ever after.

It survived review and tests because nothing exercised the path with real
CDS-issued certs: the broker's integration test self-signs nil-nonce RA-TLS
certs, and `scripts/secret-broker-demo.sh` deliberately runs `--peer-verify=ca`
("the ratls path needs hardware").

## Decision

The **client** embeds a second, **nil-nonce-bound** evidence in its CSR as the
`.1.1` extension, and CDS copies it verbatim into the leaf (main's original
behavior). Both cert clients now do this:

- `pkg/ratls/cdsclient` (ratls-mesh node certs) — already did, explicitly "for
  peer RA-TLS fallback"; the branch's issuer-side embed silently overrode it.
- `internal/cmds/getcert` (workload/broker pod certs) — now builds the same
  extension before creating its CSR (`attestationExtension`).

Issuance freshness is unchanged: CDS still demands and verifies the separate
challenge-bound evidence before signing. The two evidences answer different
questions — "is this caller in a TEE *right now*" (challenge-bound, verified
at issuance, never embedded) vs "was this cert's key generated in an attested
TEE" (nil-nonce, embedded, re-verifiable by anyone via the attestation-api).

## Alternatives rejected

- **Issuer-authoritative embed** (the broken shape): CDS cannot mint evidence
  on the client's behalf, and the evidence it *has* verified is
  challenge-bound — structurally unverifiable downstream.
- **Broker learns the challenge**: challenges are single-use and consumed at
  issuance; distributing them would break their freshness role.
- **CDS verifies the CSR-embedded extension before copying**: adds an online
  verify per issuance for a fail-fast nicety only — downstream ratls verifiers
  independently re-verify the embed against the leaf's key (hardware chain +
  REPORTDATA binding via the attestation-api), so a forged or stale embed
  already fails closed at the consumer. Revisit if debugging
  "cert issued but broker rejects it" becomes a support burden.

## Revisit when

- attestation-api `/verify` responses get signed (see the SECURITY note on
  `ratls.VerifyPolicy.AttestationApiURL`) — at that point issuance-time
  validation of the embed becomes cheap to cache and worth doing.
