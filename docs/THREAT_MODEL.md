# c8s threat model

## What is enforced today

The current milestone enforces these gates:

| Gate | Enforced by | Source of truth |
|---|---|---|
| TEE evidence is valid | attestation-service and Assam | hardware evidence verification |
| A CSR can be signed | cert-issuer | EAR JWT, plus `certIssuer.resourceMap` when configured |
| Image digest is allowed | nri-image-policy | Assam-served whitelist |
| Mesh peer cert chains to the mesh CA | ratls-mesh | mesh CA bundle |
| Workload is injection candidate | admission webhook | pod annotation `confidential.ai/cw` |

CRDs are not security inputs. `TrustDomain` and `ConfidentialWorkload` are
operator UX/status surfaces. A workload can be injected without a CR.

## Chart-managed bootstrap mode

When `assam.enabled=true` and `certIssuer.enabled=true`, the chart installs a
self-contained bootstrap path:

- Assam verifies evidence and issues EAR tokens.
- cert-issuer validates EAR tokens through Assam's JWKS endpoint.
- cert-issuer signs workload CSRs with a chart-managed mesh CA.
- The mesh CA private key is stored in a Kubernetes Secret.

By default this demo path does not pin measurements in cert-issuer. Set
`certIssuer.resourceMap` to restrict which measurements can call
`cert-issuer/sign-csr` and `cert-issuer/ca`.

This is acceptable for demos, development, and environments that deliberately
place these components inside the intended trust boundary. It is not the final
whitepaper production model by itself, because Kubernetes cluster-admins and any
principal able to read the mesh CA Secret can mint workload certificates without
attesting.

## Production direction

The whitepaper CDS-shaped model replaces the Secret-backed CA with a signing key
generated and held inside attested CVM memory. Replicas join through attested
key handoff. The Kubernetes control plane only sees ciphertext and public
material.

In that model:

- the mesh CA private key is not stored in Kubernetes Secrets;
- allowlists and policy are signed by an operator-held key;
- secret release is gated by workload attestation;
- recovery from total CDS outage means re-bootstrap and re-issue certificates.

## Out of scope for this milestone

- Pod-spec integrity checking beyond image digest policy.
- Per-workload peer allowlists in the mesh.
- Measurement pinning in peer certificate verification.
- Attestation-gated application secret release.
- Multi-tenant isolation and federated multi-cluster control planes.
