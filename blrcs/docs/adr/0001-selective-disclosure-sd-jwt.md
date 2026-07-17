# ADR-0001: Selective Disclosure via SD-JWT (commitment-hiding), not BBS

Status: Accepted
Date: 2026-05

## Context

BLRCS must let a holder reveal a subset of a credential's claims to a verifier
(EU DPP: a recycler sees material composition, a consumer sees carbon class,
neither sees the other's fields). The cryptographic-mechanisms survey
(arXiv:2401.08196) groups the options into two families:

- **Commitment-hiding** (salted-hash digests): SD-JWT, ISO/IEC 18013-5 mdoc.
- **Non-interactive ZKP**: BBS / BBS+ signatures.

The survey compares them on standardization maturity, cryptographic agility,
and quantum safety.

## Decision

BLRCS uses **SD-JWT** (salted SHA-256 digests over Ed25519-signed payloads),
emitting conformant SD-JWT VCs (`vct` claim, `draft-ietf-oauth-sd-jwt-vc`).

Rationale:
- Zero external dependencies — SD-JWT needs only SHA-256 + Ed25519, both in the
  Go stdlib. BBS requires pairing-friendly curve libraries (BLS12-381), which
  would break the project's stdlib-only constraint.
- Standardization maturity: SD-JWT VC is the format the EUDI Wallet ecosystem
  has converged on for 2026 rollout; BBS Cryptosuite is still stabilizing.
- Implementation simplicity (Pike) and auditability of a small surface.

## Known limitations (accepted, documented per the survey)

1. **No multi-show unlinkability.** Each SD-JWT presentation reuses the same
   issuer signature, so two verifiers can correlate that they saw the same
   credential. BBS provides unlinkable presentations; SD-JWT does not. For DPP
   this is low-risk: product passports are not privacy-sensitive personal data,
   and the issuer/subject is a product, not a person. If a future use case
   carries PII, revisit with a BBS cryptosuite behind the same `IssueSDJWTVC`
   interface.

2. **Not post-quantum.** Ed25519 is broken by a cryptographically relevant
   quantum computer. This is industry-wide for all currently-deployed VC
   suites (BBS included). Migration path: the `kms.Signer` interface already
   abstracts the signing primitive, so a PQ signature (e.g., ML-DSA / Dilithium)
   can be slotted in without touching issuance logic when a stdlib or vetted
   implementation lands.

3. **Disclosure size grows linearly** with the number of selectively-disclosable
   claims (one digest each). CSD-JWT (arXiv:2506.00262) achieves constant size
   via a cryptographic accumulator; not adopted because it reintroduces a
   pairing dependency and the DPP claim count is small (tens, not thousands).

## Consequences

- The signer primitive is swappable (`kms.Signer`); the disclosure *format* is
  not without a major version bump.
- Verifiers correlating presentations is acceptable for product data; this ADR
  is the record that the trade-off was deliberate, not an oversight.
