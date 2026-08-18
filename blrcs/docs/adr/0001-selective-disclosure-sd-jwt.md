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
   suites (BBS included). Migration path: the algorithm is reached through a
   registry seam, so a PQ signature (e.g. ML-DSA / Dilithium) can be slotted in
   without touching issuance logic when a stdlib or vetted implementation lands.
   *(Amended by Axis 149 — see the amendment below; this originally named
   `kms.Signer`, which did not in fact provide that seam.)*

3. **Disclosure size grows linearly** with the number of selectively-disclosable
   claims (one digest each). CSD-JWT (arXiv:2506.00262) achieves constant size
   via a cryptographic accumulator; not adopted because it reintroduces a
   pairing dependency and the DPP claim count is small (tens, not thousands).

## Consequences

- The signer primitive is swappable (see the amendment below); the disclosure
  *format* is not without a major version bump.
- Verifiers correlating presentations is acceptable for product data; this ADR
  is the record that the trade-off was deliberate, not an oversight.


## Amendment (Axis 149) — where crypto-agility actually lives

This ADR originally cited `kms.Signer` as the seam that made the signing
primitive swappable. That was not true when written and was never made true:
`kms` carried hard-coded 32/64-byte key-size checks that admitted Ed25519 keys
and nothing else, so the interface it exposed could not have carried a P-256 or
ML-DSA key. The claim was aspiration recorded as fact.

Rather than retrofit `kms` to match its own ADR, Axis 149 deleted the package —
nothing in the tree called it, so it was optimising a part that should not
exist. The agility the ADR wanted is delivered instead by the seams the P-256
work (Axes 135–148) actually built and exercised:

- `compliance`'s `jwsSigner` interface, through which `Issuer` (EdDSA) and
  `ES256Issuer` (ES256) share one disclosure/decoy/shuffle path, so adding an
  algorithm cannot fork the privacy-critical logic.
- `cbor.RegisterVerifier` plus the COSE algorithm registry, which dispatches
  COSE verification on the signed `alg` header (and refuses a header that
  disagrees with the signature actually produced).
- `compliance.RegisterJWSVerifier` and the per-call `AllowedAlgs` allowlists on
  both the JOSE and COSE sides, so agility never becomes silent downgrade.
- `ecdsakey` for P-256 key encoding shared across JOSE, COSE and X.509 paths.

The substantive claim of this ADR — that the signing primitive is swappable
while the disclosure format is not — still holds. Only the named mechanism was
wrong, and it is corrected here rather than quietly dropped.
