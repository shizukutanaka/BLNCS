# BLRCS Specification (core subsystems)

Normative spec for the BLRCS credential/transparency stack. Key words MUST /
SHOULD / MAY per RFC 2119. This document is the contract; the **Conformance
matrix** at the end tracks implementation status and remaining gaps. Companion to
`IMPROVEMENT_RESEARCH.md` / `CATEGORY_RESEARCH.md` (which hold the prioritized
backlog and references).

## 1. Identifiers & keys
- DIDs MUST be resolvable via `didresolver` for methods `did:web`, `did:key`,
  `did:jwk`. Issuer/holder signing keys are Ed25519 (`crypto/ed25519`).
- `did:web` resolution MUST enforce HTTPS, bound the response size, and fetch
  `/.well-known/did.json` (or `<path>/did.json`).

## 2. Credential issuance (SD-JWT VC)
- Issued credentials are SD-JWT VCs: a JWS over a JSON payload, `~`-separated
  disclosures, optional trailing KB-JWT.
- The issuer JWT header MUST set `alg` (EdDSA) and `typ` (`vc+sd-jwt`).
- The payload MUST contain `iss`, `vct`, `iat`, and `_sd_alg` (`sha-256`); it
  MUST contain `exp` when a validity period is given.
- Selectively-disclosable claims MUST be salted (≥128-bit CSPRNG salt), digested
  with SHA-256, and listed in `_sd`; their disclosures are appended after `~`.
- Holder binding (optional): when requested, the payload MUST carry `cnf.jwk`
  (OKP/Ed25519) bound to the holder key.
- Status (optional): when a status reference is given, the payload MUST carry
  `status.status_list` with `idx` and `uri` (draft-ietf-oauth-status-list).

## 3. Credential verification — normative rules
A verifier MUST:
1. Parse the issuer JWS header and verify `alg` is **supported** (reject
   `none`/unknown → `ErrSDJWTUnsupportedAlg`); verify the issuer signature.
2. Reject a payload whose `_sd_alg` is present and **≠ `sha-256`**
   (`ErrSDJWTUnsupportedHashAlg`); absent `_sd_alg` defaults to sha-256.
3. Require `vct` (SD-JWT-VC) → else `ErrSDJWTMissingVCT`.
4. Enforce `exp`/`iat` with bounded clock skew (≤60s) →
   `ErrSDJWTExpired` / `ErrSDJWTNotYetValid`.
5. Reject **duplicate digests** in `_sd` (`ErrSDJWTDuplicateDigest`); accept a
   disclosure only when its SHA-256 digest is present in `_sd`.
6. When `cnf` is present (or key binding is required), require and verify a
   trailing **KB-JWT**: holder signature over `nonce`/`aud`/`sd_hash`, with
   `sd_hash` = SHA-256 of the presentation up to and including the final `~`.
7. Never let reserved claims (`_sd`, `_sd_alg`, `cnf`, `status`, …) leak into the
   returned claim set.
A bare JWS without `~` MUST verify as a credential with no disclosures (no panic).

## 4. Status / revocation
- The status list is a SHA-compressible bit array (W3C Bitstring, ≥16KB for herd
  privacy). Decode MUST bound compressed input and decompressed output
  (anti-bomb).
- The list SHOULD be published as a signed **Status List Token** (`statuslist+jwt`)
  carrying `sub` (= the credential's `status.uri`), `iat`, and `exp`/`ttl`.
- A verifier checking status MUST authenticate the token, bind its `sub` to the
  credential's `status.uri` (`ErrStatusListMismatch`), and read the bit at `idx`.

## 5. Presentation (OpenID4VP)
- `CreateRequest`/`CreateRequestDCQL` MUST generate a fresh `nonce` + `state` and
  persist them with a TTL; `state` MUST be one-time (consumed on use).
- `ProcessResponse` MUST verify the vp_token per §3, bind it to the request
  `nonce`+`client_id` via KB-JWT when the credential is holder-bound, enforce all
  `RequiredClaims` are disclosed, and consume `state`.

## 6. Transparency (SCITT)
- `Register` MUST durably persist, then update the in-memory Merkle tree, then
  sign a Receipt (inclusion proof). Ordering MUST hold under failure.
- The log MUST provide inclusion and consistency proofs.

## 7. Cross-cutting
- Zero external dependencies (stdlib + Ed25519 only). Crypto agility: additional
  JWS `alg`s MAY be registered via `RegisterJWSVerifier` without a core dep.
- All HTTP servers SHOULD set Read/Write/Idle timeouts and body-size limits.

---

## Conformance matrix
✅ implemented · ⚠️ partial · ❌ gap (see backlog item)

| Requirement | Status | Notes |
|---|---|---|
| §1 did:web/key/jwk resolution | ✅ | did:webvh (verifiable history) ❌ — backlog #5 |
| §2 SD-JWT VC issuance (vct/iat/exp/_sd_alg) | ✅ | |
| §2 holder binding (cnf) | ✅ | |
| §2 status reference (status_list) | ✅ | |
| §3.1 alg pinning + sig verify | ✅ | **implemented this pass** |
| §3.2 `_sd_alg` = sha-256 enforced | ✅ | **implemented this pass** |
| §3.3 `vct` required | ✅ | **implemented this pass** |
| §3.4 exp/iat enforcement | ✅ | |
| §3.5 duplicate-digest rejection | ✅ | **implemented this pass** |
| §3.6 KB-JWT nonce/aud/sd_hash | ✅ | |
| §3 bare-JWS no-panic | ✅ | |
| §4 anti-bomb decode | ✅ | |
| §4 signed Status List Token + sub binding | ✅ | |
| §4 issuer-metric privacy (padding/accumulator) | ❌ | backlog #11 (CRSet) |
| §5 OpenID4VP nonce binding + one-time state | ✅ | |
| §5 client_id scheme validation | ❌ | backlog #6 |
| §6 SCITT register ordering + proofs | ✅ | COSE Receipts ❌ #3 |
| §6 witness cosigning (split-view defense) | ✅ | **implemented** (`scitt.Witness`) |
| §2 mdoc/mDL format | ❌ | backlog #10 (dcapi stub only) |
| §3 SD-JWT-VC Type Metadata / vct#integrity | ❌ | backlog #7 |
| §7 crypto-agility hook | ✅ | EdDSA built-in; ML-DSA pluggable |
| §7 HTTP server timeouts / rate-limit enforce | ❌ | backlog #9 (config exists, unenforced) |

### Gaps found while writing this spec and **fixed in this change**
§3.1 alg pinning, §3.2 `_sd_alg` enforcement, §3.3 mandatory `vct`, and §3.5
duplicate-digest rejection were all specified-but-unimplemented in the SD-JWT
verifier (it assumed EdDSA, ignored `_sd_alg`, did not require `vct`, and silently
collapsed duplicate digests). All four are now implemented with tests.

### Highest-value remaining gaps (ordered)
1. HTTP rate-limit enforcement (§7) — backlog #9 (config exists, unenforced).
2. mdoc/mDL format (§2) — backlog #10.
3. client_id scheme validation (§5) — backlog #6.
4. COSE Receipts for SCITT (§6) — backlog #3.
