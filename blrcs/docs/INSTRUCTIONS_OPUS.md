# BLRCS 指示書 — Opus track (large/architectural axes)

This document tells a **Claude Opus** session how to execute the large,
multi-package, design-decision-heavy improvements to BLRCS. These are NOT
autonomous-loop tasks: each has a design surface that warrants staged
milestones and explicit **stop-and-confirm** gates with the user before the
irreversible or far-reaching parts.

See `docs/PRODUCT_ASSESSMENT.md` for the why and the strength/weakness map.
See `docs/INSTRUCTIONS_SONNET.md` for the small/well-scoped tasks and the
shared **working discipline** (branch rules, verify cycle, commit/push/CHANGELOG
format) — that discipline applies here too, in full, per milestone.

---

## How to run an Opus track

- **One track at a time.** Do not interleave.
- **Milestone = axis.** Each numbered milestone is its own axis: fully
  implemented, tested, E2E-verified, committed, pushed, CHANGELOG'd — a
  reviewable increment — before starting the next.
- **Stop-and-confirm gates.** Where a milestone says ⛔, present the design
  decision to the user (via AskUserQuestion or a written summary) and get
  agreement before proceeding. These are points where a wrong call is
  expensive to unwind.
- **Spec-first, always.** Verify wire formats against primary sources (raw
  GitHub mirrors; `openid.net` 403s here). Cryptographic details especially:
  do not guess curve encodings, COSE alg ids, or JWE header params.
- **Never break Ed25519.** Every track must keep the existing Ed25519 paths
  working and tested; new algorithms are additive.

---

## O1 — ES256 / P-256 end to end  ⟵ START HERE (unblocks O2, O3)

**Why:** the single biggest EUDI-interop blocker. EUDI ARF 2.9 / HAIP mandate
NIST P-256. Today the stack is Ed25519-only: `kms/kms.go` (size hardcodes
:412,440,466,469), `cbor/cose.go:32` (only `AlgEdDSA`),
`didresolver/didresolver.go:366` (OKP/Ed25519 JWK only),
`compliance/extensions.go:609` (P-256 JWK *rejected*, never accepted).

**Leverage:** the verify-side registries already exist and are exercised —
`compliance.RegisterJWSVerifier`, `cbor.RegisterVerifier`,
`compliance.VerifyOptions.AllowedAlgs`, `cbor.Verify1WithAlgs`. P-256 verifiers
can be *plugged in* without core surgery. Use `crypto/ecdsa` +
`crypto/elliptic` (stdlib — keeps zero-dependency invariant). Watch the
Ed25519-vs-ECDSA signature encoding difference (COSE uses raw r||s;
JOSE/JWS ES256 uses raw r||s too; X.509/ASN.1 DER is different — get this right).

Milestones:
1. **ES256 JWS verify** — register an ES256 verifier via
   `compliance.RegisterJWSVerifier`; accept P-256 JWKs in the SD-JWT verify
   path (replace the `:609` rejection with acceptance behind the registry).
   Tests + a known-answer vector.
2. **ES256 COSE verify** — register `AlgES256` (-7) in `cbor/cose.go`; mdoc/
   SCITT verification of a P-256-signed COSE_Sign1 (raw r||s). KAT.
3. **P-256 DID resolution** — accept `kty=EC, crv=P-256` JWKs in
   `didresolver/didresolver.go` and did:key/did:jwk parsing.
4. ⛔ **P-256 issuance** — this is where a design decision is needed: how keys
   are represented in `kms.Signer` (currently Ed25519-typed). Present the
   key-abstraction design (interface vs. algorithm enum + length tables; see
   Sonnet S5) before implementing. Then P-256 signing in kms + compliance +
   cbor + openid4vci PoP.
5. **OpenID4VCI PoP with ES256** — `parseProofJWT` currently hardcodes
   `alg=EdDSA`, OKP JWK (openid4vci.go). Accept ES256 proofs.

**Verify:** issue and verify a P-256 SD-JWT-VC end-to-end via a built binary;
prove an EdDSA credential still verifies unchanged.

## O2 — mdoc ↔ OpenID4VP / DC-API verification dispatch (depends on O1 for full mdoc)

**Why:** `openid4vp/openid4vp.go:499` `ProcessResponse` always verifies the
vp_token as SD-JWT (`:544`), ignoring the matched DCQL query's `Format`;
`dcapi/dcapi.go:157-173` `buildMdocData` is an "MVP: minimal envelope" stub;
`DoctypeValue` is declared but never read. So an `mso_mdoc` presentation cannot
be verified in a live session.

Milestones:
1. **Format dispatch** — branch `ProcessResponse` on the matched
   `CredentialQuery.Format`: SD-JWT → existing path; `mso_mdoc` → the standalone
   `mdoc.Verify` / `mdoc.VerifyDeviceAuth` (already solid). Enforce
   `DoctypeValue`.
2. ⛔ **Annex-C DC-API request** — replace `buildMdocData` with a real ISO
   18013-7 Annex-C `DeviceRequest` and the SessionTranscript/handover binding.
   Confirm the exact SessionTranscript construction against 18013-7 before
   coding (this is the subtle part).
3. **ExtractVPToken for org-iso-mdoc** — parse the real DeviceResponse instead
   of returning raw base64.

**Verify:** a full DCQL(mso_mdoc) → present → ProcessResponse flow, integration
test mirroring `integration/hardened_triangle_test.go`.

## O3 — OpenID4VP response encryption (JWE)  (depends on O1)

**Why:** no `direct_post.jwt` / `dc_api.jwt` / JWE. HAIP mandates ECDH-ES on
P-256; Chrome/Safari ship it. `kms/kms.go` has only AES-GCM + Ed25519; no ECDH.
`dcapi/dcapi.go:191,193` explicitly documents encrypted responses as
unsupported.

Milestones (all ⛔ at the crypto design gate — JWE is easy to get subtly wrong):
1. ECDH-ES P-256 key agreement + A128GCM/A256GCM content encryption (stdlib
   `crypto/ecdh`). KATs against a known JWE.
2. `response_mode=direct_post.jwt` on the verifier: publish an encryption JWK,
   decrypt the returned JWE, then run the existing ProcessResponse.
3. `dc_api.jwt` equivalent in `dcapi`.

## O4 — SD-JWT array-element + recursive disclosure (RFC 9901 core)

**Why:** only flat top-level `[salt,name,value]` disclosures exist
(`compliance/extensions.go`); no 2-element `[salt,value]` array-element
disclosures, no `...` placeholder, no recursive `_sd`. DCQL `walkPath`
(openid4vp/dcql.go) descends objects only.

Milestones: (1) issue-side recursive/array `_sd` construction; (2) verify-side
disclosure resolution; (3) DCQL path traversal into array elements. Heavy on
RFC 9901 §details — spec-first, extensive fuzzing (extend the existing SD-JWT
fuzz targets).

## O5 — OpenID4VCI Authorization Code Flow + PKCE

**Why:** only pre-authorized code flow exists
(`openid4vci/openid4vci.go:1127` rejects other grant types; no `/authorize`, no
PKCE, `TokenResponse.AuthorizationDetails` is dead). Needed for same-device
interactive issuance.

Milestones: (1) `/authorize` endpoint + PKCE challenge/verifier + `issuer_state`
round-trip; (2) authorization_code grant in the token endpoint; (3) wire
`authorization_details`. Keep pre-auth flow intact.

## O6 — mdoc PKI trust chain (IACA → DSC → VICAL)

**Why:** mdoc issuance/verification uses bare Ed25519 keys with no DSC cert in
`issuerAuth`'s `x5chain` and no chain validation to an IACA root or VICAL list
(`mdoc/`, `kms/` have no X.509 outside unrelated `tlsharden`). Without this,
any key can "issue" a structurally-valid mdoc. Depends conceptually on ECDSA
(O1) since real mDL PKI is P-256. Large; ⛔ at the trust-store design.

## O7 — issuance-side algorithm agility

**Why:** issuer signing paths hardcode EdDSA and call `ed25519.Sign` directly
(`compliance/extensions.go:240,245`, `mdoc/mdoc.go`, `scitt/cose_receipt.go`)
rather than routing through `kms.Signer`. Prerequisite for O1's issuance
milestones to generalize. Route all signers through a `kms.Signer` abstraction
so algorithm selection is centralized. ⛔ at the Signer interface design (shared
with O1.4 / Sonnet S5 — coordinate).

---

## Sequencing recommendation

`O1` first (unblocks O2/O3/O6/O7). Then `O2` (highest functional payoff for
mdoc). `O7` and `O1.4` share the kms.Signer design — do them together. `O3`
after O1. `O4`, `O5`, `O6` are independent and can be scheduled by priority.

## Explicitly deferred (do not start without new upstream movement)

BBS unlinkable signatures, PQC cryptosuites (ML-DSA/SLH-DSA), PQ/T hybrids,
HPKE, EPCIS — upstream specs are still non-final drafts; implementing now
chases moving targets. DPP access-tier actor-role enforcement — waits on the
Battery Reg implementing act (due 2026-08-18) that defines the roles.
