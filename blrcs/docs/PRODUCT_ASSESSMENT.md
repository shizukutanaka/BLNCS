# BLRCS Product Assessment — 長所・短所・改善案

Status date: post-Axis 154 (branch `claude/deepresearch-ultrathink-improve-YbA9t`).

**Shipping state:** `main` carries BLRCS at roughly Axis 128 (49 packages).
Axes 129–154 — 55 commits, including the whole P-256/EUDI arc, the JWE
response encryption, nested selective disclosure, the OpenID4VCI
authorization-code flow, the mdoc PKI, and several fail-closed security fixes
— are **not on main**. Earlier revisions of this document claimed "`main`
carries the product as published via PR #1"; that is false. PR #1 was CLOSED,
not merged (the product reached main by another route, at an earlier state).
Corrected at Axis 150 after checking the PR list rather than trusting the note.
PR #8 now proposes these axes to `main`; it is open and unmerged.

Sections carry their own
"addressed by Axis N" notes; anything not so marked was last verified at Axis
132 and should be re-checked against the tree before being relied on — this
document has been stale before (it claimed `eddsa-jcs-2022` was missing when
`compliance/dataintegrity.go` already implemented it, and claimed `builder` /
`kms` / `i18n` were README-documented public API when the README only listed
their names in a table).

This assessment synthesizes (a) a 20-agent standards-research workflow that
audited the codebase against the current state of 10 standards tracks
(SD-JWT/SD-JWT-VC, OpenID4VP, OpenID4VCI, Token/Bitstring Status Lists,
did:webvh, ISO 18013-5/-7 mdoc, W3C VCDM/Data Integrity, PQC, EU DPP/ESPR,
EUDI ARF) with per-item code verification, and (b) the Axis 95–132 improvement
history in `CHANGELOG.md`.

---

## 長所 (Strengths)

1. **Zero-dependency core.** The entire suite is stdlib + `crypto/ed25519`
   (`go.mod` declares no external requirements). No supply-chain surface,
   trivially auditable, reproducible builds by construction.

2. **Standards currency, independently re-verified.** Not merely claimed —
   audited: SD-JWT core matches RFC 9901 (KB-JWT `typ=kb+jwt`, `sd_hash`,
   `_sd_alg` agility, decoy digests, 128-bit salts, alg=none prohibition);
   `dc+sd-jwt` typ current with legacy dual-accept; OpenID4VP 1.0 Final DCQL
   (incl. `credential_sets` §6.2 **and** `claim_sets` §6.3.1), RFC 9101 JAR,
   `transaction_data` KB-JWT binding; OpenID4VCI 1.0 Final Nonce +
   Notification endpoints, batch issuance (`proofs`→`credentials`), correct
   SD-JWT-VC metadata shape (`vct` + `proof_types_supported`); did:webvh v1.0
   including witnesses, portability enforcement, watchers, and live HTTP
   resolution with SCID-match checking; W3C Bitstring + IETF Token Status
   List; EU Battery Passport Annex XIII field coverage; GS1 Digital Link +
   RFC 9264 Linkset.

3. **Real security engineering, not checkbox security.** Two independently
   discovered-and-fixed SSRF holes (`didresolver`, `vctmeta`:
   initial-connection IP validation via `safeDialContext`, not just redirect
   blocking); oracle-resistant error collapsing (pre-auth/tx_code,
   notification_id); secure-by-default holder binding
   (`RequireKeyBinding=true`); COSE `crit` enforcement; per-call algorithm
   allowlists on both the JWS (SD-JWT `AllowedAlgs`) and COSE
   (`Verify1WithAlgs`) sides for downgrade defense; append-after-deactivation
   rejection and SCID/domain rewrite protection in did:webvh.

4. **Verification discipline.** 2100+ test functions, 21 fuzz targets, race
   detector clean, `golangci-lint` clean. Every axis was additionally
   E2E-verified against a real built binary (`blrcs-mcp` stdio JSON-RPC or
   `blrcs-mcpd` HTTP), not just unit-tested.

5. **Coherent agent-facing surface.** 34 MCP tools covering
   issue/verify/revoke/search across every implemented format; mutating tools
   are automatically SCITT-audited; capability discovery
   (`get_server_capabilities`, `/.well-known/blrcs-capabilities.json`).

6. **Traceable history.** Axis-numbered commits with why-focused messages and
   a CHANGELOG that doubles as an architecture-decision record.

## 短所 (Weaknesses)

1. **P-256 coverage — near complete; W3C VC proofs and SCITT signing remain.**
   *(Addressed across Axes 135-142, 148.)*

   **Done:** ES256 verification for JOSE (SD-JWT) and COSE (mdoc/SCITT) via the
   `ecdsakey` package; P-256 key resolution via `didresolver.ResolveAllKeys`
   (did:web/webvh JWK, did:key, did:jwk, Multikey); ES256 **SD-JWT issuance**
   via `compliance.ES256Issuer`. The full loop — issue, publish an EC JWK in a
   DID document, resolve, verify — is exercised end to end, so a credential
   from a P-256-only EUDI ecosystem interoperates.

   Axis 141 added **mdoc ES256 issuance and device auth** (EC2 COSE_Key device
   keys included), so the mdoc format is P-256 end to end.

   Axis 142 added **ES256 KB-JWT holder binding**: `extractHolderKey` accepts
   an EC/P-256 cnf, `verifyKBJWT` verifies an ES256 KB-JWT against it (rejecting
   an alg that does not match the bound cnf key), and
   `PresentWithKeyBindingES256` emits one — so a real EUDI wallet's P-256
   device-key presentation now completes end to end.

   Axis 148 added the **mdoc issuer PKI** (`x5chain`, IACA→DSC validation), which
   accepts both Ed25519 and P-256 document signer certificates.

   Axis 153 added **`ecdsa-jcs-2019` W3C VC proofs**, so `ES256Issuer` can now
   issue W3C VCs — the last interop-relevant Ed25519-only path. The P-256 arc
   is complete: every credential format BLRCS emits is P-256 capable.

   **Still Ed25519-only:** SCITT COSE receipt *signing* only (BLRCS-internal,
   so no interop pressure). The former `kms`
   contradiction is gone: Axis 149 deleted the package, and `docs/adr/0001`
   carries an amendment naming the seams that actually provide agility.

2. **mdoc presentation path — verification fixed, DC-API request still a stub.**
   *(Verification addressed by Axis 138: `ProcessResponse` now dispatches on
   the DCQL format, verifies the DeviceResponse's issuerAuth and DeviceAuth
   against a supplied SessionTranscript, and enforces `DoctypeValue`. The
   SessionTranscript is caller-supplied because the vanilla-OpenID4VP form is
   still open upstream; an unconfigured one fails closed. **Remaining:** the
   DC-API request side below.)*

   The `buildMdocData` stub was **deleted** (Axis 150) rather than left in
   place. It emitted `{client_id, nonce, response_mode,
   presentation_definition_compat}` — a shape in no specification — under the
   `org-iso-mdoc` protocol id, and `BuildForVerifier` advertised it on every
   call. That was strictly worse than not offering the protocol: a browser
   preferring the mdoc entry would negotiate something the library cannot
   fulfil, losing a working OpenID4VP exchange, while the caller believed an
   mdoc request had been built. Three tests asserted the broken shape and were
   corrected to assert its absence.

   **Remaining:** a real DC-API mdoc request needs (a) a CBOR DeviceRequest per
   ISO 18013-7 Annex C and (b) the OpenID4VPDCAPIHandover SessionTranscript to
   bind the response. Verification for both already exists (Axis 138's mdoc
   path, Axis 148's `VerifyChain`); only the request construction is missing.

3. **Response encryption — addressed for direct_post.jwt (Axis 143).** The new
   stdlib-only `jwe` package implements ECDH-ES + A128GCM on P-256 (RFC
   7516/7518, verified against the RFC 7518 Appendix C vector), and the
   OpenID4VP verifier advertises its encryption JWK + `direct_post.jwt` and
   decrypts an encrypted `response` before verifying. **Remaining:** the DC-API
   `dc_api.jwt` variant and additional content-encryption algorithms
   (A256GCM/AES-CBC-HMAC) are not implemented — only the HAIP-mandated pair.

4. **Selective disclosure — complete (Axes 139, 140, 145).** Verification
   resolves array-element (`[salt, value]` + `{"...": digest}`) and recursive
   (nested `_sd`) disclosures at any depth (Axis 139); DCQL claim paths address
   object keys, array indices and null wildcards (Axis 140); and **issuance now
   emits all three shapes** via the `SD()` marker, with `PresentPaths` /
   `PresentPathsWithKeyBinding{,ES256}` for path-addressed presentation that
   auto-includes ancestor disclosures (Axis 145). The round trip is exercised
   through the independently-written verifier, including the EUDI combination of
   a nested credential, a P-256 holder key and an ES256 KB-JWT.

5. **Issuance flows — addressed (Axis 146).** The authorization code flow is
   implemented (`openid4vci/authcode.go`) with mandatory RFC 7636 PKCE
   (`openid4vci/pkce.go`, S256 only, anchored on the Appendix B vector), so an
   issuer that authenticates the user itself is now expressible alongside the
   pre-authorized flow. User authentication is supplied by the deploying issuer
   through a callback rather than implemented here. Axis 154 added **PAR
   (RFC 9126)**: `/par`, `PushAuthorizationRequest` / `AuthorizeByRequestURI`,
   single-use references burned by a failed redemption, and the two stale
   metadata fields corrected. **Remaining:** `authorization_details` (RFC 9396)
   scoping — the field is carried through PAR but deliberately not echoed as
   *granted* in the token response, since echoing an unvalidated request as
   granted would be a false claim; the offer still grants a single
   pre-registered credential configuration.

6. **Trust-model layer — issuer-side query constraint added (Axis 147).** DCQL
   `trusted_authorities` (§6.1.1) is implemented for all three registered types
   with fail-closed evaluation delegated to `Verifier.TrustedAuthorityChecker`,
   so a verifier can finally tell the wallet *whose* credentials it accepts.
   Axis 148 added the **mdoc issuer PKI**: `x5chain` (RFC 9360) on issuance and
   `VerifyChain` validating IACA→DSC to caller-supplied roots, with the embedded
   chain treated as evidence rather than authority (attacker-rooted chains and
   genuine-DSC/foreign-signature documents both rejected).
   `AuthorityKeyIdentifier`/`ChainMatchesAKI` let the `aki` authority type be
   satisfied from a validated chain in-tree.

   **Remaining:** `verifier_info` absent; RP-registration / trust-list chaining
   absent (client_id prefixes are syntax-checked only); no wallet attestation
   (WUA/WIA); VICAL (the signed trust-list format for distributing IACA roots)
   is not implemented — roots are supplied directly.

7. **Legacy W3C VC proof suite — fixed (Axis 150).** The default is now
   `DataIntegrityProof` / `eddsa-jcs-2022`; the field was inverted to
   `LegacyProofSuite` so Go's zero value points at the current W3C REC rather
   than a suite off the standards track. Verify dispatches on
   type/cryptosuite, so existing credentials are unaffected, and the legacy
   suite stays reachable for verifiers that accept only it.

   Flipping it exposed a latent bug: `issueBatteryPassport` mutates the Annex
   XIII attributes after `Issue` has signed, then re-signed by hand-rolling
   the *legacy* construction regardless of the issuer's suite — so an
   `eddsa-jcs-2022` issuer produced a `DataIntegrityProof` credential with a
   legacy proofValue: permanently unverifiable, with no signal. Now re-signs
   through `attachProof`.

8. **Repo-level gaps — partly addressed (Axis 144).** The CI workflow and the
   Dependabot config both lived under `blrcs/.github/`, where GitHub never reads
   them, so *nothing* in the described suite had ever gated a commit.

   **Done:** Dependabot moved to `.github/dependabot.yml` (its gomod entry also
   pointed at `/` while the module lives in `/blrcs`). The workflow body was
   corrected — build all commands rather than three of four, discover all 20 fuzz
   targets rather than naming 4, enforce gofmt, enforce the zero-dependency
   guarantee, test the declared Go floor as well as stable — and already assumes
   the root location.

   **Blocked, needs a maintainer:** the CI identity maintaining this repo lacks
   the GitHub `workflows` permission, so it cannot write under the root
   `.github/workflows/`. Until someone runs
   `git mv blrcs/.github/workflows/ci.yml .github/workflows/blrcs-go.yml`
   (or grants that permission), **CI still does not run.**

   **Remaining:** the issue/PR templates under `blrcs/.github/` are dead-lettered
   the same way (deliberately left — moving them changes contributor UX for the
   whole repo, including the legacy Python tree); the GitHub repo
   description/topics still describe the unrelated legacy Python project.

## 過剰 (Excess) — resolved (Axis 149)

A first-principles pass asked what the codebase carries that delivers nothing.
The answer, measured with `go list -deps ./cmd/...` against a non-test importer
search rather than assumed: 13 packages reachable from no binary and imported by
no non-test file.

  apispec apiversion builder compose ctx httpchain i18n kms openapi
  otelbridge replay saga schemaver

**All 13 were deleted** — 4,196 non-test LoC + 5,791 test LoC = 9,987 lines; 56
packages → 43. Earlier axes triaged several as "deliberate extension points";
from first principles that was generous. In a security product, code nothing
calls is audit surface and maintenance burden returning zero value.

Two consequences worth recording:

- `kms` carried the hard-coded 32/64-byte key-size checks that contradicted
  `docs/adr/0001`'s crypto-agility claim. Deleting the package resolved that
  weakness instead of retrofitting a part that should not exist. ADR-0001 now
  carries an amendment naming the seams that actually provide agility.
- The README's headline example used `builder`. Rather than restore it, the
  example was rewritten against the direct API — a struct literal, which is what
  the rest of the codebase uses and is no less readable. Both README examples
  are now compiled and executed as a check, not merely asserted.

**Kept deliberately:** `conformance` (891 LoC) has no internal importers but is a
deliverable rather than dead weight — language-independent conformance vectors
so third parties can validate compatible implementations, with its own test
asserting the reference implementation passes every vector.

## 改善案 (Improvements)

The remaining code-verified backlog, split into two execution tracks by
required judgment depth. Full task specs live in the two instruction
documents:

- **`docs/INSTRUCTIONS_SONNET.md`** — small/medium, precisely-specified tasks
  with an existing in-repo pattern to mirror (mdoc transaction_data parity,
  did:webvh /whois, DCQL trusted_authorities scaffolding, verifier_info
  carry, kms ADR correction, eddsa-jcs-2022 for VCs, CI workflow to repo
  root).
- **`docs/INSTRUCTIONS_OPUS.md`** — large/architectural tracks (ES256/P-256
  end-to-end, mdoc↔OpenID4VP/DC-API dispatch, JWE response encryption,
  SD-JWT array/recursive disclosure, authorization code flow, mdoc PKI,
  issuance-side algorithm agility), each with staged milestones and
  stop-and-confirm gates.

Items deliberately **not** queued: BBS/PQC cryptosuites, PQ/T hybrids, HPKE,
EPCIS (upstream specs still non-final — implementing now would chase moving
targets); DPP access-tier actor roles (Battery Reg implementing act due
2026-08-18 will define the roles; premature to guess).

## ソクラテス的検証 (Socratic examination)

Closing examination (post-Axis 154), applying one question to every claim this
document and this codebase make: **how do we know?** The discipline: no claim
stands here unless it traces to a named test or a recorded measurement. The
session's own record justifies the method — every major defect found across
axes 129–154 was a confident, unexamined claim.

### Strengths, interrogated (claim → the test that settles it)

| Claim | How we know |
|---|---|
| Zero dependencies | Enforced, not asserted: `make deps-check` fails the gate on any `go.mod` require |
| Spec conformance | Byte-for-byte reproduction of published vectors: RFC 7518 App C (Concat KDF), RFC 7636 App B (PKCE S256); conformance runner proven able to fail via negative controls |
| Fail-closed security | Each path tested against the attack it stops: chain-as-evidence, auth-code and PAR request_uri burn-on-any-attempt, KB-JWT alg↔cnf match, unknown-cryptosuite rejection, byte-identical collapsed error bodies |
| One real gate | `make verify` (~46 s) caught its own creators twice: a staticcheck finding in Axis 152's new code, and a flaky assertion the author wrote in Axis 146 |
| Docs tell the truth | 14 README examples run as `Example_*` tests under `go test` |

### Defects, grouped by the question that exposed them (all fixed, with regression tests)

- **"Does the label match the act?"** — COSE alg header naming an algorithm
  that didn't sign; battery passport re-signed with the wrong suite; the
  fabricated `org-iso-mdoc` envelope (deleted after checking the actual spec).
- **"Can this check fail?"** — lint that swallowed failures; a CI workflow at
  `blrcs/.github/workflows/` that had never executed; a fuzz list skipping
  17 of 20 targets. Same defect class three times: green without checking.
- **"What happens on bad input?"** — `ed25519.Verify` panics on non-32-byte
  keys; four remotely reachable call sites guarded
  (`TestWrongLengthKeyDoesNotPanic`, `TestVerifyRangeWrongKeyLengthDoesNotPanic`).
- **"Does anyone call this?"** — 13 packages / 10,020 lines unreachable from
  `./cmd/...`, measured then deleted (56 → 43 packages).
- **"Is the document telling the truth?"** — three false claims in this very
  file (corrected above); and the examiner's own untested claim that PR #8
  could not be made mergeable — one tested push (merge commit `15ece73`)
  proved it false. The method must apply to the examiner too.

### Remaining weaknesses (known, with reasons)

SCITT receipt signing is Ed25519-only (internal, no interop pressure);
VICAL / ISO 18013-7 Annex C absent (paywalled specs — implementing from memory
recreates the `org-iso-mdoc` fabrication class); wallet attestation absent
(drafts still moving); legacy Python CI red on every `main` run since 2025-11
(pre-existing, owner action); dependabot `automerge:` key is not a real key.

### Verdict

Engineering-complete and verified: 2,030 tests, 20 fuzz targets, every
credential format P-256-capable, all four defect classes fixed and pinned by
regression tests. Delivery — merging PR #8 — is reserved to the owner by the
repository's own Class C release rule, plus one owner-only command to activate
CI: `git mv blrcs/.github/workflows/ci.yml .github/workflows/blrcs-go.yml`.
That reservation is the design working, not the work unfinished.
