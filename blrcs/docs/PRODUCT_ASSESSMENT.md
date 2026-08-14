# BLRCS Product Assessment — 長所・短所・改善案

Status date: post-Axis 132 (branch `claude/deepresearch-ultrathink-improve-YbA9t`;
`main` carries the product as published via PR #1). Every file:line reference in
this document was re-verified against the tree at that state.

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

1. **P-256 coverage is now partial, not absent — remaining gaps are W3C VC /
   mdoc / SCITT signing and `kms`.** *(Largely addressed by Axes 135-137.)*

   **Done:** ES256 verification for JOSE (SD-JWT) and COSE (mdoc/SCITT) via the
   `ecdsakey` package; P-256 key resolution via `didresolver.ResolveAllKeys`
   (did:web/webvh JWK, did:key, did:jwk, Multikey); ES256 **SD-JWT issuance**
   via `compliance.ES256Issuer`. The full loop — issue, publish an EC JWK in a
   DID document, resolve, verify — is exercised end to end, so a credential
   from a P-256-only EUDI ecosystem interoperates.

   **Still Ed25519-only:** W3C VC proofs (`compliance.Issuer.Issue`, both the
   `Ed25519Signature2020` and `eddsa-jcs-2022` suites), mdoc and SCITT
   *signing* (verification already accepts ES256), and `kms/kms.go:412,440,466,469`,
   whose hard-coded 32/64-byte size checks still contradict `docs/adr/0001`'s
   crypto-agility claim. Holder binding (KB-JWT) is also Ed25519-only.

2. **mdoc presentation path — verification fixed, DC-API request still a stub.**
   *(Verification addressed by Axis 138: `ProcessResponse` now dispatches on
   the DCQL format, verifies the DeviceResponse's issuerAuth and DeviceAuth
   against a supplied SessionTranscript, and enforces `DoctypeValue`. The
   SessionTranscript is caller-supplied because the vanilla-OpenID4VP form is
   still open upstream; an unconfigured one fails closed. **Remaining:** the
   DC-API request side below.)*

   Original finding: `openid4vp/openid4vp.go:499`
   `ProcessResponse` unconditionally verifies the vp_token as SD-JWT
   (`:544`), never branching on the matched DCQL query's Format;
   `dcapi/dcapi.go:157-173` `buildMdocData` emits an "MVP: minimal envelope"
   instead of an ISO 18013-7 Annex-C DeviceRequest. The standalone `mdoc`
   package is solid, but an mdoc cannot flow through a live
   OpenID4VP/DC-API session.

3. **No response encryption.** No JWE / `direct_post.jwt` / `dc_api.jwt`
   (HAIP mandates ECDH-ES on P-256; Chrome/Safari already ship it). Depends
   on weakness 1.

4. **Selective disclosure — verification complete, issuance still flat.**
   *(Addressed for verification by Axis 139: array-element (`[salt, value]` +
   `{"...": digest}`) and recursive (nested `_sd`) disclosures now resolve at
   any depth, so credentials from conforming third-party issuers verify.)*
   **Remaining:** BLRCS issuance still emits only flat, top-level disclosures,
   and DCQL `walkPath` descends objects but not into array elements.

5. **Issuance flows limited.** Pre-authorized code flow only
   (`openid4vci/openid4vci.go:1127` rejects other grant types); no
   authorization code flow + PKCE.

6. **Trust-model layer thin.** `verifier_info` absent; RP-registration /
   trust-list chaining absent (client_id prefixes are syntax-checked only);
   no wallet attestation (WUA/WIA); no mdoc IACA→DSC→VICAL PKI (bare-key
   mdoc issuance); DCQL `trusted_authorities` explicitly scoped out
   (`openid4vp/dcql.go:179`).

7. **Legacy W3C VC proof suite.** `compliance/compliance.go:82,148,193` uses
   pre-Data-Integrity `Ed25519Signature2020`, while a correct
   `eddsa-jcs-2022` implementation already exists in-repo
   (`didwebvh/proof.go` + `multiformats/jcs.go`) scoped to DID log entries.

8. **Repo-level gaps.** `blrcs/.github/workflows/ci.yml` never runs (GitHub
   only executes workflows at the repo root); the GitHub repo
   description/topics still describe the unrelated legacy Python project.

## 過剰 (Excess) — quantified

A first-principles pass (rather than a spec checklist) also asks what the
codebase carries that delivers nothing. 13 packages have **zero non-test
internal callers** (~8,500 LoC):

- **Legitimate public API** — library consumers call these directly and the
  README documents them: `builder`, `kms`, `i18n`.
- **Unwired infrastructure** (~5,600 LoC): `apispec`, `apiversion`, `openapi`,
  `schemaver`, `httpchain`, `replay`, `saga`, `ctx`, `otelbridge`, `compose`.
  Earlier axes triaged several of these as "deliberate extension points". From
  first principles that framing is generous: in a **security** product, code
  that nothing calls is audit surface and maintenance burden delivering zero
  value, and it inflates the "53 packages" figure the project reports.

**Recommendation**: remove the unwired set, or wire the parts that earn their
place. This is deliberately *not* done unilaterally — deleting ~5,600 LoC is
hard to reverse and the owner may value some of it — so it is surfaced here as
an explicit, separately-confirmable decision.

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
