# BLRCS — Category-Organized Improvement Research

Goal: enumerate BLRCS's product categories (10) and, for each, gather related
information from **arXiv** and **GitHub / standards bodies** (~10 references) and
distill concrete improvement points mapped to the code. Companion to
`IMPROVEMENT_RESEARCH.md` (which holds the cross-cutting P0–P2 list); this file is
organized by domain so each subsystem can be driven independently.

Survey date: 2026-06. Priority tags: **[P0]** interop/correctness blocker ·
**[P1]** security/privacy · **[P2]** completeness/robustness.

---

## 1. Selective-disclosure credential formats
**Code:** `compliance/extensions.go` (SD-JWT), `types/`, `builder/`.
**References:** IETF SD-JWT (RFC 9901) · draft-ietf-oauth-sd-jwt-vc-16 · ISO/IEC
18013-5 (mdoc) · W3C VCDM 2.0 · W3C Data Integrity ECDSA-SD · AnonCreds
(hyperledger/anoncreds-spec) · arXiv 2506.00262 (compact selective disclosure) ·
arXiv 2406.19035 (SD-BLS) · walt.id / Sphereon / credo-ts (openwallet) libs ·
Microsoft Entra Verified ID.
**Improvements:**
- **[P0]** Add real **mdoc/mDL (ISO 18013-5)** CBOR `IssuerSigned`/MSO format —
  eIDAS 2.0 mandates it alongside SD-JWT-VC; `dcapi.buildMdocData` is a stub.
- **[P1]** Pad `_sd` with **decoy digests** to a fixed bucket to hide the
  hidden-claim count (arXiv 2506.00262).
- **[P2]** SD-JWT-VC **Type Metadata** resolution + JSON-Schema validation +
  `vct#integrity` (draft-ietf-oauth-sd-jwt-vc §Type Metadata).
- **[P2]** Support nested/recursive disclosures and array-element disclosures
  (RFC 9901 §5.2) — current impl only does flat top-level `_sd`.

## 2. Wallet protocols (issuance & presentation)
**Code:** `openid4vp/`, `openid4vci/`, `dcapi/`.
**References:** OpenID4VP v1.0 (DCQL §6) · OpenID4VCI v1.0 · W3C Digital
Credentials API · ISO/IEC 18013-7:2025 (mdoc-over-OpenID4VP) · OIDF/Univ.
Stuttgart formal analysis (2025) · eu-digital-identity-wallet/eudi-* repos ·
arXiv OID4VCI formal analysis (ETH Zürich) · draft attestation-based client auth.
**Improvements:**
- **[P1]** Validate `client_id` scheme (`x509_san_dns`/`redirect_uri`) and prefer
  the proven **DC-API same-device** path; document cross-device phishing risk
  (Stuttgart analysis). KB-JWT nonce binding already landed.
- **[P2]** **Wallet Unit / Key Attestation (WUA)** in OID4VCI — bind attested
  holder key into `cnf` (EUDI ARF Q4'25–Q1'26).
- **[P2]** `request_uri` (signed request object, JAR) so requests aren't passed
  inline in the QR URL — current `buildRequestURL` inlines `presentation_definition`.
- **[P2]** DCQL parity audit: `credential_sets`, value/path matching, format
  constraints vs the retired Presentation Exchange.

## 3. Transparency & supply-chain integrity
**Code:** `scitt/scitt.go`, `scitt/consistency.go`, `webhook/`.
**References:** draft-ietf-scitt-architecture-22 · COSE Receipts / COSE Merkle
Tree Proofs · sigstore/rekor · in-toto/attestation · slsa-framework/slsa ·
transparency-dev/{trillian,witness,tessera} · C2SP tlog-witness / tlog-checkpoint ·
IACR 2024/879 (Consistency-or-Die) · RFC 6962 (CT) · arXiv 2409.03720
(confidential computing transparency).
**Improvements:**
- **[P0]** Emit **COSE_Sign1** Signed Statements + CBOR **Receipts** for IETF
  SCITT interop (current is JSON+Ed25519 by the code's own admission).
- **[P1]** Publish a **signed checkpoint** + **witness cosigning** to defeat
  split-view attacks (consistency proofs already exist in `consistency.go`).
- **[P2]** Add SLSA provenance / in-toto attestation as a first-class statement
  profile for the supply-chain use case.

## 4. Credential status & revocation
**Code:** `revocation/bitstring.go`, `revocation/revocation.go`.
**References:** W3C Bitstring Status List v1.0 · draft-ietf-oauth-status-list
(Token Status List, JWT/CWT) · arXiv 2501.17089 (CRSet — issuer-metric leakage) ·
arXiv 2503.22010 (time-flexible AHIBE revocation) · arXiv 2510.09715 (zk-STARK
accumulator) · EVOKE (ECC accumulator, IoT) · hyperledger anoncreds revocation ·
status-list reference impls in EUDI RI.
**Improvements:**
- **[P0]** Wire a **`status` claim** into issued credentials (idx+uri) so
  verifiers can actually check revocation; add `VerifyStatus`.
- **[P0]** Implement **IETF Token Status List** (`statuslist+jwt/cwt`) for
  SD-JWT-VC/EUDI interop.
- **[P1]** Mask **issuer business-metric leakage**: pad list to fixed size + seed
  unused bits; longer term accumulator + ZK non-revocation (CRSet).
- **[P2]** Issue the status list itself as a **signed StatusListCredential** with
  `ttl`/`validFrom` + a cache-aware HTTP handler.

## 5. Decentralized identifiers & key management
**Code:** `didresolver/didresolver.go` (web/key/jwk), `kms/kms.go`.
**References:** W3C DID Core 1.0 · did:web · **did:webvh** (DIF, formerly did:tdw,
v0.5, Go impl underway) · did:jwk · did:key · DIF universal-resolver · arXiv
2410.15758 (already cited in code) · OpenWallet credo / aries-framework-go ·
HSM/PKCS#11 & cloud-KMS patterns · key-attestation drafts.
**Improvements:**
- **[P1]** Add **did:webvh** (did:web + verifiable history): SCID + signed
  DIDDoc update log → detect silent key substitution that plain did:web allows.
- **[P1]** Route signing through `kms.Signer` everywhere and add an HSM/cloud-KMS
  backend (current credential path calls `ed25519.Sign` directly).
- **[P2]** DID document **caching with TTL + integrity** and `did:web` resolution
  hardening (max size, redirect policy, `application/did+json` enforcement).
- **[P2]** Key rotation / `verificationMethod` selection by `kid`.

## 6. Cryptography, COSE/JOSE & post-quantum
**Code:** `compliance/extensions.go` (`alg` hardcoded EdDSA), `kms/`, `atrest/`.
**References:** FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · NIST IR 8547 (PQC
migration) · CNSA 2.0 · RFC 9053/9052 (COSE) · BBS+ / draft-irtf-cfrg-bbs ·
W3C ECDSA-SD · *Towards Post-Quantum Verifiable Credentials* (ACM 2024) ·
cloudflare/circl, open-quantum-safe/liboqs-go · arXiv 2510.10436 (PQC survey).
**Improvements:**
- **[P1]** **Crypto-agility**: read `alg` from the JOSE/COSE header, route through
  `kms.Signer`, stop assuming EdDSA (hardcoded in 2 sites, ed25519 across 15 files).
- **[P1]** Add **ML-DSA** (pure or hybrid Ed25519+ML-DSA) signer behind the
  interface; verifier selects by `alg`.
- **[P2]** A small **COSE** encoder shared by mdoc (#1) and SCITT receipts (#3).
- **[P2]** Optional **BBS+/ECDSA-SD** cryptosuite for unlinkable presentations.

## 7. Privacy & data minimization
**Code:** `privacy/`, `compliance/access_tier.go`, `revocation/bitstring.go`.
**References:** arXiv 2506.00262 / 2406.19035 (unlinkability) · arXiv 2501.17089
(status-list privacy) · BBS unlinkable proofs · zk-creds / Cinderella / Anonymous
Credentials lit · GDPR data-minimization · ESPR tiered access · Apple PrivacyInfo
manifest (the `privacy/` package's model).
**Improvements:**
- **[P1]** Document & test the **linkability threat model** (colluding
  verifiers); offer **batch issuance** of single-use credentials as the interim
  unlinkability mitigation (EUDI approach).
- **[P1]** **Predicate/range proofs** for "over 18 / capacity ≥ X" without
  revealing the value (ties into the existing TEE range-proof in `compliance`).
- **[P2]** Selective-disclosure **salt entropy audit** (16 bytes is fine; verify
  CSPRNG sourcing) and per-claim salt uniqueness tests.

## 8. EU regulatory & domain standards (DPP / GS1 / traceability)
**Code:** `compliance/` (DPP, Battery, GS1 Digital Link, linkset), `builder/`.
**References:** ESPR (EU) 2024/1781 · Battery Reg (EU) 2023/1542 · GS1 Digital
Link (ISO/IEC 18975) · GS1 **EPCIS 2.0 + CBV** (JSON-LD events) · **UN
Transparency Protocol (UNTP)** DPP + Conformity Credential + Digital Traceability
Events (uncefact/tests-untp, uncefact/spec-untp) · CIRPASS DPP · W3C VC for DPP ·
Spherity / Battery Pass consortium.
**Improvements:**
- **[P1]** Add an **EPCIS 2.0** traceability-event module (ObjectEvent/bizStep,
  JSON-LD) — README referenced `epcis` but no package exists; this is the
  lifecycle/traceability backbone.
- **[P1]** Align the DPP credential with **UNTP** (Digital Conformity Credential,
  Digital Identity Anchor) for international interop beyond EU-only schemas.
- **[P2]** Machine-readable **schema registry** for ESPR/Battery Annex XIII fields
  with validation (ties to #1 Type Metadata).
- **[P2]** GS1 Digital Link: full AI set + link resolver (`linkset.go`) conformance
  to ISO/IEC 18975 resolver spec.

## 9. Secure web service & API hardening
**Code:** `httpchain/`, `httpmw/`, `tlsharden/`, `config/`, `capability/`,
`recovery/`, `replay/`.
**References:** OWASP ASVS / API Security Top 10 · golang.org/x/time/rate ·
go-chi/httprate · eclipse-biscuit (capability tokens) · macaroons (Google) ·
RFC 9421 (HTTP Message Signatures) · OpenTelemetry Go · W3C Trace Context ·
Go `net/http` Server timeout hardening.
**Improvements:**
- **[P1]** **Enforce rate limiting**: `config.RateLimitRPS` exists (default 100)
  and errkit has a 429 code, but no limiter middleware in `httpmw`/`httpchain`
  actually enforces it — add a token-bucket middleware.
- **[P1]** Server **timeout hardening** (ReadHeader/Read/Write/Idle timeouts) and
  body size limits across all handlers (gosec G114 flagged the demo serve).
- **[P2]** Capability-based **authorization tokens** (biscuit/macaroon-style
  attenuable tokens) — `capability/` today is runtime *feature* detection, not
  request authZ; offline-attenuable tokens fit the multi-actor supply chain.
- **[P2]** **W3C Trace Context** propagation (`traceparent`) through `httpchain`
  into `otelbridge`; export **metrics** (not only spans/logs).

## 10. Reliability & engineering supply-chain
**Code:** `fuzz/`, `property/`, `conformance/`, `integration/`, `saga/`,
`recovery/`, `.github/workflows/ci.yml`, `.goreleaser.yaml`.
**References:** Go fuzzing · gopter/rapid (property testing) · SLSA provenance ·
sigstore/cosign keyless signing · CycloneDX SBOM · reproducible-builds.org ·
OpenSSF Scorecard · govulncheck · C2SP test vectors · `transparency-dev` test
suites.
**Improvements:**
- **[P1]** Publish **SLSA provenance** + **cosign** signatures for release
  artifacts (goreleaser already emits SBOMs + `-trimpath`; add keyless signing &
  provenance attestation).
- **[P2]** **OpenSSF Scorecard** workflow + pin GitHub Actions by SHA (supply-chain
  hardening of the repo itself).
- **[P2]** Expand **conformance vectors** (DCQL credential_sets, status-list,
  mdoc) and add **reproducible-build verification** to CI.
- **[P2]** Saga/recovery **chaos tests** (inject failures between SCITT durable
  write → Merkle update → receipt sign to prove the ordering invariant holds).

---

## Top cross-category sequence (where to start)
1. **Status plumbing** (#4 P0 + #4 StatusListCredential) — small, reuses
   Ed25519/bitstring, makes revocation real.
2. **Crypto-agility** (#6 P1) — foundational; unblocks ML-DSA, mdoc, COSE.
3. **COSE layer** (#6) → **SCITT receipts** (#3) + **mdoc** (#1) share it.
4. **Witness cosigning** (#3 P1) — cheap given existing consistency proofs.
5. **Rate-limit enforcement** (#9 P1) — config exists, just unenforced.

## Sources (new this pass)
- did:webvh: https://github.com/decentralized-identity/didwebvh , https://identity.foundation/didwebvh
- UNTP: https://uncefact.github.io/spec-untp/docs/specification/ , https://github.com/uncefact/tests-untp
- EPCIS 2.0: https://www.gs1.org/standards/epcis
- Biscuit capability tokens: https://github.com/eclipse-biscuit/biscuit-rust ; go-chi/httprate: https://github.com/go-chi/httprate
- (See `IMPROVEMENT_RESEARCH.md` for OpenID4VP/SD-JWT/SCITT/status-list/PQC arXiv + standards links.)
