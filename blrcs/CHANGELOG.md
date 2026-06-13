# Changelog

All notable changes to BLRCS are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`compliance.IssueSDJWTBoundStatus` / `IssueSDJWTVCBoundStatus` — holder-bound
  AND revocable in one credential.** The private issuer already supported embedding
  both a `cnf` (holder key binding) and a `status_list` reference, but no public
  method passed both — so callers had to choose *either* anti-replay binding
  (`IssueSDJWTBound`) *or* revocability (`IssueSDJWTStatus`). A regulated DPP/Battery
  passport needs both. The new methods issue a credential that is holder-bound and
  revocable at once; tests verify the result requires a KB-JWT, preserves the status
  reference through presentation, and is correctly reported revoked/not-revoked.
- **End-to-end hardened-pipeline integration test (`integration`).** A new
  `TestHardenedTriangle_TxCodeProofBoundDCQLKeyBinding` exercises the full
  secure-by-default path the per-package hardening built up — OpenID4VCI offer with
  `tx_code` (PIN) → code+PIN exchange → proof-of-possession → holder-bound credential
  (`cnf`) → OpenID4VP DCQL request → presentation with a KB-JWT bound to the request
  nonce/audience → verification with `RequireKeyBinding=true`. It asserts the issued
  credential is holder-bound, the privacy contract holds (undisclosed claims don't
  leak), PIN-less redemption is rejected, and one-time state defeats replay — proving
  all the hardened pieces compose without the permissive shortcuts.
- **`openid4vci` transaction code (tx_code / PIN) for the pre-authorized flow
  (Draft 15 §4.1.1).** The pre-authorized code flow had no tx_code, so anyone who
  intercepted the pre-authorized code (e.g. a photographed QR offer) could redeem it
  for a credential. Added `CreateOfferWithTxCode` (advertises the tx_code requirement
  as metadata — never the value — and binds the offer to a PIN) and
  `ExchangeCodeWithTxCode` (constant-time PIN check; failed attempts do not consume
  the code so a legitimate user can retry). The HTTP token endpoint reads the
  `tx_code` form field. `CreateOffer`/`ExchangeCode` delegate with no tx_code, so
  existing flows are unchanged. Tests: required/wrong/correct PIN, retry-after-wrong,
  offer advertises metadata without leaking the PIN, and no-tx back-compat.
- **`openid4vci` tx_code brute-force protection (Draft 15 §6.1).** A short numeric
  PIN with no attempt limit is brute-forceable by anyone holding the pre-authorized
  code. `Issuer.MaxTxCodeAttempts` (default 5) now caps wrong tx_code attempts;
  exceeding it invalidates the pre-authorized code so even the correct PIN no longer
  redeems it. Test covers the limit and post-burn rejection.

### Fixed
- **`compliance.Verify` accepted future-dated (not-yet-valid) credentials.** The core
  W3C VC verify enforced `validUntil` (expiry) but never checked `validFrom`, so a
  credential whose validity window had not started verified fine — asymmetric with
  the SD-JWT path, which rejects both bounds. `Verify` now also rejects credentials
  whose `validFrom` is more than a small clock-skew leeway in the future
  (`ErrNotYetValid`), and a new `VerifyAt(cred, pub, now)` gives deterministic
  time control (mirroring `VerifySDJWTAt`). Expiry behavior is unchanged (tight, no
  leeway) so existing semantics hold. Tests cover not-yet-valid, the leeway window,
  and fixed-time expiry.

### Added
- **`mdoc` device authentication (ISO 18013-5 §9.1.3).** The package issued and
  verified `IssuerSigned` mdocs and committed a `deviceKey` in the MSO, but nothing
  used that key to bind a presentation — an mdoc presentation was a replayable
  *bearer* token (the mdoc analog of the SD-JWT bearer-replay gap that KB-JWT closes
  for OpenID4VP). Added `SignDeviceAuth`/`VerifyDeviceAuth` (COSE_Sign1 over the
  `DeviceAuthentication` structure bound to a caller-supplied session transcript),
  and `PresentWithDeviceAuth`/`VerifyDocument` for the full
  Document = {docType, issuerSigned, deviceSigned} flow. `VerifyDocument` enforces
  issuer signature + validity window + disclosed-item digests AND the device
  signature against the MSO `deviceKey`, rejecting credentials with no device key,
  missing/!invalid `deviceAuth`, or a signature bound to a different transcript.
  Tests: happy path, wrong-transcript replay, wrong device key, no device key,
  missing deviceAuth, and expiry-still-enforced.

### Fixed
- **`openid4vp` dropped the credential's revocation reference; revoked credentials
  could not be rejected in-flow.** `ProcessResponse` verified signature, holder
  binding, and claims but never surfaced or acted on the `status_list` reference, so
  a revoked DPP/Battery passport verified successfully and the relying party had no
  signal to check (the `status` claim was discarded at the openid4vp boundary). Now
  `VerifiedPresentation.Status` exposes the reference for the caller, and an optional
  `Verifier.RevocationChecker` callback (caller-supplied, keeping the verification
  core network-free) makes `ProcessResponse` fail closed with `ErrCredentialRevoked`
  when a presented credential is revoked. Checks run before state consumption so a
  revoked attempt can be audited/retried; the checker is skipped for credentials
  without a status. Tests cover exposure, revoked, checker-error propagation, and the
  no-status no-op. Backward-compatible (new optional field/callback + sentinel).
- **`openid4vp` DCQL `credential_sets` were never enforced + `required` default bug
  (OpenID4VP v1.0 §6.2).** A verifier could express combination constraints
  (`credential_sets`, e.g. "present credential A OR B"); they passed `Validate()`
  and shipped on the wire, but `ProcessResponse` ignored them entirely — and
  `CredentialSetQuery.Required` was never read. The §6.2 default for `required` is
  `true`, yet a plain Go bool unmarshals an omitted `required` to `false`, so an
  absent member would have silently downgraded a required set to optional. Now:
  `enforceDCQLConstraints` evaluates `credential_sets` (every *required* set must
  have an option fully covered by the presentation; optional sets do not gate), and
  a custom `CredentialSetQuery.UnmarshalJSON` restores the spec default
  (absent `required` → `true`, explicit `false` honored). Tests cover satisfied /
  unsatisfied / optional / alternative-option / multi-id sets and the default.
- **`openid4vci` discarded the proof-of-possession holder key (Draft 15 §5.1.2).**
  `IssueCredentialWithProof` verified the wallet's proof JWT but threw away the
  recovered holder public key and issued a plain `IssueSDJWT` — a *bearer*
  credential with no `cnf`. The secure-by-default OpenID4VP verifier
  (`RequireKeyBinding=true`) then rejects such a credential with
  `ErrKeyBindingMissing`, so the VCI→VP pipeline was broken precisely for the
  secure path the proof step exists to enable. Now, when a valid proof is present,
  the credential is issued holder-bound (`IssueSDJWTBound`) against the proven key,
  so the holder can produce a KB-JWT in OpenID4VP. The no-proof path is unchanged
  (still a bearer SD-JWT) for backward compatibility. Regression tests assert the
  proof-bound credential carries a `cnf` (plain verify → `ErrKeyBindingMissing`),
  round-trips through `PresentWithKeyBinding`/`VerifySDJWTWithBinding` bound to the
  proven key, and that the no-proof path stays bearer.
- **`openid4vp` DCQL flow was unverifiable (OpenID4VP v1.0 §6).** Presentation
  Exchange was removed in v1.0, leaving DCQL (`dcql_query`) as the sole query
  language — yet `CreateRequestDCQL` produced a request that `ProcessResponse`
  could never complete: it looked for trust anchors only on
  `PresentationDefinition.AcceptableIssuers` (always empty for a DCQL request), so
  every DCQL response failed with "no acceptable issuers configured". Worse, the
  DCQL `claims`/`vct_values` constraints were never enforced against the presented
  credential — `MatchClaims` was reachable only from the conformance harness.
  - Added `Verifier.TrustedIssuers` (optional DID→pubkey map) as the trust anchor
    for the DCQL path; `ProcessResponse` falls back to it when the request carries a
    `dcql_query`. PresentationDefinition flows are unchanged.
  - `ProcessResponse` now enforces the DCQL query when present: the presented
    credential must satisfy at least one `CredentialQuery` — its `vct` within the
    query's `vct_values` (dc+sd-jwt) and every requested claim path disclosed with
    any value constraints met — else `ErrDCQLUnsatisfied`.
  - New e2e tests: full DCQL happy path, fail-closed without a trust anchor,
    unsatisfied-claim rejection, and vct-mismatch rejection. Backward-compatible
    (new optional field + sentinel; existing 805 tests unaffected).

### Test coverage & build hygiene
- **`kms` 94.9% → 98.0%** — added `NewFileSigner` error-path tests: `os.MkdirAll`
  failure (parent path is a regular file), and `save()`/`os.WriteFile` failure
  (a directory occupies the `.tmp` path).
- **`gofmt` regressions repaired** — re-aligned struct/map literals in `mcp/mcp.go`
  and several `_test.go` files that had drifted out of `gofmt` compliance, restoring
  the CI fmt gate to clean.
- **`golangci-lint` clean (v2 schema)** — resolved a `staticcheck` S1025 finding in
  `cas/cas_test.go` (the `%s`-verb Stringer-compliance assertion now carries an
  explicit `//nolint` so the intentional verb test no longer trips the gate).
- **`.gitignore`** — ignore ad-hoc `*.out` coverage profiles so `go test
  -coverprofile=` artifacts no longer pollute `git status`.

### Security & robustness audit (per-category)
A category-by-category audit of the whole product surfaced and fixed defects
across credential formats, identity/trust, protocols/HTTP, and storage/infra.
Highlights (full detail in the git history):

- **HIGH** — `cbor` non-canonical negative-integer map-key ordering (broke COSE_Key/
  mdoc deterministic encoding); `mcp` JSON-injection via concatenated error text;
  `openid4vp` verifier now secure-by-default (`RequireKeyBinding=true`) so bearer
  presentations can't replay; `didwebvh` pre-rotation bypass (omitting `updateKeys`
  kept a compromised key); `didresolver` multibase 'm' key length not validated
  (panicked `ed25519.Verify` → DoS).
- **MED** — webhook SSRF guard + crypto/rand event IDs; `httpmw` no longer trusts
  spoofable `X-Forwarded-For` for rate-limit keying by default; `recovery` no longer
  double-writes a 500 over a partial response; `storage` directory fsync for true
  crash-safety + frame-size bound on replay; Status List Token `bits` validation;
  `types` NaN/Inf rejection; `builder` error count formatting; `jsonschema`
  `multipleOf` precision; `conformance` no longer swallows malformed-vector errors.
- **LOW** — `config.FromEnv` returns an error and rejects malformed ints; `cas`
  provenance de-dups reverse-index entries; `ctx.RegisterSCITT` no longer reports a
  false cancellation while the ledger commit proceeds; cmd entrypoints close storage
  and fail fast on a malformed rate-limit value.

All fixes ship with regression tests; secure-by-default behavior changes have
explicit opt-outs for legitimate local/bearer flows. `go test -race ./...` clean.

### Added
- **did:webvh verifiable-history DID method (`didwebvh` package).** Implements
  the did:webvh model that hardens did:web against key-substitution and silent
  history rewrites: self-certifying SCID
  (`base58btc(multihash(sha-256(JCS(genesis with {SCID}))))`), hash-chained log
  entries (`versionId = "<n>-<entryHash>"`), `eddsa-jcs-2022` Data Integrity
  proofs, and key pre-rotation via `nextKeyHashes`. `Create` issues a genesis
  DID, `Update` appends signed/rotated entries, and `Verify` replays a log
  enforcing SCID self-certification, entry chaining, sequential versions,
  monotonic `versionTime`, update-key authorization, and pre-rotation
  commitments. Built on the KAT-validated `multiformats` primitives and the new
  Ed25519 Multikey codec. 14 tests (incl. tamper/truncation/unauthorized-key/
  pre-rotation-violation) + runnable example + `FuzzDIDWebVH`. Wire-vector
  interop with the official did:webvh test vectors, witness cosigning, and
  did:web fallback are follow-ups. Closes spec §1 / backlog #5 (model).

- **Ed25519 Multikey + multibase codec (`multiformats`).** `EncodeEd25519Multikey`
  / `DecodeEd25519Multikey` (the `z6Mk…` did:key/did:webvh verification-method
  form, multicodec 0xed01) and `EncodeMultibaseBase58` / `DecodeMultibaseBase58`
  for Data Integrity `proofValue`.

### Added
- **Multiformats primitives (`multiformats` package): base58btc, multihash,
  JCS.** Zero-dependency, known-answer-validated building blocks for did:webvh
  and W3C Data Integrity proofs: `Base58Encode`/`Base58Decode` (Bitcoin/IPFS
  alphabet, KATs incl. "Hello World!"→"2NEpo7TZRRrLZSi2U"), `MultihashSHA256` /
  `HashThenBase58` (the `Qm…` SCID/entryHash encoding used by did:webvh), and
  `CanonicalizeJSON` (RFC 8785 JCS: UTF-16 key ordering, JCS string escaping,
  integer-exact via json.Number). Follows the same foundation-first pattern as
  the cbor layer; unblocks a faithful did:webvh resolver (backlog #5). 17 tests
  + `FuzzBase58` + `FuzzJCS` (idempotence/round-trip, clean over 190k+ execs).

### Added
- **Minimal zero-dependency JSON Schema validator (`jsonschema` package).**
  Implements the draft 2020-12 / draft-07-compatible subset needed to validate
  SD-JWT-VC claim sets against the `schema` in Type Metadata: `type` (incl.
  unions and `integer`), `enum`/`const`, string (`minLength`/`maxLength`/
  `pattern`/`format`), numeric (`minimum`/`maximum`/exclusive/`multipleOf`),
  object (`required`/`properties`/`additionalProperties`/`patternProperties`/
  min-max-properties), array (`items`/`prefixItems`/`minItems`/`maxItems`/
  `uniqueItems`/`contains`), combinators (`allOf`/`anyOf`/`oneOf`/`not`), local
  `$ref` (`#/...` JSON pointers), and boolean schemas. Errors aggregate all
  violations. `format` is lenient (unknown formats pass). 30 tests + `FuzzJSONSchema`.

- **SD-JWT-VC claim-set schema validation (`vctmeta.TypeMetadata.ValidateClaims`).**
  Wires the new validator into Type Metadata: `HasSchema` reports an embedded
  `schema`; `ValidateClaims` validates a verified claim set against it (or
  `ValidateClaimsWithSchema` for an explicit schema).

- **Remote `schema_uri` resolution (`vctmeta.ResolveSchema` / `ResolveAndValidate`).**
  When Type Metadata references its schema by `schema_uri` instead of embedding
  it, the schema is fetched over https (size-bounded) and, when
  `schema_uri#integrity` is present, verified against it (W3C SRI) before use.
  `ResolveAndValidate` is the one-call path: resolve (embedded or remote) then
  validate the claim set. Completes spec §3 / backlog #7.

### Added
- **ISO/IEC 18013-5 mdoc / mDL credential format (`mdoc` package).** Full
  `IssuerSigned` issuance, verification, and selective disclosure on top of the
  `cbor` layer — the format every comparable EUDI stack ships (eudi-lib,
  walt.id, A-SIT vck) and previously only a `dcapi` request stub in BLRCS.
  `Issue` builds `IssuerSignedItem`s (≥16-byte CSPRNG salt each), records
  `SHA-256(IssuerSignedItemBytes)` in the MobileSecurityObject `valueDigests`, and
  signs the MSO with a COSE_Sign1 `issuerAuth`. `Verify` checks the issuerAuth
  signature, MSO `version`/`digestAlgorithm`, the validity window, and every
  disclosed item's digest. `Present` performs selective disclosure (drop items;
  the MSO still attests to the full set). Holder binding via COSE_Key (OKP
  Ed25519) `deviceKey` is supported. Device-signature / session-transcript
  binding (proximity transport) is out of scope. Closes spec §2a / backlog #10.
  11 tests + runnable example.

- **Fuzz targets for the CBOR decoder and mdoc verifier (`FuzzCBOR`, `FuzzMdoc`).**
  Both passed ~100k executions each; `FuzzCBOR` surfaced an unhashable-map-key
  panic that is now fixed (see below). Brings the fuzz suite to 11 targets.

### Fixed
- **CBOR decoder panic on unhashable map keys.** A crafted CBOR map with a
  composite key (byte/text array, map, …) caused `map[k]=v` to panic when used as
  a Go map key. The decoder now rejects non-hashable keys
  (`cbor: unsupported map key type`) — integer/text/bool/null keys cover all real
  COSE/mdoc/SD-JWT usage. Found by `FuzzCBOR`.

### Added
- **Minimal zero-dependency CBOR/COSE layer (`cbor` package).** Implements RFC
  8949 CBOR encoding/decoding (major types 0–7, deterministic integer-key and
  string-key map ordering per §4.2.1, tag 18 for COSE_Sign1, depth/size bounds
  to prevent stack exhaustion or OOM) and RFC 9052 COSE_Sign1 sign/verify over
  Ed25519 with algorithm-confusion defense (missing/unknown `alg` rejected) and a
  `RegisterVerifier` hook for pluggable algorithms. Serves as the foundation for
  SCITT COSE receipts and future mdoc/mDL (ISO 18013-5) support. 36 tests.

- **COSE_Sign1 receipts for IETF SCITT (`scitt.IssueCOSEReceipt` /
  `VerifyCOSEReceipt`).** An alternative to the JSON+Ed25519 receipt format that
  is interoperable with IETF SCITT-compliant verifiers: the COSE_Sign1 payload is
  a CBOR map carrying `leaf_index`, `tree_size`, `root_hash`, `audit_path`, `ts_id`,
  and `reg_at`; the protected header pins `alg=EdDSA` and carries the TS key-ID.
  Existing JSON receipts and all prior tests are unaffected. Closes spec §6 backlog
  #3 (COSE Receipts). 5 new tests.

### Added
- **SD-JWT-VC Type Metadata resolution + `vct#integrity` (`vctmeta` package).**
  `vctmeta.Resolve` fetches Type Metadata from an https `vct` and verifies it
  against the credential's `vct#integrity` (W3C SRI `sha256-…`) so the metadata
  can be trusted and cached; `Integrity` computes the value for issuers,
  `HTTPFetcher` is the default (size-bounded) transport, and the fetcher is
  injectable for tests. JSON-Schema validation (`schema`/`schema_uri`) is left to
  an external validator (zero-dependency policy). Spec §3 / backlog #7 (partial).

### Security
- **OpenID4VP `client_id` scheme validation (`ValidateClientID`).** Authorization
  Requests now reject malformed verifier identifiers at creation
  (`CreateRequest`/`CreateRequestDCQL` → `ErrClientIDInvalid`): empty/whitespace,
  and per-scheme format errors for the OpenID4VP v1.0 Client Identifier Prefixes
  (`redirect_uri`/`web-origin`/`openid_federation` must be absolute https,
  `decentralized_identifier` must be a DID, `x509_san_dns` a DNS name, etc.).
  Bare/pre-registered identifiers (incl. plain https URLs) remain accepted.
  Completes the OpenID4VP anti-phishing story (spec §5 / backlog #6).

### Added
- **Hardened HTTP server helper (`tlsharden.HardenedServer`).** Returns an
  `*http.Server` with Read/ReadHeader/Write/Idle timeouts + 1 MiB `MaxHeaderBytes`
  (slowloris / resource-exhaustion defense); `HardenedServerWith` allows
  per-deployment overrides (e.g. `Write=0` for SSE streaming). `cmd/blrcs-demo`
  now uses it instead of a bare, timeout-less `http.ListenAndServe`. Closes spec
  §7 server-timeouts / backlog #9.

### Added
- **HTTP rate-limit enforcement (`httpmw.RateLimiter`).** A zero-dependency,
  per-client-IP token-bucket middleware that actually enforces `config.RateLimitRPS`
  (previously configured but never applied): 429 + `Retry-After` on exhaustion,
  `rps<=0` disables it, and `GC(ttl)` reclaims idle buckets. Compose via
  `chain.Use(rl.Middleware)`. Closes spec §7 / backlog #9 (enforcement half).

### Added
- **SCITT witness cosigning (split-view defense).** `scitt.VerifyCheckpoint`
  authenticates a log's signed tree head; `scitt.Witness` cosigns a checkpoint
  only after verifying the issuer signature and an append-only **consistency
  proof** from the last checkpoint it cosigned (`ErrSplitView` /
  `ErrCheckpointRegression` on inconsistency or rollback). `VerifyCosignature`
  checks a witness attestation. Reuses the existing consistency-proof machinery;
  closes spec §6 / backlog #4.

### Added
- **`docs/SPECIFICATION.md`** — normative spec (RFC 2119) for the core
  subsystems with a conformance matrix tracking implemented vs missing behavior.
  Writing it surfaced four specified-but-unimplemented SD-JWT verifier rules,
  now fixed (below).

### Security
- **SD-JWT verifier conformance hardening** (gaps found via the new spec):
  `_sd_alg` is now enforced to `sha-256` (hash-downgrade defense,
  `ErrSDJWTUnsupportedHashAlg`); `vct` is required per SD-JWT-VC
  (`ErrSDJWTMissingVCT`); duplicate digests in `_sd` are rejected
  (`ErrSDJWTDuplicateDigest`). Absent `_sd_alg` still defaults to sha-256.

### Added
- **JWS algorithm agility + algorithm-confusion hardening.** SD-JWT verification
  now parses the issuer JWT header, pins the `alg` against a registry, and rejects
  unknown algs (`alg:none`/substitution → `ErrSDJWTUnsupportedAlg`) instead of
  blindly assuming EdDSA. `RegisterJWSVerifier(alg, fn)` lets integrators plug in
  additional algorithms (e.g. post-quantum ML-DSA) without BLRCS taking a core
  dependency; EdDSA (Ed25519) ships built-in.
- **Signed Status List Token (`statuslist+jwt`) + serving helper.**
  `BitstringStatusList.IssueToken` publishes the list as an Ed25519-signed token
  (draft-ietf-oauth-status-list JWT form) with `ttl`/`exp`; `VerifyStatusListToken`
  checks the signature + freshness and returns the decoded list; `TokenHandler`
  serves it as `application/statuslist+jwt` with `Cache-Control`. `compliance.CheckRevokedToken`
  is the end-to-end verifier helper: it authenticates the fetched list, binds the
  token `sub` to the credential's `status.uri` (anti-substitution), and checks the bit.
- **Credential status / revocation wiring (status_list claim).** Issued SD-JWT VCs
  can now carry a `status.status_list` reference (`IssueSDJWTStatus` /
  `IssueSDJWTVCStatus`, draft-ietf-oauth-status-list form); `VerifySDJWT*`
  populates `VerifiedClaims.Status`, and `CheckRevoked(vc, list)` checks the bit
  against a (caller-fetched) `revocation.BitstringStatusList`. Previously the
  revocation package existed but was never referenced by issued credentials, so
  verifiers had no way to check revocation. (Top P0 item from `docs/IMPROVEMENT_RESEARCH.md`.)

### Security
- **SD-JWT now rejects expired / not-yet-valid credentials.** `VerifySDJWT` previously
  parsed `exp`/`iat` but never enforced them, so an expired DPP or Battery Passport still
  verified. Validation now runs with a 60s clock-skew leeway; `VerifySDJWTAt` allows a
  caller-supplied clock for deterministic tests.
- **SD-JWT Key Binding (KB-JWT) / holder binding** per IETF SD-JWT & SD-JWT-VC. Issuers
  can bind a credential to a holder key (`IssueSDJWTBound` / `IssueSDJWTVCBound` /
  `IssueSDJWTTieredBound`, embedding a `cnf` JWK); holders present with
  `PresentWithKeyBinding` (signs a `kb+jwt` over `nonce`/`aud`/`sd_hash`); verifiers use
  `VerifySDJWTWithBinding`. This closes the OpenID4VP replay gap — `Verifier.ProcessResponse`
  now cryptographically binds the presentation to the request `nonce` and `client_id`
  instead of relying on one-time `state` consumption alone. New `Verifier.RequireKeyBinding`
  rejects unbound presentations outright (recommended in production).
- **revocation:** `DecodeBitstringStatusList` now caps both the encoded input and the
  decompressed output (decompression-bomb guard) instead of an unbounded `io.ReadAll`.

### Fixed
- **CI lint gate restored.** `.golangci.yml` was on the legacy v1 schema, which
  golangci-lint v2 (installed via the `latest` action) refuses to load. Migrated to the v2
  schema; the correctness+security linter set now runs green.
- Dead/incorrect code surfaced while greening the linters: discarded `attrs` slice in
  `telemetry.SlogRecorder.Record`, empty branch in `apispec.Registry.Register`, redundant
  nil-check in `i18n.NewBundle`, plus assorted `errcheck`/`staticcheck`/`copyloopvar` cleanups.
- **README:** removed Architecture/quick-start references to packages that do not exist
  (`epcis`, `jwe`, `lifecycle`, `benchmark`, `examples/factory_e2e`) and pointed the
  end-to-end example at the real `integration/` suite.

### Improved
- **healthprobe wired into `blrcs-mcpd`.** `/healthz` and `/readyz` now return
  structured JSON reports (per-check status, duration, timestamp) via `healthprobe.Probe`
  instead of plain-text stubs. `/readyz` includes ledger reachability and, when
  persistence is enabled, storage read checks.
- **OpenID4VCI wallet client: context-aware methods.** `FetchCredentialCtx`,
  `FetchMetadataCtx`, and `FetchJWKSCtx` accept a `context.Context` for timeout and
  cancellation. All HTTP response bodies are now bounded with `io.LimitReader` (4 MiB)
  to guard against unbounded responses from untrusted issuers.
- **`blrcs-mcp` stdio binary added to GoReleaser builds.** The stdio MCP transport is
  now released alongside `blrcs` and `blrcs-mcpd`, with `go install` instructions in the
  release footer.
- **SCITT `subProof`: integer cast eliminated.** `largestPow2Below(int(n))` round-trip
  replaced with a direct `math/bits.Len64` computation, removing a theoretical
  `uint64→int` truncation on very large trees.
- **`types` package coverage 69% → 91%.** Added tests for `GTIN.UnmarshalJSON`,
  `CountryCode.MarshalJSON`/`UnmarshalJSON`, `MustCountryCode`,
  `CarbonFootprint.String`, `Percent.Value`/`IsZero`/`String`/`UnmarshalJSON`,
  and `Duration.IsZero`.
- **README stats updated:** 1000+ tests, 17 fuzz targets (was 15).
- **golangci-lint clean (6 issues fixed):** unused `versionTimeValid` (didwebvh),
  unnecessary type casts in `scitt/cose_receipt` and `vctmeta`, De Morgan
  simplification in `httpchain`, unused `time` import in `didwebvh`.

## [0.1.0] - 2026-06-03

Initial public release. EU Digital Product Passport (ESPR) and Battery Passport
(Reg. 2023/1542) reference implementation in zero-dependency Go.

### Added
- `conformance/` — `tier` test-vector category validating the ESPR three-tier access
  model, including the security invariant that no non-public claim leaks into the
  clear (publicly readable) set.
- `fuzz/` — `FuzzTieredClaims`: fuzzes arbitrary claim keys and tier strings against
  the split invariant (authority/restricted data must never reach the public clear
  set). Added to CI. Completes the access-tier work across implementation,
  conformance harness, and fuzzing.
- `compliance/` — **ESPR three-tier access model** (`AccessTier`, `TieredClaims`).
  ESPR and the EU Battery Regulation require DPP data partitioned into public
  (consumer), restricted (recyclers/repairers), and authority (market surveillance)
  tiers. The issuer declares a tier per claim; `IssueSDJWTTiered` maps public→clear
  and restricted/authority→selectively-disclosed, and `ClaimsAtOrBelow` returns the
  claims a given verifier role is entitled to. Every same-domain implementation
  (Spherity, Battery Pass, GS1) names this as a core requirement.
- `conformance/` — new `dcql` test-vector category validating OpenID4VP v1.0 DCQL
  query structure (§6) and claim matching. Completes the DCQL work across the full
  surface: `openid4vp` (core) → `dcapi` (browser DC-API) → `conformance` (the
  language-independent harness third parties run against BLRCS).
- `dcapi/` — `BuildForVerifierDCQL`: emits a W3C Digital Credentials API request
  carrying an OpenID4VP v1.0 `dcql_query` (instead of the deprecated
  `presentation_definition`), so a v1.0 browser/wallet can be queried through the
  DC-API. Completes the DCQL support added to `openid4vp/` across the API surface.
- `openid4vp/` — **DCQL (Digital Credentials Query Language)** per OpenID4VP v1.0 §6.
  Presentation Exchange was removed in v1.0 (DCQL is now the only query language),
  so a v1.0 wallet cannot process a `presentation_definition` request. Adds
  `DCQLQuery`/`CredentialQuery`/`ClaimQuery`/`CredentialSetQuery`, the `dcql_query`
  Authorization Request parameter, `Verifier.CreateRequestDCQL`, format-agnostic
  claim matching, and a `DCQLFromPresentationDefinition` migration bridge.

### 10-category research scan (arXiv + GitHub)
Surveyed VP request protocols (OpenID4VP v1.0 — PE→DCQL), revocation privacy
(arXiv:2501.17089), and ZK carbon claims (arXiv:2506.16347). Implemented the DCQL
conformance gap; CRSet-style private revocation and zk-SNARK carbon proofs remain
candidates requiring larger crypto dependencies.
- `semconv/` — OpenTelemetry-aligned telemetry attribute keys. Span/log attributes
  now use dotted, vendor-namespaced keys (`blrcs.issuer`, `blrcs.product_id`,
  `blrcs.ledger.tree_size`) and standard OTel keys (`service.name`, `error.type`)
  instead of ad-hoc names, so traces are portable across Grafana/Jaeger/Datadog and
  dashboards are reusable. `ctx/` instrumentation migrated to these keys.

### 10-category research scan (arXiv + GitHub)
Surveyed revocation privacy (arXiv:2501.17089 CRSet — Bitstring Status List leaks
issuer activity), ZK carbon claims (arXiv:2506.16347), and OTel semantic conventions.
Implemented the OTel-conventions gap; CRSet-style metadata-private revocation and
zk-SNARK carbon proofs recorded as candidates requiring larger crypto dependencies.
- `scitt/` — **proof of consistency** (RFC 6962 §2.1.2, COSE Receipts): proves the
  transparency log is append-only between two tree sizes. This is SCITT's core
  non-equivocation guarantee — an auditor who saw the log at size m can verify
  size n still contains the same prefix, proving the issuer never rewrote history.
  `Ledger.ConsistencyProof(m, n)`, `VerifyConsistency(...)`, `Ledger.Root()`.
- `compliance/` — **GS1 Digital Link Linkset** (RFC 9264): a scanned GTIN URI
  resolves to a linkset routing to the DPP, conformity doc, due-diligence report,
  sustainability info, and recall status by `linkType`. This is the discovery
  standard every same-domain implementation (Spherity, Trace4EU, Battery Pass)
  converges on — a globally resolvable identifier → passport URL.
- `didresolver/` — DID document **service endpoint** parsing + `ResolveServices`.
  Per arXiv:2410.15758, DID resolution returns only key metadata, not credentials;
  service endpoints (`DPPService`, `BitstringStatusList`, `LinkedDomains`) advertise
  where the DPP data and status list actually live.
- `docs/adr/0001` — ADR recording the SD-JWT (vs BBS) selective-disclosure choice
  and its accepted limits (no multi-show unlinkability, not post-quantum), grounded
  in the arXiv:2401.08196 mechanism survey. PQ migration path noted via `kms.Signer`.
- `compliance/` — **IETF SD-JWT VC** (`draft-ietf-oauth-sd-jwt-vc`) conformance:
  issued SD-JWTs now carry the mandatory `vct` claim (default
  `https://schema.europa.eu/dpp/sd-jwt-vc/v1`). New `IssueSDJWTVC(vct, ...)` for
  custom types. `vct` survives selective disclosure.
- `conformance/` — new `vc` test-vector category validating VC 2.0 context and
  `validFrom`; SD-JWT vectors now assert `vct`.
- CI — `security` job (`govulncheck` + `golangci-lint`) and `sbom` job
  (CycloneDX SBOM generation + artifact upload) for supply-chain assurance.
- `compliance/` — **W3C Verifiable Credentials Data Model 2.0** support. Context
  upgraded to `https://www.w3.org/ns/credentials/v2`; `validFrom`/`validUntil`
  replace `issuanceDate`/`expirationDate` (signed payload updated accordingly).
- `compliance/` — `IssueWithStatus`: attaches a W3C `BitstringStatusListEntry`
  (`credentialStatus`) to issued credentials; the status entry is part of the
  signed payload so tampering is detected at verification.
- `revocation/` — **W3C Bitstring Status List v1.0** (`BitstringStatusList`):
  GZIP + base64url-encoded bitstring with 16KB herd-privacy minimum. Supersedes
  the deprecated StatusList2021 model.
- `compliance/` — EU 2023/1542 Annex XIII full field coverage: renewable content
  (Art.7), expected lifetime, EU declaration of conformity (Art.6), separate
  collection symbol (Art.13), commissioning date.
- `compliance/` — Art.52 due-diligence enforcement: EV and >2kWh industrial
  batteries now require a due-diligence report URL at issuance (`ErrDueDiligenceRequired`).
- `builder/` — `DueDiligenceReport`, `EUDeclarationOfConformity`, `RenewableContent`,
  `ExpectedLifetime`, `SeparateCollection` fluent setters.
- `.golangci.yml` — curated linter set (gosec, errorlint, bodyclose, contextcheck,
  revive, gocritic) for the CI quality gate.
- `cmd/blrcs` — refactored to a testable `run() error` pattern; `os.Exit` confined
  to `main()`. Coverage 54.5% → 95.0%.

## [1.0.0] — 2026-05-05

### Core Domain
- `compliance/` — W3C Verifiable Credentials issuance and verification (Ed25519)
- `compliance/` — SD-JWT selective disclosure (IETF draft, SHA-256 digests)
- `compliance/` — ZK Range Proof with TEE-attested sensor commitments
- `compliance/` — GS1 Digital Link (ISO/IEC 18975) URI build/parse
- `compliance/` — EU Battery Passport (Regulation 2023/1542 Annex XIII)
- `scitt/` — IETF SCITT Merkle transparency log (RFC 6962 compatible)
- `storage/` — MemoryStorage + FileStorage with fsync crash safety

### Standards Integration
- `openid4vp/` — OpenID for Verifiable Presentations verifier + MockWallet
- `openid4vci/` — OpenID for Verifiable Credential Issuance (Pre-Authorized Code)
- `dcapi/` — W3C Digital Credentials API adapter (Safari 26 / Chrome 141 / Firefox 149)
- `mcp/` — Model Context Protocol stdio + Streamable HTTP server (14 tools)
- `epcis/` — GS1 EPCIS 2.0 event model
- `jwe/` — JSON Web Encryption (ECDH-ES)
- `kms/` — Key Management Service interface + memory implementation

### Type Safety
- `types/` — DID, GTIN, CountryCode, CarbonFootprint, Percent, Duration
- `errkit/` — Structured errors (Op/Code/Public/Detail/Retryable/HTTPStatus)
- `builder/` — Fluent typed DPP + Battery Passport builder with error accumulation

### Observability
- `telemetry/` — Span, Counter, Histogram (atomic lock-free, slog backend)
- `metrics/` — Prometheus text format exporter + dashboard handler
- `otelbridge/` — OpenTelemetry OTLP/JSON bridge (span + log)
- `doctor/` — 13-check self-diagnostic suite (7ms runtime)
- `healthprobe/` — Liveness/Readiness/Startup probes (parallel, timeout-enforced)

### Security
- `recovery/` — Panic recovery for HTTP handlers + goroutines + defer
- `replay/` — SHA-256 fingerprint dedup with TTL + LRU eviction
- `tlsharden/` — TLS 1.2/1.3 Modern/Strict config builder (ATS-equivalent)
- `privacy/` — Privacy Manifest + DataLineage tracker + MinimizationGuard
- `didresolver/` — DID resolution (did:web/key/jwk) + Trust Anchor allow-list

### Infrastructure
- `ctx/` — Context propagation with telemetry span auto-instrumentation
- `cas/` — Content-Addressed Storage (SHA-256 dedup + Provenance index)
- `compose/` — Integration layer (IssueAndPublish + VerifyByDID in 1 call)
- `webhook/` — Outbound HMAC-SHA256 signed webhooks with exponential backoff
- `httpchain/` — HTTP middleware composition (recovery+traceContext+logging+auth+CORS)
- `schemaver/` — Schema versioning with sequential migration chain
- `config/` — Declarative configuration (JSON + env vars + validation)

### Testing
- `fuzz/` — 6 parser fuzz targets (DID/GTIN/SD-JWT/GS1/Merkle/RangeProof)
- `property/` — 9 generative invariant tests (round-trip/privacy/merkle monotonic)
- `benchmark/` — 19 hot-path performance baselines
- `conformance/` — Reference test suite runner
- `integration/` — E2E triangle test (issuer → wallet → verifier)

### Developer Experience
- `i18n/` — Multi-language message bundle (en/ja built-in)
- `openapi/` — OpenAPI 3.0.3 spec builder + HTTP handler
- `capability/` — Machine-readable capability manifest
- `examples/factory_e2e/` — Complete factory → SCITT → webhook → verify demo
- `README.md` — Quick start, architecture, performance table
- `Makefile` — test/cover/bench/fuzz/build/doctor/ci targets
- `.github/workflows/ci.yml` — 3-OS CI + coverage + fuzz

### Architecture
- Zero external dependencies (stdlib + crypto/ed25519 only)
- go 1.22 minimum
- 46 packages, 550+ tests
- Apple design principles throughout (type safety, sensible defaults, progressive disclosure)
