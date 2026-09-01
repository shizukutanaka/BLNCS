# Changelog

All notable changes to BLRCS are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Documentation for four undocumented exported declarations (Axis 158).**
  `compliance.Issuer`, `mcp.Server`, `mcp.NewServer` and
  `mcp.NewTokenBucketLimiter` produced no output in `go doc` — and therefore
  none on pkg.go.dev. `compliance.Issuer` is the flagship type of the flagship
  package, and `ES256Issuer`'s own documentation ends "Use a regular Issuer for
  those", pointing readers at a type that documented nothing.

  Two things are worth recording about how this was found and written, because
  both are the defect class this project keeps auditing for:

  1. **The detector was wrong twice before it was right.** An awk heuristic
     ("exported declaration whose previous line is not a comment") flagged 32
     identifiers; most were false positives, because `errkit` and `semconv`
     document their one-line families with a group comment. Switching to
     `go doc` still misled, because `go doc` prints a type's doc comment *after*
     the type body — `head` truncated it away and made the documented
     `ES256Issuer` look undocumented. Only unambiguous full output settled it:
     four genuine gaps, not 32.
  2. **The first draft of the new documentation contained two false claims.**
     It named a constructor `NewIssuerFromSeed` that does not exist (the real
     pair is `NewIssuer` / `NewIssuerFromKey`), and asserted `mcp.Server` "is
     safe for concurrent use" — a claim nothing in the tree establishes; there
     is no concurrent-access test for the type. Both were caught by checking
     each sentence against the code before committing, and corrected to what is
     actually true.

### Fixed
- **A KB-JWT header could name an algorithm that did not sign it (Axis 157).**
  `presentWithKB` took the JOSE `alg` string and the signing function as two
  independent arguments, and built the protected header by concatenating that
  string into JSON. The four call sites paired them correctly, but nothing
  enforced it: `presentWithKB(presented, "EdDSA", …, es256KBSigner(k))` would
  have compiled and emitted a holder-binding JWT whose header lies about its own
  signature. This is the same defect the COSE path closed at Axis 150, still
  open in the SD-JWT holder-binding path — found by asking where else an
  algorithm label and the act of signing were separable.

  The signing function now carries its own algorithm (`kbSigner{alg, sign}`), so
  `presentWithKB` takes one argument instead of two and a mismatch is
  unrepresentable rather than merely unlikely. The header is also marshalled
  from a struct instead of concatenated. Header bytes are unchanged — every
  existing key-binding test passes untouched.

  `TestKBJWTHeaderAlgIsTheAlgorithmThatSigned` asserts the observable
  consequence for both holder key types: the header names EdDSA only when the
  Ed25519 key verifies it, and ES256 only when the P-256 key verifies a 64-byte
  raw R‖S signature. Mutation-checked: mislabelling the ES256 signer fails it.

### Examined and deliberately not changed
- **The other two signed-header construction sites (Axis 157).**
  `openid4vp/jar.go` and `revocation/token.go` also build a JWS protected header
  from a hardcoded `"EdDSA"` literal. Both are safe by construction: the literal
  sits three lines above the `ed25519.Sign` call in the same function, over a
  statically-typed `ed25519.PrivateKey`, so there is no parameter through which
  the label and the signing act could be made to disagree. Giving them the
  `kbSigner` treatment would add indirection without removing a risk. The sweep
  for this defect class is therefore complete: one real instance
  (`presentWithKB`), two sites safe by construction, one apparent duplicate
  correctly rejected.
- **`didwebvh.Cryptosuite` and `compliance.CryptosuiteEdDSAJCS2022` (Axis 157).**
  Both are `"eddsa-jcs-2022"`, which looks like a constant duplicated across two
  packages. They are not: one is the suite the did:webvh specification requires
  for *log-entry* proofs, the other the suite W3C Data Integrity uses for
  *credentials*. The packages import neither direction. Coupling them would
  create a false dependency in which changing the credential default silently
  changes did:webvh log verification. Recorded because "these two literals are
  equal" is not the same claim as "these two things are the same thing".

### Added
- **Tests for the last genuinely uncovered paths (Axis 156).** Found by
  measurement, not by guessing where tests were thin — and the first
  measurement was itself wrong, which is the point. `go test -coverprofile`
  over `./...` reported 89.9% and 18 zero-coverage functions, but Go only
  instruments the package under test, so cross-package exercise is not counted:
  `cbor.Sign1ES256` showed 0% while the SCITT ES256 tests were calling it.
  Re-measured with `-coverpkg=./...`: 90.6%, and only five genuinely uncovered
  functions outside `cmd/` wiring. Three were real gaps, now closed:
  - `didresolver.multibaseToPublicKey` P-256 branch — a DID document publishing
    its verification method as a Multikey (`publicKeyMultibase`) rather than a
    JWK. Multikey is the form W3C Data Integrity recommends, so a P-256 issuer
    publishing a did:web document that way was never exercised.
  - `compliance.ES256Issuer.Alg` — now asserted to equal the `alg` that actually
    appears in the header of a credential the issuer produces, so what it
    advertises cannot drift from what it signs.
  - `compliance.ES256Issuer.PublicKeyECDSA` — asserted to agree with
    `PublicKey()` and to verify a signature made by the private half, rather
    than merely returning non-nil.
  - `storage.EncryptedStorage.SaveKeyPair` — asserted to reach the underlying
    store, since a pass-through wired to the wrong method still compiles.

  The fifth, `telemetry.NopRecorder.Record`, has an empty body: zero statements,
  so 0.0% is a measurement artifact with nothing to cover. Coverage now 90.8%.

### Changed
- **One definition of the ES256 algorithm string (Axis 156).**
  `ES256Issuer.Alg()` and `jwsAlg()` each carried their own `"ES256"` literal.
  `Alg()` now delegates to `jwsAlg()`. Mutation-checked: making them disagree
  fails the new header assertion.

### Added
- **SCITT COSE receipts can be signed with P-256 / ES256 (Axis 155).**
  `IssueCOSEReceiptES256` signs a COSE_Sign1 receipt with `cbor.Sign1ES256`
  (COSE alg `-7`, raw R||S per RFC 9053 section 2.1); `VerifyCOSEReceipt` and
  `VerifyCOSEReceiptWithAlgs` now take the raw public key as `[]byte` so a SEC1
  P-256 key (65-byte uncompressed or 33-byte compressed) can be supplied
  alongside the existing 32-byte Ed25519 form. The change is source-compatible:
  `ed25519.PublicKey` is a named slice type and remains assignable to the
  widened parameter, so every existing caller compiles unchanged. Payload
  construction is shared by both signers (`coseReceiptPayload`), so an ES256
  receipt and an EdDSA receipt cover exactly the same bytes.

  This closes the last algorithm gap on an interoperable artifact. The prior
  assessment justified leaving SCITT Ed25519-only as "internal, no interop
  pressure" — but `cose_receipt.go`'s own package doc states the COSE receipt
  exists to be "interoperable with IETF SCITT-compliant verifiers". The
  justification was an unexamined claim contradicted by the file it described.
  The JSON receipt, checkpoint, witness cosignature and statement paths remain
  Ed25519 deliberately: they are the internal/back-compat formats with no
  third-party consumer, and changing them would break `Ledger`'s key fields and
  the `storage` `LoadKeyPair`/`SaveKeyPair` interface.

  Tests (`scitt/cose_receipt_es256_test.go`) cover the ES256 round trip with
  both SEC1 encodings, an assertion that the protected header declares the
  algorithm that actually signed (and the kid it claims), tamper rejection,
  wrong-key rejection, inclusion-proof enforcement under ES256, cross-algorithm
  confusion refused in both directions via the allowlist, and nine malformed
  key shapes against both receipt algorithms without a panic. Each test was
  mutation-checked: blanking the root hash, corrupting it, and falsifying the
  header kid each make the suite fail.

### Fixed
- **The red CI checks diagnosed, not just labelled (Axis 155).** Previous
  revisions said only that the failing checks were "pre-existing legacy Python
  CI". Reading the job logs gives three independent root causes, all in the
  workflow files and none caused by this branch: (1) `requirements.txt` pins
  `numpy>=1.26.0`, which ships no Python 3.8 wheel, while the matrix includes
  3.8 — those legs can never install; (2) the job uses containers/`services`
  across a three-OS matrix, so Windows fails with "Container operations are only
  supported on Linux runners" and macOS with "docker: command not found";
  (3) fail-fast cancels the sibling legs, which is why the red-check count
  varies per run. Fixes: drop 3.8 from the matrix (or relax the numpy pin) and
  pin the container-using job to `ubuntu-latest`. Not applied here: they live in
  `.github/workflows/`, which this identity cannot author.
- **A stale backlog presented as current (Axis 155).** `docs/PRODUCT_ASSESSMENT.md`
  described the two instruction documents as "the remaining code-verified
  backlog", but axes 129–155 completed most of it: O1, O3, O4, O5, O7, S3 and
  S6 are done, O2 and S5 were resolved by deletion, O6 is partial. Listing
  finished work as pending is the same defect as claiming unfinished work is
  done. Replaced with a status table where every row cites evidence in the tree.
  Genuinely open: S1 (mdoc `transaction_data`), S2 (did:webvh `/whois`), S4
  (`verifier_info` carry); blocked: S7 (CI at repository root). Those three were
  left open deliberately — this environment's egress allowlist blocks
  `openid.net` and `docs.github.com` (verified by request), and implementing a
  wire format from memory is precisely how the fabricated `org-iso-mdoc`
  envelope was written.
- **A correction that was itself false (Axis 155).** Axis 150 rewrote the
  assessment's shipping-state note to say PR #1 "was CLOSED, not merged". That
  is wrong and the note it replaced was right: GitHub marks a merged pull
  request `state: closed` *and* sets `merged_at`, and Axis 150 read only the
  state field. PR #1 has `merged_at = 2026-07-17T16:08:19Z`, its head commit is
  an ancestor of `origin/main` (`git merge-base --is-ancestor`), and main's
  history contains the merge commit `67d7f7e`. Recorded in
  `docs/PRODUCT_ASSESSMENT.md` as a correction of a correction rather than
  silently overwritten.
- **Unsupported package counts (Axis 155).** The assessment said `main` carries
  49 packages; no measurement supports that. Re-measured from `git ls-tree` on
  each ref using the measure that equals `go list ./...`: main 53, branch 43,
  with 13 packages deleted and 3 added (53 − 13 + 3 = 43). The `−10,020 LoC`
  figure was checked and stands — it is the deletion commit's diffstat
  (`0c81c14`, 27 files, 10020 deletions).
- **An unverified claim stated as fact (Axis 155).** The assessment asserted the
  dependabot `automerge:` key "is not a real key". That was never verified and
  cannot be verified from this environment (egress to the schema documentation
  is blocked). Downgraded to what is actually known, with the one-click check
  the owner can run.

### Fixed
- **A flaky test I introduced in Axis 146 (Axis 152).**
  `TestAuthorizationCodeFlowRoundTrip` asserted no claims leaked into the
  credential offer with `strings.Contains(offerURL, "42")`. The offer URL also
  carries a random 43-character base64 `issuer_state`, in which "42" occurs by
  chance roughly 1–2% of the time — so the test failed intermittently for a
  reason unrelated to what it tested. Replaced with a structural assertion: the
  offer must carry exactly the members the spec defines and nothing else.
  Verified over 60 consecutive runs. This is the third instance of one bug class
  in this branch (after the base64 "z"-prefix sniff and the `sig[0] != 0x30`
  DER check) — matching a short literal against random base64 is a
  false-positive generator, not an assertion. A sweep found no others.

### Added
- **`openid4vci`: Pushed Authorization Requests, RFC 9126 (Axis 154).** The
  authorization request reached the issuer only through the front channel —
  client_id, redirect_uri, scope, the PKCE challenge and any
  `authorization_details` all visible to the user agent, browser history and
  referrers. PAR inverts that: the client POSTs the request directly over TLS
  and receives an opaque one-time `request_uri`, so the front channel carries
  only a reference. It pairs with Axis 146's mandatory PKCE — PKCE binds the
  code to its requester, PAR keeps the request itself off the browser.
  `PushAuthorizationRequest` validates with exactly the checks `Authorize`
  applies, at PUSH time (§2.2: an unusable request must fail on the back
  channel where the client can act on it, not later in the browser where the
  user cannot); `AuthorizeByRequestURI` redeems it, single-use and **burned by
  a failed redemption**, with a constant-time client_id binding (§2.2). The
  `/par` endpoint returns 201 + `no-store`, rejects a nested `request_uri`
  (§2.1), and collapses every validation failure to one identical body. 10 new
  tests.
- **`compliance`: `ecdsa-jcs-2019` W3C VC proofs (Axis 153).** `ES256Issuer`
  could not issue a W3C Verifiable Credential at all — the Credential path
  existed only on the Ed25519 issuer — so the W3C VC was the one format a
  P-256-only EUDI ecosystem could not consume, even after Axes 135–148. The
  suite shares its entire hashData construction with `eddsa-jcs-2022`, so this
  touched no canonicalization code. `VerifyAt` now switches on cryptosuite and
  **rejects an unknown one** instead of falling through to legacy rules the
  credential never claimed. `newPassportCredential`/`newStatusEntry` extracted
  so the two issuers cannot drift on @context, type, validity or status shape.

### Fixed
- **Remote panic on a wrong-length verification key (Axis 153).** `ed25519.Verify`
  *panics* on a key that is not 32 bytes, and `ed25519.PublicKey` is a named
  `[]byte` — so nothing at compile time stops a P-256 point or garbage reaching
  it. Neither Data Integrity verification nor the legacy Ed25519Signature2020
  path length-checked the key, so a caller passing the wrong key type to the
  public `Verify` API crashed the process instead of receiving an error; on a
  verifier service that is a remote DoS. Audited every `ed25519.Verify` call in
  the tree: most were already guarded, four were not — `verifyDataIntegrity`,
  `VerifyAt`'s legacy branch, `VerifyRange` and `scitt.VerifyReceipt` — and all
  now fail closed. Also added the signature-length check `didwebvh/proof.go`
  performs and compliance's equivalent omitted.
- **`openid4vci`: stale issuer metadata (Axis 154).** `grant_types_supported`
  advertised only the pre-authorized code even after Axis 146 added the
  authorization code grant, so a wallet could not discover a flow the issuer
  supports; and `response_types_supported` was `["vp_token"]`, an OpenID4VP
  presentation value that never belonged in issuer metadata (now `["code"]`).

### Added
- **`conformance`: P-256 / EUDI test vectors (Axis 152).** The reference suite
  covered everything the project could do *before* Axis 135 — GTIN, DID, SD-JWT,
  Merkle, GS1, VC, DCQL, tiers — while the entire P-256 arc shipped with no
  vectors at all, so a third party could claim "BLRCS-compatible" while sharing
  none of the cryptography a real EUDI deployment exercises. New `p256`
  category, all vectors deterministic (ECDSA signing and JWE encryption are
  randomised by design, so only the verification/derivation direction is a legal
  vector): PKCE `S256` derivation lifted from **RFC 7636 Appendix B**; ES256
  verification over raw R‖S (RFC 7518 §3.4 — an implementation emitting ASN.1
  DER fails, which is the commonest ES256 interop mistake), valid and tampered;
  JWE ECDH-ES + A128GCM decryption end to end, which covers the Concat KDF
  OtherInfo construction that is the usual source of RFC 7518 §4.6 bugs;
  fixed-width JWK coordinate encoding (§6.2.1.2); and off-curve point rejection.
  A negative-control test asserts the runner *fails* deliberately corrupted
  expectations, because "all vectors pass" is meaningless if a wrong one also
  passes.

### Changed
- **One gate: `make verify` (Axis 151).** There were three disagreeing
  definitions of "passing": `make ci` (vet+test+cover+build — no race detector,
  no gofmt, no lint, no dependency check), the GitHub workflow's job list (which
  had never executed), and whatever maintainers ran by hand. A gate that differs
  from the one CI runs is not a gate. `make verify` is now the single definition
  — fmt-check, dup-check, vet, deps-check, build, race tests, lint, fuzz-smoke,
  cheapest-first — and the workflow's job body is literally `make verify`; `make
  ci` is an alias. Runs in ~46s. Holes closed while consolidating: `lint` ended
  in `|| echo "(not installed)"` which swallowed real failures too; `build`
  enumerated four binaries so a new command was never build-checked; `fuzz`
  hardcoded 3 of 20 targets, silently skipping every one added since it was
  written; `test` had neither `-race` nor `-count`. Added `deps-check`, which
  *proves* the zero-dependency claim (tidy no-op + no go.sum + no external
  modules) instead of trusting it.
- **README examples are now executable (Axis 151).** They live in
  `compliance/example_test.go` as Go Examples with Output assertions, run by
  `go test`. The previous README example was written against the deleted
  `builder` package and kept claiming to work because nothing ever compiled it.

### Changed
- **BREAKING: `compliance` defaults to `eddsa-jcs-2022` (Axis 150).** The W3C VC
  proof default was `Ed25519Signature2020`, a pre-Data-Integrity suite off the
  W3C standards track, while the current REC suite sat behind an opt-in nothing
  set. A product whose claim is *compliance* shipping a deprecated suite in its
  zero value is itself a conformance defect. `Issuer.DataIntegrity bool` is
  replaced by `Issuer.LegacyProofSuite bool`, inverting the field so Go's zero
  value points at the current standard — a default is what you get for writing
  nothing, and that must not be the deprecated option. Verify already dispatches
  on proof type/cryptosuite, so existing credentials are unaffected; callers who
  set `DataIntegrity: true` get a compile error whose fix is deleting the line.

### Fixed
- **`compliance`: battery passports re-signed with the wrong suite (Axis 150).**
  Exposed by the default flip. `issueBatteryPassport` calls `Issue` (which
  signs), mutates `Type` and the Annex XIII `Subject.Attrs`, then re-signs — and
  that re-sign hand-rolled ed25519 over `canonicalPayload`, the *legacy*
  construction, whatever suite the issuer had chosen. An `eddsa-jcs-2022` issuer
  therefore produced a `DataIntegrityProof`-typed credential carrying a legacy
  base64 proofValue: signed, returned, and permanently unverifiable, with no
  signal to the caller — the same class as Axis 141's mdoc alg-header mismatch.
  Now re-signs through `attachProof`. Reachable before this axis by anyone
  combining `DataIntegrity=true` with a battery passport; it had no test because
  the two features were only ever exercised separately.
- **`dcapi`: stopped advertising an mdoc protocol the library cannot service
  (Axis 150).** `BuildForVerifier` attached an `org-iso-mdoc` request to every
  DC-API call carrying `{client_id, nonce, response_mode,
  presentation_definition_compat}` — a shape in no specification, where
  org-iso-mdoc requires an ISO 18013-7 Annex C DeviceRequest. Strictly worse
  than offering nothing: a browser preferring that entry negotiates a protocol
  we cannot fulfil, losing a working OpenID4VP exchange, while the caller
  believes an mdoc request was built. Deleted rather than guessed at from a
  paywalled spec; what a real implementation needs is recorded in the code.
  Three tests asserted the broken shape and were corrected to assert its
  absence.

### Added
- **`mdoc`, `cbor`: x5chain and IACA→DSC certificate validation (Axis 148).**
  mdoc issuance and verification were bare-key — `Verify` required the caller to
  already hold and trust the issuer key out of band — while every real mdoc
  ecosystem is X.509. ISO/IEC 18013-5 Annex B defines a long-lived IACA root per
  issuing authority with short-lived Document Signer Certificates under it, and
  the DSC travels with the credential in the COSE `x5chain` header (RFC 9360
  label 33), so a verifier holding only the roots can verify a document from an
  issuer it has never seen. `Issue` gained `IssuerAuthUnprotected` (built by
  `X5ChainHeader`, bstr for one certificate and an array of bstr for a chain per
  §2); `VerifyChain` validates to caller-supplied roots and then verifies
  issuerAuth **with the key from the validated leaf**. The embedded chain is
  evidence, never authority: an attacker-rooted chain is rejected, a *genuine*
  DSC attached to a document signed by a different key is rejected
  (`ErrDSCKeyMismatch` — without this the chain would be decorative), no
  configured roots refuses rather than trusting the document, and a missing or
  malformed x5chain is an error rather than a silent downgrade to bare-key.
  `ChainVerifyOptions.Now` supports validating an archived document as of its
  signing time. `AuthorityKeyIdentifier`/`ChainMatchesAKI` let Axis 147's
  `trusted_authorities` `aki` type be satisfied from a validated chain. New
  `cbor.ParseSign1Headers` reads headers before the verifying key is known, and
  is documented as returning unauthenticated values. Bare-key `Verify` and
  chain-free output are unchanged. VICAL remains out of scope. 10 new tests.

### Added
- **`openid4vp`: DCQL `trusted_authorities` (Axis 147).** A query could say what
  claims it wanted but not whose credential it would accept — OpenID4VP 1.0
  §6.1.1 defines `trusted_authorities` for that, and `dcql.go` explicitly scoped
  it out. Without it a verifier's only issuer control is its private
  `TrustedIssuers` map, which the wallet cannot see, so the wallet cannot pick a
  credential the verifier will accept and the user is walked through a disclosure
  that is then refused. All three registered types (`aki`, `etsi_tl`,
  `openid_federation`) are validated and matched with §6.1.1's OR-at-both-levels
  semantics. Evaluation is delegated to `Verifier.TrustedAuthorityChecker`
  because resolving an X.509 chain, an ETSI Trusted List or a federation chain
  needs network I/O and separate trust config that this network-free core
  deliberately excludes — and **a restricted query with no checker is refused,
  not accepted**, since a restriction advertised to the wallet but silently
  unenforced is worse than none. A checker error also refuses rather than
  degrading to "unrestricted", and the unverifiable case is distinguishable from
  an ordinary claim mismatch so a misconfigured verifier is not hidden. Queries
  without the member are unrestricted and unchanged on the wire. 12 new tests.

### Added
- **`openid4vci`: authorization code flow with mandatory PKCE (Axis 146).** The
  token endpoint accepted only the pre-authorized code grant, which fits just the
  case where the issuer already knows the subject and hands them a code out of
  band. It could not express the ordinary case — a wallet that discovers an
  issuer and needs the user to authenticate *at* the issuer — which OpenID4VCI
  1.0 §4.1.1 defines and the EUDI ARF assumes. New `pkce.go` implements RFC 7636
  S256, anchored on the Appendix B worked example (its published challenge is
  reproduced byte-for-byte); `plain` is rejected rather than supported, since it
  protects against nothing in PKCE's threat model, OAuth 2.1 forbids it, and
  accepting it enables a method-downgrade on the authorization request. New
  `authcode.go` adds `CreateAuthorizationCodeOffer` / `Authorize` /
  `ExchangeAuthorizationCode`; user authentication stays the deploying issuer's
  decision, supplied through the same callback seam the package already uses.
  Bindings, each with a test for the attack it stops: PKCE required, exact
  `redirect_uri` matching (RFC 6749 §3.1.2.3), `client_id` matching, codes that
  are single-use *and burned by a failed redemption* (§4.1.2, §10.5), single-use
  `issuer_state`, claims kept off the front channel, the authenticated subject
  overriding the offer's, `response_type=code` only, and every token-endpoint
  failure collapsed to one byte-identical response so redemption is not an
  oracle. 20 new tests.

### Added
- **`compliance`: nested, recursive and array-element disclosure at issuance
  (Axis 145).** Axis 139 taught the verifier all three RFC 9901 disclosure
  shapes at any depth, but issuance emitted only flat top-level properties — a
  claim was disclosable whole or not at all, so revealing `address` revealed
  every field in it. An `SD()` marker anywhere in a claim tree now makes that
  position disclosable: object members become 3-element disclosures whose digest
  joins that object's own `_sd`, array elements become 2-element disclosures
  replaced in place by `{"...": digest}` (length and order preserved), and
  because the walk is bottom-up a disclosed value may still carry `_sd`/`...` —
  recursive disclosure. Trees with no marker are unchanged, so existing callers
  are unaffected. `PresentPaths` addresses claims by DCQL-style `[]any` paths and
  auto-includes the ancestor disclosures each selection needs (name-based
  `Present` could not reach array elements at all, and an orphaned nested
  disclosure must be rejected as unused); `DisclosablePaths` enumerates what a
  credential offers; `PresentPathsWithKeyBinding{,ES256}` pair paths with the
  KB-JWT OpenID4VP requires. Fail-closed at issuance on reserved/structural
  disclosable names, a caller-supplied literal `_sd`, a misplaced `SD()` marker,
  and unknown presentation paths. Also fixed two discarded `json.Marshal` errors
  that turned an unencodable claim value into a signed but permanently
  unverifiable credential. Decoys now apply at every `_sd`-bearing object (never
  to arrays, whose length is semantic). 15 new tests.

### Fixed
- **CI had never run a single job (Axis 144).** GitHub resolves workflows only
  from the root `.github/workflows/` and Dependabot only from the root
  `.github/dependabot.yml`, but both lived under `blrcs/.github/` — so the
  2100+ tests, 20 fuzz targets, govulncheck, golangci-lint and SBOM job the
  config described had never gated a commit, and neither the module nor the
  pinned Actions were monitored. **Dependabot is fixed** (moved to
  `.github/dependabot.yml`; its gomod entry also pointed at `/` while the module
  lives in `/blrcs`). **The workflow is corrected but still needs a maintainer to
  install it**: the CI identity maintaining this repo lacks the GitHub
  `workflows` permission and cannot write under the root `.github/workflows/`,
  so `blrcs/.github/workflows/ci.yml` carries the fixes plus a header stating it
  must be moved (`git mv blrcs/.github/workflows/ci.yml
  .github/workflows/blrcs-go.yml`) to take effect. Its body already assumes the
  root location (`defaults.run.working-directory: blrcs`, `blrcs/**` path
  filters, `blrcs/`-prefixed artifact paths). Gaps fixed in it: build all
  commands (`blrcs-mcp` was never build-checked), discover all 20 fuzz targets
  from source rather than naming 4 by hand, enforce gofmt, enforce the
  zero-dependency guarantee (`go mod tidy` no-op + no go.sum + no external
  modules), and test both the Go floor go.mod declares and stable.

### Added
- **`jwe`, `openid4vp`: encrypted OpenID4VP Authorization Response (Axis 143).**
  HAIP and OpenID4VP §8.3 require verifiers to accept an encrypted Authorization
  Response and pin ECDH-ES direct key agreement on P-256 with A128GCM — what
  Chrome/Safari's Digital Credentials API emit — but BLRCS had no JWE, so the
  holder's disclosed claims travelled in cleartext through the browser/relay
  boundary. The gap was blocked on P-256, now delivered by the Axis 135–142 arc.
  New stdlib-only `jwe` package (RFC 7516 compact serialization, RFC 7518 §4.6
  ECDH-ES with the NIST SP 800-56A Concat KDF, §5.3 A128GCM), anchored on the
  RFC 7518 Appendix C worked example — its published derived key is reproduced
  byte-for-byte, so interop is proven. Only the one ECDH-ES/A128GCM pair is
  implemented; any other alg/enc, or the JWE Encrypted Key that direct agreement
  forbids, is rejected before any crypto. Wired into the verifier:
  `ResponseEncryptionKey` (P-256) makes the request advertise the encryption JWK
  in client_metadata and switch response_mode to `direct_post.jwt`; the callback
  transparently decrypts a `response` JWE before verifying. Verifiers without the
  key are unchanged (plaintext direct_post). 17 new tests + a public-API E2E
  driver.

### Fixed
- **`compliance`: KB-JWT holder binding was Ed25519-only, blocking real EUDI
  presentations (Axis 142).** An EUDI wallet's device key is P-256, so its
  key-binding JWT is ES256-signed and its `cnf` key is EC/P-256, but the
  verifier pinned the KB-JWT alg to EdDSA and the cnf key to OKP/Ed25519 — so
  a presentation could not complete even though the credential (Axis 137) and
  its disclosure resolution (Axis 136/139) were already P-256 capable. This
  closes the last gap in the P-256 presentation loop. `extractHolderKey` now
  yields either the Ed25519 or the P-256 holder key (EC/P-256 validated
  on-curve via `ecdsakey.ParseP256PublicKey` — invalid-curve defence at the
  parse boundary); `verifyKBJWT` dispatches on the KB-JWT alg but **requires**
  it to name the algorithm of the key the issuer bound in `cnf`, so an EdDSA
  KB-JWT against a P-256 cnf (or vice versa) is rejected — the binding is to
  THE cnf key, closing alg-confusion. `buildSDJWT` embeds an EC/P-256 cnf for
  a 65-byte SEC1 holder key; `PresentWithKeyBindingES256` emits the ES256
  KB-JWT (raw R‖S per RFC 7518 §3.4), sharing the sd_hash/transaction_data
  logic with the Ed25519 path. 6 new tests + a public-API E2E driver. W3C VC
  proofs and SCITT receipt signing remain the last Ed25519-only paths.
- **`openid4vp`: DCQL claims paths could not address array elements (Axis
  140).** OpenID4VP §6.3 allows a path component to be a string (object key),
  a non-negative integer (array index) or null (all elements), but
  `ClaimQuery.Path` was `[]string` — the latter two were inexpressible — and
  the walker descended objects only. So after Axis 139 a verifier could accept
  a credential with selectively-disclosed array elements but not constrain
  them. `Path` is now `[]any` and `resolvePath` returns every selected value.
  Wildcard + `values` matches when **any** selected value is in the allowlist
  (identical to before for single-valued paths). Components are validated up
  front (`ErrDCQLInvalidPath`); a fractional or negative index is rejected
  rather than truncated. 9 new tests; the `[]any` change rippled to `dcapi`
  and `integration` call sites.
- **`compliance`: RFC 9901 array-element and recursive disclosures were
  rejected as malformed (Axis 139).** The resolver understood only the flat,
  top-level `[salt, name, value]` shape whose digest sat in the top-level
  `_sd`, so a credential from any conforming issuer using array-element
  (`[salt, value]` + `{"...": digest}`) or recursive (nested `_sd`)
  disclosures was refused — an interop failure that looks like tampering. New
  `disclosure.go` walks the payload and substitutes disclosures at any depth,
  enforcing the spec's MUSTs: each digest referenced at most once, every
  presented disclosure used, distinct `_sd` strings, single-key `...`
  placeholders, collision checks at every depth, and rejection of shape
  confusion in both directions. Recursion is depth-bounded. Also stops the
  issuer emitting the invalid `"_sd": null` for credentials with no
  disclosable claims (tolerated on the verify side for older credentials).
  New error sentinels wrap `ErrSDJWTMalformed` so `errors.Is` callers are
  unaffected. 17 new tests. Verification only — issuance still emits flat
  disclosures, which no longer blocks interop.
- **`openid4vp`: mso_mdoc presentations were mis-routed to the SD-JWT verifier
  (Axis 138).** `ProcessResponse` verified every vp_token as an SD-JWT
  whatever format the DCQL query requested, so an mdoc presentation failed
  with a misleading "signature/issuer mismatch"; and
  `CredentialQuery.Meta.DoctypeValue` was declared but never read, so any
  doctype was accepted. Now dispatches on format: the mdoc path decodes the
  DeviceResponse, verifies issuerAuth and DeviceAuth, and enforces the
  doctype twice (envelope, then the MSO-attested value, since the envelope is
  unauthenticated until the signature verifies). **SessionTranscript is
  supplied, not invented** — it is the replay defence, and while OpenID4VP
  Annex C defines the DC-API form, the vanilla (direct_post) form is still
  open upstream (OpenID4VP#402/#519, HAIP#137). An mdoc presentation with no
  configured `Verifier.MdocSessionTranscript` is **rejected**, not verified
  unbound. Adds the `FormatSDJWT`/`FormatMsoMdoc` constants. 7 new tests.

### Added
- **`cbor`, `mdoc`: ES256 mdoc issuance and device auth (Axis 141).**
  Completes the P-256 story — COSE *signing* was still Ed25519-only, so BLRCS
  could consume a real mDL but not produce one. New `cbor.Sign1ES256` (raw
  fixed-width `R‖S` per RFC 9053 §2.1, `*ecdsa.PrivateKey`-typed so keys cannot
  cross paths), plus `IssuerPrivES256` / `DeviceKeyES256` on `mdoc.IssueParams`
  with the device key as an EC2 COSE_Key (RFC 9052 §7) validated on-curve when
  parsed back. Implementing it surfaced a real bug — mdoc stamped
  `AlgEdDSA` on ES256 signatures, yielding well-formed but unverifiable
  credentials — now fixed and closed as a class: both signers reject a
  protected header declaring a different algorithm (`ErrAlgHeaderMismatch`).
  10 new tests. SCITT COSE receipts remain EdDSA (BLRCS-internal, no interop
  argument).
- **`compliance`: ES256 SD-JWT issuance (Axis 137).** Completes the P-256
  story — BLRCS can now **issue** credentials a P-256-only EUDI ecosystem
  accepts, verified end to end (issue → publish EC JWK in a DID document →
  resolve → verify from the DID alone). New `ES256Issuer` is a distinct type,
  not a flag: `Issuer.PrivateKey()` feeds Ed25519-only subsystems (SCITT,
  did:webvh, status lists), so a mode flag would hand them a nil key at
  runtime — a separate type makes that a compile error. The SD-JWT
  construction is shared via an unexported `jwsSigner` seam, so decoys and
  disclosure logic cannot fork per algorithm. Signatures use `FillBytes` for
  the RFC 7518 §3.4 fixed 64-octet width (a leading-zero coordinate would
  otherwise emit a short encoding conforming verifiers reject). Nonces rely on
  Go's *hedged* ECDSA (k from an AES-CTR CSPRNG keyed by
  `SHA2-512(priv.D‖entropy‖hash)`), which resists RNG failure while keeping
  the fault-injection tolerance strict RFC 6979 determinism gives up. 9 new
  tests. Scope: SD-JWT only — W3C VC, mdoc, SCITT and `kms` remain Ed25519.
- **`didresolver`, `multiformats`: P-256 key resolution (Axis 136).** Axis 135
  could verify an ES256 credential only if the key was already in hand — no
  resolver path could return a P-256 key. Adds an algorithm-tagged
  `PublicKey{Alg, Bytes}` + `ResolveAllKeys` covering did:web / did:webvh JWKs,
  did:key, did:jwk and Multikey, so resolve-then-verify now works end to end.
  Deliberately a **parallel** API: `ed25519.PublicKey` is a named `[]byte`, so
  widening it would let a P-256 key masquerade as Ed25519; the legacy
  Ed25519-typed functions are unchanged and `PublicKey.Ed25519()` returns
  `ok=false` for P-256. Encodings verified against RFC 7518 §6.2 (32-octet
  fixed-width `x`/`y`) and multicodec `p256-pub` = 0x1200 → varint `0x80 0x24`
  + compressed point (hence `zDn…`). Invalid-curve points are rejected at the
  resolution boundary; Ed25519 and P-256 multikeys cannot cross-decode.
  10 new tests.
- **`ecdsakey`, `compliance`, `cbor`: ES256 / P-256 verification (Axis 135).**
  The assessment's #1 weakness — Ed25519-only, while the EUDI ARF and
  OpenID4VC HAIP mandate P-256, so no real EUDI wallet could interoperate.
  Adds the verify half via the existing algorithm registries (no core changes,
  stdlib only). Encoding verified against the specs: RFC 7518 §3.4 and
  RFC 9053 §2.1 both require the raw fixed-width `R‖S` concatenation (32+32
  octets, leading zeros preserved) and neither permits ASN.1 DER — which is
  what Go and most libraries emit by default — so a signature that is not
  exactly 64 bytes is rejected as an encoding-confusion hazard. On-curve
  validation via `crypto/ecdh` guards invalid-curve attacks; malleability is
  documented rather than enforced (neither RFC requires low-S). 23 new tests.
  Issuance-side P-256 and `didresolver` remain a separate, larger axis.
- **`bundle`, `mcp`: long-term, offline-verifiable DPP bundle (Axis 134).**
  A first-principles gap the standards backlog never surfaced: a DPP must stay
  verifiable for the product's 10-25 year life at frequently-offline scan
  points (recyclers, ports, customs), and after the issuer's server is gone —
  yet every verification path fetched something at verify time. New `bundle`
  package packages a credential with its issuer key, did:webvh provenance log,
  signed status snapshot and archive timestamps into one artifact that
  verifies with **zero network calls** (enforced by a test that fails on any
  outbound dial). Design corrected by the long-term-signature literature:
  ETSI LTV requires a trusted **timestamp** beside the key chain and
  revocation data — without it a 2045 verifier cannot tell a legitimate 2026
  signature from a later forgery with a dead key — and RFC 4998 (Evidence
  Record Syntax) requires renewing that timestamp as a **chain**, each anchor
  taken over the prior evidence, before the algorithms weaken. The SCITT
  ledger serves as the timestamping authority. `Verify` reports which checks
  actually ran (absence is never success) and fails closed on `Require*`.
  New tools `build_dpp_bundle` / `anchor_dpp_bundle` / `verify_dpp_bundle`
  (`TestToolsList` 34 → 37). 23 new tests.
- **`compliance`: opt-in `eddsa-jcs-2022` Data Integrity suite for W3C VCs
  (Axis 133).** Issued DPP credentials used the pre-Data-Integrity
  `Ed25519Signature2020` suite; a correct `eddsa-jcs-2022` implementation
  already existed in-repo (`didwebvh/proof.go` + `multiformats/jcs.go`),
  scoped to DID-log entries. New `Issuer.DataIntegrity` flag (default false =
  byte-unchanged legacy suite) switches issuance to a W3C `DataIntegrityProof`
  with `cryptosuite=eddsa-jcs-2022`, reusing the same JCS+base58 hashData
  construction (multibase `z`-prefixed proofValue). Both issue paths route
  through a shared `attachProof`; `Verify` auto-dispatches on the proof
  suite. 7 new tests. `eddsa-jcs-2022` is the current W3C REC (EdDSA
  Cryptosuites v1.0, 2025-05-15).
- **`docs`: product assessment + Opus/Sonnet work-instruction sheets.**
  `docs/PRODUCT_ASSESSMENT.md` (長所/短所/改善案, every file:line re-verified),
  `docs/INSTRUCTIONS_SONNET.md` (small/well-scoped tasks with in-repo patterns
  to mirror + the mandatory per-axis discipline), and
  `docs/INSTRUCTIONS_OPUS.md` (large/architectural tracks — ES256/P-256,
  mdoc↔OpenID4VP dispatch, JWE, array/recursive disclosure, auth-code flow,
  mdoc PKI, issuance agility — with staged milestones and stop-and-confirm
  gates). Turns the remaining standards backlog into executable instructions
  for future sessions.
- **`scitt`, `mcp`: SCITT ledger lifecycle search index + `search_passports`
  (Axis 132).** The ledger offered only append + linear scan — no way to
  query "all passports for product X / manufacturer Y" (CEN-CENELEC EN 18222
  lifecycle searchability). Added `bySubject`/`byIssuer` secondary indexes
  maintained on `Register` and rebuilt on replay, `FindBySubject`/
  `FindByIssuer` query methods returning indexed results (no full scan), and
  a `search_passports` MCP tool (by subject and/or issuer; both = intersection).
  `TestToolsList` 33 → 34. 4 new tests.
- **`didwebvh`, `mcp`: did:webvh `watchers` parameter (Axis 131).** The
  did:webvh v1.0 out-of-band monitoring signal — an array of URLs that have
  agreed to watch a DID — was absent. Added as `Parameters.Watchers`
  (`*[]string`, matching the `Portable` rigor so omit/retain vs. explicit
  set/clear is representable). `Verify` tracks the active list across entries
  (explicit replaces, omitted retains) and surfaces it as
  `Resolution.Watchers`, satisfying the spec's "resolvers MUST expose the
  active watcher list in resolution metadata" (watchers are not a
  verification gate). `create_did_webvh`/`update_did_webvh` gained a
  `watchers` arg; `verify_did_webvh_log` now returns `watchers`. 6 new tests.
- **`openid4vci`: batch issuance (`proofs` → `credentials` array, Axis
  130).** `CredentialRequest` carried only a singular `Proof`; there was no
  plural `proofs`/`credentials` path. Batch issuance is the standard
  mechanism for a wallet to obtain multiple single-use, unlinkable credential
  copies in one round trip — the EUDI-approved-crypto mitigation for
  presentation linkability. New `IssueBatchWithProofs` validates every proof
  up-front (all-or-nothing: a failed batch issues nothing and leaves the
  access token reusable), signs one credential per holder key, and returns
  one `notification_id` for the whole response. Bounded by `maxBatchProofs`
  (32). The security-sensitive crypto (proof/nonce validation, signer switch)
  was extracted into shared helpers so single and batch paths use one code
  path. `/credential` dispatches on request shape. 8 new tests including a
  full HTTP-layer batch and a proof-key-binding/unlinkability check.
- **`openid4vp`: DCQL `claim_sets` support (OpenID4VP 1.0 §6.3.1, Axis
  128).** `CredentialQuery` had a flat `Claims` list but no `ClaimSets`,
  and no logic requiring at least one claim-set option to be fully
  disclosed — distinct from the already-implemented query-level
  `credential_sets` (§6.2). `ClaimQuery` gains an optional `id`, required
  when `claim_sets` is present on that credential query; a credential
  satisfies the query if it can fully disclose every claim referenced by
  *at least one* `claim_sets` option (OR-of-ANDs — e.g. "passport number OR
  license number"), not a mechanism for making individual claims optional.
  `Validate()` enforces unique ids and valid references, mirroring the
  existing `credential_sets` validation exactly. 8 new tests.
- **`openid4vci`: Notification Endpoint (OpenID4VCI 1.0 §10, Axis 127).**
  No `notification_id` in `CredentialResponse`, no `POST /notification`
  handler, not advertised in `Metadata()` — the audit trail for whether a
  wallet actually stored an issued credential was missing entirely.
  `IssueCredentialWithProof` now generates a `notification_id` alongside
  every issuance, bound to the access_token used (spec requires the same
  token to submit the notification). New `HandleNotification` validates the
  event (`credential_accepted`/`credential_failure`/`credential_deleted`),
  single-use, and collapses all failure modes into one
  `ErrUnknownNotification` (mirrors the existing pre-authorized_code/tx_code
  oracle defense). New `OnNotification` audit hook mirrors `OnTxCodeLockout`.
  HTTP: `POST /notification`, Bearer auth, 204 on success. 13 new tests.
  Verified end-to-end against the built `blrcs-mcpd` binary.
- **`didresolver`: live HTTP resolution for did:webvh identifiers (Axis
  126).** `Resolve`/`ResolveAll` switched on `case "key"/"jwk"/"web"` but had
  no `case "webvh"` — did:webvh could only be verified from a caller-supplied
  in-memory log, never resolved as a live trust anchor the way did:web
  already is. Verified the exact DID-to-HTTPS transformation against the
  canonical spec source before implementing: strip the SCID segment, decode
  `%3A`-encoded ports, join remaining segments into a path, fetch
  `.../did.jsonl` (or `.well-known/did.jsonl`). New
  `didresolver/didwebvh.go` fetches, parses the `text/jsonl` log, calls
  `didwebvh.Verify`, and — critically — confirms the verified log's resolved
  SCID matches the SCID segment parsed from the identifier itself, since
  `Verify` alone only checks a log's internal self-consistency and has no way
  to know which DID was actually requested (a malicious server could
  otherwise serve a valid log for a *different* SCID at the same URL).
  `resolve_did`/`discover_did_services` (existing generic MCP tools)
  transparently gained did:webvh support with no MCP-layer code change.
  Reuses the same SSRF-hardened fetcher as did:web — no new attack surface.
  12 new tests. Verified end-to-end against the built `blrcs-mcp` binary +
  a real local HTTP server.
- **`mcp`: wire GS1 Digital Link Linkset to `build_gs1_linkset`/
  `parse_gs1_linkset` (Axis 125).** `compliance/linkset.go` fully implements
  the RFC 9264 Linkset — the standard EU DPP discovery mechanism (a QR
  resolves to a GTIN URI, and the linkset routes from there to the passport,
  declaration of conformity, due-diligence statement, instructions, etc.) —
  but nothing wired it to the MCP tool surface or an HTTP handler, unlike
  its sibling `build_gs1_link`/`parse_gs1_link` (Axis 106). A complete,
  tested feature was sitting completely unused. New tools follow the exact
  same pure/read-only, not-audited pattern as the existing GS1 link tools.
  `TestToolsList` count updated 31 → 33. 12 new tests. Verified end-to-end
  against the built `blrcs-mcp` binary: build → parse round-trips the
  anchor and every linkType's links losslessly.
- **`cbor`, `mdoc`, `scitt`: per-call COSE algorithm allowlist (Axis 124).**
  `cbor.RegisterVerifier` lets a second COSE algorithm be registered
  globally, but `Verify1` had no allowlist parameter — once any second alg
  is registered, every mdoc/SCITT verification call anywhere in the process
  silently accepted either algorithm, with no way to pin one verification
  to PQC-only. Mirrors the downgrade defense
  `compliance.VerifyOptions.AllowedAlgs` already provides on the SD-JWT
  side. New `cbor.Verify1WithAlgs` (`Verify1` now a thin wrapper) plus
  `ErrCOSEAlgNotAllowed`, wired through to its real callers —
  `mdoc.VerifyWithAlgs`, `mdoc.VerifyDeviceAuthWithAlgs`,
  `scitt.VerifyCOSEReceiptWithAlgs` — rather than left cbor-internal only.
  Also switched the COSE-error wrapping at those three call sites from
  `%w: %v` to `%w: %w` so `errors.Is` can see through to the underlying
  cbor sentinel, not just each package's own top-level one. 5 new tests.
- **`didwebvh`, `mcp`: enforce the did:webvh Portable parameter in `Verify`
  (Axis 123).** `Parameters.Portable` was round-tripped on the wire but never
  actually checked: `Verify` never confirmed that a log entry's `state.id`
  SCID segment matched the DID's SCID, nor that a domain/path change was
  gated by `portable=true` declared at genesis — a malicious or buggy log
  could silently rewrite a DID's SCID or move it to an attacker-controlled
  domain and `Verify` would still accept it. Verified the exact rules
  (defaults to false; only the first entry may ever set it true; a later
  entry may omit it to retain the prior value or set it false to permanently
  disable further moves; the SCID segment must never change, only host/path,
  and only while portability is in effect) against the canonical spec source
  before implementing. `Parameters.Portable` changed from `bool` to `*bool`
  so "omitted" and "explicit false" are distinguishable on the wire (the
  field had no working writer anywhere in the codebase before this, so this
  is not a breaking change to any real caller). Also fixed a bug this
  surfaced: `Resolution.DID` was hardcoded to the genesis entry's id, so a
  legitimately-moved portable DID resolved to its stale original address
  instead of its current one. `create_did_webvh`/`update_did_webvh` gained an
  optional `portable` arg. Refreshed the package doc comment, which still
  claimed witness cosigning was unimplemented despite Axis 119. 7 new tests.
  Verified end-to-end against the built `blrcs-mcp` binary over real stdio
  JSON-RPC: an unauthorized domain move is rejected, a `portable=true` move
  verifies and resolves to its new address.
- **`didwebvh`, `mcp`: did:webvh witness support, v1.0 spec (Axis 119).**
  Closes a gap the package's own doc comment flagged: "Witness cosigning …
  not implemented here." Verified the exact wire format against the
  canonical spec source before implementing — witness proofs live in a
  separate `did-witness.json` file (not appended to the entry's own
  `proof` field), keyed by `versionId`:
  `parameters.witness = {"threshold": n, "witnesses": [{"id": "did:key:..."}]}`.
  New `SignWitnessProof` (reuses the existing `eddsa-jcs-2022` signing
  primitives — same hash construction as the controller's own proof, just
  a different key source/storage location) and `VerifyWithWitnesses`
  (counts distinct valid witness proofs against the declared list,
  rejecting duplicate/undeclared/tampered proofs, enforcing the declared
  threshold). `VerifyWithWitnesses(log, nil)` is exactly equivalent to
  `Verify(log)` when no entry declares a witness requirement — plain
  `Verify` continues to ignore any declared requirement entirely
  (opt-in enforcement). `create_did_webvh`/`update_did_webvh` gained an
  optional `witness` arg; `verify_did_webvh_log` gained an optional
  `witnessLog` arg; new `sign_witness_proof` MCP tool reuses the existing
  pre-registered-issuer-key mechanism (a witness identity is just an
  Issuer registered under a `did:key:` ID instead of `did:web:`).
  Verified end-to-end against the built `blrcs-mcp` binary. 15 new tests.
  `TestToolsList` updated (30 → 31).
- **`cmd/blrcs-mcpd`: `.well-known` capabilities and privacy discovery
  endpoints (Axis 118).** Continuing the zero-caller triage: `openapi`'s
  `BLRCSDefault()` spec (also unwired) documents
  `/.well-known/blrcs-capabilities.json` and `/.well-known/privacy.json`
  as expected endpoints, but neither was ever mounted — and the spec is
  itself stale/inaccurate in other ways (omits `/mcp`, `/diag`; always
  claims OpenID4VCI/VP paths regardless of whether those features are
  actually enabled for a given instance), so `/openapi.json` itself was
  deliberately **not** wired this round — publishing a misleading spec
  under a URL that implies authoritative completeness would be worse than
  not publishing it. The two `.well-known` documents it references *were*
  independently fixable: `GET /.well-known/blrcs-capabilities.json` serves
  `mcp.Server.CapabilitiesSnapshot()` (new exported method,
  refactored out of Axis 116's `get_server_capabilities` tool so both
  transports return the same data by construction, not by convention);
  `GET /.well-known/privacy.json` serves `privacy.BLRCSDefaultManifest()`
  (a static GDPR Art.30-style declaration of data categories processed —
  legitimate to always serve, unlike a live technical/API claim, since it
  doesn't describe runtime-configurable endpoints). Both always-on (not
  gated behind an opt-in env var like `BLRCS_DIAG`), served through the
  full `httpmw.Default` chain. Verified end-to-end against the built
  binary. 1 new test proving the MCP tool and the HTTP endpoint return the
  same capability data from a single source.

### Fixed
- **`openid4vci`: `credential_configurations_supported` metadata shape (Axis
  129).** `Metadata()` omitted `proof_types_supported` and used the
  jwt_vc_json-style `credential_definition.type` shape for the SD-JWT-VC
  format profile, where OpenID4VCI 1.0 Final wants a top-level `vct`. A
  wallet reading the metadata for an SD-JWT-VC (`dc+sd-jwt`) config expects
  `vct`, and needs `proof_types_supported` to know which proof algorithms the
  issuer accepts. Now branches on the format: SD-JWT-VC configs emit `vct`,
  other formats keep `credential_definition.type`; all configs advertise
  `proof_types_supported = {"jwt": {"proof_signing_alg_values_supported":
  ["EdDSA"]}}`, mirroring what `parseProofJWT` enforces. 2 new tests; verified
  end-to-end against the built `blrcs-mcpd`.
- **`openid4vp`: DC-API client_id prefix used the wrong wire string (Axis
  122).** OpenID4VP 1.0 Final §5.10 defines the DC-API Client Identifier
  Prefix as the literal `origin` (`origin:<calling origin>`); `clientid.go`
  instead implemented it as `web-origin`, which no spec-conformant
  wallet/browser recognizes. Renamed the known-prefix entry and its
  scheme-validation branch. New test locks in both directions: `origin:`
  validates as the DC-API prefix, and the retired `web-origin:` string no
  longer gets scheme-validated as one. Continues the standards-research
  audit backlog started at Axis 120.
- **`openid4vci`: legacy `vc+sd-jwt` format-id default and un-threaded `vct`
  (Axis 120-121).** A background research workflow re-verified blrcs
  against the current state of 10 standards and surfaced these as the
  top-ranked, highest-confidence gaps. `RegisterConfiguration` defaulted an
  unset `Format` to the retired `vc+sd-jwt` discriminator (and
  `cmd/blrcs-mcpd/main.go`'s demo config used the same string), even though
  `compliance.Issuer` has issued `dc+sd-jwt`-typed credentials by default
  since Axis 113 — a wallet reading `credential_configurations_supported`
  saw the retired format id while receiving a `dc+sd-jwt` JWT. Separately,
  `IssueCredentialWithProof` always signed with the vct-parameterized
  variants hardcoded to `VCTDigitalProductPassport`, ignoring the matched
  configuration's own `CredentialType` — two differently-configured
  `credential_configurations` on the same issuer (e.g. `BatteryPassport` vs
  `DigitalProductPassport`) silently collapsed to the same `vct` despite
  advertising distinct types in issuer metadata. Now threads
  `cfg.CredentialType` into the (previously unused)
  `IssueSDJWTVC*`/`IssueSDJWTVCBound*`/`IssueSDJWTVCStatus*` variants,
  falling back to the DPP default only when `CredentialType` is unset. Also
  refreshed stale "OpenID4VCI Draft 15" doc comments to "1.0 Final" (spec
  reached Final status 2025-09-16), and removed a hardcoded
  `Format: "vc+sd-jwt"` from `WalletClient.FetchCredentialCtx` that would
  otherwise re-drift on every future format-string change. 2 new tests
  proving distinct configs issue distinct `vct` claims and that an unset
  `CredentialType` still falls back correctly. Verified against a built
  `blrcs-mcpd`: `/.well-known/openid-credential-issuer` now advertises
  `"format":"dc+sd-jwt"` matching what is actually signed.
- **`httpmw`: `statusWriter`/`loggingResponseWriter` didn't forward
  `http.Flusher`/`Unwrap` (Axis 117).** Found while auditing why
  `cmd/blrcs-mcpd` only ever applied bare `Recovery` instead of the
  documented recommended `httpmw.Default` chain (Recovery → RequestID →
  SecurityHeaders → AccessLog) to any route. The reason: applying it to
  `/mcp` (which serves SSE) would have hard-broken streaming —
  `mcp/http.go`'s SSE handler does a direct `w.(http.Flusher)` type
  assertion, and neither wrapper type implemented `Flush()` or the Go
  1.20+ `Unwrap() http.ResponseWriter` convention `http.NewResponseController`
  needs to drill through wrapper chains. Added both to each wrapper. A
  rigorous regression test opens a real TCP connection to a real
  `net/http.Server` wrapped in the full `Default` chain and proves a
  flushed chunk arrives well within a 2s deadline (not just that the
  `Flush()` call itself doesn't error, which a `httptest.ResponseRecorder`
  can't catch). 8 new tests.

### Added
- **`cmd/blrcs-mcpd`: apply the full recommended middleware chain to every
  route (Axis 117).** Every route was using bare `httpmw.Recovery`
  (`/mcp`, the OpenID4VCI/VP endpoints, `/diag`) while `/metrics`,
  `/healthz`, `/readyz` had **no middleware at all** — zero panic
  protection, no security response headers
  (`X-Content-Type-Options`/`X-Frame-Options`/HSTS/`Referrer-Policy`/
  `Permissions-Policy`), no request-ID correlation, no structured access
  log — despite `httpmw.Default` bundling exactly this as BLRCS's own
  documented recommended chain. Upgraded `/mcp`, the OpenID4VCI catch-all,
  both OpenID4VP endpoints, and `/diag` to `httpmw.Default` (safe now that
  Flush/Unwrap forward correctly through it); `/metrics`/`/healthz`/`/readyz`
  gained `httpmw.Recovery` (kept lighter — full access-logging of frequent
  health-check polling is noise, not signal). Also confirmed
  `httpmw.MaxBodyBytes` (also previously unused anywhere) is *not* a gap:
  every handler that reads a request body already caps it individually via
  `http.MaxBytesReader`. Verified end-to-end against the built binary:
  security headers and `X-Request-Id` present on `/mcp` responses, SSE
  streaming still works, `/diag`/`/healthz`/`/metrics` all still reachable.
- **`mcp`, `capability`: `get_server_capabilities` tool for agent capability
  discovery (Axis 116).** The `capability` feature-detection package was
  implemented and tested but reachable from no binary (zero-caller triage,
  same shape as Axis 115's `diag`). Added a read-only MCP tool that reports
  which optional features are actually operational — `protocol.openid4vci`
  (issuance), `protocol.openid4vp` (verification), both reflecting real
  registration state — plus always-present `crypto.ed25519`,
  `compliance.dpp`, `compliance.battery`, `audit.scitt`, and runtime info.
  Lets an agent discover, before calling them, whether config-dependent
  tools like `create_credential_offer` / `create_presentation_request` will
  work. Added `CapOpenID4VCI`/`CapOpenID4VP` capability constants.
  Persistence is deliberately not reported — it isn't self-detectable from
  inside the Server (in-memory `MemoryStorage` also implements
  `BlobStorage`), and a guessed value would be worse than omitting it.
  Verified end-to-end against the built `blrcs-mcp` binary. 3 new tests
  incl. one proving the report flips when a verifier is registered.
  `TestToolsList` updated (29 → 30).
- **`cmd/blrcs-mcpd`: mount the `diag` sysdiagnose-style snapshot endpoint
  (Axis 115).** The `diag` package (runtime/goroutine/memory stats,
  telemetry counters & histograms, a recent-error ring, custom resources)
  is fully implemented and tested with a ready-to-mount `Handler()`, but
  nothing was mounting it — the same "part exists but isn't connected"
  shape as the openid4vci/openid4vp `Handler()` gaps (Axis 103/105).
  Wired into the daemon opt-in via `BLRCS_DIAG=1` (off by default, since
  the snapshot exposes runtime internals an operator may not want on an
  unauthenticated port — matching the `BLRCS_VCI_URL`/`BLRCS_VP_CLIENT_ID`
  posture), reusing the same `telemetry.Telemetry` the `/metrics` exporter
  reads so the two stay consistent. Registers `ledger.size` and `persist`
  as diagnostic resources. Serves `/diag/snapshot.json` and
  `/diag/snapshot.txt`. Verified end-to-end against the built binary:
  enabled returns the snapshot with live runtime + resource data; 404 by
  default.
- **`compliance`, `openid4vp`, `mcp`: OpenID4VP 1.0 `transaction_data`
  binding (Axis 114).** Implements the OpenID4VP 1.0 (final, Jul 2025)
  Transaction Data mechanism — the basis for qualified e-signatures /
  payment-consent in the EUDI ecosystem, previously absent. A verifier can
  bind an Authorization Request to specific transaction_data entries
  (base64url JSON objects); the holder hashes each into the KB-JWT
  (`transaction_data_hashes` + `_alg`), and the verifier requires the hashes
  to cover every entry — cryptographically proving the holder saw and
  approved *this exact* transaction. `compliance.VerifyOptions` gains
  `ExpectedTransactionData` and a new `ErrKeyBindingTransactionData`;
  `PresentWithKeyBindingTx` is the holder-side variant.
  `openid4vp.CreateRequestTx` carries transaction_data through both the
  unsigned query-param path and the signed RFC 9101 JAR request object; the
  MockWallet binds it on both. The `create_presentation_request` MCP tool
  gains an optional `transactionData` arg (plain JSON objects, base64url-
  encoded per spec by the tool). Verified end-to-end against the built
  `blrcs-mcpd` binary and via a replay test proving a presentation bound to
  a €42 payment does not verify against a request binding €4200. 8 new
  tests. Fully backward-compatible: a verifier that sets no
  `ExpectedTransactionData` behaves exactly as before.

### Fixed
- **`compliance`: issue SD-JWT-VCs with the current `dc+sd-jwt` typ, not the
  retired `vc+sd-jwt` (Axis 113).** Found via a standards-currency review
  (latest draft-ietf-oauth-sd-jwt-vc, OpenID4VP 1.0, Token Status List,
  did:webvh v1.0, ISO 18013-7:2025). The SD-JWT-VC media type was renamed
  `vc+sd-jwt` → `dc+sd-jwt` in Nov 2024 to avoid colliding with the W3C VC
  Data Model's `vc` media type; current drafts use `dc+sd-jwt`. The
  verifier already accepted both (`isSDJWTVCType`), but the single
  production issuance site still emitted the retired value. Added
  `Issuer.SDJWTVCType` (mirrors the `Issuer.DecoyDigests` pattern): empty →
  `dc+sd-jwt` default; set to `"vc+sd-jwt"` for legacy verifiers.
  Backward-compatible with any conformant current verifier (dual-accept on
  both sides). Verified end-to-end: `issue_sdjwt` now produces a JWS header
  of `{"alg":"EdDSA","typ":"dc+sd-jwt"}`. 3 new tests.

### Added
- **`mcp`: `resolve_vct_metadata` / `validate_claims_against_vct` (Axis
  112).** Closes the gap that motivated the `vctmeta` SSRF fix above:
  `resolve_vct_metadata` wraps `vctmeta.Resolve` (README: "SD-JWT-VC Type
  Metadata + schema validation ✅"), and `validate_claims_against_vct` is
  the natural complement to `verify_sdjwt` — after checking a credential's
  signature, check its disclosed claims actually conform to the JSON
  Schema its declared `vct` points to. `Server` gains a `vctFetcher` field
  (defaults to the now SSRF-hardened `vctmeta.HTTPFetcher(nil)`) so tests
  can inject a mock and exercise the full happy path without a real
  network round-trip. Both tools are read-only, not in `auditableTool`.
  Verified end-to-end against the built `blrcs-mcp` binary:
  `resolve_vct_metadata` against a cloud-metadata URL is correctly refused
  by the SSRF guard through the real MCP tool surface. 7 new tests,
  including IETF SD-JWT-VC §5 vct-mismatch (type-confusion) rejection.
  `TestToolsList` updated (27 → 29).

### Security
- **`vctmeta`: SSRF via direct type-metadata resolution to private/loopback/
  metadata addresses (Axis 112).** Same vulnerability class as Axis 107's
  `didresolver` fix, found while investigating whether to wire `vctmeta`
  into MCP tools. `HTTPFetcher(nil)`'s default client was explicitly
  commented and tested as "SSRF-hardened," but only blocked *redirects* —
  the existing `TestHTTPFetcherRejectsRedirect` test called it directly
  against a real loopback server and passed, proving no protection against
  resolving *directly* to a private/loopback/metadata address. `vctmeta`
  has zero callers today, so this wasn't yet live, but wiring an MCP tool
  around it without this fix would have introduced a fresh SSRF in the
  same threat position as the `didresolver` one (a credential's `vct` is
  attacker-influenced input). Fixed identically: `isBlockedIP`/
  `safeDialContext` wired as `Transport.DialContext`; a caller-supplied
  `*http.Client` is unaffected (documented escape hatch, matching
  `didresolver.Resolver.HTTPFetcher`). 3 new/updated tests, including a
  dedicated regression test proving the real default client now refuses a
  loopback target it would previously have reached.

### Added
- **`mcp`: `create_did_webvh` / `update_did_webvh` / `verify_did_webvh_log`
  (Axis 111).** `didwebvh` (README: "did:webvh (verifiable history +
  pre-rotation) ✅") had zero callers anywhere despite being a complete,
  tested DID method implementation — same shape as the `mdoc`/GS1 gaps,
  larger in scope (a full create/rotate/verify lifecycle). The signing key
  is always a pre-registered issuer's private key (`issuerId`/
  `signKeyIssuerId`), never a raw key over the wire, matching
  `issue_passport`/`issue_sdjwt`/`issue_mdoc`. This server does not
  persist did:webvh logs — the caller receives and passes back the growing
  log array between calls, the same statelessness contract
  `verify_passport` has for `credentialJson`. Verified a subtle but
  important asymmetry with a dedicated test: `update_did_webvh` does not
  itself reject an unauthorized signing key (append-only log design means
  that check only happens at verify time against the log's own recorded
  update-key history) — an unauthorized update succeeds at write time but
  correctly fails `verify_did_webvh_log`. Verified end-to-end against the
  built `blrcs-mcp` binary: produces a real `did:webvh:<SCID>:<path>`
  identifier with a signed genesis entry. 7 new tests, including a full
  create→update→verify lifecycle round-trip. `TestToolsList` updated
  (24 → 27).

### Fixed
- **`cmd/blrcs-mcp`, `cmd/blrcs-mcpd`: stop defaulting server identity to a
  nonexistent `.example` domain.** Both real server binaries silently
  defaulted `BLRCS_TS_ID`/`BLRCS_SERVER_DID` to
  `did:web:blrcs.example/...` when unset, and hardcoded the bootstrap demo
  issuer's DID to `did:web:blrcs.example/demo-issuer`. `blrcs.example` is
  an RFC 2606 reserved domain that will never resolve — fine for
  documentation examples (left alone in doc comments and
  `cmd/blrcs-demo`), wrong as a live runtime default: any wallet/verifier
  resolving this server's own DID, or the bootstrap issuer's DID it hands
  out by default, gets nothing back. This also could back the real
  OpenID4VCI issuer signer (Axis 103) if an operator never set
  `BLRCS_TS_ID`/`BLRCS_SERVER_DID`. Changed the fallback to
  `did:web:localhost/...` (a real, resolvable-to-loopback address that
  honestly signals a local/non-production identity), and derived the demo
  issuer's DID from `serverDID` instead of a separate hardcoded literal so
  it always tracks whatever domain the operator actually configures.

### Added
- **`mcp`, `cmd/blrcs-mcpd`: `verify_passport_by_did` / `verify_sdjwt_by_did`
  (Axis 110).** `compose.Composer.VerifyByDID`/`VerifySDJWTByDID`
  (DID-resolved + trust-anchor-gated verification with key-rotation
  support) had zero MCP wiring, and `compose` itself has zero callers
  anywhere. Rather than wire the whole `Composer` (which also bundles CAS
  publishing and webhook notification — deferred as a separate design
  decision), called `didresolver.ResolveAndVerifyAll` directly, reusing
  the `didResolver` already wired for `resolve_did`/`discover_did_services`
  (Axis 108–109). Closes a real gap: `verify_passport`/`verify_sdjwt`
  require the caller to already have the issuer's raw public key; an agent
  previously had to chain `resolve_did` → `verify_passport` manually with
  no trust-anchor concept at all. `Server` gains a `trustAnchor` field
  defaulting to allow-all (same posture as that manual chain) and
  `RegisterTrustAnchor` for operators wanting a real PKI-style
  restriction; new `BLRCS_TRUSTED_DIDS` env var in `cmd/blrcs-mcpd` opts
  into it. 7 new tests, including a dedicated test proving an empty trust
  anchor actually rejects an otherwise-valid signature. `TestToolsList`
  updated (22 → 24).

### Added
- **`mcp`: `discover_did_services` — completes the DID Document read surface
  (Axis 109).** Complements `resolve_did` (Axis 108): a DID Document has two
  halves relevant to this server's callers — verification keys
  (`resolve_did`) and declared service endpoints
  (`didresolver.Resolver.ResolveServices`, e.g. a wallet's credential-offer
  or presentation endpoint) — and only the first half had MCP wiring. Same
  SSRF-hardened fetcher as `resolve_did`; no `TrustAnchor` gating, for the
  same reason `resolve_did` has none. 3 new tests using a mock
  `HTTPFetcher`. `TestToolsList` updated (21 → 22).

### Added
- **`mcp`: `resolve_did` — DID resolution previously reachable from zero
  tools (Axis 108).** `didresolver.Resolver.ResolveAll` (did:web/did:key/
  did:jwk → Ed25519 public key) had zero MCP wiring, leaving no way for an
  agent to go from "I have a DID" to "I have a key to verify against" for
  `verify_passport`/`verify_sdjwt`/`verify_mdoc`, which all require a raw
  base64 public key. Only safe to add now that Axis 107 hardened
  `didresolver`'s default fetcher against SSRF — verified end-to-end that
  `resolve_did` against `did:web:169.254.169.254` (cloud metadata) is
  correctly refused by the real production path. Deliberately does not
  gate on a `TrustAnchor`; the caller decides whether to trust the
  returned key(s), matching how `verify_passport`/`verify_mdoc` already
  work. 4 new tests. `TestToolsList` updated (20 → 21).

### Security
- **`didresolver`: SSRF via direct did:web resolution to private/loopback/
  metadata addresses (Axis 107).** The default did:web fetcher blocked
  *redirects* to a private/loopback/metadata address (`CheckRedirect`
  refuses all 3xx) but had no protection against resolving *directly* to
  one — a DID like `did:web:169.254.169.254` needs no redirect at all.
  This is live and reachable today: `compose.Composer.VerifyByDID`/
  `VerifySDJWTByDID` resolve a credential's issuer DID over the network
  *before* checking the trust anchor (trust is only checked on the
  result), and the issuer DID is exactly the untrusted input from a
  credential being verified. Fixed by mirroring `webhook.Bus`'s existing
  `isBlockedIP`/`safeDialContext` pattern into `didresolver`, wired as
  `defaultClient`'s `Transport.DialContext` — every did:web fetch through
  the default fetcher now validates the resolved IP before connecting.
  Callers needing internal-network did:web resolution keep their existing
  escape hatch: inject a custom `Resolver.HTTPFetcher`. 7 new/updated
  tests, including a dedicated regression test proving the real
  production path now refuses a loopback target it would previously have
  reached successfully.

### Added
- **`mcp`: `build_gs1_link` / `parse_gs1_link` — GS1 Digital Link previously
  reachable from zero tools (Axis 106).** README lists "GS1 Digital Link
  (ISO/IEC 18975) ✅", and `compliance.BuildDLURI`/`ParseDLURI` (GTIN
  validation, serial/batch application identifiers) are fully implemented
  and tested, but had zero MCP wiring — same shape as the `mdoc` gap (Axis
  104), just smaller. Both tools are pure/read-only (no ledger side
  effects), so neither is in `auditableTool`. Verified end-to-end against
  the built `blrcs-mcp` binary: building a link for GTIN
  `04012345678901` with a serial produces
  `https://example.com/01/04012345678901/21/SN-1`. 6 new tests, including
  a build→parse round-trip and confirmation these tools don't grow the
  SCITT ledger. `TestToolsList` updated (18 → 20).

### Added
- **`mcp`, `cmd/blrcs-mcpd`: wire `openid4vp` verifier — closes the last
  major deficiency from the feature-gap review (Axis 105).** README lists
  "OpenID4VP Verifier ✅", and the package's production HTTP integration
  (`AuthorizeHandler`/`CallbackHandler`) was fully implemented and tested,
  but reachable only from `cmd/blrcs-demo` (a throwaway demo binary using a
  demo-specific wrapper), never `cmd/blrcs-mcpd`. Same shape as Axis 103's
  `openid4vci` gap, this time for the verifier side. Added
  `Server.RegisterVPVerifier` + a bounded presentation-results cache (10k
  entries / 15min TTL), a new `create_presentation_request` tool (wraps
  `CreateRequest`; added a JSON-facing `acceptableIssuerKeys` field since
  `PresentationDefinition.AcceptableIssuers` is deliberately `json:"-"`),
  and `get_presentation_result` (retrieves a completed verification by
  state — the agent that created the request has no other way to learn the
  result, since the wallet's response arrives over HTTP outside the MCP
  tool-calling loop). Added an optional `BLRCS_VP_CLIENT_ID` env var to
  `cmd/blrcs-mcpd`: when set, mounts `AuthorizeHandler` at
  `/openid4vp/authorize` and `CallbackHandler` (wired to
  `RecordPresentationResult`) at `/openid4vp/callback` — off by default,
  same reasoning as `BLRCS_VCI_URL`. Verified end-to-end against the built
  `blrcs-mcpd` binary: a `create_presentation_request` tool call returns a
  well-formed `openid4vp://authorize` URL whose `response_uri` correctly
  points at the mounted callback endpoint. 6 new tests, including a full
  lifecycle test using `openid4vp`'s own `MockWallet` test double.
  `TestToolsList` updated for the tool count (16 → 18).

### Added
- **`mcp`: `issue_mdoc` / `verify_mdoc` — ISO 18013-5 previously reachable
  from zero tools (Axis 104).** README lists "ISO 18013-5 mdoc / mDL
  (IssuerSigned + MSO) ✅", and the `mdoc` package is fully implemented and
  tested, but its only caller anywhere was `doctor`'s self-check — no MCP
  tool, no `cmd/` wiring. Added `issue_mdoc` (maps a nested JSON
  `nameSpaces` object to `mdoc.IssueParams`'s `[]Element` form, returns
  base64-encoded IssuerSigned CBOR) and `verify_mdoc` (mirrors
  `verify_passport`'s `{"valid":false,"reason":...}` contract on failure).
  No status/revocation embedding — ISO 18013-5's `IssueParams` has no
  status field and mDLs conventionally use short validity windows rather
  than this server's W3C-style status list, so this doesn't force a
  non-standard extension onto the format. Verified end-to-end against the
  built `blrcs-mcp` binary: issuing an mDL with `family_name`/`given_name`/
  `age_over_18` namespace elements produces valid IssuerSigned CBOR. 7 new
  tests, including a full issue→verify round-trip confirming revealed
  claim values match what was issued. `TestToolsList` updated (14 → 16).

### Added
- **`mcp`, `cmd/blrcs-mcpd`: wire `openid4vci` — reachable from zero
  binaries despite full Axis 90 hardening (Axis 103).** README lists
  "OpenID4VCI Issuer ✅", and `openid4vci` is one of the most heavily
  hardened packages in this codebase (Axis 90's full §7 Nonce Endpoint
  proof-replay mitigation), but it was reachable from zero `cmd/` binaries
  — not even `cmd/blrcs-demo`, which wires `openid4vp`+`dcapi` but never
  imports `openid4vci`. Wallets had no way to reach this protocol from any
  shipped binary. Added `Server.RegisterVCIIssuer` + a new
  `create_credential_offer` MCP tool wrapping
  `openid4vci.Issuer.CreateOfferWithOptions`, drawing from the same shared
  revocation index space as `issue_passport`/`issue_sdjwt`/
  `issue_battery_passport` (`revoke_passport`/`check_revocation` work
  unchanged for VCI-issued credentials). Added an optional `BLRCS_VCI_URL`
  env var to `cmd/blrcs-mcpd`: when set, mounts
  `openid4vci.Issuer.Handler()` (its own `/.well-known/...`, `/token`,
  `/nonce`, `/credential` routes) alongside the existing `/mcp` endpoint.
  Off by default — unlike the MCP tool surface, these are unauthenticated
  endpoints a real wallet talks to directly per spec, so enabling them is
  an explicit operator choice. Not wired into `cmd/blrcs-mcp` (stdio) —
  OpenID4VCI needs a real externally-reachable HTTP base URL for wallets to
  redeem offers against, which a stdio-only process can't provide. Verified
  end-to-end against the built `blrcs-mcpd` binary over its real HTTP
  transport: `GET /.well-known/openid-credential-issuer` returns real
  metadata; a `create_credential_offer` tool call over `POST /mcp` returns
  a redeemable offer; the returned pre-authorized code is successfully
  exchanged against `POST /token` for a real access token. 9 new tests.
  `TestToolsList` updated for the tool count (13 → 14).

### Added
- **`mcp`: `issue_battery_passport` — closes the last major "issue-but-can't-
  issue" gap (Axis 102).** README lists "EU Battery Passport (Reg 2023/1542)
  ✅" as a headline feature, but the MCP tool surface — the primary
  agent-facing interface — had no way to issue one.
  `compliance.BatteryPassportClaim` (25 fields, full Annex XIII coverage)
  and `compliance.IssueBatteryPassport` were fully implemented and tested,
  just never exposed as a tool. Wired `issue_battery_passport` into
  `toolDefs()`/`dispatch()`/`auditableTool`. Added
  `compliance.IssueBatteryPassportWithStatus` (refactored
  `IssueBatteryPassport` into a shared `issueBatteryPassport` helper) so
  Battery Passports embed a `credentialStatus` and draw from the same
  shared revocation index space as `issue_passport`/`issue_sdjwt` —
  `revoke_passport`/`check_revocation`/`get_revocation_list` work unchanged
  for Battery Passports, no new revocation tools needed. Verified
  end-to-end against the built `blrcs-mcp` binary: an EV battery with a
  due-diligence URL produces a signed credential with the `BatteryPassport`
  type marker and an embedded `credentialStatus`. 10 new tests (3
  compliance, 7 mcp) covering the happy path, Art.52 due-diligence
  enforcement, malformed-date rejection, and the full revoke/check
  lifecycle. `TestToolsList` updated for the tool count (12 → 13).

### Fixed
- **`mcp`: `issue_sdjwt` now embeds `status_list` too — closes the same gap
  for the second issuance tool (Axis 101).** Continuing the Socratic-method
  review from Axis 100: since `issue_passport` now embeds a
  `credentialStatus`, the natural next question is whether `issue_sdjwt`
  does the same. It didn't — `toolIssueSDJWT` called `iss.IssueSDJWT` (no
  status), not `IssueSDJWTStatus`, even though `compliance` already has
  that variant fully implemented and tested, plus a purpose-built
  `CheckRevokedToken` verification helper. SD-JWT VCs issued via MCP were
  unrevocable while plain-VC passports (as of Axis 100) were not — an
  inconsistency between the two issuance tools. Since Axis 100 built all
  the hard infrastructure, this fix is small: `toolIssueSDJWT` now
  allocates a status index via the same `s.allocateStatusIndex()` and calls
  `IssueSDJWTStatus`. Both issuance tools draw from the same shared index
  space, so the existing `revoke_passport`/`check_revocation`/
  `get_revocation_list` tools work unchanged for SD-JWT-issued credentials
  too — no new tools needed. Added `statusListIndex` to `issue_sdjwt`'s
  JSON response so callers don't have to decode the JWT payload to find
  their index. 3 new tests, including a full issue→check→revoke→check
  lifecycle for an SD-JWT VC using the shared `revoke_passport` tool.

### Added
- **`mcp`, `storage`: `revoke_passport` / `get_revocation_list` — close the
  issue-but-never-revoke gap (Axis 100).** Socratic-method review of the MCP
  tool surface: `issue_passport` let an agent create trust artifacts, but
  the only revocation-related tool, `check_revocation`, was a stateless
  verifier taking an externally-supplied status list token as input — there
  was no way for the same server that issued a passport to ever revoke it.
  All the underlying building blocks already existed and were tested
  (`revocation.BitstringStatusList`, `compliance.Issuer.IssueWithStatus`,
  `Credential.Status`) — the same "part exists but isn't connected" shape as
  Axis 95-98, just for a whole capability instead of a single fix. Added a
  new optional `storage.BlobStorage` interface (`SaveBlob`/`LoadBlob`,
  checked via type assertion so existing `Storage` implementations don't
  break) implemented for `MemoryStorage`/`FileStorage`/`EncryptedStorage`
  (pass-through). `Server` now owns a server-wide revocation list + a
  persisted next-index counter, restored together on startup (restoring
  only one would let a restarted server reassign an already-used index to a
  new credential). `issue_passport` now embeds a `credentialStatus` into
  every issued passport; new `revoke_passport` tool flips the bit (audited
  on the SCITT ledger, same trust model as `issue_passport`); new
  `get_revocation_list` tool serves a freshly-signed status list token
  directly through the tool surface, since this server may run over stdio
  with no HTTP endpoint to dereference a `statusListCredential` URL from.
  Verified end-to-end against the built `blrcs-mcp` binary over its real
  stdio JSON-RPC transport. 13 new tests, including a restart-persistence
  test backed by real `FileStorage` that verifies both the revoked bit and
  the index counter survive a process restart.

### Documentation
- **README: fix doctor-check-count drift, document `BLRCS_ENCRYPTION_KEY`
  (Axis 99).** "13 subsystems, ~7ms" was stale — `DefaultChecks()` now
  returns 16 (Axis 88 added 3 checks). Verified against the built `blrcs`
  binary: 16/16 passed in 7.6ms. Bumped "1800+ tests · ~24,500 LoC" to
  "1900+ tests · ~25,000 LoC" (verified: 1906 test funcs, 25,054 impl LoC).
  Added a `BLRCS_ENCRYPTION_KEY` quick-start example and an "Encryption at
  rest" row to the feature status table — Axis 96/98 wired this into both
  server binaries but the README never mentioned it.

### Added
- **`cmd/blrcs-mcp`: extend encryption-at-rest to the stdio binary too (Axis
  98).** Axis 96 wired `storage.EncryptedStorage` into `cmd/blrcs-mcpd` (the
  HTTP daemon) via `BLRCS_ENCRYPTION_KEY`. `cmd/blrcs-mcp` — the stdio binary
  used by Claude Desktop / Cursor / VS Code MCP clients, whose own doc
  comment explicitly documents `BLRCS_DATA_DIR` as "永続モード
  (プロダクション)" — had the identical gap: it called
  `storage.NewFileStorage` directly with no encryption option, so any real
  deployment using this binary in persistent mode still wrote DPP/Battery-
  Passport statements to disk in plaintext. Mirrors the `blrcs-mcpd` wiring
  exactly. Verified against the built binary: a truncated key exits 1 with
  a clear error; a valid key logs "encrypted at rest" and starts normally.
  No new tests needed — reuses `storage.EncryptedStorage`/`atrest.NewCipher`,
  already covered by Axis 96.

### Fixed
- **`compose`: `IssueAndPublish` silently swallowed CAS/Provenance/SCITT step
  failures (Axis 97).** The package's flagship "1-call" convenience API runs
  Issue → CAS.Put → Provenance.Record → SCITT sign+register → Webhook. Every
  step after Issue discarded its error on an `if err == nil { ... }` happy
  path with no else branch: a failing `CAS.Put` left `res.Hash` empty, a
  failing `Ledger.Register` left `res.Receipt` nil, and the function still
  returned `(res, nil)` — indistinguishable from "CAS/Ledger not configured"
  (both are documented optional/nil-to-skip fields). For a compliance system
  whose value proposition is the SCITT audit trail, a silently failed
  registration is a real integrity gap: the caller has no signal the
  passport was issued but never actually logged. (Found while investigating
  why `blrcs/saga` — built for exactly "Issue→CAS→SCITT→Webhook 失敗時
  partial state" per its own doc — is never imported anywhere; its rollback
  model doesn't obviously fit here since SCITT/CAS are append-only/
  idempotent, not resources you compensate, so the narrower fix is to stop
  hiding the failure rather than force-fit saga.) Added
  `IssuanceResult.StepFailures []error`, populated for each non-fatal step
  that fails after Issue succeeds, plus telemetry failure counters
  (`compose.cas.failed`/`provenance.failed`/`scitt.failed`). Backward
  compatible — Issue's own failure still returns a non-nil error as before;
  existing callers ignoring the new field see identical behavior. 3 new
  tests, including a real (non-mocked) `ErrUntrustedIssuer` SCITT rejection.

### Added
- **`storage`, `cmd/blrcs-mcpd`: wire `atrest` encryption-at-rest into the
  daemon — previously fully disconnected (security, Axis 96).**
  `atrest/atrest.go`'s own package doc states its purpose: "解決する短所:
  Storage encryption at rest無 — FileStorage は平文 (PII/機密含む可能性)".
  But nothing in the codebase imported `blrcs/atrest` outside its own test
  file — the package was fully implemented and tested in isolation, and
  never wired to `storage.FileStorage` or any `cmd/` entrypoint. Every
  persisted DPP/Battery-Passport statement (product IDs, supplier names,
  sensor readings) was written to disk in plaintext, protected only by
  filesystem permissions. Same shape of gap as Axis 95 — a hardening feature
  that exists but was never connected to the real code path. Added
  `storage.EncryptedStorage`, a `Storage` decorator that encrypts/decrypts
  `StatementBlob` via a small `BlobCipher` interface (satisfied by both
  `atrest.Cipher` and `atrest.Keyring`, keeping `storage` decoupled from the
  encryption implementation); scoped to the statement log only — the TS
  signing keypair passes through unchanged since it's a bootstrapping secret
  that belongs to an external KMS/HSM per `atrest`'s own design. Added an
  optional `BLRCS_ENCRYPTION_KEY` env var (64 hex chars = 32 bytes) to
  `cmd/blrcs-mcpd`: when set, wraps the persisted storage in
  `EncryptedStorage` before handing it to the server; a malformed key
  `fatal()`s at startup like the existing fail-fast env vars. Off by
  default — fully backward compatible. Verified against the built binary
  (malformed key → exit 1; valid key → "encrypted at rest" log line + normal
  startup). 4 new integration tests against the real `atrest.Cipher`,
  including one that asserts the plaintext never reaches the underlying
  unwrapped store.

### Fixed
- **`cmd/blrcs-mcpd`: production daemon bypassed the hardened auth-token parser
  (security, Axis 95).** The actual HTTP daemon entrypoint never imported the
  `config` package — it read `BLRCS_AUTH_TOKENS` directly and parsed it with a
  hand-rolled, unhardened `parseTokens()` that silently skipped malformed
  pairs (missing `:`, empty principal) and let duplicate tokens silently
  overwrite each other (last-wins), instead of failing startup. This is
  exactly the vulnerability Axis 89 fixed in `config.parseTokens` — an
  empty-principal token is a session-hijack risk since sessions are bound to
  their principal — but that fix lived in a package the real daemon never
  called, so it never reached production. Exported `config.ParseTokens` and
  wired `cmd/blrcs-mcpd/main.go` to use it, `fatal()`-ing on error like the
  existing `BLRCS_RATE_LIMIT_RPS` fail-fast path; deleted the dead local
  copy. Verified against the built binary:
  `BLRCS_AUTH_TOKENS="tokA:,tokB:admin"` now exits 1 with a clear error
  instead of silently starting; valid tokens still work end-to-end. No other
  `cmd/` entrypoint had this pattern. 1 new test: `TestParseTokensExported`.

### Testing
- **`openid4vci`, `didresolver`: close coverage gaps in nonce-mismatch and
  key-hash pinning paths (Axis 94).** A fresh sweep of the remaining unaudited
  packages (`httpmw`, `didresolver`, `mdoc`, `conformance`, `capability`,
  `builder`, `compose`, `telemetry`, `metrics`, `i18n`, `apispec`, `openapi`)
  found no new exploitable bugs — existing defenses (rate limiting, SSRF
  guards, constant-time comparison, bounded caches) hold up. Coverage analysis
  found two security-relevant functions under-tested: `verifyProofJWT`'s
  nonce-match success path and `ErrProofNonceMismatch` rejection path (the
  actual anti-replay check) were never exercised (only its parse-error
  branches were); `TrustAnchor.AddKeyHash` (Ed25519 key pinning by SHA-256 hex
  digest) was at 0% coverage. Both were correct on inspection — this closes
  the verification gap with 5 new tests, no production code changed.

### Fixed
- **`jsonschema`: bound `uniqueItems` DoS + add `deepEqual` depth cap (security,
  Axis 91).** `uniqueItems` validation ran an O(N²) loop of `deepEqual()` calls with
  no accounting against the shared `maxValidateOps` budget. An adversarial Type
  Metadata schema with `uniqueItems:true` on an array keyword could force the
  validator into O(N²×depth) CPU work while the complexity budget remained at zero.
  Fix: each pair comparison now increments `*v.ops` and returns early when the budget
  is exhausted (`ErrComplexityBudget`). Additionally `deepEqual` now takes an explicit
  depth parameter (`maxDeepEqualDepth=64`) and returns `false` at the limit rather
  than recursing unboundedly into arbitrarily-nested credential claim values.  5 new
  tests: `TestUniqueItemsBudgetCapped`, `TestUniqueItemsDepthCapNoPanic`,
  `TestDeepEqualDepthZeroReturnsFalse`, `TestUniqueItemsSmallArrayUnique/Duplicate`.

- **`scitt`: add `maxStatementPayloadBytes` cap in `SignStatement` (Axis 92).**
  `SignStatement` accepted any payload length, performing a full SHA-256 over an
  unbounded byte slice. An authenticated-but-misbehaving issuer could submit a
  gigabyte payload, stalling the call for seconds and exhausting ledger storage.
  Added `maxStatementPayloadBytes = 1 MiB` constant and `ErrPayloadTooLarge` sentinel;
  payload is rejected before SHA-256 and before any ledger write. 2 new tests:
  `TestSignStatementOversizedPayload`, `TestSignStatementAtLimitPayload`.

- **`revocation`: add upper-bound guard in `NewBitstringStatusList` (Axis 93).**
  `NewBitstringStatusList` accepted any positive `sizeBits`, so a caller could pass
  `sizeBits = 2^31` and trigger a ~256 MiB allocation (or integer overflow on 32-bit
  platforms in `(sizeBits+7)/8`). Added `maxBitstringBits = 512 Mi-entries` (64 MiB
  of bits, matching `maxDecodedListBytes` to keep the allocator and the decompression
  cap consistent) — `NewBitstringStatusList` returns `nil` for oversized requests.  2
  new tests: `TestNewBitstringStatusListOversizeReturnsNil`,
  `TestNewBitstringStatusListAtMaxAllowed`.

### Added
- **`openid4vci`: OpenID4VCI §7 Nonce Endpoint — proof-replay mitigation (security,
  Axis 90).** Informed by deep-research into the Proof Replay attack on OID4VCI key
  proofs (Takahiko Kawasaki, Qiita): the spec's own countermeasure is a dedicated
  Nonce Endpoint that issues unpredictable, server-bound, **single-use** `c_nonce`
  values, decoupled from the token response so every credential request can be
  bound to a fresh challenge. Added `POST {issuer}/nonce` (`Issuer.handleNonce`)
  returning a non-cacheable `{c_nonce, c_nonce_expires_in}`, backed by
  `Issuer.IssueNonce()` (bounded store, capped at `maxNonces`=50k with opportunistic
  expiry sweep + `ErrNonceStoreFull` backpressure) and `consumeNonce()` (delete-
  before-expiry-check → strictly one-shot, no replay). The credential endpoint now
  accepts a proof whose `nonce` is **either** the token-bound `c_nonce` (legacy,
  unchanged) **or** a Nonce Endpoint nonce, which is consumed on use. Refactored the
  proof verifier into a nonce-agnostic `parseProofJWT` (returns the embedded nonce)
  with `verifyProofJWT` kept as a thin token-bound wrapper for backward compat
  (existing tests/fuzz unaffected). `nonce_endpoint` is now advertised in issuer
  metadata. The existing replay defenses (aud binding, iat freshness, single-use
  access token) are unchanged; Ed25519 verification uses Go's stdlib (cofactorless,
  no malleability), so the insecure-Ed25519 implementation pitfalls from the
  research do not apply. 5 new tests: fresh/single-use issuance, end-to-end §7
  acceptance, replay rejection, HTTP handler (405/200/no-store), metadata.

### Fixed
- **`config.parseTokens`: reject empty principal and duplicate tokens (security,
  Axis 89).** `BLRCS_AUTH_TOKENS` is parsed as `token:principal` pairs. The parser
  rejected an empty *token* but accepted an empty *principal* (e.g. the typo
  `"tokA:,tokB:admin"`) and silently last-wins on duplicate tokens. Empty principals
  are a real security footgun: the MCP server binds each session to its principal
  and blocks cross-principal reuse by *comparing* principals — so two tokens both
  authenticating to `""` could hijack each other's sessions, defeating that binding.
  `parseTokens` now returns a startup error for an empty principal or a repeated
  token, consistent with the package's documented "catch misconfiguration at
  startup" contract. A principal containing a colon (`tok:realm:alice`) is still
  accepted (SplitN keeps it). 4 new test cases.

### Added
- **`doctor`: add revocation + mdoc subsystem self-checks (Axis 88).** The doctor's
  stated purpose is to exercise *all* features as a pre-deploy/startup sanity check
  ("全機能を実走行"), but the default suite covered only compliance, SCITT, storage,
  and telemetry — leaving two core, security-critical subsystems unverified at
  startup: credential revocation and ISO 18013-5 mdoc device authentication. A
  deployment could boot "green" while its revocation or mdoc paths were broken.
  Added three checks: `revocation.SignedListRoundTrip` (revoke → IsRevoked → sign →
  verify, plus wrong-key rejection), `revocation.BitstringStatusList` (W3C bitstring
  set/get + gzip encode/decode round-trip), and `mdoc.DeviceAuthRoundTrip`
  (issue with device key → present with device auth → VerifyDocument, asserting
  selective disclosure holds, undisclosed claims do not leak, and a replay under a
  different session transcript is rejected). Default suite grows from 13 to 16
  checks. 4 new tests.

- **`cas.GetVerified` + read-path integrity check in `Provenance.LookupByID`
  (security, Axis 87).** The package's sole invariant is `hash(content) == address`
  and its `Store` interface is explicitly pluggable ("backend 差替可能"), yet the
  exported `Verify(payload, h)` function was never used on the retrieval path:
  `Provenance.LookupByID` returned `store.Get(h)` bytes without checking they hash
  to `h`. With the in-memory store this is benign, but the moment a real backend is
  swapped in (file/network/object-store), disk bitrot, a tampered object, or a
  buggy cache would silently hand back wrong content for an audit-trail lookup —
  defeating the entire point of content-addressed storage. Added
  `GetVerified(store, h)` which fetches then enforces the content-address contract,
  returning the new sentinel `ErrCorrupted` on mismatch (backend `Get` errors such
  as `ErrNotFound` propagate unchanged). Wired `Provenance.LookupByID` to use it so
  the SCITT-receipt→payload reverse lookup is integrity-checked end to end. The bare
  `Store.Get` is unchanged (backward compatible). 4 new tests: happy path,
  corruption detected via `ErrCorrupted`, `ErrNotFound` propagation, and
  `LookupByID` against a corrupting backend.

- **Test coverage uplift: `openid4vp`, `mdoc/deviceauth`, `MemoryStore.GC` (quality
  hardening).** Addressed three coverage clusters surfaced by `go tool cover -func`:
  (1) `openid4vp/jar.go` — `VerifyRequestObject` expired-JAR rejection and bad
  verifier-key paths were untested (regression risk for the JAR anti-replay
  property); `signRequestObject` bad-private-key path untested. Added 3 new tests:
  expired JAR (past `exp` + 60s leeway) rejected, zero-length verifier key
  rejected, zero-length private key returns `ErrRequestObjectInvalid`.
  (2) `openid4vp/openid4vp.go` — `MemoryStore.gcLoop` was at 45.5% because the
  periodic eviction sweep fires every 5 minutes (untestable in unit tests). Extracted
  a public `MemoryStore.GC()` method that `gcLoop` now delegates to; added 2 direct
  tests verifying expired entries are swept and live entries survive. `gcLoop` now
  83.3%; `GC()` 100%.
  (3) `mdoc/deviceauth.go` — `VerifyDocument` had untested error branches for
  malformed document structures: missing `issuerSigned` field, `deviceAuth` value
  with wrong type (string instead of map), `deviceAuth` map with no
  `deviceSignature` key, and `PresentWithDeviceAuth` with invalid input. Added 4
  new tests; `VerifyDocument` 76.3%→84.2%, overall `mdoc` 92.6%→93.8%.
  Cumulative: `openid4vp` 93.1%→94.7%.

- **`mcp.TokenBucketLimiter`: self-bounding bucket map + `GC` (security,
  Axis 86).** The per-principal rate limiter that guards the MCP HTTP server kept
  one `*bucket` per distinct principal and never evicted any — unlike its sibling
  `httpmw.RateLimiter`, which has `GC`/`StartGC`. When a deployment's
  `AuthVerifier` derives `principal` from a client-supplied or per-tenant
  identifier, an attacker can mint unbounded principals and exhaust memory through
  the very component meant to *prevent* DoS. Closed the gap by making the map
  self-bounding with zero operator action: `Allow` now caps the map at
  `defaultMaxBuckets` (100k) and, on reaching the cap, opportunistically evicts
  fully-refilled buckets (a bucket refilled to `burst` carries no live throttle
  state, so eviction is lossless). Added a `GC(ttl)` method mirroring
  `httpmw.RateLimiter.GC` for callers wanting eager reclamation. 3 new tests:
  self-bounding under cap, eviction preserves still-throttled buckets, and `GC`
  drops stale entries.

- **`openid4vp.DCQLQuery.Validate`: structural complexity bounds to prevent
  DCQL-driven DoS (security, Axis 85).** `MatchClaims` performs
  O(credentials × claims × path depth × values) work per `ProcessResponse` call,
  driven entirely by the `dcql_query` parameter in the Authorization Request.
  `Validate()` (called by `ParseDCQL` and `MarshalDCQL`) previously checked
  structural rules (IDs, formats, credential_set references) but imposed no upper
  bound on any fanout dimension. A crafted query with
  `{credentials: [32768 × {claims: [32768 × {path: [1024 segments], values: [1024]}]}]}`
  forces O(10⁹+) iterations in a single `ProcessResponse`, enabling server DoS via
  one Authorization Request. Closed the gap by adding four constants:
  `dcqlMaxCredentials=32`, `dcqlMaxClaims=64`, `dcqlMaxPathDepth=16`,
  `dcqlMaxValuesPerClaim=32` — all generous enough for any real credential scenario
  and enforced in `Validate()`. Violations return the new sentinel
  `ErrDCQLQueryTooComplex` (wrapping details for diagnosis). 7 new tests:
  over-limit credentials, exactly-at-limit credentials (boundary), over-limit
  claims, path-too-deep, over-limit values, all-at-limits happy path, and
  `ParseDCQL` rejection of oversized JSON.

- **`scitt.Ledger.RegisterTrustedIssuer`: trusted-issuer allowlist for the
  transparency log (security, Axis 84).** `Ledger.Register` previously called
  `VerifyStatement`, which only proves the signature is consistent with the
  statement's embedded `IssuerKey` — it does NOT prove the embedded key belongs
  to the entity named in the `Issuer` field. Anyone could call `SignStatement`
  with their own Ed25519 key, set `Issuer = "did:web:certified-lab.eu"`, and
  pass `Register` unchallenged: the signature is valid against their key, which
  they also embed. The result is attestation forgery — a certified-looking entry
  from an authority the attacker does not control. Added
  `Ledger.RegisterTrustedIssuer(issuerID string, pub ed25519.PublicKey)`: once
  at least one entry is registered, `Register` enforces that the statement's
  `Issuer` is present in the allowlist AND its embedded `IssuerKey` matches the
  registered key (compared via `subtle.ConstantTimeCompare`). Mismatch returns
  `ErrUntrustedIssuer`. When no trusted issuers are registered the ledger
  remains in open mode (backward-compatible with existing tests and single-party
  deployments). 4 new tests: open-policy backward-compat; unknown-issuer
  rejected; wrong-key-for-known-issuer rejected; happy-path trusted acceptance.

- **`vctmeta.ResolveChain`: require `extends#integrity` on every hop (security,
  Axis 83).** SD-JWT-VC Type Metadata documents may declare an `extends` parent
  URL and an optional `extends#integrity` SRI hash. Previously `ResolveChain`
  treated `extends#integrity` as genuinely optional and fetched parent nodes
  without integrity verification when the field was absent — only the leaf's
  `vct#integrity` was ever checked. This meant the credential's SRI pin protected
  only the leaf document; any intermediate node could be silently substituted by a
  CDN misconfiguration, DNS cache poisoning, or on-path attacker without breaking
  the leaf's cryptographic binding. Closed the gap by requiring `extends#integrity`
  at every link in the chain. `ResolveChain` now returns the new sentinel
  `ErrExtendsIntegrityRequired` (wrapping the offending node's VCT and extends
  URL for diagnosis) when a node has an `extends` link but no `extends#integrity`.
  The integrity value itself is still verified by the existing `VerifyIntegrity`
  path (wrong hash → `ErrIntegrityMismatch`). Single-node chains (no `extends`)
  and chains with proper `extends#integrity` at every hop are unaffected. Note:
  a genuine `extends` cycle cannot carry consistent integrity hashes (circular
  hash dependency), so cycles now surface as `ErrExtendsIntegrityRequired` rather
  than `ErrExtendsCycle`; `TestResolveChainCycle` updated to accept either error.
  2 new tests: `TestResolveChainMissingExtendsIntegrity` and
  `TestResolveChainExtendsIntegrityMismatch`; 3 existing chain tests updated to
  use the new `chainFetcherWithIntegrity` helper.
- **`compliance.VerifyOptions.AllowedAlgs`: per-verification JWS algorithm
  allowlist — crypto-agility downgrade defense (security, Axis 82).** The JWS
  verifier registry (`RegisterJWSVerifier`) lets a deployment add post-quantum
  algorithms (e.g. ML-DSA) without bundling them — but it introduced a downgrade
  risk: once a second algorithm is registered globally, **every**
  `VerifySDJWT*` call accepts **either** algorithm, collapsing deployment
  security to the weakest registered algorithm. An attacker who breaks (or has
  precomputed against) the legacy algorithm can still present a legacy-signed
  credential and the verifier accepts it, because that algorithm remains in the
  global registry. Closed the gap with `VerifyOptions.AllowedAlgs []string`:
  when non-empty, the issuer JWS `alg` must be a member, checked **before** the
  registry lookup so an excluded-but-registered algorithm is rejected as a
  policy violation (new sentinel `ErrSDJWTAlgNotAllowed`) rather than a
  capability gap (`ErrSDJWTUnsupportedAlg`). Empty/nil = accept any registered
  algorithm (backward-compatible — `VerifySDJWT`, `VerifySDJWTAt`, and all
  existing callers are unaffected). A post-quantum deployment can now pin
  `AllowedAlgs: []string{"ML-DSA"}`; a legacy verifier can pin
  `["EdDSA"]`. Also surfaced end-to-end via the new
  `openid4vp.Verifier.AllowedAlgs` field, which passes straight through to
  `compliance.VerifyOptions` in `ProcessResponse`. 3 new tests covering: empty
  allowlist accepts; explicit EdDSA allowlist accepts; ML-DSA-only allowlist
  rejects an EdDSA credential with `ErrSDJWTAlgNotAllowed`; multi-alg allowlist
  accepts; and the policy-before-capability ordering.
- **`conformance.ReferenceSuite`: three SD-JWT negative test vectors (security,
  Axis 81).** The reference conformance suite had one SD-JWT test vector
  (`sdjwt/basic-issue-verify`) — a positive "happy path" case. Third-party
  implementations that pass only positive vectors could still accept tokens that
  must be rejected (wrong key, malformed structure, truncated signature), making
  their conformance claims misleading. Added three negative vectors under the
  `"negative","security"` tags, all with `"verifyOK": false`:
  1. `sdjwt/wrong-issuer-key-rejected` — a legitimately-issued SD-JWT verified
     against a different key must be rejected. Uses the new `wrongKeyHex` input
     field (an alternate Ed25519 seed) to supply the wrong public key to the
     runner.
  2. `sdjwt/malformed-token-rejected` — a token whose structure is not valid
     base64url JWS (no decodable header/payload) must be rejected. Uses the new
     `rawToken` input field to bypass issuance and verify a pre-crafted string.
  3. `sdjwt/truncated-signature-rejected` — a syntactically 3-part JWT
     (header.payload.sig) whose signature bytes are corrupt must be rejected.
  Both `wrongKeyHex` and `rawToken` are backward-compatible additions to
  `sdjwtIn` (`omitempty`); existing positive vectors are unaffected.
  `TestReferenceSuiteAllPass` confirms all 3 new vectors pass the runner.

### Fixed
- **`kms.ExternalSigner`: data race between `Sign()` and `Close()` (safety,
  Axis 80).** `Close()` wrote `e.signFn = nil` without a lock; `Sign()` read
  `e.signFn` and then called it without a lock. Two goroutines — one signing,
  one closing — could race: `Sign()` sees a non-nil `e.signFn`, passes the nil
  guard, then reads it again to call it (Go loads the value at the call site)
  while `Close()` simultaneously zeroes it. The Go race detector catches this.
  `FileSigner.Sign` and `FileSigner.Close` already use `f.mu sync.Mutex` for
  exactly this pattern; `ExternalSigner` was missing equivalent protection.
  Fixed by adding `mu sync.RWMutex` to `ExternalSigner`: `Sign()` copies the
  function pointer under `RLock()` before releasing it (so the function is
  called outside the lock, avoiding holding the lock across a potentially
  long-running external KMS call); `Close()` zeroes both `signFn` and `closer`
  under the write `Lock()`. Added `TestExternalSignerConcurrentSignClose` with
  50 goroutines alternating Sign/Close — passes cleanly under `-race`.
- **`saga.Run`: concurrent calls on the same State cause step interleaving
  (correctness/safety, Axis 79).** The `State` struct is designed to be shared
  *among steps within a single Run* so that each step can read the previous
  step's outputs. But nothing prevented two goroutines from calling `Run()` on
  the same `State` concurrently. Both would see each other's in-flight `Set`
  calls, re-execute idempotency-sensitive operations (credential issuance,
  CAS write, SCITT registration), and produce inconsistent intermediate state
  — while the per-operation `sync.RWMutex` inside `State` only protected
  individual `Get`/`Set` calls, not the run lifecycle. Added a `runMu
  sync.Mutex` field to `State`; `Run()` calls `state.runMu.TryLock()` at the
  start and returns the new `ErrAlreadyRunning` sentinel immediately if another
  goroutine is already inside `Run()` on the same state. The mutex is deferred-
  unlocked on return, so sequential calls after a completed (or failed) run
  succeed normally. Added `TestConcurrentRunReturnErrAlreadyRunning` which
  uses a blocking step to hold the first run inside a step while a second
  goroutine attempts to start — the second must get `ErrAlreadyRunning`; the
  first must complete successfully after release; and a subsequent sequential
  run on the same state must also succeed.
- **`jsonschema`: unbounded allOf/anyOf/oneOf branch arrays — DoS via
  combinator explosion (security, Axis 78).** `Validate` had a global
  `maxValidateOps` budget but no per-combinator array length cap. An
  adversarial externally-fetched Type Metadata schema (via `vctmeta`) could
  provide an `allOf`/`anyOf`/`oneOf` with thousands of sub-schemas: each
  sub-schema is `true` (O(1) per branch) but the total work is O(branches) ×
  O(depth) — the budget is not exceeded until many iterations later. Added
  `maxCombinatorBranches = 32` constant and a length check at the start of
  each combinator path in `checkCombinators`. Schemas exceeding the limit
  abort early and return the new sentinel `ErrTooManyCombinatorBranches`
  (rather than a `ValidationError`, which is a schema-instance mismatch — not
  a resource-exhaustion signal). Also propagated the shared `tooManyBranches`
  flag through all child validator instantiations (`checkArray.contains`,
  `checkCombinators` child validators) so nested combinators are also bounded.
  4 new tests: allOf/anyOf/oneOf each with branches+1 return the sentinel;
  a combinator at exactly the limit passes through.
- **`didwebvh.Verify`: entries after deactivation silently accepted — DID
  lifecycle bypass (security, Axis 77).** `Verify` tracked `deactivated=true`
  after an entry with `Parameters.Deactivated=true` but then continued the
  loop, fully verifying any subsequent entries. An attacker who captured the
  current update key at the moment of deactivation could append a valid entry
  (signed by that still-valid key) to un-deactivate or hijack the DID
  post-mortem — exactly the scenario that the terminal deactivation state is
  meant to prevent. Fixed by adding a guard at the start of each loop
  iteration (after version sequence parsing): if `deactivated` is already
  `true` (set by a previous entry), the current entry is rejected with
  `ErrDeactivated` immediately. The deactivation entry itself continues to
  pass; only subsequent entries are blocked. Added
  `TestPostDeactivationEntryRejected` which builds a 3-entry log
  (genesis → deactivation → post-deactivation update) and verifies the
  third entry is rejected, while the 2-entry log (genesis + deactivation)
  still resolves correctly with `Deactivated=true`.

### Added
- **`integration.TestBearerCredentialRejectedByKeyBindingVerifier`: cross-
  package security contract test (security, Axis 76).** The compliance between
  `openid4vci` bearer issuance and `openid4vp` key-binding enforcement had no
  integration-level test. A bearer SD-JWT (issued without proof-of-possession,
  no `cnf` claim) should be cryptographically rejected by any verifier running
  `RequireKeyBinding=true` — but neither package alone could prove the composed
  behavior. Added a test that: (1) issues a bearer credential via VCI with
  `RequireProof=false`; (2) confirms it verifies in permissive mode (sanity);
  (3) presents it to a verifier with `RequireKeyBinding=true` (the default);
  (4) asserts the verifier returns an error. This validates the secure-by-
  default contract: a bearer token can never satisfy a key-binding verifier
  because it carries no `cnf` holder key and no KB-JWT suffix.
- **`multiformats.ParseMultihashSHA256`: codec-enforcing wrapper for
  SHA-256-only callers (security, Axis 75).** `ParseMultihash` returns the
  raw codec byte without validating its value. A caller using it to verify
  supply-chain integrity (e.g. DID:webvh `entryHash`, SCITT receipt digests)
  would accept a multihash with codec `0x11` (SHA-1) or `0x14` (SHA-512)
  without realizing the algorithm changed — a hash-algorithm-substitution
  attack where an attacker presents a collision-weak digest. Added
  `ParseMultihashSHA256(mh []byte) (digest []byte, err error)` which enforces
  `codec == 0x12` and `len(digest) == 32`, returning `ErrUnsupportedCodec`
  for any other codec. `ParseMultihash` is unchanged (backward-compat).
  3 new tests: happy path, wrong-codec rejection, short-digest rejection.

### Fixed
- **`compose.IssueAndPublish`: silently discarded `json.Marshal` error on
  credential bytes (correctness, Axis 74).** The call `credBytes, _ :=
  json.Marshal(cred)` discarded the error, so if the `Credential` struct ever
  gains a non-JSON-serializable field (function, channel, circular reference),
  the error would be swallowed and `credBytes` would be `nil` or empty.
  All downstream operations (CAS.Put, Provenance.Record, SCITT.Register) would
  then silently receive empty bytes — storing a provenance record that points to
  a zero-byte content hash, breaking supply-chain integrity without any visible
  error. Fixed by propagating the error: `credBytes, err := json.Marshal(cred);
  if err != nil { return nil, fmt.Errorf("compose: marshal credential: %w", err) }`.
- **`openid4vci` credential endpoint returned 500 for `ErrFormatMismatch`
  instead of 400 (correctness, Axis 73).** The HTTP handler `handleCredential`
  had a `switch` statement mapping errors to HTTP status codes. `ErrFormatMismatch`
  (added in Axis 69) was not included in the switch, so it fell into the `default`
  branch and returned 500 Internal Server Error. A format or configuration-id
  mismatch is a client error (400 Bad Request), not a server error — returning 500
  violates RFC 6749 §5.2 and OpenID4VCI §6.3. Added explicit case returning 400
  `invalid_request`. Added 2 HTTP-level tests: format mismatch → 400 and
  configuration-id mismatch → 400 (both confirmed to return the error code
  `invalid_request`).

### Added
- **`tlsharden.Modern`: disable session tickets by default and prefer X25519
  first (security, Axis 72).** `Modern()` returned a `tls.Config` with session
  tickets enabled (the Go default). In multi-instance deployments each process
  generates independent session-ticket keys: a ticket issued by instance A is
  rejected by instance B (different key), causing a spurious full handshake.
  Enabling tickets across instances without a shared key-rotation scheme also
  breaks TLS session resumption entirely. The code comment already said "Disable
  session tickets in cluster scenarios where keys aren't shared" but the code
  didn't set `SessionTicketsDisabled: true`. Fixed — callers running a single-
  instance server can re-enable with `cfg.SessionTicketsDisabled = false`.
  Also reordered `CurvePreferences` to list X25519 first (was P-256 first): X25519
  is faster, has no timing side-channel, and is the IETF-recommended preference.
  `Strict()` already had X25519 first — `Modern()` now matches. `MutualTLS()`,
  which inherits from `Modern()`, is updated transitively. 3 new tests.
- **`mdoc.Verify`: reject duplicate `elementIdentifier` within a namespace
  (security/correctness, Axis 71).** Two `IssuerSignedItem` entries in the same
  namespace could share the same `elementIdentifier` while carrying distinct
  `digestID`s and valid SHA-256 digests — both pass verification independently,
  but the second silently overwrites the first in the output map, hiding a
  collision from the caller's audit trail and potentially misrepresenting which
  value was actually disclosed. Added a uniqueness check (`if _, exists :=
  out[id]`) that returns the new `ErrDuplicateElement` sentinel on collision.
  Also wired `VerifyOptions.ExpectedIssuer = claimedIss` in
  `openid4vp.ProcessResponse` (replacing the post-hoc `&& vc.Issuer == claimedIss`
  check) so issuer binding is enforced inside the cryptographic verification
  path rather than as a separate string comparison — defense-in-depth.
  2 new mdoc tests: duplicate-element rejection and normal-round-trip still
  passes.
- **`webhook`: `Bus.RequireSecret` and `SubscribeSecure` — enforce HMAC secret
  (security, Axis 70).** `deliverOnce` silently skipped HMAC signing when a
  subscriber had no `Secret` (the `if len(s.Secret) > 0` guard). The receiver-
  side `VerifyRequest` correctly rejected empty secrets, but the sender gave no
  indication that delivery was unsigned — a misconfigured subscriber receives
  unsigned webhooks indefinitely without any error. Added two complementary
  mechanisms: (1) `Bus.RequireSecret bool` (default false, backward-compatible):
  when true, `deliverOnce` returns `ErrEmptySecret` immediately if the subscriber
  has no secret, making unsigned delivery an explicit error at delivery time
  rather than a silent security omission. (2) `SubscribeSecure(eventType,
  Subscriber) error`: a secure-by-default registration helper that validates non-
  empty `Secret` and `URL` at registration time and returns `ErrEmptySecret` /
  URL error before the subscriber is added, catching the misconfiguration as
  early as possible. `Subscribe` is unchanged (backward-compatible). 6 new tests.
- **`openid4vci`: credential format/configuration-id mismatch validation
  (security/correctness, Axis 69).** `IssueCredentialWithProof` ignored
  `req.Format` and `req.CredentialConfigurationID` from the wallet's credential
  request entirely — the issuer always issued from the pre-auth offer's
  `configID` regardless of what the wallet asked for. This allows
  credential-format-confusion attacks: a wallet can request a different format
  or configuration than the one the issuer registered, and the issuer silently
  issues its own version without any signal to either party that the request was
  malformed. Fixed by adding early validation (still under the mutex, before
  `consumed=true` so no rollback is needed): non-empty `req.CredentialConfigurationID`
  must equal `entry.configID`; non-empty `req.Format` must equal `cfg.Format`.
  Mismatches return the new `ErrFormatMismatch` sentinel without consuming the
  access token so the wallet may retry with the correct values. Empty fields
  continue to succeed (backward-compatible). 4 new tests: wrong format rejected,
  wrong config-id rejected, matching values pass (and empty fields pass), and
  token-not-consumed-on-mismatch (retry succeeds).
- **`httpmw.MaxBodyBytes` middleware — request body size cap (DoS defense, Axis
  68).** The default middleware chain (`Recovery → RequestID → SecurityHeaders →
  AccessLog`) applied no per-request body limit; handlers using `io.ReadAll` or
  `json.Decode` on the request body were vulnerable to DoS via unbounded memory
  allocation (a client streams a multi-GB body, the handler allocates it all).
  Added `MaxBodyBytes(limit int64) Middleware` which wraps the request body with
  `http.MaxBytesReader`, causing reads past the limit to return an error and
  optionally write 413 Request Entity Too Large before the inner handler is
  invoked. Pass limit≤0 to disable (not recommended). 3 new tests cover:
  over-limit body triggers read error, small body passes through, limit=0
  disables the cap.

### Fixed
- **`httpmw.clientIP` accepted non-IP strings from X-Forwarded-For / X-Real-IP
  — rate-limit bypass and log forgery (security, Axis 68).** When
  `TrustProxyHeaders=true`, the extracted header candidate was returned
  as-is without validating it is a parseable IP. An attacker could send
  `X-Forwarded-For: BYPASS_ME` to get a unique rate-limit key per string
  ("BYPASS_ME"), evading per-IP rate limiting. Added `net.ParseIP` validation:
  invalid candidates are silently ignored and the code falls through to
  `r.RemoteAddr`. Valid IPv4/IPv6 and comma-separated lists (first IP taken)
  still work correctly. 1 new test covering invalid XFF, invalid X-Real-IP,
  and valid multi-hop XFF.
- **`openid4vci.randomB64` silently discarded CSPRNG errors — weak tokens on
  entropy failure (security, Axis 67).** The same `_, _ = rand.Read(b)`
  pattern fixed in `openid4vp` (Axis 60) existed independently in
  `openid4vci`. Changed to return `(string, error)`; 4 callers (`CreateOffer`,
  `ExchangeCodeWithTxCode` ×2, c_nonce rotation) propagate the error.
- **`storage.FileStorage.AppendStatement` partial-write recovery via pre-write
  Stat + Truncate-on-failure (durability, Axis 66).** On disk full or an OS
  write error mid-frame, the previous implementation left a torn frame at the
  end of the ledger (partial header or partial payload), causing `rescanSize` to
  return `ErrCorrupted` on the next startup with no way to recover without
  manual truncation. Fixed by recording the file offset via `Stat()` before
  each write and, on a short write or write error, truncating the file back to
  that offset before returning the error — keeping the log parseable and
  allowing subsequent successful appends. Two new tests: exact-frame-size
  growth (verifies `Stat` gives the correct pre-write offset), and
  torn-frame-detection (directly injects a partial header and confirms reopen
  returns `ErrCorrupted`).
- **`kms.EncryptedFileSigner` — AES-256-GCM at-rest key protection for file-
  persisted signers (security, Axis 65).** `NewFileSigner` stores the Ed25519
  private key as 96 raw bytes protected only by filesystem `0600` permissions;
  a root-level attacker or backup leak exposes the key in plaintext, violating
  FIPS 140-2 and SOC2 Type II requirements. Added `NewEncryptedFileSigner(id,
  path, masterKey)` which wraps the same `FileSigner` type but stores the key
  as `[12-byte GCM nonce][AES-256-GCM ciphertext + 16-byte auth tag]` (108
  bytes total, vs. 96 for plaintext). The 12-byte nonce is re-randomized on
  every save (new key generation; existing keys don't rotate nonce except on
  explicit re-save). Added `GenerateMasterKey() ([]byte, error)` for a
  cryptographically random 32-byte AES-256 key. The two file formats are
  distinguished by size: opening a plaintext file as encrypted (or vice versa)
  returns an immediate error rather than silently misinterpreting bytes. 5 new
  tests cover: round-trip persist/reload, wrong-master-key (GCM auth failure),
  bad key length, plaintext-file-as-encrypted rejection, and `GenerateMasterKey`
  uniqueness. Stdlib only: `crypto/aes`, `crypto/cipher`.
- **Trust List scope enforcement: `TrustList.AuthorizesForScope` and
  `ToTrustAnchorForScope` (security/correctness, Axis 61).** The `Scope` field
  on `TrustListEntry` was declared and validated but never enforced: an issuer
  registered with `scope="battery"` could authorize any credential type. Added
  `AuthorizesForScope(did, pub, wantScope)` which rejects the call when the
  entry's `Scope` is non-empty and differs from `wantScope` (both are non-empty
  — an entry with no scope remains unrestricted for any caller, and a caller
  that passes `""` skips scope gating to match the existing `Authorizes`
  behaviour). Added `ToTrustAnchorForScope(scope)` to build a DID allow-list
  that excludes out-of-scope issuers when constructing a `TrustAnchor`. Both
  are backward-compatible additions (`Authorizes` / `ToTrustAnchor` unchanged).
  4 new tests: battery-scoped issuer rejected for "textile", unrestricted issuer
  accepted for any scope, revoked issuer always rejected, scope-filtered anchor
  excludes wrong-scope entries while including unrestricted ones.
- **Signed Trust Lists for issuer authorization (`didresolver.TrustList`, Axis 59
  — new feature).** A valid issuer signature proves only *who* signed, never that
  the signer is an *authorized* DPP/Battery-Passport issuer; until now trust was
  hard-coded into `TrustAnchor` in application code. New `TrustList` is an
  authority-signed (Ed25519), versioned, expirable allow-list of issuer DIDs —
  conceptually a minimal ETSI TS 119 612 Trusted List — that a verifier consumes
  to populate a `TrustAnchor` without hard-coding keys. Security properties:
  signature over the exact payload bytes (`SignTrustList`/`VerifyTrustList`,
  `ErrTrustListSig`); `exp` freshness with leeway (`ErrTrustListExpired`);
  per-issuer status with **only `active` entries trusted** (`suspended`/`revoked`
  excluded, fail-closed); strict JSON decoding (`DisallowUnknownFields`),
  duplicate-DID and status/keyHash validation; and rollback protection via a
  monotonic `version` enforced by `TrustListVerifier` (`ErrTrustListRollback`)
  so an old list that still trusts a since-revoked issuer cannot be replayed.
  `ToTrustAnchor` deliberately registers DIDs only — a per-DID `keyHash` pin is
  *not* flattened into a global key allow-list (which would trust that key under
  any DID); binding-aware pin enforcement is via `TrustList.Authorizes(did,pub)`.
  Spec §12 added. 10 tests cover round-trip, wrong-key/tamper/expiry rejection,
  malformed-list validation, active-only anchor building, the per-DID pin
  binding, rollback/idempotent-refresh, forged-list-doesn't-advance-version, and
  an end-to-end authorize-vs-counterfeit check.

### Fixed
- **SD-JWT issuance silently accepted empty `sub` and `vct` — broken credential
  issued with no diagnostic (correctness, Axis 64).** `issueSDJWT` (the shared
  internal helper for all `IssueSDJWT*` variants) set `"sub": subject` without
  checking whether `subject` is non-empty; RFC 7519 §4.1.2 defines `sub` as a
  non-empty case-sensitive string. Likewise, `IssueSDJWTVC` accepted an empty
  `vct`. Both cases produce a credential that fails `VerifySDJWT*` at verify
  time (`ErrSDJWTMissingVCT` / structural mismatch) but the caller of `Issue*`
  gets no error — a silent broken credential. Added upfront guards: empty
  `subject` → `ErrSubjectRequired` (new sentinel in `errors.go`); empty `vct`
  → `ErrSDJWTMissingVCT` (existing sentinel). Two tests cover the two
  rejection paths.
- **`revocation.VerifyStatusListToken` used a hard-coded `time.Now()` — no
  injectable clock for expiry tests (testability, Axis 63).** Extracted a new
  `VerifyStatusListTokenAt(token, pub, purpose, now)` that accepts an explicit
  `time.Time`, consistent with `VerifyTrustListAt` and `VerifySDJWTAt`. The
  original `VerifyStatusListToken` now delegates to it with `time.Now()`. One
  new test (`TestVerifyStatusListTokenAt`) verifies expiry, leeway, and the
  before-expiry happy path using a fixed reference clock.
- **`scitt.SignStatement` accepted empty issuer/subject and could panic on a
  wrong-length private key (correctness/panic-safety, Axis 62).** The function
  called `issuerPriv.Public().(ed25519.PublicKey)` before checking key length —
  a slice operation that panics when `len(issuerPriv) < 32`. An empty `issuerID`
  or `subject` produced a signed statement with no issuer/subject identity in
  the audit trail, weakening the SCITT transparency guarantee. Added upfront
  checks (private key length, non-empty issuerID/subject/contentType) that
  return `ErrStatementMalformed` before any key operation. 6 table-driven
  subtests cover each malformed case (short key, nil key, missing issuer/subject/
  content-type, empty payload).
- **`openid4vp.randomB64` silently discarded CSPRNG errors — weak nonces on
  entropy failure (security, Axis 60).** `CreateRequest` and `CreateRequestDCQL`
  generate a 32-byte nonce and a 16-byte state token via `randomB64`, which
  called `rand.Read` and discarded its return value with `_, _ =`. On pre-1.20
  Go or exotic platforms a CSPRNG failure would return all-zero bytes, producing
  identical, predictable nonces/state values across requests — breaking the
  replay-protection and state-binding these values provide. Changed `randomB64`
  to return `(string, error)` and both callers propagate the error; a CSPRNG
  failure now surfaces as a request-creation error rather than a silently
  insecure token.
- **DCQL claim-value matching could panic on composite JSON values
  (correctness/DoS, Axis 58).** `CredentialQuery.MatchClaims` compared a disclosed
  claim value against each DCQL `values` entry with `val == want` on two `any`
  operands. Go's `==` panics when both operands share an *uncomparable* dynamic
  type (`[]any`, `map[string]any`) — reachable when a verifier lists a composite
  value in DCQL `values` and a (possibly malicious) wallet discloses a same-typed
  composite claim; the panic surfaces as a 500 per crafted presentation. The
  operator also can't structurally match JSON arrays/objects even when logically
  equal. Switched to `reflect.DeepEqual`, which never panics and matches
  composites structurally (scalar behavior unchanged). Test:
  `TestMatchClaimsCompositeValues` covers matching/again-differing array & object
  values and a composite-vs-scalar mismatch (all without panic).
- **SD-JWT issuer JWS `typ` was never verified — cross-JWT-type confusion
  (security/conformance, Axis 57).** The issuer sets `typ:"vc+sd-jwt"` and spec
  §2 mandates it, but `VerifySDJWTWithBinding` only checked the KB-JWT `typ`,
  never the issuer JWS `typ`. A differently-typed JWS signed by the same key
  (e.g. `statuslist+jwt`, `openid4vci-proof+jwt`, a plain `JWT`) could thus be
  presented as a credential, defended only implicitly by the `vct`/`_sd`
  requirements. Verification now rejects an issuer JWS whose `typ`, when present,
  is not an SD-JWT-VC media type — `vc+sd-jwt` or the newer `dc+sd-jwt`, with an
  optional `application/` prefix per RFC 7515 §4.1.9 (`ErrSDJWTUnsupportedType`).
  A missing `typ` is tolerated for interop (the `vct` + `_sd` structure still
  gate it). Spec §2 updated. Tests: the accepted types (incl. prefixed and
  absent) verify; `JWT`/`statuslist+jwt`/`openid4vci-proof+jwt`/`kb+jwt` are
  rejected.
- **COSE and JWS verification ignored the `crit` (critical headers) field —
  must-understand bypass (security/conformance, Axis 56).** `cbor.Verify1`
  (COSE_Sign1) never inspected the protected-header `crit` field (RFC 9052 §3.1,
  label 2), and the SD-JWT issuer-JWS / KB-JWT verification never inspected the
  JWS `crit` header (RFC 7515 §4.1.11). Both specs mandate that if a signature
  marks an extension parameter critical and the verifier doesn't understand it,
  the signature MUST be rejected — `crit` is the issuer's "you must process this
  to use the token safely" signal. BLRCS silently ignored it, so a credential or
  receipt relying on an unimplemented critical extension would be accepted as if
  the extension didn't exist. BLRCS implements no critical extensions, so it now
  rejects any present `crit`: COSE accepts only a `crit` listing solely the
  algorithm label and rejects unknown/string/empty/malformed crit
  (`ErrCOSECritUnsupported`); the issuer JWS and KB-JWT reject any non-empty
  `crit` (`ErrSDJWTCritUnsupported` / `ErrKeyBindingInvalid`). Spec §3 and §8
  updated. Tests cover COSE (unknown int label, string label, empty array,
  non-array, and the accepted alg-only case) and SD-JWT crit rejection.
- **JCS canonicalization did not normalize negative zero (correctness, Axis 55).**
  `multiformats` JCS emitted `-0` verbatim for the integer literal `-0` and `-0`
  for the float `-0.0` (Go's `FormatFloat` renders negative zero as `-0`), but
  RFC 8785 §3.2.2.3 / ECMAScript `Number::toString` require negative zero to
  serialize as `0`. Two logically-equal numbers (`-0` vs `0`, or `-0.0` float vs
  `0` int) therefore produced **different canonical bytes** — and JCS underpins
  did:webvh SCID/entryHash and `eddsa-jcs-2022` Data Integrity proofs, so equal
  values could hash/sign differently. `writeJCSNumber` now maps the `-0` integer
  literal and every zero-valued float to `0`. Spec conformance note added. Tests:
  `-0`, `-0.0`, `-0e9`, `0`, `0.0` all canonicalize to `0` via both the byte and
  in-memory paths.
- **MCP SSE stream had no per-write deadline — slow-client backpressure leak
  (resource/DoS, Axis 54).** `handleGet` streams Server-Sent Events with the
  daemon's `http.Server` `WriteTimeout=0` (a global write timeout would kill
  long-lived streams). With no per-write deadline, a stuck or slow client — one
  whose TCP send buffer is full but whose connection stays open — makes the
  heartbeat `Write`/`Flush` block **forever**; `r.Context().Done()` does not fire
  for a slow-but-open client, so the handler goroutine and its connection leak,
  and enough such clients exhaust goroutines/FDs. Fixed by writing each SSE frame
  through `http.NewResponseController(w)` with `SetWriteDeadline(now +
  sseWriteTimeout)` (10s) per frame, via a `writeEvent` helper that returns the
  stream on any write/flush error (deadline exceeded, broken pipe). The deadline
  is best-effort — a writer without deadline/flush support (`ErrNotSupported`) is
  treated as success — so behavior is unchanged for the happy path; the existing
  `TestHTTP_SSEHeartbeat` covers it.
- **`config.FromEnv`/`FromJSON` never ran `Validate` — invalid config silently
  accepted (security/correctness, Axis 53).** The `Config` type documents
  "不正値は起動時拒否" (reject invalid values at startup) and ships a thorough
  `Validate()` (paired TLS cert/key, known `tlsMode`/`logFormat`, non-negative
  ranges) — but no loader and no caller ever invoked it, so `Validate` was dead
  code and the contract unfulfilled. Concretely, `BLRCS_RATE_LIMIT_RPS=-1` parses
  as a valid int, so the per-field fail-fast didn't catch it; `FromEnv` returned
  a config with `RateLimitRPS=-1`, and `httpmw.NewRateLimiter` treats `rps<=0` as
  **disabled** — a single-character config typo silently turns off the rate
  limiter, the exact failure the inline fail-fast comment claims to prevent.
  `FromEnv` and `FromJSON` now call `cfg.Validate()` before returning, so
  out-of-range/inconsistent values (negative RPS, TLS cert without key, unknown
  tlsMode/logFormat) are rejected at load. Tests: negative RPS, invalid tlsMode,
  and TLS-cert-without-key are each rejected via the loaders.
- **`mcp` HTTP session-GC goroutine could never stop — goroutine + ticker leak
  (resource, Axis 52).** `sessionStore.gcLoop` ran `for range t.C` with no stop
  channel, so the goroutine never exited and its `defer t.Stop()` was unreachable
  dead code; `HTTPHandler` (which starts one gcLoop per `NewHTTPHandler`) had no
  `Close`. Every handler therefore leaked a goroutine and a 5-minute ticker for
  the process lifetime — unbounded when handlers are created repeatedly (tests,
  reconfiguration, multi-tenant). Every other GC loop in the codebase (`replay`,
  `openid4vp`, `httpmw`) already uses a stop channel; this brings `mcp` in line.
  Added a `stop` channel + `stopOnce` to `sessionStore`, a `select` on it in
  `gcLoop`, a `sessionStore.close()`, and an idempotent `HTTPHandler.Close()`;
  the `blrcs-mcpd` daemon now defers `mcpHandler.Close()` on shutdown. Test:
  `TestHTTPHandlerCloseStopsGCGoroutine` starts 50 handlers, closes them, and
  asserts the goroutine count drains back to baseline (plus idempotent re-close).
- **`healthprobe` swallowed panicking checks — readiness fail-open (availability,
  Axis 51).** A check that panicked was caught by `defer func() { _ = recover() }()`
  but the goroutine then returned **without appending any `CheckResult`**, so the
  check silently vanished from the report. The comment claimed "panic → treated
  as failure," but the code did the opposite: if the other checks passed, the
  endpoint returned **200 OK while a check was broken**, so a Kubernetes
  readiness probe would keep routing traffic to a pod whose dependency check
  paniced (e.g. a nil-map write). Fixed by running each check inside an inner
  func whose deferred recover records a `fail` result (`"check panicked: …"`),
  so a panicked check now counts as a failure and the endpoint returns 503
  (fail-closed). The result is always appended, so no check is dropped. Test:
  `TestPanickingCheckFailsClosed` asserts 503, report status `fail`, the panicked
  check present as `fail`, and that both checks appear.
- **SD-JWT holder key (`cnf.jwk`) accepted any key type — missing `kty`/`crv`
  pinning (correctness/conformance, Axis 50).** `extractHolderKey` validated only
  the length of the JWK `x` value, so a `cnf.jwk` declaring a different key type —
  e.g. `{"kty":"EC","crv":"P-256","x":<32 bytes>}`, or a JWK with no `kty`/`crv`
  at all — had its `x` silently reinterpreted as an Ed25519 public key (a
  cross-algorithm type confusion and an RFC 7800 conformance gap). It was not
  exploitable because the KB-JWT `alg` is pinned to `EdDSA` and verification
  fails closed, but the rest of the codebase (`didresolver.jwkToEd25519`,
  `mdoc.parseDeviceKey`) already pins `kty`/`crv`; this brings the holder-binding
  path in line. `extractHolderKey` now requires `kty="OKP"` and `crv="Ed25519"`.
  BLRCS issuance already emits exactly that, so issued credentials are
  unaffected. Spec §2 updated. Tests: EC/P-256, OKP/X25519, and missing-`kty`
  JWKs are each rejected; a valid OKP/Ed25519 JWK still yields the key.
- **`didresolver.ResolveAll` returned its internal cached key slice — aliasing /
  data-race on cached key material (security, Axis 49).** Both the cache-hit and
  fresh-resolve return paths handed back the very `[]ed25519.PublicKey` slice the
  resolver stores in its cache. A caller that appended to, reordered, or wrote
  into the returned keys (or their bytes) therefore mutated the cached key
  material shared by every other goroutine hitting the same DID — silently
  poisoning subsequent verifications, and racing with concurrent readers of the
  cache (a `go test -race` hazard on a security-critical value). Fixed with a
  `cloneKeys` deep copy (slice header *and* each key's bytes) on both return
  paths, so the cache shares no storage with callers. Internal callers
  (`Resolve`, `ResolveAndVerifyAll`) are unaffected. Test:
  `TestResolveAllReturnsPrivateCopy` vandalizes the returned key and asserts a
  later cache hit still yields the original, and that the two results don't share
  a backing array.
- **OpenID4VP authorize/callback responses missing `Cache-Control: no-store`
  (security, Axis 48).** `Verifier.CallbackHandler` returned the holder's
  verified, selectively-disclosed claims (personal data) and `AuthorizeHandler`
  returned the request URL (carrying the one-time nonce) plus session `state`,
  both with only a `Content-Type` header. Without `Cache-Control: no-store`, a
  browser, shared proxy, or CDN may store these responses — and a CDN
  request-collapsing optimization could even replay one holder's claims to a
  different client. The OpenID4VCI `/token` and `/credential` endpoints already
  set `no-store` (per RFC 6749 §5.1); this extends the same policy to the
  OpenID4VP handlers (success and error paths). Spec §5 updated with the general
  rule. Tests assert `Cache-Control: no-store` on the authorize and callback
  success responses.
- **SD-JWT `exp`/`iat`/`nbf` fail-open on non-numeric type (security, Axis 47).**
  `VerifySDJWTWithBinding` read each RFC 7519 NumericDate claim with
  `payload["exp"].(float64)` and silently ignored the claim when the assertion
  failed. A credential carrying a present-but-wrong-typed time claim — most
  importantly `"exp":"1700000000"` as a JSON **string**, which some
  non-conformant issuer libraries emit — therefore had its expiry check disabled
  (`vc.Expires == 0` ⇒ "no expiry"): an expired credential would verify. Fixed
  with a `numericDateClaim` helper that distinguishes absent (skip), numeric
  (use), and present-but-wrong-type (reject with `ErrSDJWTMalformed`), applied to
  `iat`/`exp`/`nbf`. The KB-JWT `iat` path was already fail-closed and is
  unchanged. Spec §3.4 updated. Tests: string `exp`, plus `iat`/`nbf`/`exp` as
  string/bool/array all rejected; absent `exp`/`nbf` still verifies.
- **`httpmw` per-client rate limiter keyed on `IP:port`, not IP — per-connection
  bypass (security, Axis 46).** `clientIP` returned `r.RemoteAddr` verbatim, and
  Go's `net/http` server sets that to `IP:port` with a fresh ephemeral source
  port per connection. The token-bucket limiter (`RateLimiter.Allow`) therefore
  keyed each *connection* separately rather than each client IP: an attacker
  opening a new connection per request (trivial — just don't reuse keep-alive)
  got a brand-new full bucket every time, defeating the rate limit and
  re-opening the per-IP memory-exhaustion vector the GC was meant to bound. The
  package's own doc and the limiter comments claim "per client IP", and an
  existing test even codified the buggy `192.0.2.50:1234` return value. Fixed by
  stripping the port with `net.SplitHostPort` in `clientIP` (falling back to the
  raw value for an already-bare host or Unix socket); the access-log `remote`
  field is now a clean IP too. Spec gains §11 "Rate limiting & client identity".
  Tests: `TestClientIPStripsPort` (IPv4/IPv6/bare cases) and
  `TestRateLimitKeyedPerIPNotPerConnection` (same IP, different port → one
  shared bucket → second request 429); the prior test was corrected to expect
  the port-stripped IP.
- **`didresolver` / `vctmeta` default HTTP fetchers followed redirects — SSRF
  (security, Axis 45).** Both packages' default clients were plain
  `&http.Client{Timeout: …}` with no `CheckRedirect`, so Go's stdlib defaults
  applied: up to 10 redirects, blindly followed across hosts. A malicious
  `did:web` document host or SD-JWT-VC Type Metadata host could 302/301 the
  fetch into any target — including `http://169.254.169.254/...` (cloud
  metadata), `127.0.0.1:*` (internal services), or any cross-origin destination
  — and the bytes returned by the redirect target would be parsed as the issuer's
  DID document / type metadata. For `vctmeta` it also silently broke the
  `vct#integrity` SRI binding the issuer pinned: the hash would then guard a
  *different* URL than was used at issuance, defeating the whole point of the
  integrity claim. Fixed by adding `CheckRedirect` on the default clients that
  returns sentinel errors (`didresolver.ErrRedirectNotAllowed`,
  `vctmeta.ErrRedirectNotAllowed`) so every 3xx is refused before the
  follow-up request fires. The W3C did:web spec defines the document path
  exactly (`/.well-known/did.json` or `<path>/did.json`), so a legitimate
  did:web server has no reason to redirect. Caller-supplied `*http.Client`
  instances on `vctmeta.HTTPFetcher` are still respected as-is — the caller is
  in charge of their own policy. Spec gains a new §10 "Outbound HTTP (SSRF
  resistance)" codifying the scheme/redirect/dial requirements across
  `webhook`, `didresolver`, and `vctmeta`. Tests:
  `TestDefaultHTTPFetchRejectsRedirect`,
  `TestDefaultHTTPFetchRejectsRedirectChainToLoopback`,
  `TestHTTPFetcherRejectsRedirect`, `TestHTTPFetcherCustomClientRespected`
  exercise both the rejection and the custom-client respect paths.

### Added
- **`atrest` NIST nonce-limit enforcement across process restarts
  (`NewCipherWithCount` / `Cipher.EncryptionCount`) — correctness/security,
  Axis 44.** The package documents the NIST SP 800-38D random-nonce limit as
  "同一鍵で 2^32 回以上の Encrypt は ErrKeyExhausted" (per *key*), but the
  `encCount` guard is an in-memory `atomic.Uint64` that resets to 0 every time a
  `Cipher` is reconstructed. For a key reloaded from a KMS/keyfile on each start,
  the cumulative per-key-lifetime bound the doc promises was therefore only
  enforced per-process: a long-lived key reused across many restarts could exceed
  2^32 encryptions undetected, degrading AES-GCM's authentication guarantee and
  risking nonce-collision plaintext recovery. Added `NewCipherWithCount(keyID,
  key, prior)` to seed the counter from a persisted value and
  `Cipher.EncryptionCount()` to read it for persistence, so operators can enforce
  the cumulative bound across restarts (seeding at/over the limit makes the first
  `Encrypt` return `ErrKeyExhausted`). `NewCipher`'s doc now states the
  per-instance semantics explicitly and points to the cumulative path. Purely
  additive — no envelope-format or API break. Tests: `EncryptionCount` tracks
  each `Encrypt`; seeding resumes the count, enforces the limit on a fresh
  cipher, and still rejects an invalid key.
- **`revocation.IndexAllocator` — issuer-metric privacy via random status-list
  index assignment (privacy, Axis 43; spec §4 / backlog #11a).** A published
  Bitstring Status List is effectively public. Bit `0` ("not revoked") is the
  status of both an unissued index *and* a valid credential, so the list does not
  by itself reveal issuance volume — but with *sequential* index assignment every
  revoked `1` bit lands in `[0, highWaterMark)`, so the largest revoked index ≈
  the number of credentials ever issued and a credential's index is monotonic in
  its issuance time. That leaks the issuer's issuance volume and ordering. New
  `IndexAllocator` hands out uniformly-random, unique indices from a fixed-size
  space (CSPRNG rejection sampling, with a random-start probe fallback near
  saturation), spreading revoked bits across the whole list so the maximum revoked
  index ≈ the capacity regardless of true volume, and decoupling an index from
  issuance time. Correctness is unchanged (unique in-range indices →
  identical `SetStatus`/`GetStatus`). `Reserve` rebuilds allocator state after a
  restart from stored indices. The residual leak — the absolute *count* of set
  bits — is irreducible for a plain bitstring and is tracked as backlog #11b
  (accumulator / padded Bloom-cascade, CRSet). Spec §4 and the conformance matrix
  updated; new normative §9 "Resource bounds (DoS resistance)" codifies the
  SD-JWT segment cap, HTTP body caps, bounded in-memory stores, compression-bomb
  guards, and recursive-decoder depth limits added across recent passes. Tests:
  uniqueness/in-range across a full fill, exhaustion → `ErrAllocatorFull`,
  `Reserve` (idempotent + range-checked + never re-handed-out), a statistical
  anti-clustering check, the high-occupancy fallback path, and an end-to-end wire
  into a `BitstringStatusList`.
- **`openid4vci` tx_code brute-force lockout is now auditable
  (`Issuer.OnTxCodeLockout`) — forensic observability (Axis 12).** When PIN
  attempts hit `MaxTxCodeAttempts` the pre-authorized code is burned, but this —
  the single most attack-indicative event in the issuance flow — happened
  silently: an operator could not distinguish a user fat-fingering a PIN from an
  attacker exhausting all attempts. For a regulated eIDAS/DPP issuer that audit
  signal is a requirement. New optional `Issuer.OnTxCodeLockout func(subject,
  configID string)` fires once when a code is burned by brute-force, passing only
  the offer's `subject`/`configID` — never the secret code, PIN, or tx_code. It is
  invoked *after* the issuer lock is released (LIFO defer ordering), so the
  callback may safely re-enter the `Issuer` and never holds `iss.mu`. Default nil →
  no behavior change. Tests: hook fires exactly once at the limit (not before),
  carries the right identifiers, and a no-tx_code flow never triggers it.
- **SD-JWT decoy digests (`Issuer.DecoyDigests`) — hide the true claim count
  (privacy / unlinkability, Axis 11).** Auditing through a privacy lens — "beyond
  what it discloses, what does a credential's *structure* leak?" — found that the
  signed `_sd` array reveals the number of selectively-disclosable claims, including
  the undisclosed ones. That count is a fingerprint: it distinguishes credential
  types and helps correlate a holder's presentations. The SD-JWT spec (§5.6) answers
  this with decoy digests. New optional `Issuer.DecoyDigests int`: when `>0`, issuance
  appends that many dummy digests (SHA-256 of fresh random salts, indistinguishable
  from real digests) to `_sd`, and the whole array is shuffled with a crypto/rand
  Fisher-Yates so real and decoy entries are not positionally distinguishable. Decoys
  have no disclosures, so verification is unaffected (the verifier already ignores
  `_sd` entries with no presented disclosure) and they never surface as claims.
  Default `0` → no behavior change (backward-compatible); privacy-conscious issuers
  set a few. Tests: `_sd` length = real + decoys, round-trip still verifies, decoys
  disclose nothing, and default-off keeps `_sd` sized to the real claims.

### Fixed
- **SD-JWT disclosure-segment DoS via unbounded `strings.Split` (security, Axis 42).**
  `VerifySDJWTWithBinding` (and the `VerifySDJWT` / `VerifySDJWTAt` wrappers) called
  `strings.Split(sdjwt, "~")` with no limit on the number of resulting segments.
  The issuer signature covers only the first `~`-separated segment (the JWT proper),
  leaving the remaining disclosure segments attacker-editable. A malicious wallet can
  take any legitimately issued SD-JWT and append thousands of `~` characters without
  invalidating the signature; `strings.Split` on a 4 MiB input of `~` allocates
  ~4 million string-header entries (~64 MB) **before** the signature check runs,
  enabling memory exhaustion under concurrent load. Fixed by adding a package-level
  `maxSDJWTSegments = 256` constant and checking `strings.Count(sdjwt, "~") >
  maxSDJWTSegments` before the split in both `VerifySDJWTWithBinding` and `Present`.
  New sentinel: `ErrSDJWTTooManyDisclosures`. A real EU DPP / Battery Passport
  credential has at most a few dozen selective-disclosure claims; 256 is generous.
  Test: `TestVerifySDJWTTooManyDisclosures` sends a 257-tilde string and asserts
  `ErrSDJWTTooManyDisclosures` from `VerifySDJWTWithBinding`, `VerifySDJWT`, and
  `Present`.
- **Two unnecessary type conversions in `scitt/scitt_test.go` (lint, Axis 42).**
  `uint64(receipt.TreeSize)` on lines 643 and 649 were identity conversions:
  `Receipt.TreeSize` is already `uint64`. Removed both casts; `golangci-lint
  run ./...` now reports 0 issues.
- **README stats corrected (doc, Axis 42).** Fuzz-target count updated from
  20 to 21 (the `openid4vci.FuzzVerifyProofJWT` target was not counted);
  test count updated from "1000+" to "1700+" to better reflect the actual 1760
  test functions in the suite.
- **`openid4vci.Issuer` token endpoint missing `http.MaxBytesReader` — unbounded
  request body DoS (security, Axis 41).** `handleToken` called `r.ParseForm()`
  directly without first wrapping `r.Body` in `http.MaxBytesReader`. Unlike
  `handleCredential`, which explicitly caps its body at 1 MiB, the token endpoint
  had no read limit, allowing any client to stream an arbitrarily large
  `application/x-www-form-urlencoded` body that would be buffered in full before
  any application logic ran. The token endpoint only needs ≈200 bytes
  (grant_type + pre-authorized_code + tx_code), so a 64 KiB cap is extremely
  generous in practice. Fixed by inserting `r.Body = http.MaxBytesReader(w, r.Body,
  65536)` before `r.ParseForm()`. Test: `TestHandleTokenBodyTooLarge` sends a
  65537-byte POST and asserts HTTP 400.

- **`didresolver.Resolver` cache unbounded — memory exhaustion via many distinct
  DID issuers (security / DoS, Axis 40).** The DID resolver's `cache
  map[string]cacheEntry` had no maximum size and no eviction policy. Expired entries
  were only skipped on read, never removed; `InvalidateCache` could only delete a
  single named entry. In an OpenID4VP / credential-verification flow, an attacker
  presenting credentials from many distinct fake DID issuers would cause the cache
  to grow without bound — each unique DID string occupies ~100 bytes of key + a
  32-byte public key value, so 1 million entries ≈ 130 MB, reachable with a
  sustained presentation flood. Fixed by adding `MaxCacheSize int` (default 0 →
  `defaultMaxCacheSize = 4096`) to `Resolver`. On each cache write, if
  `len(cache) >= maxEntries()`, all expired entries are purged first; the new entry
  is inserted only if there is room after the purge. This bounds memory to
  `O(MaxCacheSize)` while recovering capacity organically as TTLs expire. Tests:
  `TestCacheSizeCap` (resolving `cap+2` distinct DIDs with long TTL — cache stays
  at or below cap); `TestCacheSizeCapAllowsInsertAfterPurge` (fill with short-TTL
  entries, let them expire, verify next insert triggers purge and then caches the
  new entry).

- **`types.DID.MarshalJSON` / `UnmarshalJSON` JSON injection and escape-sequence
  mishandling (security / correctness, Axis 39).** `DID.MarshalJSON` produced JSON
  by raw string concatenation (`"` + d.value + `"`), without escaping the content.
  `NewDID` does not reject `"`, `\`, or control characters in the method-specific
  identifier (the third colon-separated component), so a `DID` constructed from a
  crafted string — for instance `did:web:a","evil":true` — would produce broken or
  injected JSON when embedded in any struct marshaled with `json.Marshal`. In a DID
  resolution context, where DID values flow from externally-fetched documents into
  application data structures that are later serialized, this is an exploitable path:
  an attacker controlling a DID document (or the method-specific id in a log entry)
  can inject arbitrary JSON keys into downstream API responses or audit records.
  Compounding the issue, `UnmarshalJSON` performed the inverse operation incorrectly:
  it stripped the outer JSON quote bytes without decoding escape sequences, so a
  round-trip through `Marshal`→`Unmarshal` for a DID containing `\"` would yield a
  value with literal backslash-quote bytes rather than the original `"` character.
  Fixed by replacing both methods with stdlib-correct implementations: `MarshalJSON`
  delegates to `json.Marshal(d.value)`, which escapes all characters that require it;
  `UnmarshalJSON` delegates to `json.Unmarshal(b, &s)` and then calls `NewDID(s)`,
  which properly handles all JSON escape sequences. The GTIN and CountryCode types
  have analogous patterns but are safe because their validators admit only digits and
  uppercase ASCII letters respectively. Tests: `TestDIDMarshalJSONSpecialChars` (DIDs
  with `"`, `\`, tab, and control-character identifiers round-trip correctly through
  `json.Marshal`/`json.Unmarshal`); `TestDIDMarshalJSONInjection` (embedding a DID
  with `","evil":true` in a JSON struct produces valid, non-injected JSON — the
  injected key is absent from the parsed result).

- **`multiformats.CanonicalizeJSON` / `Canonicalize` unbounded recursive descent
  — goroutine stack exhaustion via deeply-nested DID documents (security / DoS,
  Axis 38).** `walkJSONTokens` (duplicate-key pre-scan) and `canonicalValue`
  (JCS re-serializer) both recurse without any depth cap; a DID document with
  N levels of nested objects causes N stack frames. In `didwebvh/didwebvh.go`
  and `didwebvh/proof.go`, these functions are called on externally-fetched DID
  documents, so a hostile DID host can craft a million-level JSON tree that
  exhausts the goroutine's stack (≥ 1 GB) or — at lower depths — consumes
  enough memory to deny service to other goroutines. Fixed by adding
  `maxCanonicalizeDepth = 512` and the sentinel `ErrCanonicalizeDepth`; both
  `walkJSONTokens` and `canonicalValue` accept a `depth int` parameter and
  return the error immediately when `depth > 512`. Legitimate DID documents
  and credential payloads are at most a handful of levels deep.  Tests:
  `TestCanonicalizeDepthLimitJSON` (one level beyond cap → `ErrCanonicalizeDepth`
  from `CanonicalizeJSON`), `TestCanonicalizeDepthLimitValue` (same via
  `Canonicalize` — the path used by `didwebvh/proof.go`),
  `TestCanonicalizeDepthLimitAtBoundary` (exactly-at-cap → success, verifying
  no off-by-one).

- **SCITT Merkle inclusion and consistency proof root-hash comparisons were
  timing-variable — oracle for expected root hash (security / defense-in-depth,
  Axis 37).** The `scitt` package contained a hand-rolled `equalBytes` helper
  with an early-exit byte loop, used in all three security-critical hash
  comparisons: (1) Merkle inclusion proof final root check (`VerifyInclusion`),
  (2) RFC 6962 consistency proof old-root check (`VerifyConsistency` lines
  `fr == oldRoot`), and (3) the trivial `m == n` same-size check
  (`oldRoot == newRoot`). An attacker submitting crafted SCITT receipts to the
  verification endpoint and measuring response latency could exploit the
  timing differential (up to ~32 ns per byte position) to incrementally recover
  the expected SHA-256 root hash — enabling forgery of a receipt that passes
  verification without access to the actual ledger. The same function was
  already removed from the `mdoc` package in iteration 31. Fix: removed
  `equalBytes` from `scitt.go`; added `crypto/subtle` to both `scitt.go` and
  `consistency.go`; replaced all three call sites with
  `subtle.ConstantTimeCompare(a, b) == 1`. Test files updated to use
  `bytes.Equal` (timing-indifferent for non-security comparisons in tests).
  New test `TestVerifyInclusionTamperedLastByte`: constructs a real 1-leaf
  tree, verifies with the correct root, then flips only the last byte — must
  be rejected. This is the discriminating case for constant-time vs. early-exit
  comparison (early-exit would differ by only ~0 ns on a 31-byte match, while
  constant-time always returns in the same time regardless).

- **`jsonschema.Validate` had no operation budget — exponential-time DoS via
  adversarial `$ref`/`anyOf`/`oneOf` nesting (security / algorithmic complexity,
  Axis 36).** A compact (~150 byte) schema consisting of a cyclic `$ref` inside a
  2-branch `anyOf` causes exponential validator-call growth: each schema-node
  evaluation spawns two child validators that each re-follow the same `$ref`,
  doubling work at every level. With `maxRefDepth = 64` guarding individual chains,
  the total call count reaches 2^64 ≈ 1.8 × 10^19 — effectively infinite. This
  attack is reachable via `vctmeta.ValidateClaims`, which is called with the JSON
  Schema embedded in SD-JWT-VC Type Metadata documents fetched from the credential
  `vct` URL. When `vct#integrity` is absent or the metadata server is hostile, an
  attacker can supply such a schema and lock a goroutine indefinitely. Fixed by
  adding a shared operation counter (`ops *int`) to the `validator` type; all child
  validators (created for `allOf`/`anyOf`/`oneOf`/`not`/`contains`) carry the same
  pointer so the counter is global across the entire validation call tree. Each
  `validate` invocation increments the counter and returns immediately when it
  exceeds `maxValidateOps = 1 000 000`. `Schema.Validate` checks the final counter
  and returns the new sentinel `ErrComplexityBudget` when exceeded. The budget is
  generous enough for schemas with hundreds of properties × dozens of combinator
  branches without triggering in practice. Tests: `TestComplexityBudgetExponentialRef`
  (the 2-branch anyOf cyclic bomb, confirmed to complete in milliseconds and return
  `ErrComplexityBudget`); `TestComplexityBudgetNormalSchemaUnaffected` (50 properties
  × 3-branch anyOf validates successfully without hitting the budget).

- **OpenID4VP presentation replay was possible under concurrency — TOCTOU
  between `Load` and `Consume` (security / replay, Axis 35).** `ProcessResponse`
  enforced one-time use of the authorization `state` by calling `store.Consume`
  *after* full verification, but (a) `MemoryStore.Load` reads the session without
  deleting it and (b) `MemoryStore.Consume` unconditionally deleted and returned
  `nil`, and its result was discarded (`_ = v.store.Consume(...)`). So two (or N)
  simultaneous submissions of the *same* valid `vp_token`+`state` could all pass
  `Load`, all verify (a replay carries the same valid nonce, so the nonce binding
  does not stop it), and all be accepted — a presentation double-spend. A
  regression test confirms the severity: against the old code **all 16** concurrent
  identical submissions were accepted. Fixed by making the one-time consumption an
  atomic, return-checked claim: `MemoryStore.Consume` is now a single locked
  check-and-delete that returns `ErrStateNotFound` if the state is already gone,
  the `SessionStore.Consume` contract documents this requirement, and
  `ProcessResponse` rejects the request when `Consume` fails. Late consumption is
  retained (state is preserved if verification or the revocation check fails, so
  legitimate retries still work), but only the first of any concurrent set now
  wins. Test: `TestConcurrentReplayRejected` (runs under `-race`; asserts exactly
  one of N simultaneous submissions succeeds) plus the existing
  `TestReplayRejected` sequential case.

- **`did:webvh` SCID self-certification scanned only `state`, not
  `parameters`, for the `{SCID}` placeholder → forgeable / non-canonical
  genesis (security / identity integrity, Axis 34).** `deriveSCID` rejects a
  genesis that still contains the literal `{SCID}` placeholder, because the
  verify-time real→placeholder inverse substitution would otherwise be
  non-invertible. Its own comment said *"the genesis DID document (state) **and
  its parameters** must not contain the placeholder"*, but the code checked only
  `entry.State` — leaving the more security-sensitive `parameters` half
  (`updateKeys`, `nextKeyHashes`, …) unguarded. This was exploitable: because
  `Create` does not substitute the placeholder inside `nextKeyHashes`, a genesis
  carrying `{SCID}` there **self-certifies** — the derived SCID matches, so the
  whole log verifies — yet it is non-canonical and should never be accepted. The
  new regression test confirms this is a true positive: with the old code
  `Verify` *succeeds* on such an entry, and only the fix rejects it. Fixed:
  `deriveSCID` now scans the entire hash input (parameters + state, excluding the
  `versionId` we deliberately set to the placeholder) via `containsPlaceholder`,
  so any `{SCID}` literal anywhere in the genesis is rejected with
  `ErrSCIDMismatch`. Tests: `TestSCIDPlaceholderInjectionInParametersRejected`
  (discriminating — fails against the unpatched code); the existing
  state-injection and happy-path tests stay green.

- **SCITT checkpoint signature did not bind the log identity (`TSID`) →
  cross-log checkpoint relabeling (security / transparency-log integrity,
  Axis 33).** `checkpointSigPayload` signed only `rootHash ‖ treeSize ‖
  timestamp`, omitting `cp.TSID` — the Transparency-Service / log identifier that
  is the checkpoint's *origin*. The witness split-view defense
  (`scitt/witness.go`) keys its entire per-log lineage state on that field
  (`w.seen[cp.TSID]`, regression/consistency checks scoped per TSID), so leaving
  it outside the signed body made it attacker-malleable: a validly-signed
  checkpoint could be relabeled to a different log's TSID and still pass
  `VerifyCheckpoint`, letting an attacker move a signed tree head between logs and
  defeat the non-equivocation tracking. C2SP / RFC 6962 checkpoints bind the
  origin line into the signed note for exactly this reason. Fixed: rewrite
  `checkpointSigPayload` to a domain-separated, 4-byte-length-prefixed encoding
  (`"blrcs-checkpoint-v1" ‖ TSID ‖ rootHash ‖ treeSize ‖ timestamp`) so the log
  identity is covered and variable-length fields cannot be confused for one
  another. Test: `TestCheckpointSignatureBindsTSID` confirms a genuine checkpoint
  verifies but the same checkpoint with a relabeled TSID fails with
  `ErrCheckpointSig`. (Sign and verify share the helper, so existing
  checkpoint/cosignature/witness tests stay green; checkpoints are ephemeral
  runtime artifacts, so there is no persisted-signature compatibility concern.)

- **`did:key` / multibase decoding accepted trailing bytes → DID identifier
  malleability (security / identity integrity, Axis 32).** `resolveDIDKey`
  length-checked the base58-decoded payload with `len < 2+32` and then sliced
  `decoded[2:34]`, and `base58Ed25519Decode` used `len >= 2+32` for its multicodec
  branch — both *accepted* payloads longer than the canonical 34 bytes (2-byte
  `ed25519-pub` multicodec + 32-byte key) and silently discarded the trailing
  bytes. The consequence is identifier malleability: `did:key:z<key>`,
  `did:key:z<key+0x00>`, `did:key:z<key+junk>`, … all resolve to the *same*
  issuer public key, so one key is addressable by infinitely many distinct DID
  strings. For a credential system where the DID *is* the issuer/holder identity,
  this breaks the 1:1 DID↔key invariant any allow/deny list or audit log relies
  on — a denied issuer could re-present under a non-canonical DID that maps to the
  same key, or two log entries for "different" DIDs could be the same principal.
  (The `'m'` multibase branch and `jwkToEd25519` were already strict; only the
  base58 paths were loose.) Fixed: require the EXACT length (`len != 2+32` →
  `ErrMalformedDID`) in both `resolveDIDKey` and the multicodec branch of
  `base58Ed25519Decode`, so only the canonical encoding is accepted. Tests:
  `TestResolveDIDKeyTrailingBytesRejected` confirms the canonical form still
  resolves while 1-, 2-, and 4-byte trailing suffixes are each rejected, and
  `TestBase58Ed25519DecodeTrailingBytesRejected` covers the multibase path. The
  existing too-short and wrong-multicodec tests remain green.

- **mdoc digest & device-auth comparisons were not constant-time
  (defense-in-depth / timing side-channel, Axis 31).** `mdoc/verify.go` defined a
  hand-rolled `equalBytes` with early-exit-on-first-mismatch behavior and used it
  in two security-critical paths: (1) the ISO 18013-5 MSO `valueDigests` check in
  `verifyItem` (SHA-256 digest of each disclosed `IssuerSignedItem` vs. the
  issuer-attested digest — tamper / substitution detection), and (2) the device
  authentication payload binding in `VerifyDeviceAuth` (the device-signed
  `DeviceAuthenticationBytes` vs. the verifier-reconstructed expected bytes —
  holder-binding / session-transcript check). A byte-by-byte comparison that
  returns as soon as it finds a mismatch leaks, through timing, *how many leading
  bytes matched*. While neither operand is a long-lived secret (digests are public
  once the credential is disclosed, and the binding payload is verifier-derived),
  an attacker who can submit forged credentials and measure verification latency
  could in principle use the digest comparison as an oracle to forge a colliding
  `IssuerSignedItem` byte-by-byte without ever seeing a valid signature — exactly
  the class of attack `crypto/subtle` exists to foreclose. Cryptographic
  comparisons should be constant-time unconditionally; relying on "this value is
  not secret today" is fragile. Fixed: replace both call sites with
  `crypto/subtle.ConstantTimeCompare(...) != 1` and delete the `equalBytes`
  helper. `ConstantTimeCompare` already returns 0 for length-mismatched inputs, so
  the length-guard semantics are preserved. No API or behavior change for valid
  credentials; the digest-mismatch and binding-mismatch rejection paths remain
  covered by `TestVerifyDigestMismatch`, `TestVerifyItemDigestMismatch`, and the
  device-auth tests.

- **`TieredClaims.Set` defaulted invalid tiers to `TierRestricted` instead of
  `TierAuthority` — wrong fail-safe direction in the ESPR access control model
  (security / data minimization, Axis 30).** `TieredClaims` is the central
  mechanism by which ESPR / Battery Reg 2023/1542 access tiers (public /
  restricted / authority) are assigned to DPP claims before SD-JWT issuance.
  When the caller supplied an unrecognised `AccessTier` string (e.g. a typo
  `"Authority"` instead of `TierAuthority`, or a value from an incorrect
  constant), the silent fallback was `TierRestricted` — the middle tier.
  Under ESPR's model, `TierRestricted` is accessible to recyclers and repairers;
  `TierAuthority` is accessible only to market-surveillance authorities and
  customs. A developer who intended to protect a supplier contract
  (`TierAuthority`) but misspelled the tier constant would silently produce a
  credential that exposes that secret to every certified recycler who requests
  it — a privilege escalation with no warning or error. The Apple principle
  "安全側に倒す" (fail toward the safe side) requires the fallback to be the
  *most* restrictive option when intent cannot be determined. Fixed: change the
  fallback from `TierRestricted` to `TierAuthority` and update the comment to
  explain the security rationale. Tests: `TestTieredClaimsInvalidTierFailsafe`
  now checks five different malformed tier strings (wrong case, empty string,
  etc.) and asserts each resolves to `TierAuthority`; the new
  `TestTieredClaimsInvalidTierNotExposedToRestricted` confirms the claim is
  invisible to `TierRestricted` viewers but fully visible to `TierAuthority`
  viewers.

- **`openid4vp.MemoryStore` GC goroutine leaked — no stop mechanism existed
  (reliability / goroutine leak, Axis 29).** `NewMemoryStore()` and
  `NewMemoryStoreWithCap()` each start a background `gcLoop` goroutine (5-minute
  ticker) to evict expired sessions. The goroutine ran for the lifetime of the
  process: there was no stop channel, no `Close()` method, and the goroutine held
  a reference to the store, so the store itself could never be garbage-collected
  either. In test suites that create many `Verifier` instances (each with its own
  implicit `MemoryStore`), goroutines accumulate until the test binary exits —
  causing false positives in goroutine-leak detectors and masking real leaks. In
  long-running servers that periodically create and discard verifiers (e.g. per
  tenant or per request), goroutines pile up indefinitely. Fixed: exported
  `MemoryStore` (formerly `memoryStore`), added `stop chan struct{}` and
  `once sync.Once` fields, changed `gcLoop` to `select` between the ticker and
  the stop channel, and added `Close() error` that closes the stop channel exactly
  once via `once.Do`. `NewMemoryStore()` and `NewMemoryStoreWithCap()` now return
  `*MemoryStore` (concrete, satisfies `SessionStore`), giving callers direct access
  to `Close()`. Added `Verifier.Close() error` that forwards to the store's
  `Close()` when the store implements `io.Closer`, leaving custom store
  implementations unaffected. Tests: `TestMemoryStoreCloseIdempotent` (two
  sequential closes, no panic), `TestMemoryStoreCloseStopsGC` (stop channel is
  closed after `Close()`), `TestVerifierCloseStopsStore` (verifier with implicit
  store), `TestVerifierCloseWithExternalStore` (custom store without `io.Closer`
  returns nil) — all pass under `-race`.

- **`atrest.Keyring` was not thread-safe — concurrent key rotation and
  encryption shared unprotected map/pointer fields (thread safety / AES-GCM
  key dispatch, Axis 28).** `Keyring.Add` and `SetActive` write to `k.ciphers`
  (a `map`) and `k.active` (a pointer); `Encrypt`, `Decrypt`, `HasKey`, and
  `ActiveKeyID` read those same fields — all without synchronisation. The key
  rotation use case (`SetActive` called at runtime after the keyring has already
  been shared across goroutines) is the primary reason the mutex is needed: a
  service that rotates AES-256-GCM keys while simultaneously processing
  encryption/decryption requests would trigger a data race, risking corrupted
  `active` pointer or map state and consequent plaintext exposure or goroutine
  crash. `Cipher.Encrypt` already used `atomic.Uint64` for the NIST nonce
  counter — the `Keyring` level (which routes calls to the right `Cipher`) was
  the missing layer. Fixed: added `mu sync.RWMutex` to `Keyring`; `Add` and
  `SetActive` acquire the write lock; `Encrypt`, `Decrypt`, `HasKey`, and
  `ActiveKeyID` acquire the read lock (releasing before delegating to
  `Cipher.Encrypt`, which is already concurrency-safe). New test:
  `TestKeyringConcurrentRotationAndEncrypt` — 200 key-rotation cycles,
  200 encrypt/decrypt cycles, and 200 `HasKey` calls running in parallel;
  passes cleanly under `-race`.

- **`cbor.coseVerifiers` global map had no mutex — data race between
  `RegisterVerifier` (write) and `Verify1` (read) under concurrent use
  (thread safety / Go map invariant, Axis 27).** Go's built-in map is not
  safe for concurrent reads and writes; concurrent access without
  synchronisation is a data race that can manifest as corrupted map state,
  infinite loops, or a runtime crash (`concurrent map read and map write`
  fatal). `coseVerifiers` is a package-level map that `RegisterVerifier`
  writes to and `Verify1` reads from; no mutex guarded either path. Any
  server that registers an extension algorithm at startup (or dynamically for
  crypto-agility) while handling concurrent COSE_Sign1 verifications would
  trigger this race. Fixed: added `coseVerifiersMu sync.RWMutex`; writes in
  `RegisterVerifier` acquire the exclusive lock, reads in `Verify1` acquire
  the shared lock. The hot path (verify — no concurrent registrations) pays
  only a single uncontended `RLock`/`RUnlock`. New test:
  `TestRegisterVerifierConcurrentWithVerify1` — 200 concurrent
  register/deregister cycles racing against 200 `Verify1` calls, passes
  cleanly under `-race`.

- **`replay.Detector.Close()` panicked on double-close — idempotency failure
  (reliability / Go channel pitfall, Axis 26).** `Close()` called `close(d.gcStop)`
  directly. In Go, closing an already-closed channel is an unconditional runtime
  panic. The idiomatic usage pattern — `defer d.Close()` combined with an explicit
  early-return close on an error path (or a component that also calls Close) — would
  trigger the panic and crash the process, taking the replay-detection service and
  any in-flight DPP issuance requests down with it. Fixed: added `closeOnce
  sync.Once` to the struct; `Close()` now calls `closeOnce.Do(func() { close(d.gcStop) })`.
  The GC goroutine terminates exactly once regardless of how many times or from how
  many goroutines `Close()` is called. Tests: `TestCloseIdempotent` (two sequential
  calls, no panic) and `TestCloseConcurrent` (10 goroutines calling Close in
  parallel, race detector clean).

- **`saga.compensate` used `defer cancel()` inside a for loop — timer goroutine
  leak for the entire duration of the compensation chain (resource management /
  Go pitfall, Axis 25).** `compensate()` looped over completed steps in reverse
  and, for each step whose parent context was cancelled, called
  `context.WithTimeout(context.Background(), 30s)` and then `defer cancel()`.
  In Go, `defer` executes at enclosing function return — not at the end of each
  loop iteration. For a saga with N completed steps whose context was cancelled,
  N timer goroutines were created and not cancelled until `compensate()` itself
  returned (after all N compensations had finished sequentially). Each 30-second
  timer goroutine was held live for the entire remaining compensation chain rather
  than being released promptly after its step finished. Fixed: extracted a
  `runCompensation()` helper that executes a single step; `defer cancel()` now
  fires when `runCompensation` returns (immediately after that step's
  `Compensate()` call), not accumulated until `compensate()`'s loop exit. Existing
  behavior is unchanged — compensations still get a fresh context when the parent
  is cancelled. Test: `TestCompensationContextIsLivePerStep` — 3 steps succeed,
  the 4th cancels the parent ctx and fails, triggering compensation; each of the
  3 compensations records whether its `compCtx` was live (`Err() == nil`) and
  asserts it was (proves the fresh context was provided and not pre-cancelled by
  a leaked timer).

- **`vctmeta.Resolve` did not verify that the fetched Type Metadata document's
  `vct` claim matched the requested URL — credential type-confusion attack
  (IETF SD-JWT-VC §5 compliance, Axis 24).** After fetching the metadata document
  from `vct` (e.g. `https://schema.europa.eu/dpp/sd-jwt-vc/v1`) and checking
  integrity (when provided), `Resolve` unmarshalled the JSON and returned without
  asserting `tm.VCT == vct`. A misconfigured CDN, compromised origin, or
  path-traversal response could serve a metadata document for type B (`"vct":
  "https://attacker.example.com/type"`) while being fetched as type A. The caller
  would then validate credential claims against B's JSON Schema instead of A's —
  either silently accepting invalid claims or falsely rejecting valid ones. The IETF
  SD-JWT-VC draft §5 requires: "the value of the `vct` claim in the metadata MUST
  be equal to the VC type identifier URL." Fixed: added `ErrVCTMismatch` sentinel
  and a check immediately after unmarshal in `Resolve()`; `ResolveChain` inherits
  the fix because it calls `Resolve` for every link. Tests:
  `TestResolveVCTMismatch` (server returns metadata with a foreign `vct` → error)
  and `TestResolveVCTEmptyInMetadata` (metadata has no `vct` field at all → error).

- **`kms.FileSigner.load()` and `storage.FileStorage.LoadKeyPair()` never verified
  that the stored public key matched the private key — silent keypair corruption
  (integrity, Axis 23).** Both functions read a 96-byte file (`pub(32) || priv(64)`)
  and copied the bytes into separate `pub`/`priv` fields without checking that
  `pub == priv.Public()`. A corrupted or partially-overwritten keyfile where bytes 0–31
  disagree with the derived public key would load silently; `Sign()` would produce
  signatures verifiable only under `priv.Public()`, while anything using the stored
  `pub` (including SCITT `Receipt.TSKey` and every `VerifyReceipt` call) would fail
  verification with no error surfaced at load time. Fixed: both functions now call
  `priv.Public().(ed25519.PublicKey)` and compare with `bytes.Equal`; a mismatch
  returns `ErrCorrupted` / a descriptive error immediately at startup, before any
  credential or receipt can be signed with the inconsistent pair. Tests:
  `TestFileSignerLoadPubKeyMismatch` (kms) and `TestFileStorageLoadKeyPairPubMismatch`
  (storage) each write a keyfile with a `differentPub || realPriv` payload and assert
  the loader returns an error.

- **`multiformats.CanonicalizeJSON` silently accepted JSON with duplicate keys —
  cryptographic-commitment integrity gap (JCS correctness, Axis 22).** Go's
  `json.Decode` is specified to take the last value when an object has duplicate
  keys and silently discard all earlier ones. `CanonicalizeJSON` decoded first and
  then re-serialized, so `{"a":1,"a":2}` canonicalized to `{"a":2}` without error.
  Any caller passing a raw JSON document to `CanonicalizeJSON` and using the output
  as a cryptographic commitment would commit to `2`, but the raw bytes say `1` first
  — a silent divergence between what is signed and what the document actually
  contains. In the context of did:webvh SCID derivation or Data Integrity proof
  binding, an adversary supplying a JSON document with strategically placed duplicate
  keys could craft a different canonical form than intended. Fixed by adding a
  token-by-token pre-scan (`detectDuplicateKeys` / `walkJSONTokens`) before the
  decode step; it returns `ErrJCSDuplicateKey` for any duplicate key at any nesting
  level. The `Canonicalize(v any)` path is unaffected (Go `map[string]any` cannot
  have duplicate keys). Tests: top-level and nested duplicate keys return the error;
  the same key in different nested objects (not a duplicate) still canonicalizes.

- **`httpchain.WithCORS` with `AllowedOrigins: ["*"]` reflected the incoming `Origin`
  header verbatim instead of emitting `Access-Control-Allow-Origin: *` (CORS footgun /
  future credentials-theft vector, Axis 21).** When the wildcard is configured the
  middleware computed `allow := true` and then wrote `w.Header().Set("Access-Control-Allow-Origin",
  origin)` — where `origin` is the attacker-controlled `Origin` header — instead of the
  literal token `"*"`. Functionally equivalent today (every origin is allowed either way),
  but a serious footgun: browsers permit `Access-Control-Allow-Credentials: true` only when
  the response carries an explicit origin, *not* `"*"`. If that header were ever added, any
  site on the internet could make credentialed cross-origin requests because the server would
  reflect their exact origin. Fixed: when `wildcard == true` the response is hardcoded to
  `*` and `Vary: Origin` is not set (the response is identical for every origin, so Vary is
  incorrect and would cause spurious cache misses). Per-origin allowlisting continues to
  reflect the matched origin and set `Vary`. Test: `TestCORSWildcardEmitsStarNotReflection`
  confirms the header is `"*"` (not the incoming origin) and that `Vary` is absent.

- **`didwebvh.verifyEntryProof` accepted proofs with any `proofPurpose` — key-purpose
  confusion attack (W3C Data Integrity §2.1 violation, Axis 20).** The verifier checked
  the cryptosuite, decoded the signature, and called `ed25519.Verify` but never asserted
  `p.ProofPurpose == "assertionMethod"`. Because `proofPurpose` is part of the signed data
  (included in `proofConfig` → `hashData`), a proof signed with `proofPurpose:
  "authentication"` by an authorized update key produces a cryptographically valid
  signature over a *different* hash — and the verifier accepted it. An attacker who could
  obtain a legitimate authentication challenge signed by the DID controller (e.g. during a
  WebAuthn or DIDComm flow) could replay it as a DID log-update proof. Fixed: added
  `if p.ProofPurpose != "assertionMethod" { continue }` before signature verification, so
  the loop skips every proof whose purpose is not the expected one for this operation.
  Test: `TestProofPurposeWrongRejected` builds an update entry signed with `proofPurpose:
  "authentication"` by the legitimate update key (a valid signature — the only thing
  stopping it is the purpose check) and asserts `ErrProofInvalid`.

- **`apiversion.MarkUsed` with `WarnRateLimit == 1` silently emitted zero deprecation
  warnings — the most aggressive setting disabled the safety signal entirely (off-by-one
  / modular-arithmetic, Axis 19).** The rate-limit guard was `if n%int64(rate) != 1
  { return }`, intended as "warn on the 1st call and every `rate` calls thereafter." For
  any `rate > 1` this is correct, but `WarnRateLimit: 1` means "warn on every call" — yet
  `n % 1` is always `0`, so `0 != 1` is always true and `MarkUsed` returned before ever
  warning. An operator who set the loudest possible deprecation warning got total silence,
  the exact opposite of intent, and a silent failure mode for a signal whose whole purpose
  is visibility. Fixed by switching the test to `(n-1)%int64(rate) != 0`, which is
  identical for every `rate > 1` (warns at n = 1, rate+1, 2·rate+1, …) but correctly warns
  on *every* call when `rate == 1`. Test: `TestMarkUsedRateLimitOne` asserts 5 calls with
  `WarnRateLimit: 1` produce 5 warnings; the existing `rate=10` and default-`rate=100`
  tests still pass, confirming no regression for the common path.

- **`metrics` Prometheus exporter did not escape label values or HELP text —
  exposition-format corruption and metric injection (output integrity, Axis 18).**
  `formatLabelsInner` wrote each label as `%s="%s"` with no escaping, and the `# HELP`
  lines interpolated the raw metric name verbatim. The Prometheus exposition format
  (https://prometheus.io/docs/instrumenting/exposition_formats/) requires label values
  to escape backslash (`\`→`\\`), double-quote (`"`→`\"`), and line-feed (`\n`→`\n`); HELP
  text must escape backslash and line-feed. A common label value carrying a `"` (e.g. a
  `version` string from `git describe`, or any value sourced from an env var) silently
  produced malformed output that breaks scrape parsing — and a value containing a newline
  let crafted content inject forged metric lines into the scrape (`1.0"} injected_total
  999\nevil{x="` becomes a fake `injected_total 999` series). Fix: added `escapeLabelValue`
  (escapes `\`, `"`, `\n`) applied to every label value, `escapeHelp` (escapes `\`, `\n`)
  applied to the interpolated name in HELP lines, and ran label *keys* through the existing
  `sanitize` so they always match the Prometheus name grammar. Both escapers fast-path
  values with no special characters. Tests: `TestLabelValueEscaping` confirms a malicious
  quote/newline/backslash value is escaped and cannot inject a metric line;
  `TestEscapeHelpAndLabelHelpers` unit-tests both escapers including the HELP rule that
  leaves `"` literal.

- **`jsonschema.Compile` did not pre-compile regex patterns — every `Validate` call
  re-compiled all `pattern` / `patternProperties` regexes from scratch, and an invalid
  regex silently became a per-call validation error instead of a fail-fast compile error
  (correctness / performance, Axis 17).** The `Schema` struct stored only the parsed
  schema tree; `checkString` and `checkObjectKeywords` called `regexp.Compile(p)` on
  every `Validate` invocation. For a VCT-metadata schema validated once per credential
  presentation (the `vctmeta.ValidateClaimsWithSchema` call path), the regex for each
  `pattern` / `patternProperties` keyword was compiled fresh on every call — O(N×M)
  compilations for N validations and M patterns. Beyond performance, the bigger
  correctness gap: `Compile()` accepted schemas with invalid regexes without error; only
  at validation time (for every future call) did they surface as `"invalid pattern … in
  schema"` validation errors — making an author mistake look like a data error. Fix:
  (1) Added `walkPatterns` which walks the full schema tree at `Compile()` time and
  pre-compiles every `pattern` (string keyword) and `patternProperties` key into a
  `map[string]*regexp.Regexp` stored on the `Schema` struct. Duplicate patterns across
  the tree share one compiled regexp. (2) `Compile()` now returns an error immediately
  on any invalid regex — fail-fast at schema load time. (3) `Validate` passes the
  pre-compiled map to the `validator` and all child validators (allOf/anyOf/oneOf/not/
  contains); `checkString` and `checkObjectKeywords` do a map lookup instead of
  compiling. Tests: `TestCheckStringInvalidPattern` and
  `TestCompileInvalidPatternPropertiesFails` verify fail-fast compile error;
  `TestPatternPrecompiledIsCached` verifies the pre-compiled map is shared correctly
  across duplicate patterns and that validation still accepts/rejects correctly.

- **`cbor` decoder pre-allocated array/map containers from the *declared* length
  before validating element bytes — a 5-byte header could force a ~256 MB allocation
  (allocation-amplification DoS, Axis 13 on the CBOR foundation).** `decode` capped the
  declared count at `maxItems` (16 M) and then immediately ran `make([]any, n)` /
  `make(map[any]any, n)`. A definite-length array header declaring 16,777,215 elements
  (`0x9a 0x00 0xFF 0xFF 0xFF`, just under the cap) is only 5 bytes but forces a 16 M-entry
  `[]any` (~256 MB) — and decoding then fails on the very next byte with "unexpected end
  of data," after the allocation already happened. Because `cbor.Unmarshal` sits under
  every COSE_Sign1, SCITT receipt, and ISO 18013-5 mdoc verification path, an
  unauthenticated peer presenting a malformed credential could repeatedly trigger
  multi-hundred-MB transient allocations and OOM the process. Byte/text strings were
  already safe (`readN` validates availability before `make`); only arrays and maps
  pre-sized from an untrusted count. Fix: before allocating, reject any array whose
  declared length exceeds the remaining input bytes (each element is ≥1 byte) and any map
  whose declared length exceeds (remaining bytes)/2 (each entry is a key + value, ≥2
  bytes). This bounds the container allocation to the actual input size while leaving all
  valid inputs unaffected. Tests: `TestDecodeArrayLengthExceedsInput` and
  `TestDecodeMapLengthExceedsInput` reject the sub-`maxItems` amplification headers;
  `TestDecodeArrayExactLengthStillWorks` confirms valid arrays decode unchanged.

- **`telemetry.Histogram.Observe` used `count % reservoirSize` for reservoir sampling
  — a deterministic circular-buffer that broke every percentile estimate (statistical
  correctness, Axis 15).** The comment read "reservoir sampling" but the replacement
  strategy was `h.samples[int(h.count.Load()) % histogramReservoirSize] = v`: for any
  second batch of 1024 observations this overwrites all 1024 slots in order, making the
  reservoir a rolling window of the most-recent 1024 values rather than a uniform random
  sample of all values seen. P50/P95/P99 were therefore only representative of the
  recent tail; for a DPP-issuance latency histogram with bursty traffic they could
  appear to drop dramatically even though the long-run distribution was unchanged —
  exactly the opposite of what a performance alert threshold should behave. Correct
  reservoir sampling requires Vitter's Algorithm R: for the n-th observation (n > k),
  pick a random j ∈ [0, n-1]; if j < k, replace samples[j]. This gives each past
  observation an equal k/n probability of surviving, producing an unbiased random
  sample regardless of arrival order. Fix: capture the atomic position `n :=
  h.count.Add(1)`, then use `rand.Int63n(n)` (`math/rand`, stdlib) in the replacement
  branch. Test: `TestHistogramReservoirSamplingIsRandom` fills the reservoir with
  `0.0` then sends 1024 observations of `999.0`; with the old deterministic code all
  zeros are overwritten (zeroCount == 0); with correct Vitter's approximately half
  survive — the probability of none surviving is < 10⁻³⁰⁰.

- **`compliance.VerifySDJWTWithBinding` had no issuer-binding check — a key-confusion
  attack let a verifier's trusted key validate a credential from a *different* issuer
  (key-confusion / open-key, Axis 14).** A verifier that held Ed25519 key Kₐ for
  issuer A could be fooled into accepting a token where `iss = B` if an attacker could
  obtain any other token also signed by Kₐ (shared key, compromised key material, or a
  verifier that calls `VerifySDJWTWithBinding` with a hard-coded public key rather than
  one looked up by DID). The verifier checked the signature but never confirmed that
  the `iss` claim in the payload actually corresponds to the issuer whose key it
  supplied — so a valid signature over `iss=B` was silently accepted by a verifier
  expecting `iss=A`. Added `VerifyOptions.ExpectedIssuer string`: when non-empty,
  `VerifySDJWTWithBinding` compares the JWT `iss` claim against the option and returns
  `ErrSDJWTIssuerMismatch` on mismatch — *after* the cryptographic signature check
  passes (so the guard cannot be bypassed by forging a signature). Empty (default) →
  backward-compatible, no check. `ErrSDJWTIssuerMismatch` is a new exported sentinel in
  `errors.go` following the existing `ErrSDJWT*` pattern. Tests:
  `TestVerifySDJWTExpectedIssuerMismatch` covers correct issuer (pass), empty issuer
  (pass, back-compat), wrong `ExpectedIssuer` (→ `ErrSDJWTIssuerMismatch`), and wrong
  verifier key (→ `ErrSDJWTSigFailed`, confirming the guard never short-circuits the
  crypto check).

- **`mcp` `issue_passport` accepted out-of-range `recyclability`, signing invalid data into a
  permanent credential (input-validation / schema drift).** `compliance.PassportClaim.Recyclability`
  is canonically a fraction in `[0,1]` and the tool's advertised `inputSchema` declares
  `minimum:0, maximum:1`, but the validator checked `0..100`. A client passing `recyclability: 85`
  (intending 85%) had it accepted and Ed25519-signed into a DPP as `85.0` — a nonsensical "8500%"
  value, immutable once issued. Tightened the bound to the real `[0,1]` range so the validator,
  the schema, and the underlying type agree. Test: `TestToolIssuePassportRecyclabilityFractionRange`
  asserts `85` is now rejected while `0.85` is still accepted (existing `200.0` rejection unchanged).

- **`mcp` audited tool calls *before* dispatch — rejected calls polluted the transparency
  ledger (forensic integrity + write-amplification DoS).** `handleToolCall` appended an audit
  leaf for every mutating tool (`issue_passport`, `attest_range`, `register_scitt`, `issue_sdjwt`)
  *before* the call ran, so a rejected call — unknown/unregistered issuer, invalid params, missing
  subject — still cost one Ed25519 signature plus a Merkle append and left a permanent entry in the
  append-only log for an operation that changed no state. An attacker who isn't even a registered
  issuer could flood the ledger with garbage and amplify write cost, directly undercutting the
  adjacent design note about not growing the ledger from cheap calls. Audit now fires only *after*
  a successful `dispatch`, so the immutable log records actual state changes only. Failed attempts
  belong in operational logs/metrics, not the cryptographic transparency log. Test:
  `TestFailedMutatingCallNotAudited` asserts four distinct rejected mutating calls (unknown issuer,
  negative carbon, unknown SCITT issuer, missing SD-JWT subject) leave the ledger size unchanged.

- **`mcp` HTTP session store grew without bound despite its "in-memory LRU" contract
  (resource exhaustion, Axis 10 lens on a new surface).** The doc comment promised an
  "in-memory LRU with idle expiry", but `sessionStore.create` was an unbounded map insert:
  sessions live up to `sessionIdleTimeout` (30m) and the background GC only sweeps every 5m,
  so a client issuing `initialize` repeatedly accumulates session entries far faster than they
  idle-expire — unbounded memory growth gated only by an *optional* rate limiter (none when
  `auth`/`limiter` are nil). Made it a real bounded LRU: new `defaultMaxSessions = 16384` cap
  enforced in `create` — it first reclaims any idle-expired entries, then, if still at capacity,
  evicts the least-recently-seen session, so the map can never exceed the cap regardless of
  request rate. New `HTTPHandler.SetMaxSessions(n)` tunes the bound (non-positive ignored so
  the guard can't be disabled); `gc()` now shares the same `evictIdleLocked` helper. Tests:
  cap is never exceeded and the oldest session is the one evicted (LRU); idle-expired entries
  are reclaimed before a live session is dropped; `SetMaxSessions` rejects non-positive values.

- **`scitt` Merkle recomputation was O(n) in checkpoint/root queries — DoS via
  repeated checkpoint requests (Axis 13).** `SignedCheckpoint()` and `Root()` both
  called `merkleRoot(l.leafHashes)` (O(n)) while holding the read mutex, even though
  `Register()` and `Get()` already used the `perfectSubtree`-memoizing `cachedRoot()`
  (O(log n) amortized). A client repeatedly calling the checkpoint endpoint could force
  O(n) Merkle recomputation per request with a O(1) request — and block the write mutex
  for longer. Fixed by replacing the uncached calls with `l.cachedRoot(len(l.leafHashes))`
  in both functions; correctness is asserted by `TestSignedCheckpointMatchesCachedRoot` and
  `TestRootMatchesCachedRoot` which verify bit-for-bit agreement with the reference
  `merkleRoot` for all tree sizes 1–50.
- **`scitt.VerifyReceipt` allocated unbounded slice before checking path length (resource
  exhaustion).** An untrusted receipt with an enormous `AuditPath` (e.g., 1 million entries
  in a JSON array) caused `make([][]byte, N)` allocation before the TS signature or
  inclusion-proof check caught the malformed receipt. A valid RFC 6962 audit path for any
  conceivable tree (up to 2^63 leaves) has at most 63 hashes; guard now rejects any path
  longer than 64 entries with `ErrBadReceipt` before allocating. Test:
  `TestVerifyReceiptOversizedAuditPathRejected` sends a 65-entry path.

- **`openid4vci.IssueCredentialWithProof` generated a rotated `c_nonce` but never
  stored it — nonce rotation was dead code, violating OpenID4VCI §6.3 (protocol
  correctness).** `newCNonce := randomB64(16)` was generated after successful
  issuance and returned to the wallet in the `CredentialResponse`, but `entry.cNonce`
  was never updated. For deferred issuance or multi-use token scenarios (where the
  wallet makes a second credential request with the same access token), the internal
  nonce stayed at the original value from the token exchange. Any subsequent proof
  JWT bound to the rotated `newCNonce` would be rejected with `ErrProofNonceMismatch`
  — effectively making the server's rotated nonce a lie. Fix: after signing, acquire
  the lock and update `entry.cNonce = newCNonce` before returning, so the stored
  challenge matches the nonce the server advertised. Test: `TestIssueCredentialWithProofRotatesCNonce`
  verifies the returned nonce differs from the original token-response nonce and that
  the internal entry reflects the rotated value.

- **`storage.FileStorage.SaveKeyPair` used `os.WriteFile` without fsync — same
  crash-safety gap as the `kms.FileSigner` fix, risking silent key destruction on
  power loss (key lifecycle, Axis 9).** `os.WriteFile` does not guarantee data
  durability before the file handle is closed: it opens the file, writes to the
  page cache, and closes it, but none of those steps flush to durable storage.
  `os.Rename` then moves the tmp file to `keypair.bin`. If the machine crashes
  between the rename and the OS flushing the file data, the directory entry
  `keypair.bin` exists (the rename itself is made durable by the subsequent
  `syncDir`) but its content may be zeros or partial bytes — the Transparency
  Service's Ed25519 private key is silently destroyed. All future SCITT receipt
  signing fails and the TS cannot rotate keys. An attacker who can trigger a
  controlled power-off immediately after a key rotation (cloud forced-stop, OOM
  reboot, UPS manipulation) exploits this window. Fix mirrors the `kms.FileSigner`
  crash-safety pattern already applied: `os.OpenFile` + explicit `Write` + `Sync`
  (flush file data to disk) + `Close` + `Rename` + `syncDir`. The comment in the
  original code stated "atomic write: tmp + rename" but was incomplete — `syncDir`
  alone ensures the rename is durable, not the key bytes written to the tmp file.
  Test: `TestSaveKeyPairNoStaleTemp` verifies no `.tmp` artefact survives and the
  key round-trips after reload.

- **`webhook.deliverOnce` drained subscriber response bodies without a size cap —
  rogue endpoint could stream infinite bytes and block all webhook delivery (resource
  exhaustion).** `io.Copy(io.Discard, resp.Body)` has no bound on bytes read. The
  subscriber-level `Timeout` creates a context deadline that cancels the body read
  when it fires, but a caller may set a large `Timeout` (e.g., 30 minutes) and the
  per-request context is the only protection: if the rogue server streams slowly
  (just fast enough to reset the idle timeout) and the subscriber `Timeout` is large,
  the draining goroutine can block for the full duration. Since `Publish` spawns one
  goroutine per subscriber and waits with `wg.Wait()`, a single adversarially
  configured subscriber can stall all webhook delivery for every event type during
  that window. Fixed by wrapping the body with `io.LimitReader(resp.Body, 64<<10)`:
  64 KiB is sufficient to drain any legitimate webhook ACK and allows connection
  reuse, but caps the worst-case read regardless of timeout. Test:
  `TestDeliverOnceBodyDrainIsBounded` confirms that a 1 MiB response body (16× the
  cap) returns promptly rather than blocking for seconds.

- **`openid4vci` credential endpoint leaked raw internal errors to unauthenticated
  callers — nonce oracle + signer info-disclosure (CWE-209, Axis 6).** `handleCredential`
  passed `err.Error()` verbatim as `error_description` in every failure path from
  `IssueCredentialWithProof`. Internal error strings — `"vci: sdjwt sign: ..."`,
  `ErrProofNonceMismatch`, `ErrInvalidProof`, signer/crypto library messages — were
  returned to any caller holding any Bearer token, including expired or forged ones.
  This turned the credential endpoint into a step-by-step proof-validation oracle: an
  attacker probing with crafted `proof` JWTs could distinguish nonce mismatch from
  signature failure from audience mismatch, reducing brute-force complexity. The token
  endpoint (line 668) already deliberately suppresses failure reasons with a comment
  about CWE-209; the credential endpoint undid that protection. Fix: all error paths
  now map to opaque client-safe messages via `errors.Is` dispatch. Additionally: parse
  and decode errors that previously echoed `err.Error()` (form parse, body read, JSON
  unmarshal) are replaced with generic strings. `ErrBadAccessToken` correctly returns
  401 with code `"invalid_token"` (not 400); `ErrInvalidProof`/`ErrProofNonceMismatch`
  return 400 with code `"invalid_proof"` per OpenID4VCI spec §10.3; signing failures
  return 500 `"server_error"`. Test: `TestHandleCredentialErrorsAreOpaque` confirms
  neither the 401 (bad token) nor the 400 (bad proof) paths expose any internal prefix.

- **`replay.Detector.evictOldest` evicted one entry per capacity-overflow, forcing
  O(n) map scan on every insertion under flood — write-lock DoS (Axis 10 resource
  exhaustion).** When `seen` reached `maxSize`, every new `Check` call held the write
  mutex while scanning all 100,000 entries to find and delete the single oldest one.
  An attacker flooding unique payloads keeps the map permanently at capacity, making
  every subsequent legitimate `Check` O(n) under an exclusive lock, blocking all
  concurrent readers and writers — including the GC goroutine that also holds the
  same lock. The lock contention collapses throughput proportionally to concurrent
  callers. The new two-phase bulk eviction: (1) sweep all TTL-expired entries — free,
  no replay-window loss; (2) if still at capacity, sort and delete the oldest
  `maxSize/10` entries in one pass — amortizing the O(n) scan cost 10,000-fold vs
  single-entry eviction at the default cap of 100,000. Existing `TestMaxSizeEvictsOldest`
  continues to pass (tiny map: batch still rounds up to 1). New tests:
  `TestBulkEvictionRemovesOldestBatch` verifies the batch path; 
  `TestBulkEvictionExpiredEntriesSweptFirst` verifies Phase 1 prevents unnecessary
  eviction of live replay-window entries.

- **`atrest.Cipher.Encrypt` had no per-key encryption counter — unbounded random-nonce
  GCM use degrades authentication after 2^32 calls (NIST SP 800-38D violation, Axis 8
  key lifecycle).** AES-256-GCM with 96-bit random nonces has a 2^96-size nonce space,
  but the birthday-bound collision probability reaches 2^-32 at approximately 2^32
  encryptions per key — well within reach of a busy credential store. A nonce collision
  (key, nonce) pair allows an adversary to XOR the two ciphertexts, recovering the XOR
  of plaintexts and permanently destroying the GCM authentication guarantee for those
  slots; `ErrIntegrityFail` can then be silently bypassed for forged ciphertexts
  targeting those slots. NIST SP 800-38D recommends treating 2^32 as the mandatory
  rotation trigger for random-nonce GCM. Added `maxEncryptionsPerKey = 2^32` enforced
  via an `atomic.Uint64` counter in `Cipher`. On the 2^32+1-st call `Encrypt` returns
  `ErrKeyExhausted` before generating a nonce, forcing callers to rotate via
  `Keyring.SetActive`. The sentinel is new (backward-compatible); existing code paths
  that catch `ErrIntegrityFail` are unaffected. Tests: `TestEncryptKeyExhaustedAfterLimit`
  pre-sets the counter and confirms `ErrKeyExhausted` is returned;
  `TestKeyringRotationAfterExhaustion` confirms that rotating to a new key via
  `Keyring.SetActive` resumes encryption and the new envelope round-trips correctly.

- **`compliance` W3C VC proof metadata (`proofPurpose`, `verificationMethod`) was not
  bound to the Ed25519 signature — post-issuance tampering undetectable (credential
  malleability, authentication scope).** `canonicalPayload` signed `@context`, `type`,
  `issuer`, `validFrom`, `validUntil`, `credentialSubject`, and `credentialStatus` — but
  excluded the `Proof` object entirely. A relay or storage layer could silently overwrite
  `proof.verificationMethod` (pointing to an attacker-controlled DID) or
  `proof.proofPurpose` (from `"assertionMethod"` to `"authentication"`) without
  invalidating the Ed25519 signature. Downstream systems that use `verificationMethod`
  to drive DID key lookup — standard verifier behaviour per W3C VC Data Model — would
  fetch the attacker-supplied DID document and accept a different key for future
  verifications. The W3C Ed25519Signature2020 Linked Data Proof specification requires
  that all proof option fields (except `proofValue` itself) be included in the signed
  bytes. Fix: (1) `canonicalPayload` now includes `proofPurpose` and
  `verificationMethod` from `cred.Proof` when set; (2) `Issue` and `IssueWithStatus`
  pre-set these fields on the Proof object *before* calling `canonicalPayload`, so
  they are bound at signing time; (3) `VerifyAt` asserts `ProofPurpose ==
  "assertionMethod"` after signature verification, preventing purpose-confusion
  attacks where a key-agreement proof is replayed as an assertion proof. Tests:
  `TestProofMetadataMalleabilityRejected` verifies that tampering either field after
  issuance breaks signature verification; `TestProofPurposeEnforced` verifies that a
  wrong purpose is rejected independently of the signature check.

- **`openid4vp.memoryStore` grew without bound — unauthenticated `CreateRequest` floods could
  exhaust heap (resource exhaustion, Axis 10 on a new surface).** `memoryStore.Save` was an
  uncapped map insert: an unauthenticated caller could issue unlimited `CreateRequest` calls,
  each reserving a 200-byte `memEntry` under a unique random `state` key. The GC loop runs
  every 5 minutes; during the 10-minute `DefaultTTL` window an attacker can accumulate entries
  far faster than they expire — no server-side authentication required, just repeated HTTP
  POSTs. Added `defaultMemStoreMax = 50_000` (≈10 MB) enforced inside `Save`: if at capacity,
  one expired entry is swept first to reclaim space; if still full, `Save` returns
  `"openid4vp: session store full"`. Live unexpired sessions are never silently evicted —
  returning an error is preferable to dropping an in-flight authentication flow. New
  `NewMemoryStoreWithCap(n)` (non-positive → default) enables lower limits in tests and
  constrained deployments. Tests: cap never exceeded with all-live entries; an expired entry
  is swept to admit a new save; non-positive cap falls back to default.

- **`kms.FileSigner.save()` was not crash-safe — missing fsync and syncDir after rename
  risked silently regenerating the signing key after a power failure (key lifecycle, Axis 9).**
  `save()` called `os.WriteFile` which does not guarantee data durability before the rename: a
  crash in the flush window could leave the key file absent or truncated, causing the next
  `NewFileSigner` call to silently generate a *new* Ed25519 key — invalidating every credential,
  SCITT receipt, and SD-JWT issued under the previous key with no error. The fix follows the
  identical pattern already used in `storage.FileStorage.SaveKeyPair`: (1) write to `<path>.tmp`
  using `os.OpenFile` with explicit `Sync()` to flush data to disk, (2) `os.Rename` for atomic
  name-swap, (3) `syncDir(filepath.Dir(path))` to flush the directory entry. Without step 3 the
  rename is in the page cache and can be lost on sudden power loss even after the file data is
  durable. Added `syncDir` helper (identical to the one in `storage`). Test:
  `TestFileSignerSaveIsAtomic` verifies no stale `.tmp` artefact survives a clean write and the
  key file round-trips correctly after reload.

- **`webhook` SSRF guard was bypassable via DNS rebinding + missed the CGNAT range.**
  `validateOutboundURL` resolved DNS and checked the result, but the HTTP transport
  re-resolved at connection time, so a low-TTL DNS record could pass validation and
  then rebind to a private/loopback or `169.254.169.254` cloud-metadata address when
  the client actually dialed (a TOCTOU; the check and the connection used independent
  resolutions). Delivery now enforces the policy at *dial* time via a guarded
  `DialContext` that resolves once and connects only to the validated IP, so the
  address the policy approved is the address dialed. Also added the RFC 6598
  carrier-grade-NAT range `100.64.0.0/10` (reachable inside cloud networks but not
  flagged by `net.IP.IsPrivate`) to the blocklist, refactored into a shared
  `isBlockedIP` used by both the URL check and the dialer. Tests: `isBlockedIP` covers
  loopback/RFC1918/link-local/CGNAT/IPv4-mapped/IPv6-ULA and admits public IPs; the
  dialer rejects loopback and metadata literals and steps aside when
  `AllowPrivateTargets` is set.

- **`openid4vci` issuer leaked memory without bound — abandoned offers/tokens were
  never evicted (resource exhaustion, Axis 10).** The `preAuths` and `tokens` maps
  only shrank on the success/burn paths: an offer created but never redeemed, or an
  access token issued but never used to fetch a credential, stayed in the map forever
  — well past its TTL. Over time (normal abandoned flows; faster under load) this is
  unbounded growth and a DoS surface, unlike the `openid4vp` session store which
  already swept expired state. Added a time-gated lazy sweep (`gcExpiredLocked`,
  amortized O(1), at most once per minute) invoked from `CreateOffer*` — the only
  path that adds entries — evicting expired pre-authorized codes (`expiresAt`) and
  access tokens (`tokenExpiresAt`), bounding both maps to "unexpired entries + the
  current burst." No background goroutine (so no goroutine leak per `Issuer`). Tests
  assert an expired abandoned offer and an expired abandoned token are both evicted
  on the next `CreateOffer`.
- **DID resolution collapsed a multi-key DID document to its first key — issuer
  key rotation was unverifiable (key-lifecycle gap).** `parseDIDDocument` returned
  the *first* Ed25519 verification method only, and `Resolve` returned a single key.
  A DID document legitimately lists several keys — most importantly during rotation,
  where the old and new keys co-exist — so a credential signed by any non-first key
  failed to verify even though its key was published and trusted. Added rotation-aware
  resolution, fully wired through the verify path so it is actually exercised:
  - `Resolver.ResolveAll` returns every Ed25519 key in the document (document order,
    de-duplicated); `Resolve` now returns `ResolveAll()[0]` (back-compat). The cache
    stores the full key set.
  - `ResolveAndVerifyAll` returns the trust-anchored subset of resolved keys.
  - `compose.VerifyByDID` / `VerifySDJWTByDID` now try each trusted key until one
    verifies the signature, so a credential signed by the old key still verifies
    while the new key is listed first.
  - Tests: `ResolveAll` returns both keys (and `Resolve` still returns the first);
    `ResolveAndVerifyAll` returns only trusted keys / `ErrNotTrusted` when none;
    and a compose E2E where a credential signed by the second-listed (old) key
    verifies after rotation.

### Added
- **`didresolver.TrustAnchor` trust can now be revoked (`RemoveDID` / `RemoveKey` /
  `Reset`) — key-lifecycle gap.** The trust store was append-only: `AddDID`/`AddKey`/
  `AllowAll` had no inverse, so a compromised or rotated issuer key (or an accidental
  `AllowAll`) stayed trusted forever — an operator had no way to un-trust it without
  rebuilding the process. A trust decision that cannot be reversed is an operational
  hazard. Added `RemoveDID(did)` and `RemoveKey(pub)` (no-ops on unregistered
  entries) and `Reset()` (clears all DIDs, keys, and `allowAll` — an emergency stop
  returning the anchor to secure-by-default "trust nothing"). Tests: removed DID/key
  no longer trusted, removal is targeted (other entries survive), and `Reset` clears
  an accidental `AllowAll`.
- **`MockWallet` now exercises the JAR defense end-to-end (`VerifierKey`).** The
  signed-request capability added above was unreachable from the bundled wallet —
  `MockWallet.Present` still read `nonce`/`client_id` from the *unsigned* query
  params, so the secure path had no end-to-end exercise and a relay tamper of those
  params would still have fooled it. New `MockWallet.VerifierKey ed25519.PublicKey`:
  when set, `Present` requires a signed request object, verifies it with
  `VerifyRequestObject`, and binds the KB-JWT to the **authenticated** nonce/client_id
  only. Unset → legacy unsigned behavior (back-compat). Tests prove the contrast:
  `TestJARE2E_RelayNonceTamperDefeated` (JAR wallet ignores a substituted nonce →
  verifier still accepts) vs `TestJARE2E_LegacyWalletFooledByNonceTamper` (legacy
  wallet binds to the tampered nonce → verifier rejects) — the exact exposure JAR
  closes — plus happy-path and "refuses an unsigned request" cases.
- **OpenID4VP signed Authorization Requests (RFC 9101 JAR, by value) — closes the
  unauthenticated-request relay gap (Axis 8: authentication scope).** Auditing
  through an authentication-scope lens — "what data does the verifier/wallet act
  upon that is NOT inside a signed envelope?" — found mdoc (Document↔MSO docType,
  deviceAuth↔docType, item↔namespace) and the `state`/`presentation_submission`
  handling all correctly bound, but surfaced one real, high-severity gap: the
  Authorization Request was sent as **unsigned** query parameters. The wallet binds
  its KB-JWT `aud` to a `client_id` it reads from that unauthenticated request, so a
  relay attacker can keep the genuine `client_id` while substituting their own
  `response_uri` — and the wallet has no way to detect it (the known OpenID4VP
  cross-device/relay threat). RFC 9101 exists precisely for this.
  - New optional `Verifier.RequestSigningKey ed25519.PrivateKey`. When set,
    `CreateRequest`/`CreateRequestDCQL` additionally emit a `request` parameter
    carrying the whole request as an Ed25519-signed JWT
    (`typ=oauth-authz-req+jwt`); the unsigned params remain for non-JAR wallets.
  - New wallet-side `VerifyRequestObject(requestURL, verifierPub)` verifies the
    signature, pins `alg=EdDSA`/`typ` (no header-dispatched verifier → no
    alg-confusion), enforces `exp`, and requires the signed `client_id` to match
    the top-level `client_id` (binds the dispatcher to the signed content). It
    returns the **authenticated** `response_uri`/`nonce`/`client_id`, so a wallet
    that rewrites where it POSTs based on the signed object defeats the relay.
  - Pure Ed25519 + JSON + base64url (same primitives as the SD-JWT issuer); zero
    new dependencies. Fully backward-compatible: no signing key → unsigned request
    exactly as before.
  - Tests: round-trip; tampered-`response_uri` param has no effect on the
    authenticated value; tampered signed payload, wrong verifier key, `client_id`
    mismatch, and `alg`/`typ` confusion (`none`/`HS256`/wrong-typ) each rejected;
    missing-request-object reported distinctly; unsigned back-compat.
- **Cross-protocol / cross-credential signature-confusion regression tests
  (domain separation).** Auditing through a domain-separation lens — "when one key
  signs several message types, or material from one credential is grafted onto
  another, is the confusion rejected?" — surfaced two real, previously-untested
  confusion surfaces (both currently defended, neither pinned):
  - `TestCrossCredentialDisclosureRejected` (compliance): a disclosure minted for
    credential A grafted onto a presentation of credential B is rejected outright
    (its digest is absent from B's issuer-signed `_sd`) — never silently dropped.
  - `TestReceiptCheckpointSigNotTransferable` (scitt): the Transparency-Service key
    signs both receipts and checkpoints (shared `RootHash` prefix); the test pins
    that a checkpoint signature does not verify a receipt and vice versa.
- **Downgrade-resistance regression test for the holder-binding path.** Auditing the
  KB-JWT verifier through an algorithm-confusion lens confirmed it pins `alg=EdDSA` +
  `typ=kb+jwt` and verifies with hardcoded Ed25519 (no header-dispatched verifier) —
  but only the wrong-`typ` branch of that guard was tested; the **alg-downgrade**
  branch (correct typ, `alg` = `none`/`HS256`/`RS256`/empty) was not. Added
  `TestKeyBindingRejectsAlgDowngrade` so a future refactor that loosened the
  holder-binding alg check (e.g. a header-dispatched registry) cannot silently
  reintroduce alg-confusion. The issuer-JWT (`alg=none`), `_sd_alg`, and COSE
  downgrade paths were already covered.
- **Adversarial-robustness fuzzing of the hardened verification entry points.** The
  hardening pass added parsers that consume attacker-controlled bytes — the KB-JWT
  segment (`VerifySDJWTWithBinding`), the mdoc `deviceSigned` CBOR (`VerifyDocument`),
  and the OpenID4VCI proof JWT (`verifyProofJWT`) — none of which the existing fuzz
  suite exercised (it covered only the non-binding `VerifySDJWT`, IssuerSigned-only
  `mdoc.Verify`, and DCQL parsing). Added `FuzzSDJWTKeyBinding`, `FuzzMdocDeviceAuth`
  (in `fuzz/`), and white-box `FuzzVerifyProofJWT` (in `openid4vci/`). Each ran clean
  (no panic; tens of thousands of execs, dozens of interesting inputs), confirming the
  new entry points fail safe on malformed input — closing a robustness gap that the
  logical-correctness tests could not see. (17 → 20 fuzz targets.)
- **Fuzzing of the RFC 9101 JAR request-object parser (`FuzzVerifyRequestObject`).**
  `VerifyRequestObject`, added this session for signed Authorization Requests, parses
  an attacker-suppliable request URL (the signed `request` JWT rides in a query
  parameter) but had no fuzz coverage — the same untrusted-input-parser gap the
  hardening pass closed for the other new entry points. Added a black-box fuzz target
  (in `fuzz/`) seeded with a valid signed request plus malformed URLs/JWTs; it ran
  clean (300k+ execs, ~170 interesting inputs, no panic) against both a real and a nil
  verifier key, confirming the JAR parser fails safe.
- **`openid4vci` credentials can now carry a revocation status.** `IssueCredentialWithProof`
  always issued without a `status_list` reference, so VCI-issued credentials could
  never be revoked. New `OfferOptions{Status}` (via `CreateOfferWithOptions`) records a
  status reference on the offer; issuance then selects the right credential shape —
  holder-bound + revocable when proof-of-possession is present, bearer + revocable
  otherwise — connecting the compliance bound/status methods to the VCI layer.
  `CreateOffer`/`CreateOfferWithTxCode` are unchanged delegators. Tests cover the
  proof-bound+revocable and bearer+revocable paths.
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
  `TestHardenedTriangle_RevocationLifecycle` extends this across the full credential
  lifecycle: a VCI-issued holder-bound + revocable credential verifies while valid,
  then is rejected in-flow with `ErrCredentialRevoked` once the issuer flips its
  status-list bit.
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
- **`issueSDJWT` accepted `sdClaims`/`clearClaims` overlap and reserved-name
  injection without error — credential broken silently at issuance (Axis 7).**
  Two missing guards in `issueSDJWT`:
  - A claim appearing in both `sdClaims` and `clearClaims` was accepted by the
    issuer: the JWT embeds the clear value AND creates a disclosure. At verify
    time, `ErrSDJWTMalformed` fires when the disclosure's name collides with
    the already-present clear claim. The credential subject never knows the
    credential was already broken.
  - A reserved JWT/SD-JWT claim name (`iss`, `sub`, `vct`, `iat`, `exp`,
    `_sd`, `_sd_alg`, `cnf`, `status`) in `sdClaims` was similarly accepted
    at issuance but always rejected at verification — the verifier's
    disclosure-reserved-name guard fires but the issuer never warned the caller.
  
  Both cases now return a clear error from `issueSDJWT` at the moment of
  signing, before a bad credential is ever produced. The existing `clearClaims`
  reserved-name check was extended to `sdClaims`, and a new cross-map overlap
  check was added. Tests: `TestIssueSDJWTSDClaimReserved` (each reserved name
  → error), `TestIssueSDJWTClearSDOverlap` (same key in both maps → error).

- **KB-JWT has no standalone freshness guarantee — `openid4vp` `ProcessResponse`
  never set `MaxKBAge` (Axis 6: temporal integrity).**
  The SD-JWT specification (§KB-JWT) requires verifiers to enforce that a
  key-binding JWT is freshly generated for the current transaction — a wallet
  must not pre-generate KB-JWTs and cache them. `VerifyOptions.MaxKBAge` already
  existed and the underlying `verifyKBJWT` already enforces it, but `ProcessResponse`
  never wired the field: `MaxKBAge` was always 0, so KB-JWTs of any age were
  accepted as long as the nonce matched. Fixed: `ProcessResponse` now sets
  `MaxKBAge: v.DefaultTTL` (10 min default), binding KB-JWT freshness to the
  session lifetime. A wallet that somehow holds a nonce and presents a 30-minute-old
  KB-JWT is rejected. Test: `TestStaleKBJWTRejected` presents a KB-JWT with
  `iat = 30 minutes ago` and asserts rejection.
- **`c_nonce_expires_in` advertised longer than access token lifetime —
  `openid4vci` token endpoint.**
  Both the `ExchangeCode` and `IssueCredentialWithProof` responses hard-coded
  `c_nonce_expires_in: 600` (10 minutes) while `tokenTTL` is 300 s (5 minutes).
  A compliant wallet that caches the c_nonce for up to the advertised 600 s would
  find its access token already expired by T+300s, causing a confusing
  authentication error when it tries to use the still-"valid" nonce. Fixed: both
  responses now set `c_nonce_expires_in = int(iss.tokenTTL.Seconds())` so the
  advertised nonce window never exceeds the token window. Test:
  `TestCNonceExpiresInMatchesTokenTTL` asserts `c_nonce_expires_in ≤ expires_in`.

- **Information disclosure at HTTP trust boundaries (CWE-209) — `openid4vp` and
  `openid4vci` handlers.**
  Both HTTP endpoints returned verbatim internal error messages to the client,
  giving an attacker a free oracle for probing the system:
  - `CallbackHandler` propagated `ProcessResponse`'s raw error text, so an
    attacker presenting forged credentials could distinguish "issuer unknown" /
    "signature mismatch" / "revoked" / "claim missing" by reading the 400
    response body — narrowing a forgery or replay attack step by step.
  - The VCI token endpoint propagated the `ExchangeCodeWithTxCode` error, so a
    holder of a stolen pre-authorized code could confirm whether a guessed PIN
    was "wrong PIN" vs "code already consumed", accelerating a brute-force.
  
  Fix: both handlers now return a single generic message to the client
  (`"presentation verification failed"` / `"pre-authorized_code or tx_code
  invalid"`). Server-side detail is preserved via the new optional
  `Verifier.OnVerifyError func(error)` hook so operators can log/audit without
  leaking to the wire. Tests assert the generic string reaches the client AND
  the full error reaches the hook.

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
