# Changelog

All notable changes to BLRCS are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
