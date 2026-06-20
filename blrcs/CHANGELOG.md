# Changelog

All notable changes to BLRCS are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
