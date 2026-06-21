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
- `did:webvh` DIDs carry a verifiable history. A resolver MUST: derive and match
  the genesis SCID (`base58btc(multihash(sha-256(JCS(genesis with {SCID}))))`);
  verify each entry's `entryHash` chains from its predecessor `versionId`;
  enforce sequential version numbers and monotonic `versionTime`; verify each
  entry's `eddsa-jcs-2022` Data Integrity proof against an authorized `updateKey`;
  and enforce key pre-rotation (a newly-effective update key MUST be committed in
  the predecessor's `nextKeyHashes`).

## 2. Credential issuance (SD-JWT VC)
- Issued credentials are SD-JWT VCs: a JWS over a JSON payload, `~`-separated
  disclosures, optional trailing KB-JWT.
- The issuer JWT header MUST set `alg` (EdDSA) and `typ` (`vc+sd-jwt`).
- The payload MUST contain `iss`, `vct`, `iat`, and `_sd_alg` (`sha-256`); it
  MUST contain `exp` when a validity period is given.
- Selectively-disclosable claims MUST be salted (≥128-bit CSPRNG salt), digested
  with SHA-256, and listed in `_sd`; their disclosures are appended after `~`.
- Holder binding (optional): when requested, the payload MUST carry `cnf.jwk`
  (OKP/Ed25519) bound to the holder key. A verifier resolving `cnf.jwk` MUST pin
  the key type (`kty="OKP"`, `crv="Ed25519"`) before using the `x` value — it
  MUST NOT reinterpret the `x` of a different key type as an Ed25519 key.
- Status (optional): when a status reference is given, the payload MUST carry
  `status.status_list` with `idx` and `uri` (draft-ietf-oauth-status-list).

### 2a. Credential issuance (ISO 18013-5 mdoc / mDL)
- An mdoc credential is an `IssuerSigned` structure (CBOR): `nameSpaces` mapping
  each NameSpace to an array of `IssuerSignedItemBytes` (`#6.24(bstr .cbor
  IssuerSignedItem)`), plus an `issuerAuth` COSE_Sign1 over the
  MobileSecurityObject (MSO).
- Each `IssuerSignedItem` MUST carry a `digestID`, a ≥16-byte CSPRNG `random`
  salt, an `elementIdentifier`, and an `elementValue`.
- The MSO MUST set `version` (`1.0`), `digestAlgorithm` (`SHA-256`),
  `valueDigests` (NameSpace → DigestID → SHA-256 of the corresponding
  `IssuerSignedItemBytes`), `docType`, and `validityInfo`
  (`signed`/`validFrom`/`validUntil` as tdate). It MAY carry `deviceKeyInfo`
  (`deviceKey` as COSE_Key) for holder binding.
- A verifier MUST verify the `issuerAuth` signature, enforce `version` /
  `digestAlgorithm`, enforce the validity window, and confirm every disclosed
  item's SHA-256 digest matches the MSO `valueDigests` entry for its `digestID`.
- Selective disclosure: a holder MAY drop items from `nameSpaces`; the credential
  still verifies (MSO attests to the full digest set).

## 3. Credential verification — normative rules
A verifier MUST:
1. Parse the issuer JWS header and verify `alg` is **supported** (reject
   `none`/unknown → `ErrSDJWTUnsupportedAlg`); verify the issuer signature.
2. Reject a payload whose `_sd_alg` is present and **≠ `sha-256`**
   (`ErrSDJWTUnsupportedHashAlg`); absent `_sd_alg` defaults to sha-256.
3. Require `vct` (SD-JWT-VC) → else `ErrSDJWTMissingVCT`.
4. Enforce `exp`/`iat` with bounded clock skew (≤60s) →
   `ErrSDJWTExpired` / `ErrSDJWTNotYetValid`. A NumericDate claim (`exp`/`iat`/
   `nbf`) that is **present but not a JSON number** MUST be rejected as malformed
   (`ErrSDJWTMalformed`), never silently ignored — ignoring a string-typed `exp`
   would disable expiry enforcement (fail-open).
5. Reject **duplicate digests** in `_sd` (`ErrSDJWTDuplicateDigest`); accept a
   disclosure only when its SHA-256 digest is present in `_sd`.
6. When `cnf` is present (or key binding is required), require and verify a
   trailing **KB-JWT**: holder signature over `nonce`/`aud`/`sd_hash`, with
   `sd_hash` = SHA-256 of the presentation up to and including the final `~`.
7. Never let reserved claims (`_sd`, `_sd_alg`, `cnf`, `status`, …) leak into the
   returned claim set.
8. Reject a JWS whose header carries a `crit` field (RFC 7515 §4.1.11) —
   BLRCS implements no JWS extensions, so any critical parameter is unsupported
   (`ErrSDJWTCritUnsupported`). The KB-JWT header is held to the same rule.
A bare JWS without `~` MUST verify as a credential with no disclosures (no panic).

## 4. Status / revocation
- The status list is a SHA-compressible bit array (W3C Bitstring, ≥16KB for herd
  privacy). Decode MUST bound compressed input and decompressed output
  (anti-bomb).
- The list SHOULD be published as a signed **Status List Token** (`statuslist+jwt`)
  carrying `sub` (= the credential's `status.uri`), `iat`, and `exp`/`ttl`.
- A verifier checking status MUST authenticate the token, bind its `sub` to the
  credential's `status.uri` (`ErrStatusListMismatch`), and read the bit at `idx`.
- **Issuer-metric privacy:** because `0` ("not revoked") is the status of both an
  unissued index and a valid credential, the published list does not by itself
  reveal issuance volume — *unless* indices are assigned sequentially, in which
  case the largest revoked index ≈ issuance volume and a credential's index is
  monotonic in issuance time. Issuers SHOULD therefore assign status indices
  **uniformly at random** from a fixed-size space (`revocation.IndexAllocator`),
  which spreads revoked bits across the whole list and decouples an index from
  both issuance volume and ordering. The residual leak — the absolute *count* of
  set bits — is irreducible for a plain bitstring and requires an accumulator /
  padded Bloom-cascade (CRSet); see backlog #11.

## 5. Presentation (OpenID4VP)
- `CreateRequest`/`CreateRequestDCQL` MUST generate a fresh `nonce` + `state` and
  persist them with a TTL; `state` MUST be one-time (consumed on use).
- `ProcessResponse` MUST verify the vp_token per §3, bind it to the request
  `nonce`+`client_id` via KB-JWT when the credential is holder-bound, enforce all
  `RequiredClaims` are disclosed, and consume `state`.
- HTTP responses carrying credentials, verified claims, access tokens, or
  per-session secrets (nonce/state) MUST set `Cache-Control: no-store` so they
  are never retained by a browser, shared proxy, or CDN (cf. RFC 6749 §5.1 for
  token responses). This covers the OpenID4VCI `/token` and `/credential`
  endpoints and the OpenID4VP authorize/callback handlers.

## 6. Transparency (SCITT)
- `Register` MUST durably persist, then update the in-memory Merkle tree, then
  sign a Receipt (inclusion proof). Ordering MUST hold under failure.
- The log MUST provide inclusion and consistency proofs.
- Receipts SHOULD be available as **COSE_Sign1** (tag 18, RFC 9052) structures for
  IETF SCITT interoperability; the JSON+Ed25519 format remains supported for
  backward compatibility. `IssueCOSEReceipt` / `VerifyCOSEReceipt` implement this.

## 8. CBOR / COSE foundation
- A minimal zero-dependency CBOR encoder/decoder (`cbor` package, RFC 8949) MUST
  support: major types 0–7, definite-length arrays/maps, tag 18 (COSE_Sign1), and
  deterministic encoding (integer keys sorted numerically, string keys sorted by
  encoded length then lexicographically per RFC 8949 §4.2.1).
- `cbor.Sign1` / `cbor.Verify1` MUST use Sig_Structure (RFC 9052 §4.4) with
  algorithm pinning (reject absent or unknown `alg`). Additional algorithms MAY be
  registered via `cbor.RegisterVerifier` without modifying the core package.
- `cbor.Verify1` MUST reject a protected-header `crit` field (RFC 9052 §3.1, label
  2) that lists any label it does not understand, or that is malformed/empty
  (`ErrCOSECritUnsupported`). BLRCS understands only the algorithm label.

## 7. Cross-cutting
- Zero external dependencies (stdlib + Ed25519 only). Crypto agility: additional
  JWS `alg`s MAY be registered via `RegisterJWSVerifier` without a core dep.
- All HTTP servers SHOULD set Read/Write/Idle timeouts and body-size limits.
- At-rest encryption (`atrest`) uses AES-256-GCM with random 96-bit nonces. An
  encryptor MUST enforce the NIST SP 800-38D limit of 2^32 encryptions per key
  (`ErrKeyExhausted`). Because the in-memory counter resets on restart, a key
  reused across process lifetimes MUST persist and restore the count
  (`NewCipherWithCount` / `EncryptionCount`) to keep the bound cumulative, or
  rotate keys well before the limit.

## 9. Resource bounds (DoS resistance)
Every parser that consumes attacker-influenced input MUST bound the work and
memory it commits **before** completing authentication of that input. Normative
bounds:
- **Untrusted bytes are signed only in part.** Where a signature covers only a
  prefix of the wire string (e.g. an SD-JWT JWS covers `parts[0]` but the `~`
  disclosure trailer is editable), the parser MUST cap the structural size of the
  *unsigned* remainder before allocating proportionally to it. SD-JWT
  verification MUST reject inputs with more than 256 `~`-separated segments
  (`ErrSDJWTTooManyDisclosures`) before `strings.Split`.
- **HTTP bodies MUST be capped** with `http.MaxBytesReader` (or an
  `io.LimitReader`) before parsing: OpenID4VCI token endpoint ≤64 KiB, credential
  endpoint ≤1 MiB; OpenID4VP callback ≤4 MiB; MCP ≤16 MiB; `did:web` document
  fetch ≤64 KiB.
- **In-memory stores MUST be bounded.** The DID-resolution cache, OpenID4VP
  session store, OpenID4VCI offer/token maps, and replay detector MUST each cap
  their entry count and evict (TTL purge or refuse-when-full) so an attacker
  presenting many distinct items cannot exhaust memory.
- **Compression MUST be bomb-guarded.** Status-list decode bounds both compressed
  input (≤8 MiB) and decompressed output (≤64 MiB) via `io.LimitReader`.
- **Recursive decoders MUST bound depth.** CBOR (≤64), JCS (≤512), and JSON
  Schema `$ref` (≤64) enforce explicit depth/complexity ceilings.

## 10. Outbound HTTP (SSRF resistance)
All outbound HTTP fetchers that take attacker-controllable URLs (webhook
delivery, `did:web` document resolution, SD-JWT-VC Type Metadata, schema-URI
resolution) MUST:
- restrict the scheme to `http`/`https`,
- refuse 3xx redirects in their default client (`CheckRedirect` returning a
  sentinel error such as `didresolver.ErrRedirectNotAllowed` /
  `vctmeta.ErrRedirectNotAllowed`), because the canonical document path is
  fixed by spec (W3C did:web well-known) or pinned by an integrity hash
  (`vct#integrity`, SRI) — a redirect would either silently break the
  URL→content binding the hash guards or let a malicious host bounce the fetch
  into a private/loopback/cloud-metadata target,
- where the caller may supply a custom `*http.Client`, respect that client's
  redirect policy as-is (the caller is in charge).

Webhook delivery additionally enforces DNS-revalidating dial (`safeDialContext`
in `webhook.Bus`) so an allowlisted host with a low-TTL record cannot rebind
between the URL check and the connect (DNS-rebinding TOCTOU).

## 11. Rate limiting & client identity
- The per-client rate limiter (`httpmw.RateLimiter`) MUST key buckets on the
  client **IP only**, never on `r.RemoteAddr` verbatim. Go's HTTP server sets
  `RemoteAddr` to `IP:port` with a per-connection ephemeral port; keying on it
  makes the limiter per-connection, so a client opening a new connection per
  request gets a fresh bucket and bypasses the limit. `httpmw.clientIP` strips
  the port.
- Client-supplied forwarding headers (`X-Forwarded-For` / `X-Real-IP`) are
  spoofable and MUST be ignored for the rate-limit key and access log unless the
  server is explicitly configured to sit behind a trusted proxy
  (`httpmw.TrustProxyHeaders`, default false).
- The bucket map MUST be bounded by periodic GC of idle entries
  (`RateLimiter.StartGC`/`GC`) so many distinct source IPs cannot exhaust memory.

---

## Conformance matrix
✅ implemented · ⚠️ partial · ❌ gap (see backlog item)

| Requirement | Status | Notes |
|---|---|---|
| §1 did:web/key/jwk resolution | ✅ | |
| §1 did:webvh verifiable history (SCID + hash chain + pre-rotation) | ✅ | **implemented** (`didwebvh`); wire-vector interop pending official vectors |
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
| §4 issuer-metric privacy — random index assignment (volume/order hiding) | ✅ | **implemented** (`revocation.IndexAllocator`) |
| §4 issuer-metric privacy — revocation-count hiding (accumulator/CRSet) | ❌ | backlog #11 (irreducible for plain bitstring) |
| §5 OpenID4VP nonce binding + one-time state | ✅ | |
| §5 client_id scheme validation | ✅ | **implemented** (`openid4vp.ValidateClientID`) |
| §6 SCITT register ordering + proofs | ✅ | |
| §6 COSE_Sign1 receipts (IETF SCITT interop) | ✅ | **implemented** (`scitt.IssueCOSEReceipt`, `cbor` package) |
| §6 witness cosigning (split-view defense) | ✅ | **implemented** (`scitt.Witness`) |
| §1 multiformats: base58btc + multihash (sha2-256) | ✅ | **implemented** (`multiformats`, KAT-validated) — did:webvh foundation |
| §1 JCS canonicalization (RFC 8785) | ✅ | **implemented** (`multiformats.CanonicalizeJSON`) — did:webvh / DI proofs foundation; integers verbatim, negative zero normalized to `0` (§3.2.2.3), arbitrary-float ES `Number::toString` is best-effort |
| §8 CBOR encoder/decoder (RFC 8949, deterministic) | ✅ | **implemented** (`cbor` package) |
| §8 COSE_Sign1 sign/verify (RFC 9052) | ✅ | **implemented** (`cbor.Sign1`, `cbor.Verify1`) |
| §8 COSE algorithm agility (`RegisterVerifier`) | ✅ | **implemented** |
| §2 mdoc/mDL format (ISO 18013-5 IssuerSigned + MSO) | ✅ | **implemented** (`mdoc` package: Issue/Verify/Present) |
| §2 mdoc selective disclosure + value-digest integrity | ✅ | **implemented** (`mdoc.Present`, digest checks in `mdoc.Verify`) |
| §2 mdoc device/holder binding (COSE_Key) | ✅ | deviceKey recovered; device-signature transport ❌ (out of scope) |
| §3 SD-JWT-VC Type Metadata / vct#integrity | ✅ | resolution + integrity ✅ (`vctmeta`); JSON-Schema validation ✅ (`jsonschema` + `vctmeta.ValidateClaims`) |
| §3 JSON Schema validator (draft 2020-12 subset) | ✅ | **implemented** (`jsonschema` package) |
| §3 remote `schema_uri` resolution + integrity | ✅ | **implemented** (`vctmeta.ResolveSchema` / `ResolveAndValidate`) |
| §7 crypto-agility hook (JWS) | ✅ | EdDSA built-in; ML-DSA pluggable |
| §7 HTTP rate-limit enforcement | ✅ | **implemented** (`httpmw.RateLimiter`) |
| §7 HTTP server read/write/idle timeouts | ✅ | **implemented** (`tlsharden.HardenedServer`) |
| §9 SD-JWT segment cap (unsigned-trailer DoS) | ✅ | **implemented** (`maxSDJWTSegments`, `ErrSDJWTTooManyDisclosures`) |
| §9 HTTP body-size caps (all endpoints) | ✅ | **implemented** (`http.MaxBytesReader` across vci/vp/mcp/didresolver) |
| §9 bounded in-memory stores (cache/session/offer/replay) | ✅ | **implemented** (TTL purge + capacity caps) |
| §9 compression bomb guard | ✅ | **implemented** (`revocation` 8 MiB / 64 MiB bounds) |
| §9 recursive-decoder depth bounds (CBOR/JCS/$ref) | ✅ | **implemented** (64 / 512 / 64) |
| §1 did:webvh verifiable history | ❌ | backlog #5 |
| §4 issuer-metric privacy (CRSet accumulator) | ❌ | backlog #11 |

### Highest-value remaining gaps (ordered)
1. CRSet revocation-*count* privacy (§4) — backlog #11. Random index assignment
   (`revocation.IndexAllocator`) now hides issuance volume/order; hiding the
   absolute revocation count still needs an accumulator / padded Bloom-cascade,
   which is irreducible for a plain bitstring.
2. mdoc DeviceResponse / session-transcript binding (§2a) — proximity transport (ISO 18013-5 §8/§9), beyond the credential-format scope now covered.
3. did:webvh official-vector interop — the verification model is implemented and tested (`didwebvh`); validate byte-for-byte against the published did:webvh test vectors and add witness cosigning + did:web fallback.
