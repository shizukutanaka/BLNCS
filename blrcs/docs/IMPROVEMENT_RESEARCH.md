# BLRCS — Improvement Research (同種ソフト + arxiv 調査)

Method: surveyed the governing standards (IETF/W3C/OpenID), comparable
implementations (EUDI Wallet Reference Implementation, Spherity/Battery Pass,
transparency.dev / C2SP witnessing), and recent research (arXiv / IACR / formal
analyses), then mapped each finding to the current BLRCS code. Each item lists
**what's missing**, the **evidence** (standard + comparable impl + research), the
**code location**, and a **suggested approach**. Ranked by impact.

Survey date: 2026-06. BLRCS baseline: v0.1.0 + the security-hardening branch
(SD-JWT expiry, KB-JWT holder binding, gzip-bomb guard).

---

## P0 — Correctness / interop gaps that block real-world deployment

### 1. Credentials carry no `status` claim → revocation is unreachable by verifiers
- **Gap:** `revocation/bitstring.go` (W3C Bitstring) and `revocation/revocation.go`
  (signed list) exist as standalone packages, but `compliance.IssueSDJWT*` /
  `IssueBatteryPassport` never embed a `status` / `status_list` claim. A verifier
  receiving a vp_token has no pointer to the status list, so issued credentials
  are effectively non-revocable in practice.
- **Evidence:** W3C *Bitstring Status List v1.0* requires a `credentialStatus`
  entry; IETF *Token Status List* requires a `status.status_list` claim
  (`idx` + `uri`). Every comparable impl (EUDI RI, Spherity Battery Pass) wires
  this into the credential.
- **Code:** `compliance/extensions.go` `issueSDJWT` payload build; `VerifySDJWT*`.
- **Approach:** add a `StatusRef{URI string; Index int}` option to issuance that
  writes the `status` claim; add `VerifyStatus(vc, fetcher)` that resolves the
  list and checks the bit. Reuse `revocation.BitstringStatusList.GetStatus`.

### 2. No IETF *Token Status List* (`statuslist+jwt` / `+cwt`)
- **Gap:** only the W3C Bitstring encoding is implemented. SD-JWT-VC / EUDI use
  the IETF *Token Status List* (signed JWT/CWT status token), a different wire
  format. BLRCS issues SD-JWT-VC but can't produce/consume the matching status
  token → not interoperable with EUDI verifiers.
- **Evidence:** `draft-ietf-oauth-status-list` (JWT/CWT, `application/statuslist+jwt`);
  referenced normatively by `draft-ietf-oauth-sd-jwt-vc`. EUDI ARF mandates it.
- **Code:** new `statuslist/` package mirroring `revocation/bitstring.go`'s
  bit-array, wrapped in a signed status-list token.
- **Approach:** reuse the existing bit-array + gzip encoder; add a signed JWT
  envelope (`ttl`, `sub`, `iat`, `status_list`) using the existing Ed25519 path.

### 3. SCITT statements are JSON+Ed25519, not COSE Sign1 / COSE Receipts
- **Gap:** `scitt/scitt.go` explicitly notes "完全COSE_Sign1実装は重い … JSON+Ed25519".
  Receipts are a bespoke struct. This is **not** interoperable with the IETF SCITT
  ecosystem, which exchanges `COSE_Sign1` Signed Statements and CBOR/COSE Receipts
  (COSE Merkle-tree proofs).
- **Evidence:** `draft-ietf-scitt-architecture-22` + *COSE Receipts* / *COSE Merkle
  Tree Proofs*; this is the headline interop surface of SCITT.
- **Code:** `scitt/scitt.go` (`Statement`, `Receipt`), `scitt/consistency.go`.
- **Approach:** add a COSE encoding layer (a small CBOR encoder, staying
  zero-dependency, or document `x/cbor` as the single allowed dep) that emits
  `application/cose` Signed Statements and receipt CBOR; keep the JSON path for
  the lightweight profile. Largest effort; sequence after #1/#2.

---

## P1 — Security hardening backed by formal analysis / research

### 4. Transparency log has no witness cosigning → split-view attacks
- **Gap:** the SCITT `Ledger` produces inclusion + consistency proofs
  (`scitt/consistency.go`) but publishes no **signed checkpoint** cosigned by
  independent **witnesses**. A malicious/compromised log can present a *split view*
  (different histories to different relying parties) undetectably.
- **Evidence:** C2SP `tlog-witness`, transparency.dev witness network; IACR
  2024/879 *Consistency-or-Die*; UCL decentralized witness cosigning (CoSi). This
  is the standard defense and is cheap to add given consistency proofs already exist.
- **Code:** `scitt/scitt.go` (add `Checkpoint{Size, RootHash, Timestamp}` + sign),
  `scitt/consistency.go` (verify-before-cosign).
- **Approach:** emit a signed checkpoint (C2SP note format); add a `Witness`
  interface that verifies the consistency proof against its last checkpoint and
  returns a cosignature; expose checkpoint retrieval for monitors.

### 5. SD-JWT linkability + claim-count leakage (no unlinkable option)
- **Gap:** SD-JWT presentations are linkable — constant issuer signature, salts,
  and digests across presentations let colluding verifiers correlate sessions;
  the `_sd` array also leaks the **exact number** of hidden claims.
- **Evidence:** arXiv 2506.00262 (*Compact and Selective Disclosure for VCs*),
  arXiv 2406.19035 (*SD-BLS*); EUDI ARF is moving to BBS+ / ECDSA-SD for
  unlinkable presentations.
- **Code:** `compliance/extensions.go` `issueSDJWT` (`_sd` digests).
- **Approach (incremental):** (a) pad `_sd` with **decoy digests** to a fixed
  bucket size to blunt the claim-count leak (cheap, spec-allowed); (b) support
  **batch issuance** (issue N single-use credentials) so each presentation uses a
  fresh credential — the EUDI interim mitigation; (c) longer term, an
  `ecdsa-sd` / BBS cryptosuite behind the same `Present`/`Verify` interface.

### 6. OpenID4VP cross-device flow is phishing-exposed; tighten client_id binding
- **Gap:** `openid4vp` builds `openid4vp://` request URLs (cross-device/QR style).
  Formal analysis flags the cross-device flow as phishing-prone, and the same-device
  **DC-API** path carries the proven "claims unforgeability" guarantee.
- **Evidence:** OpenID Foundation / Univ. Stuttgart *Formal Security Analysis of
  OpenID4VP over the DC API* (2025); 2024 WIM analysis of cross-device phishing.
- **Code:** `openid4vp/openid4vp.go` (`buildRequestURL`, `ProcessResponse`),
  `dcapi/` (already present — good).
- **Approach:** validate the `client_id` scheme (e.g. `x509_san_dns` /
  `redirect_uri`) and bind the verifier identity into the request; prefer/route the
  `dcapi` same-device path; document the cross-device flow's residual phishing risk
  in `SECURITY.md`. (KB-JWT nonce binding — already added — is the prerequisite.)

---

## P2 — Spec completeness & robustness

### 7. SD-JWT-VC Type Metadata / schema validation / `vct#integrity` missing
- **Gap:** `vct` is emitted but BLRCS neither resolves Type Metadata nor validates
  claims against a schema, nor honors `vct#integrity`.
- **Evidence:** `draft-ietf-oauth-sd-jwt-vc-16` §Type Metadata (`schema`/`schema_uri`,
  `vct#integrity` for cacheable static metadata).
- **Code:** `compliance/extensions.go` (issue/verify), new `vctmeta/` resolver.
- **Approach:** add optional Type Metadata resolution + JSON-Schema validation hook;
  emit/verify `vct#integrity` (SRI-style hash) so metadata can be cached safely.

### 8. No Wallet Unit / Key Attestation (WUA) in OID4VCI
- **Gap:** `openid4vci` has no key-attestation / wallet-attestation step, so an
  issuer cannot assert the holder key lives in attested hardware.
- **Evidence:** EUDI ARF roadmap (Q4'25–Q1'26) splits WUA into Wallet Application
  Attestation + Key Attestation; `draft-ietf-oauth-attestation-based-client-auth`.
- **Code:** `openid4vci/openid4vci.go`, `kms/`.
- **Approach:** accept an attestation JWT at issuance and bind its key into the
  credential `cnf` (the KB-JWT plumbing just added makes this natural).

### 9. Bitstring status list isn't signed/served as a credential
- **Gap:** `BitstringStatusList.EncodedList()` returns the raw encoded list; there's
  no `StatusListCredential` wrapper (issuer signature, `validFrom`, `ttl`) nor an
  HTTP serving helper, so freshness/authenticity of the list itself isn't conveyed.
- **Evidence:** W3C Bitstring Status List requires the list be delivered **as a
  signed VC**; IETF TSL requires a signed token with `ttl`.
- **Code:** `revocation/bitstring.go`.
- **Approach:** add `IssueStatusListCredential` (reuse the Ed25519/SD-JWT path) and
  a `cache-control`-aware HTTP handler in `httpchain`/`httpmw`.

---

## Quick wins already shipped on this branch
SD-JWT now enforces `exp`/`iat`; KB-JWT holder binding closes the OpenID4VP nonce
replay gap; revocation decode is decompression-bomb-guarded; `.golangci.yml`
migrated to v2 so the lint gate runs. These are the prerequisites that items 5/6/8
build on.

---

## Second-pass survey (additional 同種ソフト + arXiv angles)

### 10. No mdoc / mDL (ISO/IEC 18013-5) credential format — eIDAS 2.0 mandates *both*
- **Gap:** BLRCS issues only SD-JWT-VC. `dcapi/dcapi.go` advertises the
  `org-iso-mdoc` protocol, but `buildMdocData` is an explicit MVP **stub** (it
  re-wraps the presentation definition; there is no CBOR `doctype` + `namespaces`
  `IssuerSigned`/`DeviceResponse` structure). So BLRCS cannot issue or verify a
  real mdoc.
- **Evidence:** eIDAS 2.0 mandates **both** SD-JWT-VC and mdoc/mDL; ISO/IEC
  18013-5:2021 (mdoc) + 18013-7:2025 (OpenID4VP mdoc profile). EUDI RI, walt.id,
  Sphereon, Microsoft Entra Verified ID all ship mdoc.
- **Code:** `dcapi/dcapi.go` (`buildMdocData`), new `mdoc/` package.
- **Approach:** add a CBOR `IssuerSigned` mdoc (COSE_Sign1 over MSO with
  per-element salted digests) — shares the salted-digest model already in
  `compliance` SD-JWT and the COSE layer needed for SCITT receipts (#3), so
  sequence it with #3 to amortize the CBOR/COSE work.

### 11. Bitstring Status List leaks issuer activity / business metrics
- **Gap:** `revocation/bitstring.go` publishes a contiguous list whose set bits and
  size reveal the issuer's **revocation rate and issuance volume** to anyone who
  fetches it — herd privacy (16KB minimum) hides *which* holder, not the issuer's
  aggregate business metrics.
- **Evidence:** *CRSet: Private Non-Interactive VC Revocation* (arXiv 2501.17089)
  — explicitly identifies Bitstring/Token Status List issuer-metric leakage and
  proposes a padded Bloom-filter-cascade so the published artifact is
  indistinguishable from random; *Privacy-Preserving Revocation with
  Time-Flexibility* (arXiv 2503.22010, AHIBE); EVOKE (ECC accumulator).
- **Code:** `revocation/bitstring.go`.
- **Approach (incremental):** (a) pad the list to a fixed published size and seed
  unused bits with deterministic noise to mask the true count (cheap); (b) longer
  term, an accumulator + ZK non-revocation proof variant behind the same
  `GetStatus`/status-claim interface.

### 12. No crypto-agility / post-quantum path — `alg` is hardcoded `EdDSA`
- **Gap:** the SD-JWT header (`compliance/extensions.go:153` and `:483`) hardcodes
  `"alg":"EdDSA"` and calls `ed25519.Sign` directly; Ed25519 is wired across 15
  non-test files. There is a `kms.Signer` interface but the credential path
  bypasses it, so there is no algorithm negotiation and no migration path.
- **Evidence:** NIST IR 8547 + CNSA 2.0 mandate crypto-agility and a phased move
  to **ML-DSA** (FIPS 204); *Towards Post-Quantum Verifiable Credentials*
  (ACM/techrxiv 2024) shows ML-DSA-44/65/87 + Falcon as drop-in VC signers with a
  hybrid option. EUDI ARF lists crypto-agility as a requirement.
- **Code:** `compliance/extensions.go` (issue/verify), `kms/kms.go` (`Signer`).
- **Approach:** route issuance/verification through `kms.Signer`, read `alg` from
  the JWT header instead of assuming EdDSA, and add an ML-DSA (or hybrid
  Ed25519+ML-DSA) implementation of the interface. Verifiers select by header
  `alg`. This is foundational and should precede mdoc (#10) so both formats are
  algorithm-agile from the start.

### 13. DCQL / claim-matching breadth vs Presentation Exchange parity
- **Gap:** worth auditing that the v1.0 `dcql_query` path in `openid4vp/dcql.go`
  covers `credential_sets`, value/path matching, and format constraints to the
  same depth the legacy `presentation_definition` path did, so the v1.0 migration
  doesn't silently narrow what verifiers can express.
- **Evidence:** OpenID4VP v1.0 §6 (DCQL replaced PE); EUDI/ISO 18013-7 rely on DCQL.
- **Code:** `openid4vp/dcql.go`, `dcapi/dcapi.go`.
- **Approach:** add conformance vectors covering `credential_sets` and claim value
  matching; this is a test-coverage/robustness item, not a redesign.


- OpenID4VP formal analysis (OIDF / Univ. Stuttgart, 2025): https://openid.net/formal-security-analysis-openid-verifiable-credentials/ , https://openid.net/oidf-receives-security-analysis-of-openid-for-verifiable-presentations/
- OID4VCI formal analysis (ETH Zürich): https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/information-security-group-dam/research/software/zischg-oid4vci.pdf
- SD-JWT selective disclosure / unlinkability: arXiv 2506.00262 ( https://arxiv.org/html/2506.00262 ), SD-BLS arXiv 2406.19035 ( https://arxiv.org/pdf/2406.19035 )
- IETF Token Status List: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
- SD-JWT-VC (Type Metadata): https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- IETF SCITT architecture: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- Transparency log witnessing: https://github.com/C2SP/C2SP/blob/main/tlog-witness.md , https://blog.transparency.dev/can-i-get-a-witness-network , IACR 2024/879 https://eprint.iacr.org/2024/879.pdf
- EUDI ARF / Reference Implementation roadmap: https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework , https://github.com/eu-digital-identity-wallet/eudi-wallet-reference-implementation-roadmap/discussions/79
- mdoc / mDL (ISO/IEC 18013-5 / 18013-7) in EUDI: https://shanedeconinck.be/posts/eudi-credential-formats-crash-course/ , https://darutk.medium.com/issuing-verifiable-credentials-in-the-sd-jwt-vc-and-mdoc-mdl-formats-mandated-in-eidas-2-0-87a232cfcc2a
- Privacy-preserving revocation: CRSet arXiv 2501.17089 ( https://arxiv.org/abs/2501.17089 ), Time-Flexible revocation arXiv 2503.22010 ( https://arxiv.org/html/2503.22010v1 ), ZK/accumulator framework arXiv 2510.09715 ( https://arxiv.org/abs/2510.09715 )
- Post-quantum VCs / crypto-agility: *Towards Post-Quantum Verifiable Credentials* ( https://dl.acm.org/doi/fullHtml/10.1145/3664476.3669932 ), NIST IR 8547 (PQC migration / crypto-agility)
