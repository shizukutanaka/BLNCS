# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active security fixes |
| < 1.0   | ❌ End of life |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via one of:

1. **GitHub Security Advisories** (preferred):
   Navigate to the repository → Security → Advisories → "Report a vulnerability"

2. **Email**: security@blrcs.example *(replace with real contact)*

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact assessment
- Any suggested mitigations (optional)

### Response timeline

| Milestone | Target |
|---|---|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix or mitigation | 30 days (critical), 90 days (high) |
| Public disclosure | Coordinated with reporter |

### Scope

In scope:
- Cryptographic operations (Ed25519 signature/verification)
- SCITT Merkle tree inclusion proofs
- SD-JWT selective disclosure (no secret leakage)
- Authentication bypass in MCP/HTTP handlers
- Denial of service via malformed inputs
- Private key exposure

Out of scope:
- Vulnerabilities in deployed infrastructure not part of this codebase
- Social engineering attacks
- Issues in dependencies (report to respective maintainers)

## Security Design Principles

BLRCS is built with these security properties:

- **Zero external dependencies** — attack surface limited to Go stdlib + `crypto/ed25519`
- **Immutable ledger** — SCITT append-only Merkle log, no deletion
- **PII minimisation** — Privacy Manifest enforces data minimisation (I5)
- **Constant-time operations** — All cryptographic comparisons use `hmac.Equal` or `subtle.ConstantTimeCompare`
- **Panic recovery** — All HTTP handlers and goroutines are protected against panics
- **Replay detection** — Built-in SHA-256 fingerprint deduplication with TTL

## Credential security model

The credential lifecycle is **secure-by-default** end-to-end. The knobs below are
on by default where it matters; the opt-outs exist only for local/bearer flows.

### Holder binding (anti-replay)
- `openid4vp.NewVerifier` sets `RequireKeyBinding = true`: a presentation must carry a
  KB-JWT cryptographically bound to the request `nonce` + verifier `client_id`. A
  captured `vp_token` cannot be replayed to another verifier or request. Set it to
  `false` only to accept bearer credentials (anti-replay then rests solely on
  one-time `state` consumption).
- Issue holder-bound credentials with `compliance.IssueSDJWTBound` (embeds a `cnf`
  key), or let OpenID4VCI bind automatically: when a wallet supplies a
  proof-of-possession JWT, `IssueCredentialWithProof` binds the credential to the
  proven key.
- mdoc (ISO 18013-5): presentations are bound with **device authentication**
  (`mdoc.PresentWithDeviceAuth` / `VerifyDocument`, §9.1.3). `VerifyDocument` rejects
  credentials with no device key or a device signature bound to a different session
  transcript — no bearer mdoc presentations.

### Query enforcement (OpenID4VP v1.0 §6, DCQL)
- `ProcessResponse` enforces the `dcql_query`: the presented credential must satisfy a
  `CredentialQuery` (vct within `vct_values`, every requested claim disclosed, value
  constraints met) and every **required** `credential_set` (§6.2; the `required`
  default is `true`).
- DCQL flows take trust anchors from `Verifier.TrustedIssuers` (the query carries no
  keys); PresentationDefinition flows use the per-request `AcceptableIssuers`.

### Revocation (draft-ietf-oauth-status-list)
- Verified presentations expose `VerifiedPresentation.Status`; set
  `Verifier.RevocationChecker` to fail closed (`ErrCredentialRevoked`) on revoked
  credentials in-flow (the caller fetches the status list, keeping verification
  network-free).
- Issue credentials that are holder-bound **and** revocable with
  `compliance.IssueSDJWTBoundStatus`, or via OpenID4VCI `OfferOptions{Status}`.

### Temporal validity
- Both `validFrom` (not-yet-valid) and `validUntil` (expired) are enforced for W3C VC
  (`compliance.Verify`/`VerifyAt`) and SD-JWT (`VerifySDJWTAt`), with a small
  clock-skew leeway on the future bound.

### OpenID4VCI offer protection
- Bind a pre-authorized offer to a PIN with `CreateOfferWithTxCode` /
  `OfferOptions.TxCode` so an intercepted offer (e.g. a photographed QR) is useless
  without the out-of-band code. `Issuer.MaxTxCodeAttempts` (default 5) invalidates the
  pre-authorized code after repeated wrong PINs to stop brute force.

## Vulnerability History

| Date | CVE | Severity | Description |
|---|---|---|---|
| — | — | — | No reported vulnerabilities yet |
