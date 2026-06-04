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

## Vulnerability History

| Date | CVE | Severity | Description |
|---|---|---|---|
| — | — | — | No reported vulnerabilities yet |
