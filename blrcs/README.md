# BLRCS

**Blockchain Logistics / Compliance / Supply chain** — production-grade Go reference implementation for EU Digital Product Passport (ESPR) + Battery Passport (Reg 2023/1542), with W3C VC, IETF SCITT transparency log, OpenID4VP/VCI wallet integration, and W3C Digital Credentials API browser support.

```
stdlib + ed25519 only — zero external dependencies
880+ tests · 50 packages · ~16,400 LoC implementation · 11 fuzz targets
```

## Status

| Subsystem | Status | Tests |
|---|---|---|
| W3C Verifiable Credentials | ✅ | compliance |
| SD-JWT (selective disclosure) | ✅ | compliance, property, fuzz |
| ZK Range Proof (TEE-attested) | ✅ | compliance |
| GS1 Digital Link (ISO/IEC 18975) | ✅ | compliance, fuzz |
| EU Battery Passport (Reg 2023/1542) | ✅ | compliance |
| EU ESPR Digital Product Passport | ✅ | compliance |
| ISO 18013-5 mdoc / mDL (IssuerSigned + MSO) | ✅ | mdoc, cbor, fuzz |
| IETF SCITT Merkle Log + COSE_Sign1 Receipts | ✅ | scitt, cbor |
| OpenID4VP Verifier | ✅ | openid4vp |
| OpenID4VCI Issuer | ✅ | openid4vci |
| W3C DC-API (Safari 26 / Chrome 141) | ✅ | dcapi |
| MCP (Model Context Protocol) | ✅ | mcp |
| DID Resolver (web/key/jwk) | ✅ | didresolver |
| Webhook outbound | ✅ | webhook |
| Content-Addressed Storage | ✅ | cas |
| Privacy Manifest (PrivacyInfo equivalent) | ✅ | privacy |

## Quick start

```bash
go install ./cmd/blrcs/
go install ./cmd/blrcs-mcpd/
go install ./cmd/blrcs-demo/

# Self-test: 13 subsystems, ~7ms
blrcs doctor

# Live browser demo on Safari 26 / Chrome 141
blrcs-demo
# → http://localhost:8090/demo

# MCP HTTP daemon
BLRCS_DATA_DIR=/data BLRCS_AUTH_TOKENS=tok1:agent-1 blrcs-mcpd
```

## Library usage

```go
import (
    "blrcs/compliance"
    "blrcs/builder"
    "blrcs/types"
)

issuer, _ := compliance.NewIssuer("did:web:factory.example")

cred, err := builder.NewDPP().
    Issuer(types.MustDID(issuer.ID)).
    ProductID(types.MustGTIN("04012345678901")).
    Category("battery/ev").
    OriginCountry(types.MustCountryCode("JP")).
    Carbon(types.MustCarbonFootprint(48.5)).
    Recyclability(types.MustPercent(82)).
    Build(issuer)
```

For the end-to-end factory flow (SCITT + webhook + CAS + DID resolution), see the
integration suite:

```bash
go test ./integration/
```

## Architecture

```
core domain          compliance / scitt / storage / revocation
typed primitives     types / builder / errkit / telemetry / ctx
standards            openid4vp / openid4vci / dcapi / mdoc / mcp / vctmeta / conformance
crypto/keys          kms / atrest
encoding             cbor (RFC 8949 encoder/decoder + COSE_Sign1 RFC 9052)
hardening            recovery / replay / saga / fuzz / property / schemaver
observability        metrics / otelbridge / doctor / healthprobe / diag
privacy              privacy
trust/distribution   didresolver / webhook / cas / compose
http composition     httpchain / httpmw (recovery+trace+log+auth+CORS+rate-limit)
TLS                  tlsharden (Modern / Strict / mTLS / hardened server timeouts)
config/spec          openapi / apispec / apiversion / config / capability / semconv
i18n                 i18n
integration          integration (E2E triangle test)
```

## Performance baseline

| Operation | Time | Allocs |
|---|---|---|
| `Telemetry.Counter.Inc()` | 7 ns | 0 |
| `cas.Get` | 58 ns | 1 |
| `cas.Put (dedup hit)` | 325 ns | 2 |
| `types.NewDID` | 99 ns | 1 |
| `types.NewGTIN` | 83 ns | 0 |
| `Ed25519 sign` | 29 µs | 0 |
| `Verify DPP` | 78 µs | 5 |
| `Issue SD-JWT (3 claims)` | 110 µs | 77 |
| `SCITT Register` | 253 µs | 447 |

Measured on Intel Xeon Platinum 8581C @ 2.10 GHz.

## Testing

```bash
# Full suite
go test ./...

# With coverage
go test -cover ./...

# Fuzz key parsers (5s each)
go test -fuzz=FuzzDID -fuzztime=5s ./fuzz/
go test -fuzz=FuzzSDJWT -fuzztime=5s ./fuzz/

# Benchmarks
go test -bench=. -benchmem ./...
```

## Standards reference

- [W3C VC Data Model 1.1](https://www.w3.org/TR/vc-data-model/)
- [IETF SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- [IETF SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
- [GS1 Digital Link](https://ref.gs1.org/standards/digital-link/)
- [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [EU Regulation 2024/1781 ESPR](https://eur-lex.europa.eu/eli/reg/2024/1781)
- [EU Regulation 2023/1542 Battery](https://eur-lex.europa.eu/eli/reg/2023/1542)

## License

This reference implementation is provided as-is. The exact license terms are
documented in LICENSE in the repository root.
