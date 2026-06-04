// Package semconv defines BLRCS telemetry attribute keys aligned with
// OpenTelemetry Semantic Conventions (https://opentelemetry.io/docs/specs/semconv/).
//
// OTel requires dotted, domain-namespaced attribute keys so that traces, metrics,
// and logs are portable across backends (Grafana, Jaeger, Datadog) and dashboards
// can be reused. Ad-hoc keys like "issuer" or "subject" break that portability.
//
// Domain-specific keys use the "blrcs." prefix per the OTel guidance that
// application-specific attributes not covered upstream carry a vendor namespace.
// Standard keys (service.*, error.*, http.*) reuse the OTel names verbatim.
package semconv

import "log/slog"

// Standard OTel resource/span attribute keys (reused verbatim).
const (
	ServiceName    = "service.name"
	ServiceVersion = "service.version"
	ErrorType      = "error.type"
	ErrorMessage   = "error.message"
	HTTPMethod     = "http.request.method"
	HTTPStatusCode = "http.response.status_code"
)

// BLRCS domain-specific attribute keys (vendor-namespaced per OTel guidance).
const (
	Issuer        = "blrcs.issuer"          // DID of the credential issuer
	Subject       = "blrcs.subject"         // credential subject identifier
	ProductID     = "blrcs.product_id"      // GTIN or product identifier
	Attester      = "blrcs.attester"        // sensor/range attester DID
	RangeName     = "blrcs.range.name"      // range statement name
	SDClaimsCount = "blrcs.sd_claims_count" // number of selectively-disclosable claims
	CredentialVCT = "blrcs.credential.vct"  // SD-JWT VC type
	LedgerTSID    = "blrcs.ledger.tsid"     // transparency service ID
	TreeSize      = "blrcs.ledger.tree_size"
	BatteryID     = "blrcs.battery_id"
)

// Helper constructors so call sites read naturally and key spelling is centralized.

func IssuerAttr(did string) slog.Attr    { return slog.String(Issuer, did) }
func SubjectAttr(s string) slog.Attr     { return slog.String(Subject, s) }
func ProductIDAttr(id string) slog.Attr  { return slog.String(ProductID, id) }
func AttesterAttr(did string) slog.Attr  { return slog.String(Attester, did) }
func RangeNameAttr(n string) slog.Attr   { return slog.String(RangeName, n) }
func SDClaimsCountAttr(n int) slog.Attr  { return slog.Int(SDClaimsCount, n) }
func VCTAttr(vct string) slog.Attr       { return slog.String(CredentialVCT, vct) }
func LedgerTSIDAttr(id string) slog.Attr { return slog.String(LedgerTSID, id) }
func TreeSizeAttr(n uint64) slog.Attr    { return slog.Uint64(TreeSize, n) }
func ErrorTypeAttr(t string) slog.Attr   { return slog.String(ErrorType, t) }
