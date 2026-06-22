package compliance

import "errors"

// Additional sentinel errors (supplements the core set in compliance.go)
//
// Apple NSError domain+code 設計: errors.Is() で型安全にエラー判定可能

var (
	// Issuer construction
	ErrIssuerIDRequired     = errors.New("compliance: issuer ID required")
	ErrBatteryIDRequired    = errors.New("compliance: batteryID required")
	ErrDueDiligenceRequired = errors.New("compliance: due-diligence report required for EV/industrial batteries (Art.52)")
	ErrAttesterIDRequired   = errors.New("compliance: attester ID required")

	// SD-JWT
	ErrSDJWTEmpty          = errors.New("compliance: sd-jwt empty")
	ErrSDJWTMalformed      = errors.New("compliance: sd-jwt malformed")
	ErrSDJWTSigFailed      = errors.New("compliance: sd-jwt signature failed")
	ErrSDJWTExpired        = errors.New("compliance: sd-jwt expired (exp in past)")
	ErrSDJWTNotYetValid    = errors.New("compliance: sd-jwt not yet valid (iat in future)")
	ErrSDJWTUnsupportedAlg = errors.New("compliance: sd-jwt unsupported JWS alg")
	// ErrSDJWTCritUnsupported is returned when the issuer JWS header carries a
	// `crit` (RFC 7515 §4.1.11) listing extension parameters this verifier does
	// not implement. Silently ignoring crit would bypass the issuer's
	// "must-understand" safety signal.
	ErrSDJWTCritUnsupported = errors.New("compliance: sd-jwt unsupported critical header parameter")
	// ErrSDJWTUnsupportedType is returned when the issuer JWS `typ` header is
	// present but is not an SD-JWT-VC media type (`vc+sd-jwt` / `dc+sd-jwt`).
	// Enforcing typ blocks cross-JWT-type confusion (replaying a differently
	// typed JWS signed by the same key as a credential).
	ErrSDJWTUnsupportedType    = errors.New("compliance: sd-jwt issuer JWS typ is not an SD-JWT-VC type")
	ErrSDJWTUnsupportedHashAlg = errors.New("compliance: sd-jwt unsupported _sd_alg (only sha-256)")
	ErrSDJWTMissingVCT         = errors.New("compliance: sd-jwt-vc missing required vct claim")
	ErrSDJWTDuplicateDigest    = errors.New("compliance: sd-jwt duplicate digest in _sd")
	// ErrSDJWTTooManyDisclosures is returned when the number of ~-separated
	// segments in a presented SD-JWT exceeds the configured cap (256). An
	// attacker who appends thousands of ~ characters to any SD-JWT string can
	// force strings.Split to allocate a proportionally large slice before the
	// signature check runs; this cap makes the allocation O(1) instead.
	ErrSDJWTTooManyDisclosures = errors.New("compliance: sd-jwt too many disclosure segments")
	// ErrSDJWTIssuerMismatch is returned by VerifySDJWTWithBinding when
	// VerifyOptions.ExpectedIssuer is set and the JWT iss claim does not match.
	// This prevents key-confusion: a verifier who obtains a public key for a
	// specific issuer should also confirm the credential claims that issuer.
	ErrSDJWTIssuerMismatch = errors.New("compliance: sd-jwt issuer does not match expected issuer")

	// SD-JWT Key Binding (KB-JWT) — IETF SD-JWT / SD-JWT-VC holder binding
	ErrHolderKeyRequired = errors.New("compliance: holder public key required for key binding")
	ErrKeyBindingMissing = errors.New("compliance: key binding (KB-JWT) required but absent")
	ErrKeyBindingInvalid = errors.New("compliance: key binding JWT malformed or signature failed")
	ErrKeyBindingNonce   = errors.New("compliance: key binding nonce/audience mismatch")
	ErrKeyBindingSDHash  = errors.New("compliance: key binding sd_hash mismatch")

	// Credential status (revocation)
	ErrStatusListRequired = errors.New("compliance: status list required to check revocation")
	ErrStatusListMismatch = errors.New("compliance: status list token subject does not match credential status URI")

	// GS1
	ErrGTINInvalid    = errors.New("compliance: invalid GTIN")
	ErrDomainRequired = errors.New("compliance: domain required")
	ErrGS1ParseFailed = errors.New("compliance: GS1 URI parse failed")
)
