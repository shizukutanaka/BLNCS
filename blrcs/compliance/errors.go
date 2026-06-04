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
	ErrSDJWTEmpty       = errors.New("compliance: sd-jwt empty")
	ErrSDJWTMalformed   = errors.New("compliance: sd-jwt malformed")
	ErrSDJWTSigFailed   = errors.New("compliance: sd-jwt signature failed")
	ErrSDJWTExpired     = errors.New("compliance: sd-jwt expired (exp in past)")
	ErrSDJWTNotYetValid = errors.New("compliance: sd-jwt not yet valid (iat in future)")

	// SD-JWT Key Binding (KB-JWT) — IETF SD-JWT / SD-JWT-VC holder binding
	ErrHolderKeyRequired = errors.New("compliance: holder public key required for key binding")
	ErrKeyBindingMissing = errors.New("compliance: key binding (KB-JWT) required but absent")
	ErrKeyBindingInvalid = errors.New("compliance: key binding JWT malformed or signature failed")
	ErrKeyBindingNonce   = errors.New("compliance: key binding nonce/audience mismatch")
	ErrKeyBindingSDHash  = errors.New("compliance: key binding sd_hash mismatch")

	// GS1
	ErrGTINInvalid    = errors.New("compliance: invalid GTIN")
	ErrDomainRequired = errors.New("compliance: domain required")
	ErrGS1ParseFailed = errors.New("compliance: GS1 URI parse failed")
)
