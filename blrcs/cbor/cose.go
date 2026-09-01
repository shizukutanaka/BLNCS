// COSE_Sign1 (RFC 9052 §4.2) over Ed25519 — zero external dependencies.
//
// COSE_Sign1 = #6.18([
//
//	protected:   bstr .cbor Header,
//	unprotected: Header,
//	payload:     bstr / nil,
//	signature:   bstr
//
// ])
//
// Only EdDSA (alg=-8) is built in. Other algorithms may be registered via
// RegisterVerifier for crypto-agility without adding core dependencies.
package cbor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"blrcs/ecdsakey"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

// Standard COSE header parameters (RFC 9052 §3.1).
const (
	HeaderAlg  = 1 // algorithm
	HeaderCrit = 2 // critical headers (RFC 9052 §3.1)
	HeaderKid  = 4 // key ID
)

// Algorithm identifiers (IANA COSE Algorithms registry).
const (
	AlgEdDSA = -8 // Ed25519 / Ed448
	// AlgES256 is ECDSA w/ SHA-256 on P-256 (RFC 9053 §2.1). Mandated by the
	// EUDI ARF / OpenID4VC HAIP, so mdoc and SCITT receipts from real wallets
	// and transparency services use it. Its signature is the raw fixed-width
	// R‖S concatenation, NOT ASN.1 DER — see the ecdsakey package.
	AlgES256 = -7
)

// ErrCOSEInvalidTag is returned when the outer CBOR tag is not 18.
var ErrCOSEInvalidTag = errors.New("cbor/cose: not a COSE_Sign1 (tag 18)")

// ErrCOSEBadStructure is returned when the COSE_Sign1 array is malformed.
var ErrCOSEBadStructure = errors.New("cbor/cose: malformed COSE_Sign1 structure")

// ErrCOSESigFailed is returned when signature verification fails.
var ErrCOSESigFailed = errors.New("cbor/cose: signature verification failed")

// ErrNotP256Key is returned by Sign1ES256 when the supplied key is nil or not
// on P-256.
var ErrNotP256Key = errors.New("cbor/cose: ES256 requires a P-256 private key")

// ErrAlgHeaderMismatch is returned when the protected header declares an
// algorithm that differs from the one the signing function actually uses.
// Signing anyway would produce a COSE_Sign1 whose header sends a verifier to the
// wrong algorithm — an unverifiable credential that looks well-formed.
var ErrAlgHeaderMismatch = errors.New("cbor/cose: protected header alg does not match the signing algorithm")

// ErrCOSEUnsupportedAlg is returned for unknown or disallowed algorithms.
var ErrCOSEUnsupportedAlg = errors.New("cbor/cose: unsupported algorithm")

// ErrCOSEAlgNotAllowed is returned by Verify1WithAlgs when the COSE_Sign1's
// algorithm is registered (so it COULD be verified) but is not a member of
// the caller-supplied allowedAlgs allowlist. Distinct from
// ErrCOSEUnsupportedAlg (no verifier registered at all): this is a policy
// rejection, not a capability gap.
var ErrCOSEAlgNotAllowed = errors.New("cbor/cose: algorithm not in caller's allowlist")

// ErrCOSECritUnsupported is returned when the protected header carries a `crit`
// (label 2) field that lists a critical label this implementation does not
// understand. RFC 9052 §3.1 requires processing to fail in that case. BLRCS
// implements no critical header extensions, so any non-understood (or malformed)
// crit entry is rejected rather than silently ignored — otherwise an issuer's
// "you MUST understand this to use the token safely" signal would be bypassed.
var ErrCOSECritUnsupported = errors.New("cbor/cose: unsupported critical header parameter")

// ============================================================================
// Algorithm registry (crypto-agility)
// ============================================================================

// COSEVerifier verifies a COSE_Sign1 Ed25519-style signature.
// pub is the raw public key bytes (32 bytes for Ed25519).
// sigInput is the Sig_Structure byte string that was signed.
type COSEVerifier func(pub, sigInput, sig []byte) bool

var (
	coseVerifiersMu sync.RWMutex
	coseVerifiers   = map[int]COSEVerifier{
		AlgEdDSA: verifyEdDSA,
		AlgES256: ecdsakey.VerifyES256,
	}
)

// RegisterVerifier registers a custom signature verifier for the given COSE
// algorithm identifier. It is safe to call concurrently with Verify1.
// Registering a nil verifier removes support for that algorithm.
func RegisterVerifier(alg int, v COSEVerifier) {
	coseVerifiersMu.Lock()
	defer coseVerifiersMu.Unlock()
	if v == nil {
		delete(coseVerifiers, alg)
	} else {
		coseVerifiers[alg] = v
	}
}

func verifyEdDSA(pub, sigInput, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), sigInput, sig)
}

// ============================================================================
// Header
// ============================================================================

// Header is a COSE header map (integer keys → arbitrary CBOR values).
type Header map[int]any

// encodedHeader encodes a Header to CBOR bytes (the protected bstr content).
func encodedHeader(h Header) ([]byte, error) {
	if h == nil {
		h = Header{}
	}
	return Marshal(map[int]any(h))
}

// ============================================================================
// Sign1
// ============================================================================

// Sign1 creates and signs a COSE_Sign1 structure using Ed25519.
//
// protected must include the algorithm identifier (Header{HeaderAlg: AlgEdDSA}).
// unprotected may be nil. payload is the content bytes (nil for detached payload).
// externalAAD should be nil or empty for most use cases.
func Sign1(protected, unprotected Header, payload, externalAAD []byte, priv ed25519.PrivateKey) ([]byte, error) {
	// Symmetric to Sign1ES256: signing under a header that declares a different
	// algorithm yields a credential the verifier dispatches to the wrong code.
	if alg, ok := protected[HeaderAlg]; ok {
		if n, isInt := alg.(int); !isInt || n != AlgEdDSA {
			return nil, fmt.Errorf("%w: protected header declares alg %v, not EdDSA (%d)", ErrAlgHeaderMismatch, alg, AlgEdDSA)
		}
	} else {
		protected = copyHeader(protected)
		protected[HeaderAlg] = AlgEdDSA
	}
	protectedBytes, err := encodedHeader(protected)
	if err != nil {
		return nil, fmt.Errorf("cbor/cose: encode protected: %w", err)
	}

	sigInput, err := sigStructure(protectedBytes, payload, externalAAD)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, sigInput)

	if unprotected == nil {
		unprotected = Header{}
	}
	// Payload must be CBOR null for detached payload (nil []byte), not bstr(0).
	// Storing []byte(nil) in any{} would match case []byte and encode as bstr.
	var payloadVal any
	if payload != nil {
		payloadVal = payload
	}
	return Marshal(Tag{
		Number: TagCOSESign1,
		Content: []any{
			protectedBytes,
			map[int]any(unprotected),
			payloadVal,
			sig,
		},
	})
}

// ============================================================================
// Verify1
// ============================================================================

// Verify1Result contains the parsed fields of a verified COSE_Sign1.
type Verify1Result struct {
	Protected   Header
	Unprotected Header
	Payload     []byte // nil for detached payload
}

// Verify1 decodes and verifies a COSE_Sign1 structure.
//
// pub is the Ed25519 public key of the signer. externalAAD should be nil or
// empty for most use cases. Returns the protected header and payload on success.
//
// Detached payloads are not supported: if the encoded payload is CBOR null, the
// signature is verified over an empty payload (matching Sign1 with a nil
// payload). Callers needing true detached COSE (payload transmitted separately)
// must embed the payload instead — every BLRCS user (mdoc, SCITT receipts) does.
//
// Verify1 accepts any algorithm registered in the global coseVerifiers map. Once
// a second algorithm is registered via RegisterVerifier (e.g. a future
// post-quantum COSE alg id), this makes EVERY call process-wide silently accept
// either algorithm, with no way for an individual caller to pin verification to
// one alg only (mirrors the downgrade risk compliance.VerifyOptions.AllowedAlgs
// closes on the SD-JWT side). Callers that need to pin should use
// Verify1WithAlgs instead.
func Verify1(data []byte, pub ed25519.PublicKey, externalAAD []byte) (*Verify1Result, error) {
	return Verify1WithAlgs(data, pub, externalAAD, nil)
}

// Verify1WithAlgs is Verify1 with an optional per-call algorithm allowlist.
// A non-empty allowedAlgs restricts acceptance to those COSE algorithm
// identifiers even if other algorithms are registered globally via
// RegisterVerifier — letting a post-quantum-only deployment pin verification
// to (say) only a registered ML-DSA id, or a legacy caller pin to only
// AlgEdDSA, regardless of what else has been registered process-wide. An
// empty/nil allowedAlgs accepts any registered algorithm (Verify1's
// behavior, preserved for backward compatibility).
func Verify1WithAlgs(data []byte, pub ed25519.PublicKey, externalAAD []byte, allowedAlgs []int) (*Verify1Result, error) {
	v, err := Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("cbor/cose: decode: %w", err)
	}

	tag, ok := v.(Tag)
	if !ok || tag.Number != TagCOSESign1 {
		return nil, ErrCOSEInvalidTag
	}

	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, ErrCOSEBadStructure
	}

	protectedBytes, ok := arr[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrCOSEBadStructure)
	}

	sig, ok := arr[3].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: signature must be bstr", ErrCOSEBadStructure)
	}

	// payload may be nil (detached) — both nil and []byte are valid
	var payload []byte
	switch p := arr[2].(type) {
	case []byte:
		payload = p
	case nil:
		// detached — caller provides payload separately
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or nil", ErrCOSEBadStructure)
	}

	// Parse protected header
	protected, err := parseHeader(protectedBytes)
	if err != nil {
		return nil, fmt.Errorf("cbor/cose: parse protected header: %w", err)
	}

	// RFC 9052 §3.1: reject any critical header parameter we do not understand.
	if err := checkCrit(protected); err != nil {
		return nil, err
	}

	// Determine algorithm
	alg, err := headerAlg(protected)
	if err != nil {
		return nil, err
	}

	// Per-verification algorithm allowlist (crypto-agility downgrade defense).
	// Checked BEFORE the registry lookup so an excluded-but-registered alg is
	// rejected as policy (ErrCOSEAlgNotAllowed), not capability.
	if len(allowedAlgs) > 0 && !containsInt(allowedAlgs, alg) {
		return nil, fmt.Errorf("%w: %d", ErrCOSEAlgNotAllowed, alg)
	}

	coseVerifiersMu.RLock()
	verifier, ok := coseVerifiers[alg]
	coseVerifiersMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrCOSEUnsupportedAlg, alg)
	}

	// Rebuild Sig_Structure and verify
	sigInput, err := sigStructure(protectedBytes, payload, externalAAD)
	if err != nil {
		return nil, err
	}
	if !verifier(pub, sigInput, sig) {
		return nil, ErrCOSESigFailed
	}

	// Parse unprotected header (best-effort; errors are non-fatal)
	var unprotected Header
	if rawMap, ok := arr[1].(map[any]any); ok {
		unprotected = Header(IntMap(rawMap))
	}

	return &Verify1Result{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
	}, nil
}

// ============================================================================
// Sig_Structure (RFC 9052 §4.4)
// ============================================================================

// sigStructure encodes the Sig_Structure used as the signing input:
//
//	["Signature1", protected_bstr, external_aad, payload]
func sigStructure(protectedBytes, payload, externalAAD []byte) ([]byte, error) {
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	return Marshal([]any{
		"Signature1",
		protectedBytes,
		externalAAD,
		payload,
	})
}

// ============================================================================
// helpers
// ============================================================================

func parseHeader(data []byte) (Header, error) {
	if len(data) == 0 {
		return Header{}, nil
	}
	v, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	rawMap, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("header must be a CBOR map")
	}
	return Header(IntMap(rawMap)), nil
}

// checkCrit enforces RFC 9052 §3.1 critical-header handling. The `crit` field
// (label 2), when present, MUST be a non-empty array of labels the processor is
// required to understand. BLRCS understands only the algorithm label
// (HeaderAlg); any other listed label — or a malformed/empty crit — is rejected.
// String labels are always unsupported here (Header is keyed by integer label).
func checkCrit(h Header) error {
	critRaw, present := h[HeaderCrit]
	if !present {
		return nil
	}
	crit, ok := critRaw.([]any)
	if !ok || len(crit) == 0 {
		// crit MUST be a non-empty array (RFC 9052 §3.1).
		return fmt.Errorf("%w: crit must be a non-empty array", ErrCOSECritUnsupported)
	}
	for _, lblRaw := range crit {
		lbl, ok := GetInt(lblRaw)
		if !ok || int(lbl) != HeaderAlg {
			return fmt.Errorf("%w: %v", ErrCOSECritUnsupported, lblRaw)
		}
	}
	return nil
}

func headerAlg(h Header) (int, error) {
	algRaw, ok := h[HeaderAlg]
	if !ok {
		return 0, fmt.Errorf("%w: missing alg header", ErrCOSEUnsupportedAlg)
	}
	alg, ok := GetInt(algRaw)
	if !ok {
		return 0, fmt.Errorf("%w: alg must be integer", ErrCOSEUnsupportedAlg)
	}
	return int(alg), nil
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func copyHeader(h Header) Header {
	out := make(Header, len(h)+1)
	for k, v := range h {
		out[k] = v
	}
	return out
}

// ============================================================================
// Axis 141: ES256 COSE_Sign1 signing
//
// Verification of AlgES256 landed in Axis 135; this is the signing half, so
// BLRCS can produce mdoc credentials a P-256-only ecosystem accepts (real mDLs
// are ES256-signed).
//
// The signature is the raw fixed-width R‖S concatenation RFC 9053 §2.1
// mandates — Signature = I2OSP(R, n) | I2OSP(S, n), n = ceiling(key_length/8),
// so 32+32 for P-256 — NOT the ASN.1 DER that ecdsa.SignASN1 and most libraries
// emit by default. FillBytes does the zero-padding; r.Bytes() would emit a short
// encoding whenever a coordinate has a leading zero byte (~1 in 256), which a
// conforming verifier rejects.
//
// Nonce generation is Go's hedged ECDSA: k comes from an AES-CTR CSPRNG keyed by
// SHA2-512(priv.D || entropy || hash), so both the key and the message feed it.
// That resists RNG failure while keeping the fault-injection tolerance strict
// RFC 6979 determinism gives up. See compliance/es256_issuer.go for the fuller
// note; the reasoning is identical here.
// ============================================================================

// Sign1ES256 creates and signs a COSE_Sign1 using ECDSA on P-256 (alg -7).
//
// It mirrors Sign1 exactly apart from the algorithm: protected gains
// HeaderAlg: AlgES256 when unset, unprotected may be nil, and a nil payload
// produces a detached-payload structure.
//
// The key is *ecdsa.PrivateKey rather than a generic signer so that an Ed25519
// key cannot reach this path (and vice versa) — the compiler enforces the split
// instead of a runtime type check.
func Sign1ES256(protected, unprotected Header, payload, externalAAD []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, ErrNotP256Key
	}
	// A protected header declaring some OTHER algorithm would be signed as-is and
	// then dispatched to that algorithm's verifier, silently producing a
	// credential nothing can verify. Reject rather than sign a lie.
	if alg, ok := protected[HeaderAlg]; ok {
		if n, isInt := alg.(int); !isInt || n != AlgES256 {
			return nil, fmt.Errorf("%w: protected header declares alg %v, not ES256 (%d)", ErrAlgHeaderMismatch, alg, AlgES256)
		}
	} else {
		protected = copyHeader(protected)
		protected[HeaderAlg] = AlgES256
	}
	protectedBytes, err := encodedHeader(protected)
	if err != nil {
		return nil, fmt.Errorf("cbor/cose: encode protected: %w", err)
	}
	sigInput, err := sigStructure(protectedBytes, payload, externalAAD)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(sigInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("cbor/cose: ES256 sign: %w", err)
	}
	sig := make([]byte, ecdsakey.ES256SignatureSize)
	r.FillBytes(sig[:ecdsakey.P256CoordSize])
	s.FillBytes(sig[ecdsakey.P256CoordSize:])

	if unprotected == nil {
		unprotected = Header{}
	}
	var payloadVal any
	if payload != nil {
		payloadVal = payload
	}
	return Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{protectedBytes, map[int]any(unprotected), payloadVal, sig},
	})
}

// ParseSign1Headers decodes only the header maps of a COSE_Sign1, WITHOUT
// verifying the signature.
//
// This exists for headers a verifier must read before it knows which key to
// verify with — most importantly `x5chain` (RFC 9360), where the certificate
// that carries the signing key is itself in the message. The returned headers
// are therefore UNAUTHENTICATED: treat them as a hint about which key to try,
// never as a fact. Callers must still verify the signature afterwards, and must
// anchor anything trust-bearing (a certificate chain) to their own configured
// roots rather than to the message.
func ParseSign1Headers(data []byte) (protected, unprotected Header, err error) {
	v, err := Unmarshal(data)
	if err != nil {
		return nil, nil, fmt.Errorf("cbor/cose: decode: %w", err)
	}
	tag, ok := v.(Tag)
	if !ok || tag.Number != TagCOSESign1 {
		return nil, nil, ErrCOSEInvalidTag
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, nil, ErrCOSEBadStructure
	}
	protectedBytes, ok := arr[0].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("%w: protected must be bstr", ErrCOSEBadStructure)
	}
	protected, err = parseHeader(protectedBytes)
	if err != nil {
		return nil, nil, err
	}
	unprotected = Header{}
	if rawMap, ok := arr[1].(map[any]any); ok {
		unprotected = Header(IntMap(rawMap))
	}
	return protected, unprotected, nil
}
