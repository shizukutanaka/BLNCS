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
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

// Standard COSE header parameters (RFC 9052 §3.1).
const (
	HeaderAlg = 1 // algorithm
	HeaderKid = 4 // key ID
)

// Algorithm identifiers (IANA COSE Algorithms registry).
const (
	AlgEdDSA = -8 // Ed25519 / Ed448
)

// ErrCOSEInvalidTag is returned when the outer CBOR tag is not 18.
var ErrCOSEInvalidTag = errors.New("cbor/cose: not a COSE_Sign1 (tag 18)")

// ErrCOSEBadStructure is returned when the COSE_Sign1 array is malformed.
var ErrCOSEBadStructure = errors.New("cbor/cose: malformed COSE_Sign1 structure")

// ErrCOSESigFailed is returned when signature verification fails.
var ErrCOSESigFailed = errors.New("cbor/cose: signature verification failed")

// ErrCOSEUnsupportedAlg is returned for unknown or disallowed algorithms.
var ErrCOSEUnsupportedAlg = errors.New("cbor/cose: unsupported algorithm")

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
	if _, ok := protected[HeaderAlg]; !ok {
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
func Verify1(data []byte, pub ed25519.PublicKey, externalAAD []byte) (*Verify1Result, error) {
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

	// Determine algorithm
	alg, err := headerAlg(protected)
	if err != nil {
		return nil, err
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

func copyHeader(h Header) Header {
	out := make(Header, len(h)+1)
	for k, v := range h {
		out[k] = v
	}
	return out
}
