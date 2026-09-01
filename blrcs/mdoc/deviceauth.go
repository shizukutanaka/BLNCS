package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"blrcs/cbor"
	"blrcs/ecdsakey"
)

// ============================================================================
// Device authentication — ISO 18013-5 §9.1.3
//
// IssuerSigned alone is a *bearer* credential: anyone who captures it can replay
// it. Device authentication binds a presentation to the holder by having the
// device key (the one the issuer committed to in the MSO `deviceKey`) sign a
// DeviceAuthentication structure that includes a verifier-supplied session
// transcript. This is the mdoc analog of the SD-JWT KB-JWT holder binding.
//
// DeviceAuthentication = [
//	"DeviceAuthentication",
//	SessionTranscript,        ; opaque bytes the verifier binds the session to
//	DocType,
//	DeviceNameSpacesBytes,    ; #6.24(bstr .cbor DeviceNameSpaces)
// ]
//
// The deviceSignature is a COSE_Sign1 over DeviceAuthenticationBytes
// (= #6.24(bstr .cbor DeviceAuthentication)). Per the BLRCS COSE convention the
// payload is embedded (not detached); the verifier reconstructs the expected
// DeviceAuthenticationBytes from the session transcript + docType and checks both
// the signature (against the MSO deviceKey) and the payload binding.
//
// SessionTranscript is left opaque here: the caller supplies the bytes the
// session is bound to (e.g. an OpenID4VP handover, or a hash of verifier
// nonce+audience). Both sides must agree on the exact bytes.
// ============================================================================

// Document map keys (ISO 18013-5 §8.3.2.1.2.2 DeviceResponse Document).
const (
	docDocType      = "docType"
	docIssuerSigned = "issuerSigned"
	docDeviceSigned = "deviceSigned"
)

// DeviceSigned / deviceAuth map keys.
const (
	dsNameSpaces      = "nameSpaces"
	dsDeviceAuth      = "deviceAuth"
	daDeviceSignature = "deviceSignature"
)

// deviceAuthContext is the fixed first element of the DeviceAuthentication array.
const deviceAuthContext = "DeviceAuthentication"

// Device-auth errors.
var (
	ErrNoDeviceKey       = errors.New("mdoc: credential has no device key; cannot verify device authentication")
	ErrDeviceAuth        = errors.New("mdoc: device authentication signature invalid")
	ErrDeviceAuthMissing = errors.New("mdoc: deviceSigned/deviceAuth missing")
)

// deviceAuthenticationBytes builds DeviceAuthenticationBytes for the given docType
// and session transcript. DeviceNameSpaces is empty (this implementation does not
// device-sign additional elements; selective disclosure happens in IssuerSigned).
func deviceAuthenticationBytes(docType string, sessionTranscript []byte) ([]byte, error) {
	deviceNS, err := cbor.Marshal(map[string]any{})
	if err != nil {
		return nil, err
	}
	da := []any{
		deviceAuthContext,
		sessionTranscript,
		docType,
		cbor.Tag{Number: tagEncodedCBOR, Content: deviceNS}, // DeviceNameSpacesBytes
	}
	daCBOR, err := cbor.Marshal(da)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: daCBOR})
}

// SignDeviceAuth produces the deviceSignature (COSE_Sign1) for a presentation,
// binding it to docType and sessionTranscript using the device private key.
func SignDeviceAuth(docType string, sessionTranscript []byte, devicePriv ed25519.PrivateKey) ([]byte, error) {
	payload, err := deviceAuthenticationBytes(docType, sessionTranscript)
	if err != nil {
		return nil, err
	}
	return cbor.Sign1(cbor.Header{}, nil, payload, nil, devicePriv)
}

// SignDeviceAuthES256 is SignDeviceAuth for a P-256 device key, producing a
// COSE_Sign1 with alg ES256 — what a real mDL holder device emits.
func SignDeviceAuthES256(docType string, sessionTranscript []byte, devicePriv *ecdsa.PrivateKey) ([]byte, error) {
	payload, err := deviceAuthenticationBytes(docType, sessionTranscript)
	if err != nil {
		return nil, err
	}
	return cbor.Sign1ES256(cbor.Header{}, nil, payload, nil, devicePriv)
}

// VerifyDeviceAuth verifies a deviceSignature against the device key, checking both
// the COSE_Sign1 signature and that its payload equals the expected
// DeviceAuthenticationBytes for docType + sessionTranscript.
func VerifyDeviceAuth(deviceSignature []byte, docType string, sessionTranscript []byte, deviceKey ed25519.PublicKey) error {
	return VerifyDeviceAuthWithAlgs(deviceSignature, docType, sessionTranscript, deviceKey, nil)
}

// VerifyDeviceAuthWithAlgs is VerifyDeviceAuth with an optional per-call COSE
// algorithm allowlist (see cbor.Verify1WithAlgs). A nil/empty allowedAlgs
// accepts any registered algorithm, identical to VerifyDeviceAuth.
func VerifyDeviceAuthWithAlgs(deviceSignature []byte, docType string, sessionTranscript []byte, deviceKey ed25519.PublicKey, allowedAlgs []int) error {
	// Accept an Ed25519 key (32 bytes) or a P-256 key as an uncompressed SEC1
	// point (65 bytes). The parameter is typed ed25519.PublicKey for backward
	// compatibility, but that is a named []byte and cbor.Verify1WithAlgs
	// dispatches on the COSE alg in the protected header, so the right verifier
	// is selected by the credential rather than by this type.
	if len(deviceKey) != ed25519.PublicKeySize && len(deviceKey) != ecdsakey.P256UncompressedSize {
		return ErrNoDeviceKey
	}
	want, err := deviceAuthenticationBytes(docType, sessionTranscript)
	if err != nil {
		return err
	}
	res, err := cbor.Verify1WithAlgs(deviceSignature, deviceKey, nil, allowedAlgs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDeviceAuth, err)
	}
	if subtle.ConstantTimeCompare(res.Payload, want) != 1 {
		return fmt.Errorf("%w: session-transcript/docType binding mismatch", ErrDeviceAuth)
	}
	return nil
}

// PresentWithDeviceAuth selectively discloses issuerSigned (see Present) and wraps
// it in a Document with a deviceSigned proving control of the device key, bound to
// sessionTranscript. The result verifies with VerifyDocument.
func PresentWithDeviceAuth(issuerSigned []byte, reveal map[string][]string, docType string, devicePriv ed25519.PrivateKey, sessionTranscript []byte) ([]byte, error) {
	filtered, err := Present(issuerSigned, reveal)
	if err != nil {
		return nil, err
	}
	deviceSig, err := SignDeviceAuth(docType, sessionTranscript, devicePriv)
	if err != nil {
		return nil, err
	}
	deviceNS, err := cbor.Marshal(map[string]any{})
	if err != nil {
		return nil, err
	}
	deviceSigned := map[string]any{
		dsNameSpaces: cbor.Tag{Number: tagEncodedCBOR, Content: deviceNS},
		dsDeviceAuth: map[string]any{daDeviceSignature: rawCBOR(deviceSig)},
	}
	return cbor.Marshal(map[string]any{
		docDocType:      docType,
		docIssuerSigned: rawCBOR(filtered),
		docDeviceSigned: deviceSigned,
	})
}

// VerifyDocument verifies a Document produced by PresentWithDeviceAuth: it checks
// the issuerSigned (signature, validity window, disclosed-item digests) AND the
// device authentication (deviceSignature over the session transcript against the
// MSO deviceKey). A credential without a device key, or a Document without a valid
// deviceAuth bound to sessionTranscript, is rejected — no bearer presentations.
func VerifyDocument(document []byte, issuerPub ed25519.PublicKey, sessionTranscript []byte, now time.Time) (*VerifiedDoc, error) {
	top, err := cbor.Unmarshal(document)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	m, ok := top.(map[any]any)
	if !ok {
		return nil, ErrMalformed
	}

	docType, _ := m[docDocType].(string)

	isRaw, ok := m[docIssuerSigned]
	if !ok {
		return nil, fmt.Errorf("%w: missing issuerSigned", ErrMalformed)
	}
	isBytes, err := cbor.Marshal(isRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode issuerSigned: %v", ErrMalformed, err)
	}
	vd, err := Verify(isBytes, issuerPub, now)
	if err != nil {
		return nil, err
	}
	if docType != "" && vd.DocType != "" && docType != vd.DocType {
		return nil, ErrDocTypeMismatch
	}
	// Pick whichever device key the credential bound itself to.
	deviceKey := vd.DeviceKey
	if len(deviceKey) == 0 {
		deviceKey = vd.DeviceKeyES256
	}
	if len(deviceKey) == 0 {
		return nil, ErrNoDeviceKey
	}

	// Extract deviceSigned.deviceAuth.deviceSignature.
	dsRaw, ok := m[docDeviceSigned].(map[any]any)
	if !ok {
		return nil, ErrDeviceAuthMissing
	}
	daRaw, ok := dsRaw[dsDeviceAuth].(map[any]any)
	if !ok {
		return nil, ErrDeviceAuthMissing
	}
	sigRaw, ok := daRaw[daDeviceSignature]
	if !ok {
		return nil, ErrDeviceAuthMissing
	}
	sigBytes, err := cbor.Marshal(sigRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode deviceSignature: %v", ErrMalformed, err)
	}

	// Bind against the docType the issuer committed to (vd.DocType is authoritative).
	bindDocType := vd.DocType
	if bindDocType == "" {
		bindDocType = docType
	}
	if err := VerifyDeviceAuth(sigBytes, bindDocType, sessionTranscript, deviceKey); err != nil {
		return nil, err
	}
	return vd, nil
}
