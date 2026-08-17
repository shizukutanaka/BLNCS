// Package mdoc — ISO/IEC 18013-5 mobile document (mdoc / mDL) issuance and
// verification, built on the zero-dependency blrcs/cbor (CBOR + COSE_Sign1) layer.
//
// Supports the IssuerSigned structure used both for proximity (ISO 18013-5)
// and online (ISO 18013-7 / OpenID4VP "mso_mdoc") presentation:
//
//	IssuerSigned = {
//	  ? "nameSpaces": IssuerNameSpaces,
//	  "issuerAuth": IssuerAuth                 ; COSE_Sign1, payload = MSO
//	}
//	IssuerNameSpaces = { + NameSpace => [ + IssuerSignedItemBytes ] }
//	IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
//	IssuerSignedItem = {
//	  "digestID": uint, "random": bstr,
//	  "elementIdentifier": tstr, "elementValue": any
//	}
//	MobileSecurityObject = {
//	  "version": "1.0", "digestAlgorithm": "SHA-256",
//	  "valueDigests": { + NameSpace => { + DigestID => Digest } },
//	  "deviceKeyInfo": { "deviceKey": COSE_Key },
//	  "docType": tstr,
//	  "validityInfo": { "signed", "validFrom", "validUntil": tdate }
//	}
//
// Holder binding is supported via the device key (COSE_Key, Ed25519/OKP). Device
// signature / session transcript verification (proximity transport) is out of
// scope — this package covers issuance and the issuer-side trust chain
// (issuerAuth signature + value-digest integrity + validity window).
package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"blrcs/cbor"
	"blrcs/ecdsakey"
)

// MSO constants (ISO 18013-5 §9.1.2).
const (
	MSOVersion      = "1.0"
	DigestAlgSHA256 = "SHA-256"

	// tagEncodedCBOR is CBOR tag 24: a byte string containing an encoded CBOR
	// data item (#6.24(bstr .cbor ...)). Used for IssuerSignedItemBytes and
	// MobileSecurityObjectBytes.
	tagEncodedCBOR = 24
	// tagDateTime is CBOR tag 0: an RFC 3339 date-time text string (tdate).
	tagDateTime = 0

	// randomLen is the IssuerSignedItem salt length. ISO requires ≥16 bytes.
	randomLen = 16
)

// COSE_Key parameters (RFC 9052 §7 / RFC 8152) for OKP Ed25519.
const (
	coseKeyKty   = 1  // key type
	coseKeyCrv   = -1 // curve (for OKP/EC2)
	coseKeyXCoor = -2 // public key / x-coordinate
	coseKeyYCoor = -3 // y-coordinate (EC2 only)
	ktyOKP       = 1  // Octet Key Pair
	ktyEC2       = 2  // Elliptic Curve, x/y coordinate pair
	crvEd25519   = 6  // Ed25519
	crvP256      = 1  // NIST P-256 (secp256r1)
)

// MSO payload map keys.
const (
	msoVersion       = "version"
	msoDigestAlg     = "digestAlgorithm"
	msoValueDigests  = "valueDigests"
	msoDeviceKeyInfo = "deviceKeyInfo"
	msoDocType       = "docType"
	msoValidityInfo  = "validityInfo"
	msoDeviceKey     = "deviceKey"
)

// IssuerSigned map keys.
const (
	isNameSpaces = "nameSpaces"
	isIssuerAuth = "issuerAuth"
)

// IssuerSignedItem map keys.
const (
	isiDigestID   = "digestID"
	isiRandom     = "random"
	isiElementID  = "elementIdentifier"
	isiElementVal = "elementValue"
)

// ValidityInfo map keys.
const (
	viSigned     = "signed"
	viValidFrom  = "validFrom"
	viValidUntil = "validUntil"
)

// Errors.
var (
	ErrNoElements      = errors.New("mdoc: at least one element required")
	ErrMalformed       = errors.New("mdoc: malformed IssuerSigned structure")
	ErrIssuerAuth      = errors.New("mdoc: issuerAuth signature invalid")
	ErrDigestMismatch  = errors.New("mdoc: element digest does not match MSO")
	ErrUnknownDigestID = errors.New("mdoc: element digestID not present in MSO")
	ErrNotYetValid     = errors.New("mdoc: credential not yet valid (validFrom)")
	ErrExpired         = errors.New("mdoc: credential expired (validUntil)")
	ErrUnsupportedMSO  = errors.New("mdoc: unsupported MSO version or digest algorithm")
	ErrDocTypeMismatch = errors.New("mdoc: docType mismatch")
	// ErrDuplicateElement is returned when two IssuerSigned items in the same
	// namespace share the same elementIdentifier. Both items may have valid,
	// distinct digestIDs and pass digest checks independently; without a
	// uniqueness check the second silently overwrites the first, which could
	// hide a collision from the caller's audit trail.
	ErrDuplicateElement = errors.New("mdoc: duplicate elementIdentifier in namespace")
)

// Element is a single mdoc data element (claim) within a namespace.
type Element struct {
	Identifier string
	Value      any // any cbor-encodable value (string, int, bool, []byte, []any, map[string]any, ...)
}

// ValidityInfo is the MSO validity window (ISO 18013-5 §9.1.2.4).
type ValidityInfo struct {
	Signed     time.Time
	ValidFrom  time.Time
	ValidUntil time.Time
}

// IssueParams configures mdoc issuance.
type IssueParams struct {
	DocType    string               // e.g. "org.iso.18013.5.1.mDL" or "eu.europa.ec.dpp.1"
	NameSpaces map[string][]Element // namespace → elements
	Validity   ValidityInfo         // signed/validFrom/validUntil
	DeviceKey  ed25519.PublicKey    // optional holder/device public key (binds the credential)
	IssuerPriv ed25519.PrivateKey   // issuer signing key (issuerAuth), EdDSA
	// IssuerPrivES256 signs issuerAuth with ECDSA/P-256 (COSE alg -7) instead of
	// EdDSA. Real mDLs are ES256-signed, so this is what a P-256-only ecosystem
	// expects. Exactly one of IssuerPriv / IssuerPrivES256 must be set.
	IssuerPrivES256 *ecdsa.PrivateKey
	// IssuerAuthUnprotected are extra COSE unprotected headers for issuerAuth.
	// Its purpose is the x5chain header (RFC 9360 label 33) carrying the Document
	// Signer Certificate, so a verifier holding only the IACA roots can validate
	// a document from an issuer it has never seen — see X5ChainHeader and
	// VerifyChain in x509chain.go. Unprotected is the right bucket: the chain is
	// not integrity-critical because it is validated against the verifier's own
	// configured roots however it arrived. Nil keeps the previous bare-key output
	// byte-for-byte.
	IssuerAuthUnprotected cbor.Header
	// DeviceKeyES256 binds the credential to a P-256 holder key instead of an
	// Ed25519 one, encoding deviceKeyInfo as an EC2 COSE_Key. Mutually exclusive
	// with DeviceKey.
	DeviceKeyES256 *ecdsa.PublicKey
}

// Issue creates a signed IssuerSigned mdoc credential and returns its CBOR bytes.
//
// For each element it builds an IssuerSignedItem (with a fresh ≥16-byte salt),
// wraps it as #6.24(bstr), records SHA-256(IssuerSignedItemBytes) in the MSO
// valueDigests, then signs the MSO with a COSE_Sign1 (issuerAuth).
func Issue(p IssueParams) ([]byte, error) {
	if p.DocType == "" {
		return nil, errors.New("mdoc: docType required")
	}
	total := 0
	for _, els := range p.NameSpaces {
		total += len(els)
	}
	if total == 0 {
		return nil, ErrNoElements
	}

	// Build IssuerNameSpaces and ValueDigests in lock-step.
	issuerNameSpaces := map[string]any{}
	valueDigests := map[string]any{}
	digestID := 0

	for ns, els := range p.NameSpaces {
		items := make([]any, 0, len(els))
		digests := map[int]any{}
		for _, el := range els {
			salt := make([]byte, randomLen)
			if _, err := rand.Read(salt); err != nil {
				return nil, fmt.Errorf("mdoc: salt: %w", err)
			}
			itemBytes, err := cbor.Marshal(map[string]any{
				isiDigestID:   uint64(digestID),
				isiRandom:     salt,
				isiElementID:  el.Identifier,
				isiElementVal: el.Value,
			})
			if err != nil {
				return nil, fmt.Errorf("mdoc: encode item %q: %w", el.Identifier, err)
			}
			// IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
			wrapped, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: itemBytes})
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(wrapped)
			digests[digestID] = sum[:]
			items = append(items, cbor.Tag{Number: tagEncodedCBOR, Content: itemBytes})
			digestID++
		}
		issuerNameSpaces[ns] = items
		valueDigests[ns] = digests
	}

	// Build MobileSecurityObject.
	mso := map[string]any{
		msoVersion:      MSOVersion,
		msoDigestAlg:    DigestAlgSHA256,
		msoValueDigests: valueDigests,
		msoDocType:      p.DocType,
		msoValidityInfo: map[string]any{
			viSigned:     tdate(p.Validity.Signed),
			viValidFrom:  tdate(p.Validity.ValidFrom),
			viValidUntil: tdate(p.Validity.ValidUntil),
		},
	}
	switch {
	case p.DeviceKeyES256 != nil:
		mso[msoDeviceKeyInfo] = map[string]any{
			msoDeviceKey: deviceKeyCOSEP256(p.DeviceKeyES256),
		}
	case p.DeviceKey != nil:
		mso[msoDeviceKeyInfo] = map[string]any{
			msoDeviceKey: deviceKeyCOSE(p.DeviceKey),
		}
	}

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode MSO: %w", err)
	}
	// COSE_Sign1 payload = MobileSecurityObjectBytes = #6.24(bstr .cbor MSO)
	msoTagged, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: msoBytes})
	if err != nil {
		return nil, err
	}

	// The protected header must declare the algorithm actually used: a verifier
	// dispatches on it, so stamping EdDSA on an ES256 signature makes the
	// credential unverifiable (and stamping ES256 on an EdDSA one likewise).
	var issuerAuth []byte
	if p.IssuerPrivES256 != nil {
		issuerAuth, err = cbor.Sign1ES256(cbor.Header{cbor.HeaderAlg: cbor.AlgES256}, p.IssuerAuthUnprotected, msoTagged, nil, p.IssuerPrivES256)
	} else {
		issuerAuth, err = cbor.Sign1(cbor.Header{cbor.HeaderAlg: cbor.AlgEdDSA}, p.IssuerAuthUnprotected, msoTagged, nil, p.IssuerPriv)
	}
	if err != nil {
		return nil, fmt.Errorf("mdoc: sign issuerAuth: %w", err)
	}

	// IssuerSigned is encoded with raw COSE_Sign1 bytes for issuerAuth, so we
	// wrap them with a Marshaler that emits them verbatim.
	return cbor.Marshal(map[string]any{
		isNameSpaces: issuerNameSpaces,
		isIssuerAuth: rawCBOR(issuerAuth),
	})
}

// ============================================================================
// helpers
// ============================================================================

// tdate encodes a time as CBOR tag 0 (RFC 3339 date-time text string).
func tdate(t time.Time) cbor.Tag {
	return cbor.Tag{Number: tagDateTime, Content: t.UTC().Format(time.RFC3339)}
}

// deviceKeyCOSE builds a COSE_Key (OKP/Ed25519) map for the device public key.
func deviceKeyCOSE(pub ed25519.PublicKey) map[int]any {
	return map[int]any{
		coseKeyKty:   ktyOKP,
		coseKeyCrv:   crvEd25519,
		coseKeyXCoor: []byte(pub),
	}
}

// deviceKeyCOSEP256 builds an EC2 COSE_Key (RFC 9052 §7) for a P-256 device key:
// kty=EC2, crv=P-256, with x and y each written as the fixed 32-octet big-endian
// coordinate. FillBytes rather than Bytes() so a coordinate with a leading zero
// is not silently shortened — a short coordinate changes the key's encoding and
// therefore the MSO digest a verifier recomputes.
func deviceKeyCOSEP256(pub *ecdsa.PublicKey) map[int]any {
	x := make([]byte, ecdsakey.P256CoordSize)
	y := make([]byte, ecdsakey.P256CoordSize)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[int]any{
		coseKeyKty:   ktyEC2,
		coseKeyCrv:   crvP256,
		coseKeyXCoor: x,
		coseKeyYCoor: y,
	}
}

// rawCBOR emits pre-encoded CBOR bytes verbatim (for embedding a COSE_Sign1).
type rawCBOR []byte

func (r rawCBOR) MarshalCBOR() ([]byte, error) { return []byte(r), nil }
