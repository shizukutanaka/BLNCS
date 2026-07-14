package mdoc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"

	"blrcs/cbor"
)

// VerifiedDoc is the result of verifying an IssuerSigned mdoc.
type VerifiedDoc struct {
	DocType    string
	NameSpaces map[string]map[string]any // namespace → elementIdentifier → elementValue
	Validity   ValidityInfo
	DeviceKey  ed25519.PublicKey // nil if the credential has no device binding
}

// Verify checks an IssuerSigned mdoc against the issuer public key at time now.
//
// It verifies:
//  1. the issuerAuth COSE_Sign1 signature over the MSO,
//  2. MSO version == "1.0" and digestAlgorithm == "SHA-256",
//  3. the validity window (now within [validFrom, validUntil]),
//  4. that every disclosed IssuerSignedItem's SHA-256 digest matches the MSO
//     valueDigests entry for its digestID (tamper / substitution detection).
//
// Selectively-disclosed credentials (a subset of items) verify fine: only the
// present items are digest-checked; the MSO still attests to the full set.
func Verify(issuerSigned []byte, issuerPub ed25519.PublicKey, now time.Time) (*VerifiedDoc, error) {
	return VerifyWithAlgs(issuerSigned, issuerPub, now, nil)
}

// VerifyWithAlgs is Verify with an optional per-call COSE algorithm allowlist
// (see cbor.Verify1WithAlgs) — lets a caller pin issuerAuth verification to a
// specific algorithm (e.g. post-quantum-only) even if other algorithms are
// registered globally via cbor.RegisterVerifier. A nil/empty allowedAlgs
// accepts any registered algorithm, identical to Verify.
func VerifyWithAlgs(issuerSigned []byte, issuerPub ed25519.PublicKey, now time.Time, allowedAlgs []int) (*VerifiedDoc, error) {
	top, err := cbor.Unmarshal(issuerSigned)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	topMap, ok := top.(map[any]any)
	if !ok {
		return nil, ErrMalformed
	}

	// --- issuerAuth: re-encode and verify COSE_Sign1 ---
	issuerAuthRaw, ok := topMap[isIssuerAuth]
	if !ok {
		return nil, fmt.Errorf("%w: missing issuerAuth", ErrMalformed)
	}
	issuerAuthBytes, err := cbor.Marshal(issuerAuthRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode issuerAuth: %v", ErrMalformed, err)
	}
	coseRes, err := cbor.Verify1WithAlgs(issuerAuthBytes, issuerPub, nil, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssuerAuth, err)
	}

	// --- MSO: payload = #6.24(bstr .cbor MSO) ---
	mso, err := decodeTagged24(coseRes.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: MSO payload: %v", ErrMalformed, err)
	}
	msoMap, ok := mso.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: MSO not a map", ErrMalformed)
	}

	if s, _ := msoMap[msoVersion].(string); s != MSOVersion {
		return nil, fmt.Errorf("%w: version %q", ErrUnsupportedMSO, s)
	}
	if s, _ := msoMap[msoDigestAlg].(string); s != DigestAlgSHA256 {
		return nil, fmt.Errorf("%w: digestAlgorithm %q", ErrUnsupportedMSO, s)
	}

	docType, _ := msoMap[msoDocType].(string)

	// --- validity window ---
	validity, err := parseValidity(msoMap[msoValidityInfo])
	if err != nil {
		return nil, err
	}
	if now.Before(validity.ValidFrom) {
		return nil, ErrNotYetValid
	}
	if now.After(validity.ValidUntil) {
		return nil, ErrExpired
	}

	// --- valueDigests: namespace → digestID → digest ---
	valueDigests, err := parseValueDigests(msoMap[msoValueDigests])
	if err != nil {
		return nil, err
	}

	// --- device key (optional) ---
	deviceKey := parseDeviceKey(msoMap[msoDeviceKeyInfo])

	// --- IssuerNameSpaces: verify each disclosed item against its digest ---
	disclosed := map[string]map[string]any{}
	if nsRaw, ok := topMap[isNameSpaces]; ok && nsRaw != nil {
		nsMap, ok := nsRaw.(map[any]any)
		if !ok {
			return nil, fmt.Errorf("%w: nameSpaces not a map", ErrMalformed)
		}
		for nsKey, itemsRaw := range nsMap {
			ns, ok := nsKey.(string)
			if !ok {
				return nil, fmt.Errorf("%w: namespace key not text", ErrMalformed)
			}
			items, ok := itemsRaw.([]any)
			if !ok {
				return nil, fmt.Errorf("%w: namespace %q not an array", ErrMalformed, ns)
			}
			nsDigests := valueDigests[ns]
			if nsDigests == nil {
				return nil, fmt.Errorf("%w: namespace %q not in MSO", ErrUnknownDigestID, ns)
			}
			out := map[string]any{}
			for _, itemRaw := range items {
				id, value, digestID, err := verifyItem(itemRaw, nsDigests)
				if err != nil {
					return nil, err
				}
				_ = digestID
				// Two items in the same namespace with the same elementIdentifier
				// both pass digest checks independently (different digestIDs) but
				// the second would silently overwrite the first, hiding a
				// collision from the caller's audit trail and potentially
				// misrepresenting which value was actually disclosed.
				if _, exists := out[id]; exists {
					return nil, fmt.Errorf("%w: %q in %q", ErrDuplicateElement, id, ns)
				}
				out[id] = value
			}
			disclosed[ns] = out
		}
	}

	return &VerifiedDoc{
		DocType:    docType,
		NameSpaces: disclosed,
		Validity:   validity,
		DeviceKey:  deviceKey,
	}, nil
}

// verifyItem checks a single IssuerSignedItemBytes against the namespace digests
// and returns the element identifier and value.
func verifyItem(itemRaw any, nsDigests map[int][]byte) (id string, value any, digestID int, err error) {
	// itemRaw must be a Tag 24 wrapping the IssuerSignedItem bytes.
	tag, ok := itemRaw.(cbor.Tag)
	if !ok || tag.Number != tagEncodedCBOR {
		return "", nil, 0, fmt.Errorf("%w: item not tag-24 wrapped", ErrMalformed)
	}
	innerBytes, ok := tag.Content.([]byte)
	if !ok {
		return "", nil, 0, fmt.Errorf("%w: tag-24 content not bstr", ErrMalformed)
	}

	// Digest is over the full tag-24 encoding (IssuerSignedItemBytes).
	reWrapped, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: innerBytes})
	if err != nil {
		return "", nil, 0, err
	}
	sum := sha256.Sum256(reWrapped)

	inner, err := cbor.Unmarshal(innerBytes)
	if err != nil {
		return "", nil, 0, fmt.Errorf("%w: decode item: %v", ErrMalformed, err)
	}
	innerMap, ok := inner.(map[any]any)
	if !ok {
		return "", nil, 0, fmt.Errorf("%w: item not a map", ErrMalformed)
	}

	didRaw, ok := cbor.GetInt(innerMap[isiDigestID])
	if !ok {
		return "", nil, 0, fmt.Errorf("%w: item missing digestID", ErrMalformed)
	}
	digestID = int(didRaw)
	id, _ = innerMap[isiElementID].(string)
	value = innerMap[isiElementVal]

	want, ok := nsDigests[digestID]
	if !ok {
		return "", nil, 0, fmt.Errorf("%w: digestID %d", ErrUnknownDigestID, digestID)
	}
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return "", nil, 0, fmt.Errorf("%w: element %q (digestID %d)", ErrDigestMismatch, id, digestID)
	}
	return id, value, digestID, nil
}

// ============================================================================
// parsing helpers
// ============================================================================

func decodeTagged24(payload []byte) (any, error) {
	v, err := cbor.Unmarshal(payload)
	if err != nil {
		return nil, err
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != tagEncodedCBOR {
		return nil, fmt.Errorf("expected tag 24, got %T", v)
	}
	inner, ok := tag.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("tag 24 content not bstr")
	}
	return cbor.Unmarshal(inner)
}

func parseValidity(raw any) (ValidityInfo, error) {
	m, ok := raw.(map[any]any)
	if !ok {
		return ValidityInfo{}, fmt.Errorf("%w: validityInfo not a map", ErrMalformed)
	}
	signed, err := parseTDate(m[viSigned])
	if err != nil {
		return ValidityInfo{}, fmt.Errorf("%w: signed: %v", ErrMalformed, err)
	}
	from, err := parseTDate(m[viValidFrom])
	if err != nil {
		return ValidityInfo{}, fmt.Errorf("%w: validFrom: %v", ErrMalformed, err)
	}
	until, err := parseTDate(m[viValidUntil])
	if err != nil {
		return ValidityInfo{}, fmt.Errorf("%w: validUntil: %v", ErrMalformed, err)
	}
	return ValidityInfo{Signed: signed, ValidFrom: from, ValidUntil: until}, nil
}

func parseTDate(raw any) (time.Time, error) {
	tag, ok := raw.(cbor.Tag)
	if !ok || tag.Number != tagDateTime {
		return time.Time{}, fmt.Errorf("not a tdate (tag 0)")
	}
	s, ok := tag.Content.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("tdate content not text")
	}
	return time.Parse(time.RFC3339, s)
}

func parseValueDigests(raw any) (map[string]map[int][]byte, error) {
	m, ok := raw.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: valueDigests not a map", ErrMalformed)
	}
	out := map[string]map[int][]byte{}
	for nsKey, digestsRaw := range m {
		ns, ok := nsKey.(string)
		if !ok {
			return nil, fmt.Errorf("%w: valueDigests namespace not text", ErrMalformed)
		}
		dm, ok := digestsRaw.(map[any]any)
		if !ok {
			return nil, fmt.Errorf("%w: digests for %q not a map", ErrMalformed, ns)
		}
		nsDigests := map[int][]byte{}
		for idRaw, digRaw := range dm {
			id, ok := cbor.GetInt(idRaw)
			if !ok {
				return nil, fmt.Errorf("%w: digestID not int", ErrMalformed)
			}
			dig, ok := cbor.GetBytes(digRaw)
			if !ok {
				return nil, fmt.Errorf("%w: digest not bstr", ErrMalformed)
			}
			nsDigests[int(id)] = dig
		}
		out[ns] = nsDigests
	}
	return out, nil
}

func parseDeviceKey(raw any) ed25519.PublicKey {
	m, ok := raw.(map[any]any)
	if !ok {
		return nil
	}
	dkRaw, ok := m[msoDeviceKey]
	if !ok {
		return nil
	}
	dk, ok := dkRaw.(map[any]any)
	if !ok {
		return nil
	}
	keyMap := cbor.IntMap(dk)
	kty, _ := cbor.GetInt(keyMap[coseKeyKty])
	crv, _ := cbor.GetInt(keyMap[coseKeyCrv])
	if kty != ktyOKP || crv != crvEd25519 {
		return nil
	}
	x, ok := cbor.GetBytes(keyMap[coseKeyXCoor])
	if !ok || len(x) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(x)
}
