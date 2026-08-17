package compliance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ============================================================================
// Axis 145: issuance-side nested, recursive and array-element disclosure
//
// Axis 139 taught the VERIFIER to resolve all three RFC 9901 disclosure shapes
// at any depth, but issuance still emitted only flat, top-level object
// properties: a claim was disclosable as a whole or not at all, so revealing
// `address` revealed every field inside it. A holder could not disclose their
// country without also disclosing their street.
//
// The issuer marks disclosable positions with the SD() wrapper anywhere in a
// claim tree, and the redaction walk below converts each marker into the digest
// form the spec defines:
//
//   - An object member  SD(v)  becomes a 3-element disclosure [salt, name, v];
//     the member is removed and its digest joins that object's own `_sd`.
//   - An array element  SD(v)  becomes a 2-element disclosure [salt, v]; the
//     element is replaced in place by {"...": digest}, so array length and
//     element order survive redaction.
//   - Because the walk is bottom-up, a disclosed value may itself still contain
//     `_sd` / `...` — which is exactly RFC 9901's recursive disclosure. Nested
//     digests never appear in the top-level `_sd`.
//
// Back-compatible by construction: a claim tree containing no SD() marker is
// returned structurally unchanged and produces no extra disclosures, so existing
// callers see identical output.
// ============================================================================

// Disclosable marks a value as selectively disclosable at its position in a
// claim tree. Construct it with SD; the zero value is not meaningful.
type Disclosable struct{ Value any }

// SD marks v as selectively disclosable at the position it occupies.
//
// Use it inside the values passed to an issuer's sdClaims/clearClaims maps:
//
//	clearClaims := map[string]any{
//	    "address": map[string]any{
//	        "country": SD("JP"),          // disclosable on its own
//	        "city":    SD("Osaka"),       // ...and so is this, independently
//	        "planet":  "Earth",           // always visible
//	    },
//	    "markets": []any{SD("JP"), SD("DE"), "public"},
//	}
//
// A marker may nest: SD applied to a map whose members are themselves SD-marked
// produces a recursive disclosure, where revealing the parent exposes the nested
// digests rather than the nested values.
func SD(v any) Disclosable { return Disclosable{Value: v} }

var (
	// ErrDisclosableMisplaced is returned when an SD() marker sits somewhere it
	// cannot become a disclosure: at the root of a claim value, or directly
	// inside another marker (SD(SD(x))), which would silently collapse a level.
	ErrDisclosableMisplaced = fmt.Errorf("compliance: SD() marker is not inside an object or array")
	// ErrDisclosableName is returned when a disclosable object member uses a name
	// the verifier will refuse: `_sd`, `...`, or a reserved JWT/SD-JWT claim.
	// Issuing such a credential would produce one that can never verify.
	ErrDisclosableName = fmt.Errorf("compliance: invalid selectively-disclosable claim name")
	// ErrDisclosableValue is returned when a claim value cannot be JSON-encoded.
	// Left unchecked this yields an empty disclosure whose digest matches nothing
	// — a signed credential that always fails verification.
	ErrDisclosableValue = fmt.Errorf("compliance: claim value is not JSON-encodable")
	// ErrDisclosableDepth is returned when a claim tree nests deeper than the
	// verifier is willing to walk, so the credential could never be resolved.
	ErrDisclosableDepth = fmt.Errorf("compliance: claim tree nested too deeply")
)

// saltBytes is the disclosure salt length. RFC 9901 §5.2.1 requires at least
// 128 bits of entropy per salt.
const saltBytes = 16

// redactTree walks a claim value, converting every SD() marker into the digest
// form RFC 9901 defines and appending the resulting disclosures to out.
//
// decoys is the number of decoy digests to add to each object that gains an
// `_sd` (see redactObject). depth mirrors the verifier's own recursion bound so
// the issuer cannot mint a credential too deep for the resolver to walk.
func redactTree(v any, decoys, depth int, out *[]Disclosure) (any, error) {
	if depth > maxDisclosureDepth {
		return nil, fmt.Errorf("%w: deeper than %d levels", ErrDisclosableDepth, maxDisclosureDepth)
	}
	switch t := v.(type) {
	case Disclosable:
		// Reached only at a claim-value root or directly inside another marker:
		// object members and array elements are unwrapped by their container
		// below, because only the container knows which disclosure shape applies.
		return nil, ErrDisclosableMisplaced
	case map[string]any:
		return redactObject(t, decoys, depth, out)
	case []any:
		return redactArray(t, decoys, depth, out)
	default:
		return v, nil
	}
}

// redactObject replaces SD-marked members with digests in the object's own `_sd`.
func redactObject(obj map[string]any, decoys, depth int, out *[]Disclosure) (any, error) {
	if _, clash := obj[sdKey]; clash {
		// A caller-supplied literal `_sd` would be silently overwritten below,
		// and the verifier would try to resolve it as a digest array.
		return nil, fmt.Errorf("%w: %q is issuer-controlled and may not be set directly", ErrDisclosableName, sdKey)
	}
	result := make(map[string]any, len(obj))
	var digests []string

	for name, val := range obj {
		marker, marked := val.(Disclosable)
		if !marked {
			redacted, err := redactTree(val, decoys, depth+1, out)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			result[name] = redacted
			continue
		}
		// The verifier refuses a disclosure whose name is reserved or structural,
		// at ANY depth (see resolveObject). Refuse at issuance instead of minting a
		// credential that is signed, returned, and permanently unverifiable.
		if name == sdKey || name == arrayDigestKey {
			return nil, fmt.Errorf("%w: %q is structural", ErrDisclosableName, name)
		}
		if reservedSDJWTClaim(name) {
			return nil, fmt.Errorf("%w: %q is a reserved claim", ErrDisclosableName, name)
		}
		// Bottom-up: redact the value FIRST, so a marker nested inside it stays a
		// digest after this claim is disclosed — RFC 9901 recursive disclosure.
		inner, err := redactTree(marker.Value, decoys, depth+1, out)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		d, err := newObjectDisclosure(name, inner)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		*out = append(*out, d)
		digests = append(digests, digestOf(d.Encoded))
	}

	if len(digests) == 0 {
		// No `_sd` member at all when nothing here is disclosable: an empty or
		// decoy-only `_sd` on every nested object would be both noise and a
		// fingerprint of this implementation.
		return result, nil
	}
	for n := 0; n < decoys; n++ {
		salt, err := randomB64(32)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256([]byte(salt))
		digests = append(digests, base64.RawURLEncoding.EncodeToString(h[:]))
	}
	// Real and decoy digests must not be positionally distinguishable.
	if err := shuffleDigests(digests); err != nil {
		return nil, err
	}
	result[sdKey] = digests
	return result, nil
}

// redactArray replaces SD-marked elements with {"...": digest} placeholders,
// preserving array length and the position of every element.
//
// Decoy digests are deliberately NOT added to arrays. In an object a decoy only
// inflates the apparent number of disclosable members, but an array's length is
// itself semantic data — padding "three suppliers" to "five" would misstate the
// claim to any verifier that reads the length.
func redactArray(arr []any, decoys, depth int, out *[]Disclosure) (any, error) {
	result := make([]any, 0, len(arr))
	for i, el := range arr {
		marker, marked := el.(Disclosable)
		if !marked {
			redacted, err := redactTree(el, decoys, depth+1, out)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			result = append(result, redacted)
			continue
		}
		inner, err := redactTree(marker.Value, decoys, depth+1, out)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		d, err := newArrayDisclosure(inner)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		*out = append(*out, d)
		result = append(result, map[string]any{arrayDigestKey: digestOf(d.Encoded)})
	}
	return result, nil
}

// newObjectDisclosure builds the 3-element [salt, name, value] disclosure for a
// selectively-disclosable object member.
func newObjectDisclosure(name string, value any) (Disclosure, error) {
	salt, err := randomB64(saltBytes)
	if err != nil {
		return Disclosure{}, err
	}
	encoded, err := encodeDisclosure([]any{salt, name, value})
	if err != nil {
		return Disclosure{}, err
	}
	return Disclosure{Salt: salt, Name: name, Value: value, Encoded: encoded}, nil
}

// newArrayDisclosure builds the 2-element [salt, value] disclosure for a
// selectively-disclosable array element. Name stays empty: an array element has
// no claim name, which is how the two shapes are told apart on the wire.
func newArrayDisclosure(value any) (Disclosure, error) {
	salt, err := randomB64(saltBytes)
	if err != nil {
		return Disclosure{}, err
	}
	encoded, err := encodeDisclosure([]any{salt, value})
	if err != nil {
		return Disclosure{}, err
	}
	return Disclosure{Salt: salt, Value: value, Encoded: encoded}, nil
}

// encodeDisclosure serialises a disclosure array to its base64url form. The
// Marshal error is surfaced rather than discarded: a value containing a channel,
// a function, a cyclic reference or a non-finite float makes Marshal fail, and
// ignoring that would emit an empty disclosure whose digest matches nothing —
// a signed credential that can never verify.
func encodeDisclosure(parts []any) (string, error) {
	raw, err := json.Marshal(parts)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDisclosableValue, err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// digestOf is the SHA-256 digest of a disclosure's ENCODED form. It must be
// computed over the encoded string exactly as it will be transmitted: JSON is
// not canonical, so digesting a re-serialization would not match.
func digestOf(encoded string) string {
	h := sha256.Sum256([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
