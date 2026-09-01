package compliance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ============================================================================
// Axis 139: full RFC 9901 disclosure resolution — array elements and recursion
//
// The previous resolver handled exactly one shape: a flat, top-level object
// property, encoded as the 3-element disclosure [salt, name, value], whose
// digest had to appear in the TOP-LEVEL `_sd`. Anything else was rejected as
// malformed. RFC 9901 defines two more shapes, and a credential from any issuer
// that uses them was therefore refused outright — an interop failure that looks
// like tampering:
//
//   - Array-element disclosure: a 2-element [salt, value]. The redacted element
//     is left in the array as the object {"...": "<digest>"}, so array length
//     and element order survive redaction.
//   - Recursive disclosure: a disclosed value may itself contain `_sd` arrays
//     or `...` placeholders, so revealing a parent exposes nested structure that
//     needs another resolution pass. Such a nested digest never appears in the
//     top-level `_sd`, which is exactly what the old top-level-only check broke.
//
// The resolver below walks the payload, substituting disclosures wherever a
// digest is referenced at any depth.
//
// # Security rules enforced (all are MUSTs in the spec's verification section)
//
//   - A digest may be referenced at most once. Two references to one disclosure
//     would let a presenter duplicate a claim into several places.
//   - Every presented disclosure MUST be used. An unused one means the presenter
//     supplied a disclosure the credential does not reference — evidence of
//     mixing disclosures across credentials.
//   - `_sd` must be an array of strings, with no duplicate digests.
//   - An array placeholder object must have EXACTLY the single key `...`; a
//     placeholder carrying extra keys is malformed, not merely odd.
//   - A disclosed claim must not collide with a claim already present, nor with
//     a reserved/registered claim name. Silently overwriting would let a
//     disclosure restate `iss` or `exp`.
//   - `_sd` and `...` must never appear as disclosed CLAIM NAMES.
//
// Undisclosed data simply disappears: a digest in `_sd` with no matching
// disclosure yields no claim, and an unresolved `...` element is removed from
// its array. That is the point of selective disclosure, not an error.
// ============================================================================

var (
	// ErrDisclosureUnused is returned when a presented disclosure is never
	// referenced by any digest in the credential. The spec requires rejection:
	// it indicates disclosures were mixed between credentials.
	ErrDisclosureUnused = fmt.Errorf("%w: presented disclosure is not referenced by the credential", ErrSDJWTMalformed)
	// ErrDisclosureReused is returned when one disclosure is referenced by more
	// than one digest position, which would duplicate a claim.
	ErrDisclosureReused = fmt.Errorf("%w: disclosure referenced more than once", ErrSDJWTMalformed)
	// ErrDisclosureMalformed is returned for a structurally invalid disclosure
	// or placeholder. It wraps ErrSDJWTMalformed so that callers written against
	// the older, coarser error keep matching with errors.Is while new callers can
	// distinguish the specific cause.
	ErrDisclosureMalformed = fmt.Errorf("%w: malformed disclosure or digest placeholder", ErrSDJWTMalformed)
	// ErrDisclosureCollision is returned when a disclosed claim would overwrite
	// an existing or reserved claim. Also wraps ErrSDJWTMalformed (see above).
	ErrDisclosureCollision = fmt.Errorf("%w: disclosed claim collides with an existing or reserved claim", ErrSDJWTMalformed)
)

// arrayDigestKey is the single key an array-element placeholder object carries.
const arrayDigestKey = "..."

// sdKey is the object member holding digests of selectively-disclosable
// properties.
const sdKey = "_sd"

// parsedDisclosure is one decoded disclosure. Name is empty exactly when the
// disclosure is an array element (the 2-element form).
type parsedDisclosure struct {
	encoded        string
	digest         string
	name           string
	value          any
	isArrayElement bool
	used           bool
}

// parseDisclosures decodes the presented disclosure segments and indexes them by
// digest. A malformed segment is rejected rather than skipped: the presenter
// controls this input, and quietly ignoring junk would let them probe which
// shapes the verifier tolerates.
func parseDisclosures(segments []string) (map[string]*parsedDisclosure, error) {
	byDigest := make(map[string]*parsedDisclosure, len(segments))
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			return nil, fmt.Errorf("%w: not base64url", ErrDisclosureMalformed)
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("%w: not a JSON array", ErrDisclosureMalformed)
		}
		// The digest is over the ENCODED string exactly as presented, not over a
		// re-serialization: JSON is not canonical, so re-encoding would change
		// the digest and break verification against a conforming issuer.
		sum := sha256.Sum256([]byte(seg))
		d := &parsedDisclosure{
			encoded: seg,
			digest:  base64.RawURLEncoding.EncodeToString(sum[:]),
		}
		switch len(arr) {
		case 2: // [salt, value] — array element
			d.isArrayElement = true
			d.value = arr[1]
		case 3: // [salt, name, value] — object property
			name, ok := arr[1].(string)
			if !ok {
				return nil, fmt.Errorf("%w: object-property disclosure name must be a string", ErrDisclosureMalformed)
			}
			if name == sdKey || name == arrayDigestKey {
				return nil, fmt.Errorf("%w: %q may not be used as a claim name", ErrDisclosureMalformed, name)
			}
			d.name = name
			d.value = arr[2]
		default:
			return nil, fmt.Errorf("%w: disclosure must have 2 or 3 elements, got %d", ErrDisclosureMalformed, len(arr))
		}
		if _, dup := byDigest[d.digest]; dup {
			// The same disclosure presented twice: its digest can legitimately be
			// referenced only once, so this can never verify.
			return nil, ErrDisclosureReused
		}
		byDigest[d.digest] = d
	}
	return byDigest, nil
}

// resolveDisclosures substitutes disclosures into the payload at every depth and
// returns the resolved claims. reserved names them claims that a disclosure may
// not introduce.
//
// It returns an error if any presented disclosure goes unused.
func resolveDisclosures(payload map[string]any, segments []string, reserved map[string]bool) (map[string]any, error) {
	byDigest, err := parseDisclosures(segments)
	if err != nil {
		return nil, err
	}
	resolvedAny, err := resolveValue(payload, byDigest, reserved, 0)
	if err != nil {
		return nil, err
	}
	resolved, ok := resolvedAny.(map[string]any)
	if !ok {
		return nil, ErrDisclosureMalformed
	}
	// Every disclosure must have been consumed.
	for _, d := range byDigest {
		if !d.used {
			return nil, ErrDisclosureUnused
		}
	}
	return resolved, nil
}

// maxDisclosureDepth bounds recursion. Recursive disclosures nest arbitrarily in
// principle, but a presenter controls the structure, so an unbounded walk is a
// stack-exhaustion vector. Real credentials nest a handful of levels.
const maxDisclosureDepth = 32

// resolveValue recursively resolves one JSON value.
func resolveValue(v any, byDigest map[string]*parsedDisclosure, reserved map[string]bool, depth int) (any, error) {
	if depth > maxDisclosureDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d levels", ErrDisclosureMalformed, maxDisclosureDepth)
	}
	switch t := v.(type) {
	case map[string]any:
		return resolveObject(t, byDigest, reserved, depth)
	case []any:
		return resolveArray(t, byDigest, reserved, depth)
	default:
		return v, nil
	}
}

// resolveObject expands an object's `_sd` digests into real properties and
// recurses into its members.
func resolveObject(obj map[string]any, byDigest map[string]*parsedDisclosure, reserved map[string]bool, depth int) (any, error) {
	out := make(map[string]any, len(obj))

	// Copy through the non-_sd members first, resolving each recursively, so
	// that collision checks below see everything already present.
	for k, val := range obj {
		if k == sdKey {
			continue
		}
		resolved, err := resolveValue(val, byDigest, reserved, depth+1)
		if err != nil {
			return nil, err
		}
		out[k] = resolved
	}

	sdRaw, present := obj[sdKey]
	if !present || sdRaw == nil {
		// Absent, or explicitly null. Null carries no digests, so it is treated
		// as absent rather than rejected: some issuers (including this one
		// before Axis 139) serialise an empty digest list as null, and refusing
		// those credentials would be an interop failure with no security gain.
		return out, nil
	}
	digests, ok := sdRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: _sd must be an array", ErrDisclosureMalformed)
	}
	seen := make(map[string]bool, len(digests))
	for _, dAny := range digests {
		digest, ok := dAny.(string)
		if !ok {
			return nil, fmt.Errorf("%w: _sd entries must be strings", ErrDisclosureMalformed)
		}
		if seen[digest] {
			return nil, ErrSDJWTDuplicateDigest
		}
		seen[digest] = true

		d, found := byDigest[digest]
		if !found {
			// Undisclosed: the holder chose not to reveal this claim. Correct
			// behaviour is to produce nothing, not to fail.
			continue
		}
		if d.used {
			return nil, ErrDisclosureReused
		}
		if d.isArrayElement {
			// An array-element disclosure referenced from `_sd` is a
			// shape confusion: `_sd` holds object properties only.
			return nil, fmt.Errorf("%w: array-element disclosure referenced from _sd", ErrDisclosureMalformed)
		}
		if reserved[d.name] {
			return nil, fmt.Errorf("%w: %q", ErrDisclosureCollision, d.name)
		}
		if _, exists := out[d.name]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDisclosureCollision, d.name)
		}
		d.used = true
		// The disclosed value may itself carry `_sd` or `...` placeholders.
		resolved, err := resolveValue(d.value, byDigest, reserved, depth+1)
		if err != nil {
			return nil, err
		}
		out[d.name] = resolved
	}
	return out, nil
}

// resolveArray replaces {"...": digest} placeholders with disclosed values and
// recurses into the remaining elements. An unresolved placeholder is dropped,
// which is how a redacted array element stays invisible.
func resolveArray(arr []any, byDigest map[string]*parsedDisclosure, reserved map[string]bool, depth int) (any, error) {
	out := make([]any, 0, len(arr))
	for _, el := range arr {
		digest, isPlaceholder, err := arrayPlaceholderDigest(el)
		if err != nil {
			return nil, err
		}
		if !isPlaceholder {
			resolved, err := resolveValue(el, byDigest, reserved, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, resolved)
			continue
		}
		d, found := byDigest[digest]
		if !found {
			continue // undisclosed element: omitted entirely
		}
		if d.used {
			return nil, ErrDisclosureReused
		}
		if !d.isArrayElement {
			// A 3-element object-property disclosure referenced from an array
			// placeholder is a shape confusion.
			return nil, fmt.Errorf("%w: object-property disclosure referenced from an array placeholder", ErrDisclosureMalformed)
		}
		d.used = true
		resolved, err := resolveValue(d.value, byDigest, reserved, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, resolved)
	}
	return out, nil
}

// arrayPlaceholderDigest reports whether an array element is a {"...": digest}
// placeholder and returns its digest. An object carrying `...` alongside other
// keys is malformed: the spec defines the placeholder as a single-member object,
// and tolerating extras would let a presenter smuggle data past the resolver.
func arrayPlaceholderDigest(el any) (digest string, isPlaceholder bool, err error) {
	obj, ok := el.(map[string]any)
	if !ok {
		return "", false, nil
	}
	raw, has := obj[arrayDigestKey]
	if !has {
		return "", false, nil
	}
	if len(obj) != 1 {
		return "", false, fmt.Errorf("%w: array placeholder must contain only %q", ErrDisclosureMalformed, arrayDigestKey)
	}
	s, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("%w: array placeholder digest must be a string", ErrDisclosureMalformed)
	}
	return s, true, nil
}
