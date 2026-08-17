package compliance

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================================
// Axis 145: path-addressed presentation
//
// Name-based Present() cannot express a nested selective disclosure. It matches
// only 3-element disclosures by claim name, so:
//
//   - array-element disclosures (the 2-element shape) are skipped outright and
//     can never be revealed;
//   - two claims with the same name at different depths are indistinguishable;
//   - revealing a nested claim without its parent produces a disclosure the
//     verifier cannot attach to anything, and RFC 9901 requires it to reject the
//     whole presentation (ErrDisclosureUnused) rather than ignore it.
//
// PresentPaths addresses a claim by its position in the claim tree — the same
// []any path form DCQL uses (string = object key, int = array index) — and
// automatically includes the ancestor disclosures each selected claim depends
// on, so a valid presentation is the only thing it can produce.
// ============================================================================

// ErrPresentPathUnknown is returned when a requested path does not name a
// selectively-disclosable claim in this credential. It is deliberately an error
// rather than a silent skip: quietly dropping a mistyped path would present
// fewer claims than the holder intended, and the holder would not find out until
// the verifier rejected the presentation for a missing claim.
var ErrPresentPathUnknown = fmt.Errorf("compliance: no selectively-disclosable claim at the requested path")

// discNode is one disclosable position in the credential's claim tree.
type discNode struct {
	encoded string
	// parent is the disclosure that must also be revealed for this one to be
	// resolvable — nil when this disclosure hangs off always-visible structure.
	parent *discNode
}

// PresentPaths builds a presentation revealing exactly the claims at the given
// paths, plus every ancestor disclosure they require.
//
// A path is a []any of object keys (string) and array indices (int); this is the
// same addressing DCQL claim paths use, so a verifier's query and a holder's
// presentation can be driven by the same path values. Always-visible claims need
// not be listed — they are never disclosures — and listing one is an error,
// because it almost always means the path was mistyped.
//
//	PresentPaths(cred, [][]any{
//	    {"address", "country"},   // nested object member
//	    {"markets", 1},           // array element
//	})
func PresentPaths(sdjwt string, paths [][]any) (string, error) {
	jwtPart, index, order, err := indexDisclosablePaths(sdjwt)
	if err != nil {
		return "", err
	}
	// Collect the selected disclosures and the ancestors they depend on.
	selected := make(map[string]bool)
	for _, p := range paths {
		key, err := pathKey(p)
		if err != nil {
			return "", err
		}
		node, ok := index[key]
		if !ok {
			return "", fmt.Errorf("%w: %s", ErrPresentPathUnknown, key)
		}
		for n := node; n != nil; n = n.parent {
			selected[n.encoded] = true
		}
	}
	// Emit in the credential's original disclosure order. Re-ordering by
	// selection would leak which claim the verifier asked for first.
	var b strings.Builder
	b.WriteString(jwtPart)
	for _, enc := range order {
		if selected[enc] {
			b.WriteString("~")
			b.WriteString(enc)
		}
	}
	b.WriteString("~")
	return b.String(), nil
}

// DisclosablePaths lists every path in the credential that can be selectively
// disclosed, in a stable order. It lets a holder (or a UI) discover what a
// credential offers without decoding disclosures by hand.
func DisclosablePaths(sdjwt string) ([][]any, error) {
	_, index, _, err := indexDisclosablePaths(sdjwt)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(index))
	for k := range index {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([][]any, 0, len(keys))
	for _, k := range keys {
		var p []any
		if err := json.Unmarshal([]byte(k), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// indexDisclosablePaths decodes an issued SD-JWT and maps every disclosable
// position to its disclosure, recording each disclosure's parent so ancestors
// can be pulled in automatically. It also returns the disclosures in their
// original wire order.
func indexDisclosablePaths(sdjwt string) (jwtPart string, index map[string]*discNode, order []string, err error) {
	if sdjwt == "" {
		return "", nil, nil, ErrSDJWTEmpty
	}
	if strings.Count(sdjwt, "~") > maxSDJWTSegments {
		return "", nil, nil, ErrSDJWTTooManyDisclosures
	}
	parts := strings.Split(sdjwt, "~")
	jwtPart = parts[0]

	// Drop a trailing KB-JWT if one is present: a holder re-presenting an already
	// key-bound credential must not carry the old binding forward. A disclosure
	// is base64url and so never contains '.', which is how the verifier tells the
	// two apart — use the same rule here.
	segments := parts[1:]
	if len(segments) > 0 {
		if last := segments[len(segments)-1]; last != "" && strings.Contains(last, ".") {
			segments = segments[:len(segments)-1]
		}
	}

	byDigest, err := parseDisclosures(segments)
	if err != nil {
		return "", nil, nil, err
	}
	for _, seg := range segments {
		if seg != "" {
			order = append(order, seg)
		}
	}

	payload, err := decodeJWTPayload(jwtPart)
	if err != nil {
		return "", nil, nil, err
	}
	index = make(map[string]*discNode, len(byDigest))
	if err := walkDisclosable(payload, nil, nil, byDigest, index, 0); err != nil {
		return "", nil, nil, err
	}
	return jwtPart, index, order, nil
}

// walkDisclosable mirrors the verifier's resolution walk (disclosure.go) but
// records the PATH of each disclosure and the disclosure it hangs beneath.
func walkDisclosable(v any, path []any, parent *discNode, byDigest map[string]*parsedDisclosure, index map[string]*discNode, depth int) error {
	if depth > maxDisclosureDepth {
		return fmt.Errorf("%w: nesting deeper than %d levels", ErrDisclosureMalformed, maxDisclosureDepth)
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == sdKey {
				continue
			}
			if err := walkDisclosable(val, appendPath(path, k), parent, byDigest, index, depth+1); err != nil {
				return err
			}
		}
		digests, _ := t[sdKey].([]any)
		for _, dAny := range digests {
			digest, ok := dAny.(string)
			if !ok {
				continue
			}
			d, found := byDigest[digest]
			if !found || d.isArrayElement {
				// Not held by this holder (or a shape confusion the verifier will
				// reject anyway): nothing addressable here.
				continue
			}
			child := &discNode{encoded: d.encoded, parent: parent}
			childPath := appendPath(path, d.name)
			key, err := pathKey(childPath)
			if err != nil {
				return err
			}
			index[key] = child
			if err := walkDisclosable(d.value, childPath, child, byDigest, index, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for i, el := range t {
			digest, isPlaceholder, err := arrayPlaceholderDigest(el)
			if err != nil {
				return err
			}
			if !isPlaceholder {
				if err := walkDisclosable(el, appendPath(path, i), parent, byDigest, index, depth+1); err != nil {
					return err
				}
				continue
			}
			d, found := byDigest[digest]
			if !found || !d.isArrayElement {
				continue
			}
			child := &discNode{encoded: d.encoded, parent: parent}
			childPath := appendPath(path, i)
			key, err := pathKey(childPath)
			if err != nil {
				return err
			}
			index[key] = child
			if err := walkDisclosable(d.value, childPath, child, byDigest, index, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// appendPath copies before appending: the caller's slice is reused across
// sibling branches, so appending in place would let one branch overwrite
// another's path segments.
func appendPath(path []any, seg any) []any {
	out := make([]any, len(path), len(path)+1)
	copy(out, path)
	return append(out, seg)
}

// pathKey renders a path as canonical JSON so it can key a map. Indices are
// normalised to a number and keys to a string, so {"a", 1} and {"a", 1.0}
// address the same position.
func pathKey(path []any) (string, error) {
	norm := make([]any, 0, len(path))
	for _, seg := range path {
		switch s := seg.(type) {
		case string:
			norm = append(norm, s)
		case int:
			norm = append(norm, float64(s))
		case int64:
			norm = append(norm, float64(s))
		case float64:
			norm = append(norm, s)
		default:
			return "", fmt.Errorf("compliance: path segment must be a string or a non-negative integer, got %T", seg)
		}
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeJWTPayload extracts the claims object from a compact JWS without
// verifying the signature. This is a holder-side operation on the holder's own
// credential, so there is no signature to check against a trusted key here; the
// verifier re-parses and authenticates the same bytes.
func decodeJWTPayload(jwt string) (map[string]any, error) {
	segs := strings.SplitN(jwt, ".", 3)
	if len(segs) != 3 {
		return nil, ErrSDJWTMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil, ErrSDJWTMalformed
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, ErrSDJWTMalformed
	}
	return payload, nil
}

// sortStrings is a tiny insertion sort, avoiding a sort import for a list that
// is at most maxSDJWTSegments long.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
