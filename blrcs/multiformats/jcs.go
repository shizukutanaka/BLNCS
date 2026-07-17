package multiformats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// ErrJCSUnsupported is returned for values JCS cannot canonicalize here.
var ErrJCSUnsupported = errors.New("multiformats: value not canonicalizable")

// ErrJCSDuplicateKey is returned when CanonicalizeJSON finds a JSON object with
// duplicate keys. Go's json.Decode silently keeps the last value for duplicate
// keys, which would make the canonical form commit to a different value than the
// raw bytes appear to encode — breaking the JCS tamper-detection guarantee.
var ErrJCSDuplicateKey = errors.New("multiformats: JSON object contains duplicate key")

// ErrCanonicalizeDepth is returned when JSON nesting exceeds maxCanonicalizeDepth.
// A DID document with pathological nesting (e.g. 1 million nested arrays) would
// exhaust goroutine stack via unbounded recursion in walkJSONTokens / canonicalValue;
// the cap prevents that at a depth that no legitimate document reaches.
var ErrCanonicalizeDepth = errors.New("multiformats: JSON nesting too deep")

// maxCanonicalizeDepth limits recursive descent in walkJSONTokens and
// canonicalValue. Legitimate DID documents and credential payloads are at most
// a handful of levels deep; 512 gives ample headroom without risk of stack
// exhaustion.
const maxCanonicalizeDepth = 512

// CanonicalizeJSON returns the RFC 8785 (JCS) canonical form of a JSON document.
//
// It parses with json.Number (so integers round-trip exactly) and re-serializes
// with: object keys sorted by UTF-16 code-unit order, no insignificant
// whitespace, and JCS string escaping (only ", \, and control characters are
// escaped; '/', '<', '>', '&', and non-ASCII are emitted literally as UTF-8).
//
// Number formatting follows RFC 8785 for integers exactly. Non-integer numbers
// are emitted via Go's shortest round-trip formatting, which matches ECMAScript
// for the values that appear in DID documents / credential metadata (which do
// not rely on float edge cases); callers needing full ES number canonicalization
// for arbitrary floats should not depend on this.
func CanonicalizeJSON(data []byte) ([]byte, error) {
	// Pre-scan for duplicate keys: Go's json.Decode silently keeps the last
	// value for duplicates, so without this check the canonical form would
	// commit to a different value than the raw bytes appear to encode.
	if err := detectDuplicateKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("multiformats: parse JSON: %w", err)
	}
	var buf bytes.Buffer
	if err := canonicalValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// detectDuplicateKeys scans raw JSON data token-by-token and returns
// ErrJCSDuplicateKey if any JSON object contains the same key more than once at
// the same nesting level. This is needed because json.Decode silently last-wins.
func detectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkJSONTokens(dec, 0)
}

func walkJSONTokens(dec *json.Decoder, depth int) error {
	if depth > maxCanonicalizeDepth {
		return ErrCanonicalizeDepth
	}
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, isDelim := t.(json.Delim)
	if !isDelim {
		return nil // scalar value — no duplicate key possible
	}
	switch d {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w: %q", ErrJCSDuplicateKey, key)
			}
			seen[key] = struct{}{}
			if err := walkJSONTokens(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token() // consume closing '}'
		return err
	case '[':
		for dec.More() {
			if err := walkJSONTokens(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token() // consume closing ']'
		return err
	}
	return nil
}

// Canonicalize serializes an in-memory JSON value (the decoded-JSON Go model:
// map[string]any, []any, string, json.Number, float64, bool, nil) to JCS form.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonicalValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalValue(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxCanonicalizeDepth {
		return ErrCanonicalizeDepth
	}
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeJCSString(buf, val)
	case json.Number:
		return writeJCSNumber(buf, val.String())
	case float64:
		return writeJCSNumber(buf, strconv.FormatFloat(val, 'g', -1, 64))
	case int:
		buf.WriteString(strconv.Itoa(val))
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalValue(buf, elem, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		return canonicalObject(buf, val, depth+1)
	default:
		return fmt.Errorf("%w: %T", ErrJCSUnsupported, v)
	}
	return nil
}

func canonicalObject(buf *bytes.Buffer, m map[string]any, depth int) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// RFC 8785: sort by UTF-16 code units. For BMP strings this equals byte-order
	// sort of the UTF-8 encoding; we sort the runes' UTF-16 units to be exact.
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJCSString(buf, k)
		buf.WriteByte(':')
		if err := canonicalValue(buf, m[k], depth); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// lessUTF16 compares two strings by UTF-16 code-unit sequence (RFC 8785 §3.2.3).
func lessUTF16(a, b string) bool {
	ar, br := []rune(a), []rune(b)
	i, j := 0, 0
	for i < len(ar) && j < len(br) {
		ua := utf16Units(ar[i])
		ub := utf16Units(br[j])
		for k := 0; k < len(ua) && k < len(ub); k++ {
			if ua[k] != ub[k] {
				return ua[k] < ub[k]
			}
		}
		if len(ua) != len(ub) {
			return len(ua) < len(ub)
		}
		i++
		j++
	}
	return len(ar) < len(br)
}

func utf16Units(r rune) []uint16 {
	if r < 0x10000 {
		return []uint16{uint16(r)}
	}
	r -= 0x10000
	return []uint16{uint16(0xd800 + (r >> 10)), uint16(0xdc00 + (r & 0x3ff))}
}

// writeJCSString writes a JSON string with JCS escaping rules.
func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u`)
				const hex = "0123456789abcdef"
				buf.WriteByte('0')
				buf.WriteByte('0')
				buf.WriteByte(hex[(r>>4)&0xf])
				buf.WriteByte(hex[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// writeJCSNumber emits an integer verbatim; for non-integers it passes through
// the already-shortest representation produced by the caller.
func writeJCSNumber(buf *bytes.Buffer, s string) error {
	// Integers (no '.', 'e', 'E') are emitted as-is — JCS keeps integer form.
	if isIntegerLiteral(s) {
		// RFC 8785 §3.2.2.3 / ECMAScript Number::toString: negative zero
		// serializes as "0". Emitting "-0" would make the canonical form of -0
		// differ from 0, so two logically-equal numbers would hash/sign
		// differently — a canonicalization defect in signing-critical code.
		if s == "-0" {
			s = "0"
		}
		buf.WriteString(s)
		return nil
	}
	// Non-integer: re-parse and emit shortest round-trip (best effort, see doc).
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("%w: number %q", ErrJCSUnsupported, s)
	}
	// Normalize every zero (0.0, -0.0, 0e9, …) to "0": Go's FormatFloat renders
	// -0.0 as "-0", but JCS/ECMAScript require "0".
	if f == 0 {
		buf.WriteString("0")
		return nil
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
	}
	if i >= len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
