// Package cbor — minimal deterministic CBOR encoder/decoder (RFC 8949 §4).
//
// Zero external dependencies. Supports the subset used by COSE_Sign1 (RFC 9052),
// IETF SCITT receipts, and ISO 18013-5 mdoc structures:
//
//   - Major types 0–7 (unsigned, negative, bytes, text, array, map, tag, simple)
//   - Deterministic integer-key map encoding (keys sorted numerically)
//   - Deterministic string-key map encoding (keys sorted by encoded length then lexicographically)
//   - Depth, size, and item-count bounds to prevent stack exhaustion or OOM
//   - A Marshaler interface for types that supply their own encoding
package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

// ============================================================================
// Major type constants (RFC 8949 §3)
// ============================================================================

const (
	majorUint   = 0
	majorNeg    = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7

	simpleTrue  = 21
	simpleFalse = 20
	simpleNull  = 22
)

// TagCOSESign1 is the CBOR tag for COSE_Sign1 (RFC 9052 §4.2).
const TagCOSESign1 = 18

// Decoder limits.
const (
	maxDepth = 64
	maxItems = 1 << 24 // 16 M items — prevents OOM on adversarial input
)

// ============================================================================
// Tag
// ============================================================================

// Tag is a CBOR tagged value (major type 6).
type Tag struct {
	Number  uint64
	Content any
}

// ============================================================================
// Marshaler interface
// ============================================================================

// Marshaler is implemented by types that supply their own CBOR encoding.
type Marshaler interface {
	MarshalCBOR() ([]byte, error)
}

// ============================================================================
// Low-level append helpers (exported for cbor/cose and blrcs/mdoc)
// ============================================================================

// AppendHead appends the CBOR initial byte + argument for the given major type.
func AppendHead(dst []byte, major byte, n uint64) []byte {
	major <<= 5
	switch {
	case n <= 23:
		return append(dst, major|byte(n))
	case n <= 0xff:
		return append(dst, major|24, byte(n))
	case n <= 0xffff:
		return append(dst, major|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(dst, major|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(dst, major|27,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// AppendUint appends a CBOR unsigned integer (major type 0).
func AppendUint(dst []byte, n uint64) []byte { return AppendHead(dst, majorUint, n) }

// AppendInt appends a CBOR integer (major 0 for n≥0, major 1 for n<0).
func AppendInt(dst []byte, n int64) []byte {
	if n >= 0 {
		return AppendHead(dst, majorUint, uint64(n))
	}
	return AppendHead(dst, majorNeg, uint64(-1-n))
}

// AppendBytes appends a CBOR byte string (major type 2).
func AppendBytes(dst []byte, b []byte) []byte {
	dst = AppendHead(dst, majorBytes, uint64(len(b)))
	return append(dst, b...)
}

// AppendText appends a CBOR text string (major type 3).
func AppendText(dst []byte, s string) []byte {
	dst = AppendHead(dst, majorText, uint64(len(s)))
	return append(dst, s...)
}

// AppendArrayHeader appends a CBOR definite-length array header.
func AppendArrayHeader(dst []byte, n int) []byte { return AppendHead(dst, majorArray, uint64(n)) }

// AppendMapHeader appends a CBOR definite-length map header.
func AppendMapHeader(dst []byte, n int) []byte { return AppendHead(dst, majorMap, uint64(n)) }

// AppendTagHeader appends a CBOR tag header.
func AppendTagHeader(dst []byte, tag uint64) []byte { return AppendHead(dst, majorTag, tag) }

// AppendNull appends the CBOR null value (0xf6).
func AppendNull(dst []byte) []byte { return append(dst, majorSimple<<5|simpleNull) }

// AppendBool appends a CBOR boolean (0xf4 false, 0xf5 true).
func AppendBool(dst []byte, b bool) []byte {
	if b {
		return append(dst, majorSimple<<5|simpleTrue)
	}
	return append(dst, majorSimple<<5|simpleFalse)
}

// ============================================================================
// Marshal
// ============================================================================

// Marshal encodes v to deterministic CBOR. Supported Go types:
//
//	nil              → null (0xf6)
//	bool             → false / true
//	uint, uint8–64   → major-0 integer
//	int, int8–64     → major-0 (≥0) or major-1 (<0)
//	[]byte           → bstr (major 2)
//	string           → tstr (major 3)
//	[]any            → definite-length array
//	map[int]any      → definite-length map, integer keys sorted ascending
//	map[string]any   → definite-length map, string keys sorted by encoded length then lex
//	Tag              → tagged value
//	Marshaler        → calls MarshalCBOR()
func Marshal(v any) ([]byte, error) {
	return appendValue(nil, v)
}

func appendValue(dst []byte, v any) ([]byte, error) {
	if m, ok := v.(Marshaler); ok {
		b, err := m.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		return append(dst, b...), nil
	}
	if v == nil {
		return AppendNull(dst), nil
	}
	switch val := v.(type) {
	case bool:
		return AppendBool(dst, val), nil
	case uint:
		return AppendUint(dst, uint64(val)), nil
	case uint8:
		return AppendUint(dst, uint64(val)), nil
	case uint16:
		return AppendUint(dst, uint64(val)), nil
	case uint32:
		return AppendUint(dst, uint64(val)), nil
	case uint64:
		return AppendUint(dst, val), nil
	case int:
		return AppendInt(dst, int64(val)), nil
	case int8:
		return AppendInt(dst, int64(val)), nil
	case int16:
		return AppendInt(dst, int64(val)), nil
	case int32:
		return AppendInt(dst, int64(val)), nil
	case int64:
		return AppendInt(dst, val), nil
	case []byte:
		return AppendBytes(dst, val), nil
	case string:
		return AppendText(dst, val), nil
	case []any:
		return appendArray(dst, val)
	case map[int]any:
		return appendIntKeyMap(dst, val)
	case map[string]any:
		return appendStrKeyMap(dst, val)
	case Tag:
		dst = AppendTagHeader(dst, val.Number)
		return appendValue(dst, val.Content)
	default:
		return nil, fmt.Errorf("cbor: unsupported type %T", v)
	}
}

func appendArray(dst []byte, elems []any) ([]byte, error) {
	dst = AppendArrayHeader(dst, len(elems))
	var err error
	for _, elem := range elems {
		dst, err = appendValue(dst, elem)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func appendIntKeyMap(dst []byte, m map[int]any) ([]byte, error) {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	dst = AppendMapHeader(dst, len(m))
	var err error
	for _, k := range keys {
		dst = AppendInt(dst, int64(k))
		dst, err = appendValue(dst, m[k])
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func appendStrKeyMap(dst []byte, m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// RFC 8949 §4.2.1: sort by length of encoded key then lexicographically
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
	dst = AppendMapHeader(dst, len(m))
	var err error
	for _, k := range keys {
		dst = AppendText(dst, k)
		dst, err = appendValue(dst, m[k])
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// ============================================================================
// Unmarshal
// ============================================================================

// Unmarshal decodes a single CBOR value from data. Returns an error if data
// has trailing bytes after the first complete value.
//
// Decoded Go types:
//
//	major 0 → uint64
//	major 1 → int64 (negative)
//	major 2 → []byte
//	major 3 → string
//	major 4 → []any
//	major 5 → map[any]any
//	major 6 → Tag
//	simple  → bool or nil
func Unmarshal(data []byte) (any, error) {
	d := &decoder{data: data}
	v, err := d.decode()
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, fmt.Errorf("cbor: %d trailing bytes", len(data)-d.pos)
	}
	return v, nil
}

// UnmarshalFirst decodes the first CBOR value from data and returns it along
// with the number of bytes consumed. Trailing bytes are allowed.
func UnmarshalFirst(data []byte) (any, int, error) {
	d := &decoder{data: data}
	v, err := d.decode()
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

// ============================================================================
// Decoder internals
// ============================================================================

type decoder struct {
	data  []byte
	pos   int
	depth int
}

func (d *decoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, errors.New("cbor: unexpected end of data")
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) readN(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.data) {
		return nil, errors.New("cbor: unexpected end of data")
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

// decodeHead returns (major type, argument value, error).
func (d *decoder) decodeHead() (byte, uint64, error) {
	b, err := d.readByte()
	if err != nil {
		return 0, 0, err
	}
	major := b >> 5
	add := b & 0x1f
	switch add {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23:
		return major, uint64(add), nil
	case 24:
		nb, err := d.readByte()
		return major, uint64(nb), err
	case 25:
		nb, err := d.readN(2)
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint16(nb)), nil
	case 26:
		nb, err := d.readN(4)
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint32(nb)), nil
	case 27:
		nb, err := d.readN(8)
		if err != nil {
			return 0, 0, err
		}
		return major, binary.BigEndian.Uint64(nb), nil
	default: // 28–31: reserved / indefinite length
		return 0, 0, fmt.Errorf("cbor: reserved additional info %d", add)
	}
}

func (d *decoder) decode() (any, error) {
	if d.depth >= maxDepth {
		return nil, errors.New("cbor: too deeply nested")
	}
	d.depth++
	defer func() { d.depth-- }()

	major, n, err := d.decodeHead()
	if err != nil {
		return nil, err
	}
	switch major {
	case majorUint:
		return n, nil

	case majorNeg:
		if n > math.MaxInt64 {
			return nil, errors.New("cbor: negative integer overflow")
		}
		return -1 - int64(n), nil

	case majorBytes:
		if n > maxItems {
			return nil, errors.New("cbor: byte string too large")
		}
		raw, err := d.readN(int(n))
		if err != nil {
			return nil, err
		}
		out := make([]byte, n)
		copy(out, raw)
		return out, nil

	case majorText:
		if n > maxItems {
			return nil, errors.New("cbor: text string too large")
		}
		raw, err := d.readN(int(n))
		if err != nil {
			return nil, err
		}
		return string(raw), nil

	case majorArray:
		if n > maxItems {
			return nil, errors.New("cbor: array too large")
		}
		arr := make([]any, n)
		for i := range arr {
			v, err := d.decode()
			if err != nil {
				return nil, fmt.Errorf("cbor: array[%d]: %w", i, err)
			}
			arr[i] = v
		}
		return arr, nil

	case majorMap:
		if n > maxItems {
			return nil, errors.New("cbor: map too large")
		}
		m := make(map[any]any, n)
		for i := uint64(0); i < n; i++ {
			k, err := d.decode()
			if err != nil {
				return nil, fmt.Errorf("cbor: map key[%d]: %w", i, err)
			}
			v, err := d.decode()
			if err != nil {
				return nil, fmt.Errorf("cbor: map val[%d]: %w", i, err)
			}
			m[k] = v
		}
		return m, nil

	case majorTag:
		v, err := d.decode()
		if err != nil {
			return nil, err
		}
		return Tag{Number: n, Content: v}, nil

	default: // majorSimple
		switch n {
		case simpleTrue:
			return true, nil
		case simpleFalse:
			return false, nil
		case simpleNull, 23: // null or undefined → nil
			return nil, nil
		default:
			return nil, fmt.Errorf("cbor: unsupported simple value %d", n)
		}
	}
}

// ============================================================================
// Convenience helpers for callers dealing with decoded map[any]any
// ============================================================================

// IntMap converts the int/uint64-keyed entries of a decoded map[any]any into
// a map[int]any. Non-integer keys are silently dropped.
func IntMap(raw map[any]any) map[int]any {
	out := make(map[int]any, len(raw))
	for k, v := range raw {
		switch ki := k.(type) {
		case uint64:
			out[int(ki)] = v
		case int64:
			out[int(ki)] = v
		}
	}
	return out
}

// GetInt returns the int64 value of a decoded integer (uint64 or int64).
// ok is false if v is nil or not an integer.
func GetInt(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// GetBytes returns the []byte value of a decoded bstr. ok is false if v is nil
// or not a bstr.
func GetBytes(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}
