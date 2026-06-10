package cbor

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ============================================================================
// Encoding — RFC 8949 §A test vectors
// ============================================================================

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var encodeVectors = []struct {
	name  string
	value any
	want  string // hex
}{
	// Unsigned integers (RFC 8949 §A.1)
	{"uint 0", uint64(0), "00"},
	{"uint 1", uint64(1), "01"},
	{"uint 10", uint64(10), "0a"},
	{"uint 23", uint64(23), "17"},
	{"uint 24", uint64(24), "1818"},
	{"uint 25", uint64(25), "1819"},
	{"uint 100", uint64(100), "1864"},
	{"uint 1000", uint64(1000), "1903e8"},
	{"uint 1000000", uint64(1000000), "1a000f4240"},
	{"uint 18446744073709551615", uint64(18446744073709551615), "1bffffffffffffffff"},

	// Negative integers (RFC 8949 §A.1)
	{"int -1", int64(-1), "20"},
	{"int -10", int64(-10), "29"},
	{"int -100", int64(-100), "3863"},
	{"int -1000", int64(-1000), "3903e7"},

	// Byte strings (RFC 8949 §A.2)
	{"bstr empty", []byte{}, "40"},
	{"bstr 0104", []byte{0x01, 0x02, 0x03, 0x04}, "4401020304"},

	// Text strings (RFC 8949 §A.3)
	{"tstr empty", "", "60"},
	{"tstr a", "a", "6161"},
	{"tstr IETF", "IETF", "6449455446"},

	// Arrays (RFC 8949 §A.4)
	{"array []", []any{}, "80"},
	{"array [1,2,3]", []any{uint64(1), uint64(2), uint64(3)}, "83010203"},
	{"array [1,[2,3],[4,5]]", []any{uint64(1), []any{uint64(2), uint64(3)}, []any{uint64(4), uint64(5)}}, "8301820203820405"},

	// Simple values
	{"false", false, "f4"},
	{"true", true, "f5"},
	{"null", nil, "f6"},
}

func TestMarshalVectors(t *testing.T) {
	for _, tc := range encodeVectors {
		got, err := Marshal(tc.value)
		if err != nil {
			t.Errorf("%s: Marshal error: %v", tc.name, err)
			continue
		}
		want := mustHex(tc.want)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: got %x, want %x", tc.name, got, want)
		}
	}
}

func TestMarshalGoInts(t *testing.T) {
	// Verify all Go integer types encode correctly
	cases := []struct {
		v    any
		want uint64
	}{
		{uint(42), 42},
		{uint8(42), 42},
		{uint16(42), 42},
		{uint32(42), 42},
		{uint64(42), 42},
		{int(42), 42},
		{int8(42), 42},
		{int16(42), 42},
		{int32(42), 42},
		{int64(42), 42},
	}
	for _, tc := range cases {
		b, err := Marshal(tc.v)
		if err != nil {
			t.Fatalf("Marshal(%T(%v)): %v", tc.v, tc.v, err)
		}
		got, err := Unmarshal(b)
		if err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		n, ok := got.(uint64)
		if !ok || n != tc.want {
			t.Errorf("got %v (%T), want uint64(%d)", got, got, tc.want)
		}
	}
}

func TestMarshalUnsupportedType(t *testing.T) {
	_, err := Marshal(struct{ X int }{1})
	if err == nil {
		t.Error("expected error for unsupported struct type")
	}
}

// ============================================================================
// Decoding — roundtrip
// ============================================================================

func TestRoundtripUint(t *testing.T) {
	for _, n := range []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, 1<<32 - 1, 1 << 32, 1<<64 - 1} {
		b, _ := Marshal(n)
		v, err := Unmarshal(b)
		if err != nil {
			t.Errorf("Unmarshal uint %d: %v", n, err)
			continue
		}
		got, ok := v.(uint64)
		if !ok || got != n {
			t.Errorf("uint %d: got %v (%T)", n, v, v)
		}
	}
}

func TestRoundtripNeg(t *testing.T) {
	for _, n := range []int64{-1, -24, -25, -256, -257, -1000, -1 << 31} {
		b, _ := Marshal(n)
		v, err := Unmarshal(b)
		if err != nil {
			t.Errorf("Unmarshal int %d: %v", n, err)
			continue
		}
		got, ok := v.(int64)
		if !ok || got != n {
			t.Errorf("int %d: got %v (%T)", n, v, v)
		}
	}
}

func TestRoundtripBytes(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x01, 0x02, 0x03},
		make([]byte, 300),
	}
	for _, c := range cases {
		b, _ := Marshal(c)
		v, err := Unmarshal(b)
		if err != nil {
			t.Errorf("Unmarshal []byte: %v", err)
			continue
		}
		got, ok := v.([]byte)
		if c == nil {
			// nil []byte marshals as empty bstr (len=0)
			if !ok || len(got) != 0 {
				t.Errorf("nil []byte: got %v (%T)", v, v)
			}
			continue
		}
		if !ok || !bytes.Equal(got, c) {
			t.Errorf("[]byte: got %x, want %x", got, c)
		}
	}
}

func TestRoundtripString(t *testing.T) {
	for _, s := range []string{"", "hello", "IETF"} {
		b, _ := Marshal(s)
		v, err := Unmarshal(b)
		if err != nil {
			t.Errorf("Unmarshal string: %v", err)
			continue
		}
		got, ok := v.(string)
		if !ok || got != s {
			t.Errorf("string %q: got %v (%T)", s, v, v)
		}
	}
}

func TestRoundtripArray(t *testing.T) {
	orig := []any{uint64(1), "hello", []byte{0xde, 0xad}}
	b, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 3 {
		t.Fatalf("got %T", v)
	}
	if arr[0].(uint64) != 1 {
		t.Errorf("arr[0]: %v", arr[0])
	}
	if arr[1].(string) != "hello" {
		t.Errorf("arr[1]: %v", arr[1])
	}
	if !bytes.Equal(arr[2].([]byte), []byte{0xde, 0xad}) {
		t.Errorf("arr[2]: %v", arr[2])
	}
}

func TestRoundtripIntKeyMap(t *testing.T) {
	orig := map[int]any{1: AlgEdDSA, 4: []byte("mykey")}
	b, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	rawMap, ok := v.(map[any]any)
	if !ok {
		t.Fatalf("not a map: %T", v)
	}
	m := IntMap(rawMap)
	alg, ok := GetInt(m[1])
	if !ok || alg != AlgEdDSA {
		t.Errorf("alg: %v", m[1])
	}
}

func TestRoundtripStrKeyMap(t *testing.T) {
	orig := map[string]any{"vct": "https://example.com/type", "iss": "did:web:issuer"}
	b, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	rawMap, ok := v.(map[any]any)
	if !ok {
		t.Fatalf("not a map: %T", v)
	}
	if rawMap["vct"].(string) != "https://example.com/type" {
		t.Errorf("vct: %v", rawMap["vct"])
	}
}

func TestRoundtripTag(t *testing.T) {
	orig := Tag{Number: TagCOSESign1, Content: []any{[]byte("protected"), map[int]any{}, nil, []byte("sig")}}
	b, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	tag, ok := v.(Tag)
	if !ok || tag.Number != TagCOSESign1 {
		t.Fatalf("not tag 18: %v", v)
	}
}

func TestRoundtripBool(t *testing.T) {
	for _, bv := range []bool{true, false} {
		b, _ := Marshal(bv)
		v, err := Unmarshal(b)
		if err != nil {
			t.Errorf("bool %v: %v", bv, err)
		}
		if v.(bool) != bv {
			t.Errorf("bool mismatch: %v", v)
		}
	}
}

func TestRoundtripNull(t *testing.T) {
	b, _ := Marshal(nil)
	v, err := Unmarshal(b)
	if err != nil {
		t.Errorf("null: %v", err)
	}
	if v != nil {
		t.Errorf("null decoded to %v", v)
	}
}

// ============================================================================
// Decode error cases
// ============================================================================

func TestDecodeTrailingBytes(t *testing.T) {
	b := []byte{0x01, 0x02} // uint 1 + trailing 0x02
	_, err := Unmarshal(b)
	if err == nil {
		t.Error("expected error for trailing bytes")
	}
}

func TestDecodeUnexpectedEOF(t *testing.T) {
	cases := [][]byte{
		{0x41},       // bstr of length 1, but no data
		{0x82, 0x01}, // array of 2, only 1 element
		{0x18},       // uint with 1-byte arg, no arg byte
	}
	for _, c := range cases {
		_, err := Unmarshal(c)
		if err == nil {
			t.Errorf("expected error for %x", c)
		}
	}
}

func TestDecodeDepthLimit(t *testing.T) {
	// Build 70 levels deep nested array: more than maxDepth=64
	b := []byte{}
	for i := 0; i < 70; i++ {
		b = append(b, 0x81) // array of 1
	}
	b = append(b, 0x00) // final uint 0
	_, err := Unmarshal(b)
	if err == nil {
		t.Error("expected error for too-deep nesting")
	}
}

// ============================================================================
// UnmarshalFirst
// ============================================================================

func TestUnmarshalFirst(t *testing.T) {
	b := []byte{0x01, 0x02} // uint 1 followed by extra byte
	v, n, err := UnmarshalFirst(b)
	if err != nil {
		t.Fatal(err)
	}
	if v.(uint64) != 1 {
		t.Errorf("value: %v", v)
	}
	if n != 1 {
		t.Errorf("consumed: %d", n)
	}
}

// ============================================================================
// Marshaler interface
// ============================================================================

type rawCBOR []byte

func (r rawCBOR) MarshalCBOR() ([]byte, error) { return []byte(r), nil }

func TestMarshalerInterface(t *testing.T) {
	payload := rawCBOR(mustHex("820102")) // [1,2]
	b, err := Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		t.Errorf("unexpected: %v", v)
	}
}

// ============================================================================
// IntMap / GetInt / GetBytes helpers
// ============================================================================

func TestIntMapHelpers(t *testing.T) {
	raw := map[any]any{
		uint64(1): int64(-8),
		int64(4):  []byte("kid"),
		"str":     "ignored-by-IntMap",
	}
	m := IntMap(raw)
	if len(m) != 2 {
		t.Errorf("expected 2 int keys, got %d", len(m))
	}
	alg, ok := GetInt(m[1])
	if !ok || alg != -8 {
		t.Errorf("alg: %v", m[1])
	}
	kid, ok := GetBytes(m[4])
	if !ok || string(kid) != "kid" {
		t.Errorf("kid: %v", m[4])
	}
}

// ============================================================================
// Deterministic encoding
// ============================================================================

func TestDeterministicIntKeyMap(t *testing.T) {
	// Same map encoded twice must produce identical bytes
	m := map[int]any{3: "c", 1: "a", 2: "b"}
	b1, _ := Marshal(m)
	b2, _ := Marshal(m)
	if !bytes.Equal(b1, b2) {
		t.Error("int key map encoding not deterministic")
	}
	// Keys must appear in ascending order: 1, 2, 3
	// Each key is a single-byte CBOR int (0x01, 0x02, 0x03)
	// Value "a"=0x6161, "b"=0x6162, "c"=0x6163
	// Expected: a3 01 61 61 02 61 62 03 61 63
	want := mustHex("a3016161026162036163")
	if !bytes.Equal(b1, want) {
		t.Errorf("got %x, want %x", b1, want)
	}
}

func TestDeterministicStrKeyMap(t *testing.T) {
	// Shorter keys first (len 1 before len 2), then lexicographic for equal lengths.
	// "c"(len1) < "aa"(len2) < "bb"(len2).
	// a3 = map(3)
	// 61 63 = tstr "c"   03 = uint 3
	// 62 61 61 = tstr "aa"  01 = uint 1
	// 62 62 62 = tstr "bb"  02 = uint 2
	want := []byte{
		0xa3,
		0x61, 'c', 0x03,
		0x62, 'a', 'a', 0x01,
		0x62, 'b', 'b', 0x02,
	}
	m := map[string]any{"bb": uint64(2), "aa": uint64(1), "c": uint64(3)}
	b, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, want) {
		t.Errorf("got %x, want %x", b, want)
	}
}

// TestDeterministicIntKeyMapNegative verifies RFC 8949 §4.2.1 bytewise key
// ordering for negative integer keys (COSE_Key uses keys 1, -1, -2). Canonical
// order is non-negatives first (ascending), then negatives by ascending
// magnitude: 1 (0x01), -1 (0x20), -2 (0x21).
func TestDeterministicIntKeyMapNegative(t *testing.T) {
	m := map[int]any{-2: "c", -1: "b", 1: "a"}
	got, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0xa3,            // map(3)
		0x01, 0x61, 'a', // 1 => "a"
		0x20, 0x61, 'b', // -1 => "b"
		0x21, 0x61, 'c', // -2 => "c"
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

// TestUnmarshalDuplicateMapKey verifies that RFC 8949 §5.4 duplicate key
// rejection is enforced: a CBOR map with two identical keys must be rejected
// rather than silently keeping the last value (which would hide injected entries).
func TestUnmarshalDuplicateMapKey(t *testing.T) {
	// Manually encode {1: "a", 1: "b"} — two entries with key 1.
	// map(2) | 0x01 "a" | 0x01 "b"
	data := []byte{
		0xa2,            // map(2)
		0x01, 0x61, 'a', // 1 => "a"
		0x01, 0x61, 'b', // 1 => "b"  (duplicate key!)
	}
	if _, err := Unmarshal(data); err == nil {
		t.Fatal("duplicate CBOR map key must be rejected per RFC 8949 §5.4")
	}
}

// TestUnmarshalDuplicateStringKey verifies duplicate string key rejection.
func TestUnmarshalDuplicateStringKey(t *testing.T) {
	// {"foo": 1, "foo": 2}
	data := []byte{
		0xa2,                      // map(2)
		0x63, 'f', 'o', 'o', 0x01, // "foo" => 1
		0x63, 'f', 'o', 'o', 0x02, // "foo" => 2  (duplicate!)
	}
	if _, err := Unmarshal(data); err == nil {
		t.Fatal("duplicate CBOR string map key must be rejected per RFC 8949 §5.4")
	}
}

// ============================================================================
// GetInt helper
// ============================================================================

func TestGetInt(t *testing.T) {
	v, ok := GetInt(uint64(42))
	if !ok || v != 42 {
		t.Errorf("uint64(42): ok=%v v=%d", ok, v)
	}
	v, ok = GetInt(int64(-5))
	if !ok || v != -5 {
		t.Errorf("int64(-5): ok=%v v=%d", ok, v)
	}
	// uint64 that overflows int64
	_, ok = GetInt(uint64(1 << 63))
	if ok {
		t.Error("uint64(1<<63) should not fit int64")
	}
	// non-integer
	_, ok = GetInt("hello")
	if ok {
		t.Error("string should return ok=false")
	}
	_, ok = GetInt(nil)
	if ok {
		t.Error("nil should return ok=false")
	}
}

// ============================================================================
// appendAnyKeyMap — map[any]any encoding with deterministic ordering
// ============================================================================

func TestAnyKeyMapRoundtrip(t *testing.T) {
	// Mixed keys: int and string
	m := map[any]any{
		uint64(1): "one",
		uint64(2): "two",
	}
	enc, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(enc)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	gm, ok := got.(map[any]any)
	if !ok {
		t.Fatalf("expected map[any]any, got %T", got)
	}
	if len(gm) != 2 {
		t.Errorf("len: %d", len(gm))
	}
}

// ============================================================================
// Coverage uplift: uncovered decoder / encoder paths
// ============================================================================

// TestHashableKeyUnhashable decodes a CBOR map with a bstr key, which is
// not a valid Go map key and must be rejected.
func TestHashableKeyUnhashable(t *testing.T) {
	// map(1) { bstr("x") : uint(5) }
	data := []byte{0xa1, 0x41, 'x', 0x05}
	if _, err := Unmarshal(data); err == nil {
		t.Fatal("bstr map key must be rejected (not hashable)")
	}
}

// TestDecodeReservedAddInfo feeds a byte with reserved additional-info bits.
func TestDecodeReservedAddInfo(t *testing.T) {
	// major 0 (uint), additional 28 → 0b00011100 = 0x1c
	if _, err := Unmarshal([]byte{0x1c}); err == nil {
		t.Fatal("reserved additional info should error")
	}
}

// TestDecodeUnsupportedSimple feeds major-7 with a simple value we don't handle.
func TestDecodeUnsupportedSimple(t *testing.T) {
	// major 7 (simple), additional 0 → 0b11100000 = 0xe0, simple value 0
	if _, err := Unmarshal([]byte{0xe0}); err == nil {
		t.Fatal("unsupported simple value should error")
	}
}

// TestDecodeNegOverflow exercises the negative-integer overflow guard.
func TestDecodeNegOverflow(t *testing.T) {
	// major 1 (negative), 8-byte argument = 0x8000000000000000 = 2^63 > MaxInt64
	data := []byte{0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := Unmarshal(data); err == nil {
		t.Fatal("negative integer overflow should error")
	}
}

// TestUnmarshalFirstError exercises UnmarshalFirst on malformed CBOR.
func TestUnmarshalFirstError(t *testing.T) {
	// Truncated bstr: claims 5 bytes but empty.
	if _, _, err := UnmarshalFirst([]byte{0x45}); err == nil {
		t.Fatal("malformed CBOR should error")
	}
}

// TestAppendArrayError verifies appendArray propagates a value-encoding error.
func TestAppendArrayError(t *testing.T) {
	if _, err := Marshal([]any{struct{ X int }{1}}); err == nil {
		t.Fatal("unsupported element type in array should error")
	}
}

// TestAppendIntKeyMapError verifies appendIntKeyMap propagates a value error.
func TestAppendIntKeyMapError(t *testing.T) {
	if _, err := Marshal(map[int]any{1: struct{ X int }{}}); err == nil {
		t.Fatal("unsupported value type in int-key map should error")
	}
}

// TestAppendStrKeyMapError verifies appendStrKeyMap propagates a value error.
func TestAppendStrKeyMapError(t *testing.T) {
	if _, err := Marshal(map[string]any{"k": make(chan int)}); err == nil {
		t.Fatal("unsupported value type in str-key map should error")
	}
}

// TestAppendAnyKeyMapKeyError verifies appendAnyKeyMap propagates a key-encoding error.
func TestAppendAnyKeyMapKeyError(t *testing.T) {
	if _, err := Marshal(map[any]any{struct{}{}: "value"}); err == nil {
		t.Fatal("unsupported key type in any-key map should error")
	}
}

// TestAppendAnyKeyMapValueError verifies appendAnyKeyMap propagates a value-encoding error.
func TestAppendAnyKeyMapValueError(t *testing.T) {
	if _, err := Marshal(map[any]any{uint64(1): struct{ X int }{42}}); err == nil {
		t.Fatal("unsupported value type in any-key map should error")
	}
}

// TestDecodeHeadTruncated25 exercises the readN(2) error path in decodeHead case 25.
func TestDecodeHeadTruncated25(t *testing.T) {
	// 0x19 = major 0 (uint), add=25 → expects 2-byte argument, but no bytes follow
	if _, err := Unmarshal([]byte{0x19}); err == nil {
		t.Fatal("truncated 2-byte uint arg should error")
	}
}

// TestDecodeHeadTruncated26 exercises the readN(4) error path in decodeHead case 26.
func TestDecodeHeadTruncated26(t *testing.T) {
	// 0x1a = major 0 (uint), add=26 → expects 4-byte argument, but no bytes follow
	if _, err := Unmarshal([]byte{0x1a}); err == nil {
		t.Fatal("truncated 4-byte uint arg should error")
	}
}

// TestDecodeHeadTruncated27 exercises the readN(8) error path in decodeHead case 27.
func TestDecodeHeadTruncated27(t *testing.T) {
	// 0x1b = major 0 (uint), add=27 → expects 8-byte argument, but no bytes follow
	if _, err := Unmarshal([]byte{0x1b}); err == nil {
		t.Fatal("truncated 8-byte uint arg should error")
	}
}

// TestDecodeTextTooLarge exercises the majorText size guard in decode.
func TestDecodeTextTooLarge(t *testing.T) {
	// 0x7b = major 3 (text), add=27 → 8-byte length follows.
	// Encode length 0x0000000001000001 = 16777217 > maxItems (16777216).
	data := []byte{
		0x7b,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	}
	if _, err := Unmarshal(data); err == nil {
		t.Fatal("oversized text string should error")
	}
}
