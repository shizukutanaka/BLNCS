package multiformats

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ============================================================================
// base58btc — known-answer tests (Bitcoin/IPFS alphabet)
// ============================================================================

func TestBase58KnownAnswers(t *testing.T) {
	cases := []struct {
		in  []byte
		out string
	}{
		{[]byte{}, ""},
		{[]byte{0x00}, "1"},
		{[]byte{0x00, 0x00}, "11"},
		{[]byte("Hello World!"), "2NEpo7TZRRrLZSi2U"},
		{[]byte("The quick brown fox jumps over the lazy dog."), "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"},
		{mustHex(t, "0000287fb4cd"), "11233QC4"},
	}
	for _, tc := range cases {
		got := Base58Encode(tc.in)
		if got != tc.out {
			t.Errorf("Base58Encode(%x) = %q, want %q", tc.in, got, tc.out)
		}
		back, err := Base58Decode(tc.out)
		if err != nil {
			t.Errorf("Base58Decode(%q): %v", tc.out, err)
			continue
		}
		if !bytes.Equal(back, tc.in) {
			t.Errorf("Base58Decode(%q) = %x, want %x", tc.out, back, tc.in)
		}
	}
}

func TestBase58RoundTrip(t *testing.T) {
	for i := 0; i < 256; i++ {
		buf := make([]byte, i%40)
		for j := range buf {
			buf[j] = byte((i*7 + j*13) & 0xff)
		}
		enc := Base58Encode(buf)
		dec, err := Base58Decode(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if !bytes.Equal(dec, buf) {
			t.Fatalf("round-trip mismatch: %x -> %q -> %x", buf, enc, dec)
		}
	}
}

func TestBase58InvalidChar(t *testing.T) {
	// '0', 'O', 'I', 'l' are not in the alphabet.
	for _, bad := range []string{"0", "O", "I", "l", "abc0def"} {
		if _, err := Base58Decode(bad); err != ErrInvalidBase58 {
			t.Errorf("Base58Decode(%q): want ErrInvalidBase58, got %v", bad, err)
		}
	}
}

// ============================================================================
// multihash — SHA-256
// ============================================================================

func TestMultihashSHA256(t *testing.T) {
	mh := MultihashSHA256([]byte("hello"))
	// prefix: 0x12 (sha2-256), 0x20 (len 32)
	if mh[0] != 0x12 || mh[1] != 0x20 {
		t.Fatalf("bad prefix: %x", mh[:2])
	}
	if len(mh) != 34 {
		t.Fatalf("length %d, want 34", len(mh))
	}
	sum := sha256.Sum256([]byte("hello"))
	if !bytes.Equal(mh[2:], sum[:]) {
		t.Errorf("digest mismatch")
	}

	codec, digest, err := ParseMultihash(mh)
	if err != nil {
		t.Fatal(err)
	}
	if codec != 0x12 || !bytes.Equal(digest, sum[:]) {
		t.Errorf("parse mismatch: codec=%x", codec)
	}
}

func TestParseMultihashBad(t *testing.T) {
	cases := [][]byte{
		{},
		{0x12},
		{0x12, 0x20, 0x01}, // declares 32, has 1
	}
	for _, c := range cases {
		if _, _, err := ParseMultihash(c); err == nil {
			t.Errorf("ParseMultihash(%x) should fail", c)
		}
	}
}

func TestHashThenBase58Format(t *testing.T) {
	// SHA-256 multihash base58btc always starts with "Qm" (0x1220 prefix).
	got := HashThenBase58([]byte("did:webvh test entry"))
	if len(got) < 2 || got[:2] != "Qm" {
		t.Errorf("expected Qm-prefixed CIDv0-style hash, got %q", got)
	}
	// Deterministic.
	if HashThenBase58([]byte("did:webvh test entry")) != got {
		t.Error("HashThenBase58 not deterministic")
	}
}

// ============================================================================
// JCS (RFC 8785)
// ============================================================================

func TestJCSKeyOrdering(t *testing.T) {
	in := []byte(`{"b":1,"a":2,"c":3}`)
	got, err := CanonicalizeJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":3}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSWhitespaceRemoved(t *testing.T) {
	in := []byte(`{ "a" : 1 ,  "b" : [ 1 , 2 , 3 ] }`)
	got, _ := CanonicalizeJSON(in)
	want := `{"a":1,"b":[1,2,3]}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSNested(t *testing.T) {
	in := []byte(`{"z":{"y":2,"x":1},"a":[{"q":1,"p":2}]}`)
	got, _ := CanonicalizeJSON(in)
	want := `{"a":[{"p":2,"q":1}],"z":{"x":1,"y":2}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSStringEscaping(t *testing.T) {
	// JCS escapes only ", \, and control chars; '/', '<', '&' stay literal.
	in := []byte(`{"k":"a/b<c>&d\"e\\f\ng"}`)
	got, _ := CanonicalizeJSON(in)
	want := `{"k":"a/b<c>&d\"e\\f\ng"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSUnicodeLiteral(t *testing.T) {
	// Non-ASCII is emitted as literal UTF-8, not \u escaped.
	in := []byte(`{"name":"日本語"}`)
	got, _ := CanonicalizeJSON(in)
	want := `{"name":"日本語"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSIntegersPreserved(t *testing.T) {
	in := []byte(`{"big":12345678901234,"neg":-42,"zero":0}`)
	got, _ := CanonicalizeJSON(in)
	want := `{"big":12345678901234,"neg":-42,"zero":0}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSControlChars(t *testing.T) {
	in := []byte("{\"k\":\"\\u0001\\u001f\"}")
	got, _ := CanonicalizeJSON(in)
	want := "{\"k\":\"\\u0001\\u001f\"}"
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJCSDeterministic(t *testing.T) {
	in := []byte(`{"c":3,"a":1,"b":2}`)
	a, _ := CanonicalizeJSON(in)
	b, _ := CanonicalizeJSON(in)
	if !bytes.Equal(a, b) {
		t.Error("JCS not deterministic")
	}
}

func TestCanonicalizeValue(t *testing.T) {
	v := map[string]any{"b": int64(2), "a": int64(1)}
	got, err := Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1,"b":2}` {
		t.Errorf("got %s", got)
	}
}

// ============================================================================
// helpers
// ============================================================================

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBase58DecodeTooLong(t *testing.T) {
	long := make([]byte, maxBase58Input+1)
	for i := range long {
		long[i] = '1'
	}
	if _, err := Base58Decode(string(long)); err != ErrBase58TooLong {
		t.Errorf("want ErrBase58TooLong, got %v", err)
	}
}

// ============================================================================
// Multikey + multibase (Ed25519)
// ============================================================================

func TestEd25519MultikeyRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := EncodeEd25519Multikey(pub)
	if len(mk) < 1 || mk[0] != 'z' {
		t.Fatalf("multikey should be multibase base58btc (z…): %q", mk)
	}
	if !strings.HasPrefix(mk, "z6Mk") {
		t.Errorf("Ed25519 multikey should start z6Mk, got %q", mk[:6])
	}
	got, err := DecodeEd25519Multikey(mk)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("round-trip key mismatch")
	}
}

func TestDecodeEd25519MultikeyBad(t *testing.T) {
	cases := []string{
		"",                                     // empty
		"6MkxxxxNoZPrefix",                     // missing 'z'
		"z",                                    // just prefix
		"z" + Base58Encode([]byte{0x01, 0x02}), // wrong codec/length
		"z" + Base58Encode(append([]byte{0xed, 0x01}, make([]byte, 10)...)), // short key
	}
	for _, c := range cases {
		if _, err := DecodeEd25519Multikey(c); err == nil {
			t.Errorf("DecodeEd25519Multikey(%q) should fail", c)
		}
	}
}

func TestMultibaseBase58RoundTrip(t *testing.T) {
	data := []byte("data-integrity-proof-value")
	enc := EncodeMultibaseBase58(data)
	if enc[0] != 'z' {
		t.Fatalf("multibase should start 'z': %q", enc)
	}
	got, err := DecodeMultibaseBase58(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("multibase round-trip mismatch")
	}
	if _, err := DecodeMultibaseBase58("no-z-prefix"); err == nil {
		t.Error("missing 'z' prefix should fail")
	}
}

// ============================================================================
// JCS — JSON Canonicalization Scheme
// ============================================================================

func TestCanonicalizeJSONRoundTrip(t *testing.T) {
	// Standard JCS: keys sorted, no whitespace.
	input := `{"z": 3, "a": 1, "m": 2}`
	out, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1,"m":2,"z":3}`
	if string(out) != want {
		t.Errorf("canonicalize: got %q want %q", out, want)
	}
}

func TestCanonicalizeFloat(t *testing.T) {
	// Float numbers should go through writeJCSNumber's non-integer path.
	input := `{"x": 1.5, "y": -0.5}`
	out, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) == "" {
		t.Error("empty output")
	}
}

func TestCanonicalizeJSONStringEscapes(t *testing.T) {
	// JSON with actual control characters represented as escape sequences
	input := []byte(`{"key": "hello\nworld"}`)
	out, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Error("empty output for string with escapes")
	}
}

func TestCanonicalizeJSONSurrogatePair(t *testing.T) {
	// Emoji (non-BMP rune) → should produce surrogate pair in JCS string
	input := `{"emoji": "😀"}`
	out, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Error("empty output for emoji")
	}
}

func TestCanonicalizeJSONInvalid(t *testing.T) {
	_, err := CanonicalizeJSON([]byte(`{not json`))
	if err == nil {
		t.Error("invalid JSON should fail")
	}
}

// TestCanonicalizeJSONDuplicateKey verifies that CanonicalizeJSON rejects
// JSON objects with duplicate keys at the top level. Go's json.Decode would
// silently keep the last value, producing a canonical form that commits to a
// different value than the raw bytes appear to encode — a JCS integrity hole.
func TestCanonicalizeJSONDuplicateKey(t *testing.T) {
	cases := []string{
		`{"a":1,"a":2}`,       // top-level dup
		`{"b":1,"a":2,"b":3}`, // dup not adjacent
		`{"x":{"k":1,"k":2}}`, // nested dup
	}
	for _, c := range cases {
		if _, err := CanonicalizeJSON([]byte(c)); !errors.Is(err, ErrJCSDuplicateKey) {
			t.Errorf("CanonicalizeJSON(%s) want ErrJCSDuplicateKey, got %v", c, err)
		}
	}
}

// TestCanonicalizeJSONDuplicateKeyDifferentLevels ensures that the same key in
// different nested objects is not mis-identified as a duplicate.
func TestCanonicalizeJSONDuplicateKeyDifferentLevels(t *testing.T) {
	in := `{"a":{"a":1}}`
	if _, err := CanonicalizeJSON([]byte(in)); err != nil {
		t.Errorf("same key in different objects should not be a dup: %v", err)
	}
}

func TestCanonicalizeJSONArray(t *testing.T) {
	input := `[3, 1, 2]`
	out, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	// Arrays preserve order
	if string(out) != `[3,1,2]` {
		t.Errorf("array: %q", out)
	}
}

// ============================================================================
// Coverage uplift: int/int64/default canonicalValue branches, writeJCSString
// special control chars, writeJCSNumber bad float, isIntegerLiteral edge case,
// utf16Units surrogate pair, DecodeEd25519Multikey error paths
// ============================================================================

// TestCanonicalizeIntTypes covers the int, int64, and default branches of
// canonicalValue, and the error return path of Canonicalize.
func TestCanonicalizeIntTypes(t *testing.T) {
	b, err := Canonicalize(int(42))
	if err != nil || string(b) != "42" {
		t.Errorf("int(42): %q %v", b, err)
	}
	b, err = Canonicalize(int64(-7))
	if err != nil || string(b) != "-7" {
		t.Errorf("int64(-7): %q %v", b, err)
	}
	// default/unsupported — also covers Canonicalize's error return path
	if _, err := Canonicalize(make(chan int)); err == nil {
		t.Error("chan should return ErrJCSUnsupported")
	}
}

// TestWriteJCSStringSpecialControls covers the \b, \f, \r, \t switch cases.
func TestWriteJCSStringSpecialControls(t *testing.T) {
	b, err := Canonicalize("a\bb\fc\rd\te")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, seq := range []string{`\b`, `\f`, `\r`, `\t`} {
		if !strings.Contains(s, seq) {
			t.Errorf("expected %s in %q", seq, s)
		}
	}
}

// TestWriteJCSNumberAndIsIntegerLiteral uses json.Number values to cover:
//   - writeJCSNumber ParseFloat error path (json.Number("1.bad"))
//   - isIntegerLiteral "i >= len(s)" path (json.Number("-"))
func TestWriteJCSNumberAndIsIntegerLiteral(t *testing.T) {
	// "-" alone: isIntegerLiteral returns false, then ParseFloat("-") errors.
	if _, err := Canonicalize(json.Number("-")); err == nil {
		t.Error(`Canonicalize(json.Number("-")) should fail`)
	}
	// "1.bad": isIntegerLiteral returns false, then ParseFloat("1.bad") errors.
	if _, err := Canonicalize(json.Number("1.bad")); err == nil {
		t.Error(`Canonicalize(json.Number("1.bad")) should fail`)
	}
}

// TestUTF16SupplementaryKey covers the utf16Units surrogate-pair path by using a
// supplementary-plane rune as a JSON object *key*, forcing lessUTF16 (via
// sort.Slice in canonicalObject) to call utf16Units with a rune ≥ 0x10000.
func TestUTF16SupplementaryKey(t *testing.T) {
	input := []byte(`{"😀":1,"a":2}`)
	out, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSON with emoji key: %v", err)
	}
	if len(out) == 0 {
		t.Error("empty output")
	}
}

// TestDecodeEd25519MultikeyBadBase58 covers the Base58Decode error path.
func TestDecodeEd25519MultikeyBadBase58(t *testing.T) {
	// '0' is not in the base58btc alphabet → ErrInvalidBase58.
	if _, err := DecodeEd25519Multikey("z0invalid"); err == nil {
		t.Error("invalid base58 char should fail")
	}
}

// TestDecodeEd25519MultikeyWrongPrefix covers the wrong-prefix guard.
func TestDecodeEd25519MultikeyWrongPrefix(t *testing.T) {
	// 34 bytes total, correct length, but wrong codec prefix (0x00,0x01 ≠ 0xed,0x01).
	raw := make([]byte, 2+ed25519.PublicKeySize)
	raw[0] = 0x00
	raw[1] = 0x01
	if _, err := DecodeEd25519Multikey("z" + Base58Encode(raw)); err == nil {
		t.Error("wrong multikey prefix should fail")
	}
}

// TestCanonicalizeFloat64 covers the float64 case in canonicalValue (distinct
// from json.Number — only triggered via Canonicalize, not CanonicalizeJSON).
func TestCanonicalizeFloat64(t *testing.T) {
	b, err := Canonicalize(float64(1.5))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "1.5" {
		t.Errorf("float64(1.5): got %q", b)
	}
}

// TestCanonicalizeObjectValueError covers the error propagation path inside
// canonicalObject when a map value cannot be canonicalized.
func TestCanonicalizeObjectValueError(t *testing.T) {
	if _, err := Canonicalize(map[string]any{"k": make(chan int)}); err == nil {
		t.Error("unsupported value in map should fail")
	}
}

// TestLessUTF16CommonPrefix covers the i++/j++ branch (equal runes) and the
// "return len(ar) < len(br)" branch by using keys with a shared prefix.
func TestLessUTF16CommonPrefix(t *testing.T) {
	// "ab" and "ac" share 'a' → inner loop increments i/j after first equal rune.
	// "a" and "ab" → outer loop ends when shorter string exhausted → uses final return.
	for _, input := range []string{`{"ab":1,"ac":2}`, `{"a":1,"ab":2}`} {
		out, err := CanonicalizeJSON([]byte(input))
		if err != nil {
			t.Fatalf("CanonicalizeJSON(%s): %v", input, err)
		}
		if len(out) == 0 {
			t.Errorf("empty output for %s", input)
		}
	}
}

// TestCanonicalizeArrayError covers the error-propagation path in the []any branch.
func TestCanonicalizeArrayError(t *testing.T) {
	if _, err := Canonicalize([]any{make(chan int)}); err == nil {
		t.Error("unsupported value in array should fail")
	}
}

// TestIsIntegerLiteralEmptyString covers the early-return for empty string.
func TestIsIntegerLiteralEmptyString(t *testing.T) {
	// json.Number("") → isIntegerLiteral("") returns false → ParseFloat("") errors.
	if _, err := Canonicalize(json.Number("")); err == nil {
		t.Error("empty json.Number should fail")
	}
}

// TestCanonicalizeNilAndBool covers the nil and bool cases in canonicalValue.
// CanonicalizeJSON with UseNumber() still decodes null→nil and true/false→bool,
// so these branches are reachable from CanonicalizeJSON as well.
func TestCanonicalizeNilAndBool(t *testing.T) {
	b, err := Canonicalize(nil)
	if err != nil || string(b) != "null" {
		t.Errorf("nil: got %q %v", b, err)
	}
	b, err = Canonicalize(true)
	if err != nil || string(b) != "true" {
		t.Errorf("true: got %q %v", b, err)
	}
	b, err = Canonicalize(false)
	if err != nil || string(b) != "false" {
		t.Errorf("false: got %q %v", b, err)
	}
	// CanonicalizeJSON round-trip for null and booleans.
	for _, tc := range []struct{ in, want string }{
		{`null`, `null`},
		{`true`, `true`},
		{`false`, `false`},
		{`{"f":false,"t":true,"n":null}`, `{"f":false,"n":null,"t":true}`},
	} {
		got, err := CanonicalizeJSON([]byte(tc.in))
		if err != nil || string(got) != tc.want {
			t.Errorf("CanonicalizeJSON(%s): got %q %v", tc.in, got, err)
		}
	}
}

// TestCanonicalizeDepthLimitJSON verifies that CanonicalizeJSON rejects JSON
// that exceeds maxCanonicalizeDepth nesting levels.  Without the cap, deeply
// nested DID documents fetched from attacker-controlled URLs would cause
// walkJSONTokens and canonicalValue to recurse until goroutine stack exhaustion.
func TestCanonicalizeDepthLimitJSON(t *testing.T) {
	// Build JSON nested one level beyond the cap.
	depth := maxCanonicalizeDepth + 1
	open := strings.Repeat(`{"x":`, depth)
	close := `0` + strings.Repeat(`}`, depth)
	bomb := open + close

	_, err := CanonicalizeJSON([]byte(bomb))
	if !errors.Is(err, ErrCanonicalizeDepth) {
		t.Fatalf("expected ErrCanonicalizeDepth for depth %d, got %v", depth, err)
	}
}

// TestCanonicalizeDepthLimitValue verifies that Canonicalize also enforces the
// depth cap on an already-decoded Go value (the path used by didwebvh/proof.go).
func TestCanonicalizeDepthLimitValue(t *testing.T) {
	// Build a map[string]any nested one level beyond the cap.
	var v any = float64(0)
	for i := 0; i <= maxCanonicalizeDepth; i++ {
		v = map[string]any{"x": v}
	}
	_, err := Canonicalize(v)
	if !errors.Is(err, ErrCanonicalizeDepth) {
		t.Fatalf("expected ErrCanonicalizeDepth for %d-deep map, got %v", maxCanonicalizeDepth+1, err)
	}
}

// TestCanonicalizeDepthLimitAtBoundary verifies that exactly-at-limit nesting
// succeeds (the cap is inclusive, not off-by-one in the wrong direction).
func TestCanonicalizeDepthLimitAtBoundary(t *testing.T) {
	// Build JSON at exactly the cap (not beyond it).
	depth := maxCanonicalizeDepth
	open := strings.Repeat(`{"x":`, depth)
	close := `0` + strings.Repeat(`}`, depth)
	ok := open + close

	_, err := CanonicalizeJSON([]byte(ok))
	if err != nil {
		t.Fatalf("expected success at depth %d, got %v", depth, err)
	}
}
