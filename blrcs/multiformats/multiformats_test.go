package multiformats

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
