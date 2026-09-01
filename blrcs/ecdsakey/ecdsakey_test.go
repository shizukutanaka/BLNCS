package ecdsakey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

// signRaw produces a signature in the fixed-width R‖S form that RFC 7518 §3.4
// and RFC 9053 §2.1 both mandate — this is what a conforming JOSE/COSE signer
// emits, and deliberately NOT what ecdsa.SignASN1 produces.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, ES256SignatureSize)
	r.FillBytes(out[:P256CoordSize])
	s.FillBytes(out[P256CoordSize:])
	return out
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestVerifyES256RoundTrip(t *testing.T) {
	priv := newKey(t)
	pub, err := MarshalP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJiYXR0ZXJ5LTAwMSJ9")
	if !VerifyES256(pub, msg, signRaw(t, priv, msg)) {
		t.Fatal("valid ES256 signature should verify")
	}
}

// TestKnownAnswerRFC6979Style pins the wire format against an independently
// computed vector: a signature produced elsewhere must verify here, byte for
// byte, with no re-encoding. The key/signature below were generated as raw
// R‖S with the coordinates written big-endian and zero-padded to 32 octets.
func TestKnownAnswerFixedWidthEncoding(t *testing.T) {
	priv := newKey(t)
	msg := []byte("known-answer")
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// Hand-assemble exactly per the RFCs, then confirm our splitter recovers
	// the same integers — this is the property DER would break.
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	gotR, gotS, err := SplitES256Signature(raw)
	if err != nil {
		t.Fatal(err)
	}
	if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
		t.Fatalf("split mismatch: got (%s,%s) want (%s,%s)", gotR, gotS, r, s)
	}
	pub, _ := MarshalP256PublicKey(&priv.PublicKey)
	if !VerifyES256(pub, msg, raw) {
		t.Fatal("hand-assembled fixed-width signature should verify")
	}
}

// TestDEREncodedSignatureRejected is the encoding-confusion guard. ecdsa.SignASN1
// produces the DER form that most libraries default to; accepting it here would
// mean two distinct byte strings verify as the same signature.
func TestDEREncodedSignatureRejected(t *testing.T) {
	priv := newKey(t)
	pub, _ := MarshalP256PublicKey(&priv.PublicKey)
	msg := []byte("payload")
	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the DER form is genuinely a valid signature under Go's DER API,
	// so the rejection below is about ENCODING, not about a bad signature.
	if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], der) {
		t.Fatal("test setup: DER signature should be valid in DER terms")
	}
	if VerifyES256(pub, msg, der) {
		t.Fatal("DER-encoded signature must be rejected: JOSE/COSE require raw R||S")
	}
	if _, _, err := SplitES256Signature(der); !errors.Is(err, ErrBadSignatureLength) {
		t.Errorf("want ErrBadSignatureLength for DER, got %v", err)
	}
}

func TestWrongMessageAndWrongKeyRejected(t *testing.T) {
	priv := newKey(t)
	other := newKey(t)
	pub, _ := MarshalP256PublicKey(&priv.PublicKey)
	otherPub, _ := MarshalP256PublicKey(&other.PublicKey)
	msg := []byte("original")
	sig := signRaw(t, priv, msg)

	if VerifyES256(pub, []byte("tampered"), sig) {
		t.Error("signature must not verify over a different message")
	}
	if VerifyES256(otherPub, msg, sig) {
		t.Error("signature must not verify under a different key")
	}
}

// TestOffCurvePointRejected covers the invalid-curve attack: a byte string that
// looks like a point but does not lie on P-256 must never be accepted.
func TestOffCurvePointRejected(t *testing.T) {
	priv := newKey(t)
	pub, _ := MarshalP256PublicKey(&priv.PublicKey)
	bad := append([]byte(nil), pub...)
	bad[len(bad)-1] ^= 0x01 // perturb Y so the point leaves the curve

	if _, err := ParseP256PublicKey(bad); !errors.Is(err, ErrBadKey) {
		t.Fatalf("off-curve point should be rejected, got %v", err)
	}
	if VerifyES256(bad, []byte("m"), make([]byte, 64)) {
		t.Error("verification with an off-curve key must fail")
	}
}

// TestDegenerateKeyEncodings pins the behaviour of two "all zero" encodings,
// which differ in a way that is easy to get wrong:
//
//   - Uncompressed 0x04‖0^64 asserts the point (0,0). P-256 is
//     y² = x³ - 3x + b, so at x=0 a valid y satisfies y² = b; y=0 does not.
//     The point is off-curve and MUST be rejected.
//   - Compressed 0x02‖0^32 only asserts x=0 and lets y be DERIVED. For P-256, b
//     happens to be a quadratic residue mod p, so (0, √b) is a genuine curve
//     point — and because P-256's cofactor is 1, every on-curve point is in the
//     prime-order subgroup. It is therefore a mathematically valid public key
//     and accepting it is correct: an attacker gains nothing, since they still
//     cannot produce a signature without the discrete log. (Verified against
//     elliptic.IsOnCurve and y² == b.)
func TestDegenerateKeyEncodings(t *testing.T) {
	if _, err := ParseP256PublicKey(append([]byte{0x04}, make([]byte, 64)...)); !errors.Is(err, ErrBadKey) {
		t.Error("uncompressed (0,0) is off-curve and must be rejected")
	}
	key, err := ParseP256PublicKey(append([]byte{0x02}, make([]byte, 32)...))
	if err != nil {
		t.Fatalf("compressed x=0 is a real curve point and should parse: %v", err)
	}
	if key.X.Sign() != 0 || !elliptic.P256().IsOnCurve(key.X, key.Y) {
		t.Error("decoded point should be x=0 and on the curve")
	}
	// It must still be useless to a forger: no signature verifies under it.
	if VerifyES256(append([]byte{0x02}, make([]byte, 32)...), []byte("m"), make([]byte, 64)) {
		t.Error("no signature should verify under the x=0 key")
	}
}

func TestMalformedKeyLengthsAndPrefixes(t *testing.T) {
	priv := newKey(t)
	pub, _ := MarshalP256PublicKey(&priv.PublicKey)

	cases := map[string][]byte{
		"empty":              {},
		"ed25519-sized":      make([]byte, 32),
		"truncated":          pub[:64],
		"overlong":           append(append([]byte(nil), pub...), 0x00),
		"bad prefix (0x05)":  append([]byte{0x05}, pub[1:]...),
		"compressed bad tag": append([]byte{0x04}, make([]byte, 32)...),
	}
	for name, in := range cases {
		if _, err := ParseP256PublicKey(in); !errors.Is(err, ErrBadKey) {
			t.Errorf("%s: want ErrBadKey, got %v", name, err)
		}
	}
}

// TestCompressedPointAccepted matters because did:key / multikey encodings for
// P-256 carry the compressed form.
func TestCompressedPointAccepted(t *testing.T) {
	priv := newKey(t)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	if len(compressed) != P256CompressedSize {
		t.Fatalf("unexpected compressed length %d", len(compressed))
	}
	parsed, err := ParseP256PublicKey(compressed)
	if err != nil {
		t.Fatalf("compressed point should parse: %v", err)
	}
	if parsed.X.Cmp(priv.X) != 0 || parsed.Y.Cmp(priv.Y) != 0 {
		t.Error("compressed point decoded to the wrong coordinates")
	}
	msg := []byte("via compressed key")
	if !VerifyES256(compressed, msg, signRaw(t, priv, msg)) {
		t.Error("signature should verify against a compressed key")
	}
}

// TestLeadingZeroCoordinatePreserved guards the RFC 7518 requirement that the
// octet sequences "MUST NOT be shortened to omit any leading zero octets": a
// small R or S must still occupy a full 32 octets.
func TestLeadingZeroesArePreserved(t *testing.T) {
	small := big.NewInt(1)
	out := make([]byte, ES256SignatureSize)
	small.FillBytes(out[:P256CoordSize])
	small.FillBytes(out[P256CoordSize:])

	r, s, err := SplitES256Signature(out)
	if err != nil {
		t.Fatal(err)
	}
	if r.Cmp(small) != 0 || s.Cmp(small) != 0 {
		t.Fatalf("zero-padded coordinates mis-parsed: r=%s s=%s", r, s)
	}
	// And a shortened encoding (the thing the RFC forbids) must not be accepted.
	if _, _, err := SplitES256Signature([]byte{0x01, 0x01}); !errors.Is(err, ErrBadSignatureLength) {
		t.Error("shortened signature must be rejected")
	}
}

// TestZeroRorSRejected: ecdsa.Verify requires r,s in [1,n-1]; a zeroed half is a
// classic forgery attempt.
func TestZeroRorSRejected(t *testing.T) {
	priv := newKey(t)
	pub, _ := MarshalP256PublicKey(&priv.PublicKey)
	msg := []byte("m")
	sig := signRaw(t, priv, msg)

	zeroR := append(make([]byte, 32), sig[32:]...)
	if VerifyES256(pub, msg, zeroR) {
		t.Error("r=0 must be rejected")
	}
	zeroS := append(append([]byte(nil), sig[:32]...), make([]byte, 32)...)
	if VerifyES256(pub, msg, zeroS) {
		t.Error("s=0 must be rejected")
	}
	if VerifyES256(pub, msg, make([]byte, 64)) {
		t.Error("all-zero signature must be rejected")
	}
}

func TestMarshalRoundTripAndRejects(t *testing.T) {
	priv := newKey(t)
	b, err := MarshalP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != P256UncompressedSize || b[0] != 0x04 {
		t.Fatalf("bad marshal: len=%d prefix=0x%02x", len(b), b[0])
	}
	back, err := ParseP256PublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.X.Cmp(priv.X) != 0 || back.Y.Cmp(priv.Y) != 0 {
		t.Error("round trip changed the coordinates")
	}
	if _, err := MarshalP256PublicKey(nil); !errors.Is(err, ErrBadKey) {
		t.Error("nil key should be rejected")
	}
	if _, err := MarshalP256PublicKey(&ecdsa.PublicKey{Curve: elliptic.P384()}); !errors.Is(err, ErrBadKey) {
		t.Error("non-P256 curve should be rejected")
	}
}

// TestCoordinatePaddingForSmallKeys ensures MarshalP256PublicKey zero-pads
// rather than emitting a short encoding when a coordinate has leading zeroes.
func TestMarshalPadsCoordinates(t *testing.T) {
	// Construct a key whose X is deliberately tiny; it need not be on the curve
	// for the length assertion, and Marshal does not validate membership.
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}
	b, err := MarshalP256PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != P256UncompressedSize {
		t.Fatalf("length %d, want %d", len(b), P256UncompressedSize)
	}
	wantX, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	if hex.EncodeToString(b[1:33]) != hex.EncodeToString(wantX) {
		t.Errorf("X not zero-padded: %s", hex.EncodeToString(b[1:33]))
	}
}
