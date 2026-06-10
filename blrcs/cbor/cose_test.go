package cbor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func genKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// ============================================================================
// Sign1 / Verify1 roundtrip
// ============================================================================

func TestCOSESign1Roundtrip(t *testing.T) {
	priv, pub := genKey(t)

	protected := Header{HeaderAlg: AlgEdDSA}
	payload := []byte("hello COSE_Sign1")

	data, err := Sign1(protected, nil, payload, nil, priv)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	res, err := Verify1(data, pub, nil)
	if err != nil {
		t.Fatalf("Verify1: %v", err)
	}
	if !bytes.Equal(res.Payload, payload) {
		t.Errorf("payload mismatch: got %q, want %q", res.Payload, payload)
	}
	alg, ok := GetInt(res.Protected[HeaderAlg])
	if !ok || alg != AlgEdDSA {
		t.Errorf("alg: %v", res.Protected[HeaderAlg])
	}
}

func TestCOSESign1WithKID(t *testing.T) {
	priv, pub := genKey(t)

	protected := Header{HeaderAlg: AlgEdDSA, HeaderKid: []byte("key-1")}
	payload := []byte("payload with kid")

	data, err := Sign1(protected, nil, payload, nil, priv)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	res, err := Verify1(data, pub, nil)
	if err != nil {
		t.Fatalf("Verify1: %v", err)
	}
	kid, ok := GetBytes(res.Protected[HeaderKid])
	if !ok || string(kid) != "key-1" {
		t.Errorf("kid: %v", res.Protected[HeaderKid])
	}
}

func TestCOSESign1ExternalAAD(t *testing.T) {
	priv, pub := genKey(t)

	protected := Header{HeaderAlg: AlgEdDSA}
	payload := []byte("payload")
	aad := []byte("binding-context")

	data, err := Sign1(protected, nil, payload, aad, priv)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	// Correct AAD → verify succeeds
	if _, err := Verify1(data, pub, aad); err != nil {
		t.Errorf("Verify1 with correct AAD: %v", err)
	}

	// Wrong AAD → verify fails
	if _, err := Verify1(data, pub, []byte("wrong-aad")); err != ErrCOSESigFailed {
		t.Errorf("Verify1 with wrong AAD: want ErrCOSESigFailed, got %v", err)
	}
}

func TestCOSESign1NilPayload(t *testing.T) {
	priv, pub := genKey(t)
	protected := Header{HeaderAlg: AlgEdDSA}

	data, err := Sign1(protected, nil, nil, nil, priv)
	if err != nil {
		t.Fatalf("Sign1 nil payload: %v", err)
	}
	res, err := Verify1(data, pub, nil)
	if err != nil {
		t.Fatalf("Verify1 nil payload: %v", err)
	}
	if res.Payload != nil {
		t.Errorf("payload: got %v, want nil", res.Payload)
	}
}

// ============================================================================
// Tamper detection
// ============================================================================

func TestCOSESign1TamperedPayload(t *testing.T) {
	priv, pub := genKey(t)
	data, _ := Sign1(Header{HeaderAlg: AlgEdDSA}, nil, []byte("real-payload"), nil, priv)

	// Find payload bytes and flip one bit
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)-10] ^= 0xff

	_, err := Verify1(tampered, pub, nil)
	if err == nil {
		t.Error("tampered payload should fail verification")
	}
}

func TestCOSESign1WrongKey(t *testing.T) {
	priv, _ := genKey(t)
	_, wrongPub := genKey(t)

	data, _ := Sign1(Header{HeaderAlg: AlgEdDSA}, nil, []byte("payload"), nil, priv)
	_, err := Verify1(data, wrongPub, nil)
	if err != ErrCOSESigFailed {
		t.Errorf("wrong key: want ErrCOSESigFailed, got %v", err)
	}
}

// ============================================================================
// Structural errors
// ============================================================================

func TestCOSEVerify1NotCOSE(t *testing.T) {
	// Pass a plain CBOR array without tag 18
	b, _ := Marshal([]any{[]byte("prot"), map[int]any{}, []byte("pay"), []byte("sig")})
	_, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil)
	if err != ErrCOSEInvalidTag {
		t.Errorf("want ErrCOSEInvalidTag, got %v", err)
	}
}

func TestCOSEVerify1WrongArrayLen(t *testing.T) {
	// Tag 18 wrapping a 3-element array (should be 4)
	b, _ := Marshal(Tag{Number: TagCOSESign1, Content: []any{[]byte("prot"), map[int]any{}, []byte("pay")}})
	_, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil)
	if err == nil {
		t.Error("wrong array length should fail")
	}
}

func TestCOSEVerify1MissingAlg(t *testing.T) {
	priv, pub := genKey(t)
	// Sign with alg in header, then remove it by constructing manually
	protected := Header{} // no alg
	protectedBytes, _ := Marshal(map[int]any{})
	sigInput, _ := sigStructure(protectedBytes, []byte("pay"), nil)
	sig := ed25519.Sign(priv, sigInput)

	data, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{protectedBytes, map[int]any{}, []byte("pay"), sig},
	})
	_, err := Verify1(data, pub, nil)
	if err == nil {
		t.Error("missing alg should fail")
	}
	_ = protected
}

func TestCOSEVerify1UnsupportedAlg(t *testing.T) {
	priv, pub := genKey(t)

	// Sign with EdDSA but claim RS256 (alg=-257 isn't registered)
	protected := Header{HeaderAlg: -257}
	protectedBytes, _ := encodedHeader(protected)
	sigInput, _ := sigStructure(protectedBytes, []byte("pay"), nil)
	sig := ed25519.Sign(priv, sigInput)

	data, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{protectedBytes, map[int]any{}, []byte("pay"), sig},
	})
	_, err := Verify1(data, pub, nil)
	if err == nil {
		t.Error("unsupported alg should fail")
	}
}

// ============================================================================
// Tag format
// ============================================================================

func TestCOSESign1IsTagged(t *testing.T) {
	priv, _ := genKey(t)
	data, _ := Sign1(Header{HeaderAlg: AlgEdDSA}, nil, []byte("x"), nil, priv)

	// First byte: 0xd2 = tag(18) in CBOR (major 6, additional 18)
	if data[0] != 0xd2 {
		t.Errorf("first byte: got %02x, want 0xd2 (tag 18)", data[0])
	}
}

// ============================================================================
// Algorithm registry
// ============================================================================

func TestCOSERegisterVerifier(t *testing.T) {
	const customAlg = -999

	called := false
	RegisterVerifier(customAlg, func(pub, sigInput, sig []byte) bool {
		called = true
		return bytes.Equal(sig, []byte("custom-sig"))
	})
	defer RegisterVerifier(customAlg, nil) // cleanup

	protected := Header{HeaderAlg: customAlg}
	protectedBytes, _ := encodedHeader(protected)
	data, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{protectedBytes, map[int]any{}, []byte("payload"), []byte("custom-sig")},
	})

	_, err := Verify1(data, ed25519.PublicKey(make([]byte, 32)), nil)
	if err != nil {
		t.Errorf("custom verifier: %v", err)
	}
	if !called {
		t.Error("custom verifier was not called")
	}
}

// ============================================================================
// Sig_Structure determinism
// ============================================================================

func TestSigStructureDeterministic(t *testing.T) {
	s1, _ := sigStructure([]byte{0x01}, []byte("payload"), nil)
	s2, _ := sigStructure([]byte{0x01}, []byte("payload"), nil)
	if !bytes.Equal(s1, s2) {
		t.Error("Sig_Structure not deterministic")
	}
}

func TestSigStructureFormat(t *testing.T) {
	// Sig_Structure must start with "Signature1" text string
	s, _ := sigStructure([]byte{}, []byte("p"), []byte{})
	// Expect: 84 ("Sig1" is 4-element array) then 6a 5369676e617475726531 (text "Signature1")
	if s[0] != 0x84 {
		t.Errorf("array header: got %02x, want 84", s[0])
	}
	// "Signature1" is 10 bytes: 6a = text(10)
	if s[1] != 0x6a {
		t.Errorf("text header for 'Signature1': got %02x, want 6a", s[1])
	}
	if string(s[2:12]) != "Signature1" {
		t.Errorf("context string: got %q", string(s[2:12]))
	}
}

func TestCopyHeader(t *testing.T) {
	orig := Header{1: int64(-7), 4: []byte("key-id")}
	cp := copyHeader(orig)
	// Same entries
	if cp[1] != orig[1] {
		t.Errorf("alg: %v", cp[1])
	}
	if string(cp[4].([]byte)) != "key-id" {
		t.Errorf("kid: %v", cp[4])
	}
	// Mutations to the copy must not affect the original.
	cp[99] = "extra"
	if _, ok := orig[99]; ok {
		t.Error("copy mutation leaked into original")
	}
}
