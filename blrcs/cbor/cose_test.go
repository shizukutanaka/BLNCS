package cbor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
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

// TestCOSEVerify1RejectsCrit verifies RFC 9052 §3.1: a COSE_Sign1 whose
// protected header marks a critical label the verifier doesn't understand MUST
// be rejected even though the signature is valid. We sign legitimately (so the
// signature is genuine) with a crit field, then assert Verify1 refuses it.
func TestCOSEVerify1RejectsCrit(t *testing.T) {
	priv, pub := genKey(t)
	payload := []byte("crit test")

	cases := []struct {
		name string
		crit any
	}{
		{"unknown integer label", []any{int64(7)}},
		{"string label", []any{"my-ext"}},
		{"empty array", []any{}},
		{"non-array", int64(7)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			protected := Header{HeaderAlg: AlgEdDSA, HeaderCrit: c.crit}
			data, err := Sign1(protected, nil, payload, nil, priv)
			if err != nil {
				t.Fatalf("Sign1: %v", err)
			}
			if _, err := Verify1(data, pub, nil); !errors.Is(err, ErrCOSECritUnsupported) {
				t.Errorf("want ErrCOSECritUnsupported, got %v", err)
			}
		})
	}

	// A crit listing only the alg label (which BLRCS understands) is accepted.
	protected := Header{HeaderAlg: AlgEdDSA, HeaderCrit: []any{int64(HeaderAlg)}}
	data, err := Sign1(protected, nil, payload, nil, priv)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}
	if _, err := Verify1(data, pub, nil); err != nil {
		t.Errorf("crit=[alg] should verify, got %v", err)
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

// TestParseHeaderBadCBOR exercises the Unmarshal error path in parseHeader.
func TestParseHeaderBadCBOR(t *testing.T) {
	// 0xff is the CBOR "break" byte — invalid outside indefinite-length encoding.
	if _, err := parseHeader([]byte{0xff}); err == nil {
		t.Fatal("invalid CBOR should fail Unmarshal in parseHeader")
	}
}

// TestHeaderAlgNonInteger exercises the non-integer alg path in headerAlg.
func TestHeaderAlgNonInteger(t *testing.T) {
	h := Header{HeaderAlg: "EdDSA"} // string value, not integer
	if _, err := headerAlg(h); err == nil {
		t.Fatal("string alg value should fail headerAlg")
	}
}

// TestVerify1ParseHeaderNotMap exercises the parseHeader error path in Verify1.
// The protected bytes decode to an integer (not a map), so parseHeader fails.
func TestVerify1ParseHeaderNotMap(t *testing.T) {
	intCBOR, _ := Marshal(uint64(99))
	b, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{intCBOR, map[int]any{}, []byte("pay"), []byte("sig")},
	})
	if _, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil); err == nil {
		t.Fatal("non-map protected bytes should fail parseHeader inside Verify1")
	}
}

// TestVerify1AlgNotInteger exercises headerAlg's non-integer-alg error via Verify1.
func TestVerify1AlgNotInteger(t *testing.T) {
	// Protected header map with integer key 1 but string value "EdDSA".
	protBytes, _ := Marshal(map[int]any{HeaderAlg: "EdDSA"})
	b, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{protBytes, map[int]any{}, []byte("pay"), []byte("sig")},
	})
	if _, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil); err == nil {
		t.Fatal("string alg value should fail headerAlg inside Verify1")
	}
}

// TestSign1EncodedHeaderError exercises the encodedHeader error path in Sign1.
// A header with an unencodable value triggers Marshal failure.
func TestSign1EncodedHeaderError(t *testing.T) {
	priv, _ := genKey(t)
	protected := Header{HeaderAlg: struct{ X int }{42}} // Marshal cannot encode struct
	if _, err := Sign1(protected, nil, []byte("x"), nil, priv); err == nil {
		t.Fatal("unencodable protected header should fail encodedHeader inside Sign1")
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

// ============================================================================
// Coverage uplift: uncovered COSE paths
// ============================================================================

// TestVerify1WrongPubKeyLength exercises the short-pub guard in verifyEdDSA.
func TestVerify1WrongPubKeyLength(t *testing.T) {
	priv, _ := genKey(t)
	data, _ := Sign1(Header{HeaderAlg: AlgEdDSA}, nil, []byte("payload"), nil, priv)
	shortPub := ed25519.PublicKey(make([]byte, 16)) // 16 bytes, not 32
	_, err := Verify1(data, shortPub, nil)
	if err != ErrCOSESigFailed {
		t.Errorf("wrong pub key length: want ErrCOSESigFailed, got %v", err)
	}
}

// TestEncodedHeaderNil exercises the nil-header branch in encodedHeader.
func TestEncodedHeaderNil(t *testing.T) {
	b, err := encodedHeader(nil)
	if err != nil {
		t.Fatalf("encodedHeader(nil): %v", err)
	}
	// Should encode as an empty CBOR map: 0xa0
	if len(b) != 1 || b[0] != 0xa0 {
		t.Errorf("unexpected encoding: %x", b)
	}
}

// TestParseHeaderEmpty exercises the empty-bytes fast-path in parseHeader.
func TestParseHeaderEmpty(t *testing.T) {
	h, err := parseHeader([]byte{})
	if err != nil {
		t.Fatalf("parseHeader empty: %v", err)
	}
	if len(h) != 0 {
		t.Errorf("expected empty header, got %v", h)
	}
}

// TestParseHeaderNotMap exercises the non-map CBOR error in parseHeader.
func TestParseHeaderNotMap(t *testing.T) {
	// CBOR uint 42 — not a map.
	b, _ := Marshal(uint64(42))
	if _, err := parseHeader(b); err == nil {
		t.Fatal("non-map CBOR should fail parseHeader")
	}
}

// TestSign1InjectsAlg exercises the missing-alg injection branch in Sign1.
func TestSign1InjectsAlg(t *testing.T) {
	priv, pub := genKey(t)
	// Pass empty header — Sign1 must inject AlgEdDSA.
	data, err := Sign1(Header{}, nil, []byte("x"), nil, priv)
	if err != nil {
		t.Fatalf("Sign1 with empty header: %v", err)
	}
	res, err := Verify1(data, pub, nil)
	if err != nil {
		t.Fatalf("Verify1: %v", err)
	}
	alg, ok := GetInt(res.Protected[HeaderAlg])
	if !ok || alg != AlgEdDSA {
		t.Errorf("injected alg: %v", res.Protected[HeaderAlg])
	}
}

// TestVerify1NonBstrProtected exercises the non-bstr protected branch.
func TestVerify1NonBstrProtected(t *testing.T) {
	b, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{uint64(99), map[int]any{}, []byte("pay"), []byte("sig")},
	})
	if _, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil); err == nil {
		t.Fatal("non-bstr protected should fail")
	}
}

// TestVerify1NonBstrSig exercises the non-bstr signature branch.
func TestVerify1NonBstrSig(t *testing.T) {
	prot, _ := encodedHeader(Header{HeaderAlg: AlgEdDSA})
	b, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{prot, map[int]any{}, []byte("pay"), "not-a-bstr-sig"},
	})
	if _, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil); err == nil {
		t.Fatal("non-bstr sig should fail")
	}
}

// TestVerify1NonBstrPayload exercises the non-nil/non-bstr payload branch.
func TestVerify1NonBstrPayload(t *testing.T) {
	prot, _ := encodedHeader(Header{HeaderAlg: AlgEdDSA})
	b, _ := Marshal(Tag{
		Number:  TagCOSESign1,
		Content: []any{prot, map[int]any{}, uint64(42), []byte("sig")},
	})
	if _, err := Verify1(b, ed25519.PublicKey(make([]byte, 32)), nil); err == nil {
		t.Fatal("non-bstr payload should fail")
	}
}

// ============================================================================
// Concurrent registry access (data-race guard)
// ============================================================================

// TestRegisterVerifierConcurrentWithVerify1 checks that concurrent
// RegisterVerifier and Verify1 calls do not race on coseVerifiers. Before the
// sync.RWMutex fix the race detector flagged this pattern.
func TestRegisterVerifierConcurrentWithVerify1(t *testing.T) {
	priv, pub := genKey(t)
	payload := []byte("concurrent-payload")
	signed, err := Sign1(Header{HeaderAlg: AlgEdDSA}, nil, payload, nil, priv)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	const customAlg = -998
	var wg sync.WaitGroup
	// Goroutine 1: repeatedly register and de-register a custom verifier.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			RegisterVerifier(customAlg, func(_, _, _ []byte) bool { return false })
			RegisterVerifier(customAlg, nil)
		}
	}()
	// Goroutine 2: repeatedly verify a valid EdDSA token (reads coseVerifiers).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			Verify1(signed, pub, nil) //nolint:errcheck
		}
	}()
	wg.Wait()
}
