package didresolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// did:key
// ============================================================================

func TestResolveDIDKey(t *testing.T) {
	// Generate Ed25519 keypair
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Build did:key by hand using multicodec ed25519-pub (0xed 0x01) + base58
	prefixed := append([]byte{0xed, 0x01}, pub...)
	encoded := base58Encode(prefixed)
	did := "did:key:z" + encoded

	r := New()
	resolved, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(resolved, pub) {
		t.Errorf("key mismatch")
	}
}

func TestResolveDIDKeyMalformed(t *testing.T) {
	r := New()
	cases := []string{
		"did:key:",
		"did:key:notbase58",
		"did:key:zXXXX", // bad multicodec
		"did:key:z",
	}
	for _, c := range cases {
		if _, err := r.Resolve(context.Background(), c); err == nil {
			t.Errorf("should reject %q", c)
		}
	}
}

// ============================================================================
// did:jwk
// ============================================================================

func TestResolveDIDJWK(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	jwkBytes, _ := json.Marshal(jwk)
	encoded := base64.RawURLEncoding.EncodeToString(jwkBytes)
	did := "did:jwk:" + encoded

	r := New()
	resolved, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(resolved, pub) {
		t.Errorf("key mismatch")
	}
}

func TestResolveDIDJWKBadAlgorithm(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA", // unsupported
		"x":   "stuff",
	}
	jwkBytes, _ := json.Marshal(jwk)
	encoded := base64.RawURLEncoding.EncodeToString(jwkBytes)
	did := "did:jwk:" + encoded

	r := New()
	if _, err := r.Resolve(context.Background(), did); err == nil {
		t.Error("RSA JWK should fail (Ed25519 only)")
	}
}

// TestResolveDIDJWKBadXBase64 exercises jwkToEd25519's base64-decode error on "x".
func TestResolveDIDJWKBadXBase64(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "!!!not-base64!!!",
	}
	jwkBytes, _ := json.Marshal(jwk)
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)
	r := New()
	if _, err := r.Resolve(context.Background(), did); err == nil {
		t.Error("bad base64 in x should fail jwkToEd25519")
	}
}

// TestResolveDIDJWKWrongKeySize exercises jwkToEd25519's wrong-size guard.
func TestResolveDIDJWKWrongKeySize(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString([]byte("too-short")), // not 32 bytes
	}
	jwkBytes, _ := json.Marshal(jwk)
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)
	r := New()
	if _, err := r.Resolve(context.Background(), did); err == nil {
		t.Error("wrong-size Ed25519 x should fail jwkToEd25519")
	}
}

// ============================================================================
// did:web with mock HTTP
// ============================================================================

func TestResolveDIDWeb(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Mock DID document
	doc := map[string]any{
		"id": "did:web:example.com",
		"verificationMethod": []map[string]any{
			{
				"id":         "did:web:example.com#key-1",
				"type":       "JsonWebKey2020",
				"controller": "did:web:example.com",
				"publicKeyJwk": map[string]any{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64.RawURLEncoding.EncodeToString(pub),
				},
			},
		},
	}
	docBytes, _ := json.Marshal(doc)

	var fetchCount atomic.Int32
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		fetchCount.Add(1)
		expected := "https://example.com/.well-known/did.json"
		if url != expected {
			t.Errorf("URL: got %s want %s", url, expected)
		}
		return docBytes, nil
	}

	resolved, err := r.Resolve(context.Background(), "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(resolved, pub) {
		t.Errorf("key mismatch")
	}
	// Cache hit: 2回目は HTTP fetch なし
	r.Resolve(context.Background(), "did:web:example.com")
	if fetchCount.Load() != 1 {
		t.Errorf("cache miss: fetched %d times", fetchCount.Load())
	}

	// Invalidate
	r.InvalidateCache("did:web:example.com")
	r.Resolve(context.Background(), "did:web:example.com")
	if fetchCount.Load() != 2 {
		t.Errorf("after invalidate, fetched %d times", fetchCount.Load())
	}
}

func TestResolveDIDWebPathStyle(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := map[string]any{
		"verificationMethod": []map[string]any{
			{"publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}},
		},
	}
	docBytes, _ := json.Marshal(doc)

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		expected := "https://example.com/users/alice/did.json"
		if url != expected {
			t.Errorf("URL: got %s want %s", url, expected)
		}
		return docBytes, nil
	}
	if _, err := r.Resolve(context.Background(), "did:web:example.com:users:alice"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveDIDWebFetchError(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return nil, errors.New("network down")
	}
	_, err := r.Resolve(context.Background(), "did:web:example.com")
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("want ErrFetchFailed, got %v", err)
	}
}

func TestResolveDIDWebNoKey(t *testing.T) {
	doc := map[string]any{"verificationMethod": []map[string]any{}}
	docBytes, _ := json.Marshal(doc)
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return docBytes, nil
	}
	_, err := r.Resolve(context.Background(), "did:web:empty.example")
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
}

// ============================================================================
// Unsupported method
// ============================================================================

func TestUnsupportedMethod(t *testing.T) {
	r := New()
	_, err := r.Resolve(context.Background(), "did:ion:something")
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("want ErrUnsupportedMethod, got %v", err)
	}
}

func TestMalformedDID(t *testing.T) {
	r := New()
	for _, did := range []string{"", "not-a-did", "did:web", ":web:x"} {
		if _, err := r.Resolve(context.Background(), did); err == nil {
			t.Errorf("should reject %q", did)
		}
	}
}

// ============================================================================
// Trust Anchor
// ============================================================================

func TestTrustAnchorAddDID(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if ta.IsTrusted("did:web:trusted", pub) {
		t.Error("empty store should not trust anything")
	}
	ta.AddDID("did:web:trusted")
	if !ta.IsTrusted("did:web:trusted", pub) {
		t.Error("registered DID should be trusted")
	}
	if ta.IsTrusted("did:web:other", pub) {
		t.Error("unregistered DID should not be trusted")
	}
}

func TestTrustAnchorAddKey(t *testing.T) {
	ta := NewTrustAnchor()
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AddKey(pub1)
	if !ta.IsTrusted("did:web:any-id", pub1) {
		t.Error("key match should trust regardless of DID")
	}
	if ta.IsTrusted("did:web:any-id", pub2) {
		t.Error("different key should not match")
	}
}

func TestAllowAllForTesting(t *testing.T) {
	ta := NewTrustAnchor()
	ta.AllowAll()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if !ta.IsTrusted("did:web:anything", pub) {
		t.Error("AllowAll should trust everything")
	}
}

// TestTrustAnchorRemoveDID — a DID can be un-trusted (key rotation / compromise).
func TestTrustAnchorRemoveDID(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AddDID("did:web:issuer")
	if !ta.IsTrusted("did:web:issuer", pub) {
		t.Fatal("DID should be trusted after AddDID")
	}
	ta.RemoveDID("did:web:issuer")
	if ta.IsTrusted("did:web:issuer", pub) {
		t.Fatal("DID must NOT be trusted after RemoveDID (compromise/rotation)")
	}
	// Removing an unregistered DID is a no-op (must not panic).
	ta.RemoveDID("did:web:never-added")
}

// TestTrustAnchorRemoveKey — a key can be un-trusted independently of its DID.
func TestTrustAnchorRemoveKey(t *testing.T) {
	ta := NewTrustAnchor()
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AddKey(pub1)
	ta.AddKey(pub2)
	ta.RemoveKey(pub1)
	if ta.IsTrusted("did:web:any", pub1) {
		t.Fatal("removed key must not be trusted")
	}
	if !ta.IsTrusted("did:web:any", pub2) {
		t.Fatal("RemoveKey must only remove the named key")
	}
	ta.RemoveKey(pub1) // no-op on already-removed key
}

// TestTrustAnchorReset — Reset clears all trust including an accidental AllowAll,
// returning the anchor to secure-by-default (trusts nothing).
func TestTrustAnchorReset(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AddDID("did:web:issuer")
	ta.AddKey(pub)
	ta.AllowAll() // simulate an accidental dev-mode enablement
	if !ta.IsTrusted("did:web:anything", pub) {
		t.Fatal("AllowAll should trust everything before Reset")
	}
	ta.Reset()
	if ta.IsTrusted("did:web:issuer", pub) {
		t.Fatal("Reset must clear DID trust")
	}
	if ta.IsTrusted("did:web:anything", pub) {
		t.Fatal("Reset must clear AllowAll (emergency stop)")
	}
}

// ============================================================================
// ResolveAndVerify
// ============================================================================

func TestResolveAndVerifyTrusted(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	did := "did:key:z" + base58Encode(prefixed)

	r := New()
	ta := NewTrustAnchor()
	ta.AddDID(did)

	resolved, err := ResolveAndVerify(context.Background(), r, ta, did)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(resolved, pub) {
		t.Errorf("key mismatch")
	}
}

func TestResolveAndVerifyNotTrusted(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	did := "did:key:z" + base58Encode(prefixed)

	r := New()
	ta := NewTrustAnchor() // empty — does not trust anything
	_, err := ResolveAndVerify(context.Background(), r, ta, did)
	if !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("want ErrNotTrusted, got %v", err)
	}
}

// twoKeyDIDWeb returns a resolver serving a did:web document with two Ed25519
// verification methods (key rotation: old + new co-exist), plus both keys.
func twoKeyDIDWeb(t *testing.T) (*Resolver, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	pubOld, _, _ := ed25519.GenerateKey(rand.Reader)
	pubNew, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := map[string]any{
		"id": "did:web:example.com",
		"verificationMethod": []map[string]any{
			{"publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pubOld)}},
			{"publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pubNew)}},
		},
	}
	docBytes, _ := json.Marshal(doc)
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return docBytes, nil }
	return r, pubOld, pubNew
}

// TestResolveAllReturnsAllKeys — a multi-key DID document yields every key, while
// the single-key Resolve still returns just the first (back-compat).
func TestResolveAllReturnsAllKeys(t *testing.T) {
	r, pubOld, pubNew := twoKeyDIDWeb(t)
	keys, err := r.ResolveAll(context.Background(), "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if !equalKeys(keys[0], pubOld) || !equalKeys(keys[1], pubNew) {
		t.Error("keys returned in wrong order or mismatched")
	}
	// Resolve (singular) keeps returning the first key only.
	first, err := r.Resolve(context.Background(), "did:web:example.com")
	if err != nil || !equalKeys(first, pubOld) {
		t.Errorf("Resolve back-compat: got %v err %v", first, err)
	}
}

// TestResolveAndVerifyAll_RotationSecondKeyTrusted — the core rotation fix: a
// credential signed by the NEW (second-listed) key must verify, even though the
// old key is listed first. With the single-key path this was impossible.
func TestResolveAndVerifyAll_RotationSecondKeyTrusted(t *testing.T) {
	r, _, pubNew := twoKeyDIDWeb(t)
	ta := NewTrustAnchor()
	ta.AddKey(pubNew) // operator trusts the rotated-in key

	trusted, err := ResolveAndVerifyAll(context.Background(), r, ta, "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 1 || !equalKeys(trusted[0], pubNew) {
		t.Fatalf("want only the trusted new key, got %d keys", len(trusted))
	}
}

// TestResolveAndVerifyAll_NoneTrusted — if no resolved key is trusted, fail.
func TestResolveAndVerifyAll_NoneTrusted(t *testing.T) {
	r, _, _ := twoKeyDIDWeb(t)
	ta := NewTrustAnchor() // trusts nothing
	if _, err := ResolveAndVerifyAll(context.Background(), r, ta, "did:web:example.com"); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("want ErrNotTrusted, got %v", err)
	}
}

// ============================================================================
// Context cancellation
// ============================================================================

func TestResolveContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := New()
	_, err := r.Resolve(ctx, "did:web:slow.example")
	if err != context.Canceled {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// ============================================================================
// Base58 round-trip (validates our impl)
// ============================================================================

func TestBase58RoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		make([]byte, 32),
		{0x00, 0x01, 0xff},
		{0xed, 0x01, 0xaa, 0xbb, 0xcc},
	}
	for _, c := range cases {
		encoded := base58Encode(c)
		decoded, err := base58Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytesEqual(decoded, c) {
			t.Errorf("round-trip mismatch: %x → %s → %x", c, encoded, decoded)
		}
	}
}

func TestBase58DecodeEmpty(t *testing.T) {
	out, err := base58Decode("")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("empty decode: %v", out)
	}
}

func TestBase58DecodeInvalidChar(t *testing.T) {
	if _, err := base58Decode("hello0OIl"); err == nil {
		t.Error("0OIl should be rejected (excluded chars)")
	}
}

// ============================================================================
// Helpers
// ============================================================================

func equalKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool { return equalKeys(a, b) }

// base58Encode — Bitcoin base58 encode (test-only impl)
func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeros := 0
	for _, b := range input {
		if b == 0 {
			zeros++
		} else {
			break
		}
	}
	// Build big int via repeated divmod
	size := (len(input)*138)/100 + 1
	b := make([]byte, size)
	length := 0
	for i := zeros; i < len(input); i++ {
		carry := int(input[i])
		j := 0
		for k := size - 1; (carry != 0 || j < length) && k >= 0; k, j = k-1, j+1 {
			carry += 256 * int(b[k])
			b[k] = byte(carry % 58)
			carry /= 58
		}
		length = j
	}
	out := make([]byte, 0, zeros+length)
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	skip := size - length
	for i := 0; i < length; i++ {
		out = append(out, b58Alphabet[b[skip+i]])
	}
	return string(out)
}

// Suppress unused import warning during incremental development
var _ = fmt.Sprintf
var _ = time.Now

// ============================================================================
// Coverage uplift — multibase, base58Ed25519, DID doc variants, cache TTL
// ============================================================================

func TestMultibaseZ(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	encoded := "z" + base58Encode(prefixed)
	got, err := multibaseToEd25519(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("z-multibase mismatch")
	}
}

func TestMultibaseM(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := "m" + base64.RawStdEncoding.EncodeToString(pub)
	got, err := multibaseToEd25519(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("m-multibase mismatch")
	}
}

func TestMultibaseUnsupported(t *testing.T) {
	_, err := multibaseToEd25519("fABCDEF")
	if err == nil {
		t.Error("unsupported prefix should fail")
	}
}

func TestMultibaseTooShort(t *testing.T) {
	_, err := multibaseToEd25519("z")
	if err == nil {
		t.Error("empty after prefix should fail")
	}
}

func TestBase58Ed25519DecodeRawKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base58Encode(pub)
	got, err := base58Ed25519Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("raw key roundtrip")
	}
}

func TestBase58Ed25519DecodeWithMulticodec(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	encoded := base58Encode(prefixed)
	got, err := base58Ed25519Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("multicodec roundtrip")
	}
}

// TestBase58Ed25519DecodeWrongLength exercises the unexpected-length error.
func TestBase58Ed25519DecodeWrongLength(t *testing.T) {
	encoded := base58Encode([]byte("ten-bytes!")) // 10 bytes, neither 32 nor 34
	if _, err := base58Ed25519Decode(encoded); err == nil {
		t.Error("unexpected decoded length should error")
	}
}

// TestBase58Ed25519DecodeBadInput exercises the base58Decode error path.
func TestBase58Ed25519DecodeBadInput(t *testing.T) {
	if _, err := base58Ed25519Decode("0OIl"); err == nil { // 0, O, I, l not in base58 alphabet
		t.Error("invalid base58 should error")
	}
}

func TestParseDIDDocMultibaseKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	mb := "z" + base58Encode(prefixed)
	doc := map[string]any{
		"verificationMethod": []map[string]any{
			{"publicKeyMultibase": mb},
		},
	}
	docBytes, _ := json.Marshal(doc)
	got, err := parseDIDDocument(docBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("multibase DID doc key mismatch")
	}
}

func TestResolveDIDJWKBadBase64(t *testing.T) {
	r := New()
	_, err := r.Resolve(context.Background(), "did:jwk:!!!invalid!!!")
	if err == nil {
		t.Error("bad base64 should fail")
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	did := "did:key:z" + base58Encode(prefixed)
	r := New()
	r.CacheTTL = 50 * time.Millisecond
	r.Resolve(context.Background(), did)
	time.Sleep(100 * time.Millisecond)
	got, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("post-expiry resolve")
	}
}

func TestTrustAnchorConcurrent(t *testing.T) {
	ta := NewTrustAnchor()
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			ta.AddKey(pub)
			ta.IsTrusted("did:web:test", pub)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

// ============================================================================
// Service endpoint resolution (arXiv:2410.15758 — DPP data location discovery)
// ============================================================================

func TestResolveServicesDIDWeb(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{
			"id": "did:web:factory.example",
			"verificationMethod": [],
			"service": [
				{"id":"did:web:factory.example#dpp","type":"DPPService","serviceEndpoint":"https://factory.example/dpp"},
				{"id":"did:web:factory.example#status","type":"BitstringStatusList","serviceEndpoint":"https://factory.example/status/1"}
			]
		}`), nil
	}
	services, err := r.ResolveServices(context.Background(), "did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0].Type != "DPPService" {
		t.Errorf("service[0] type: %s", services[0].Type)
	}
	if services[1].ServiceEndpoint != "https://factory.example/status/1" {
		t.Errorf("service[1] endpoint: %s", services[1].ServiceEndpoint)
	}
}

func TestResolveServicesDIDKeyEmpty(t *testing.T) {
	r := New()
	// did:key carries no service endpoints
	services, err := r.ResolveServices(context.Background(), "did:key:z6MkExample")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 0 {
		t.Errorf("did:key should have no services, got %d", len(services))
	}
}

func TestResolveServicesMalformed(t *testing.T) {
	r := New()
	_, err := r.ResolveServices(context.Background(), "not-a-did")
	if err == nil {
		t.Error("malformed DID should error")
	}
}

func TestResolveServicesNoServiceField(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		// DID document without a service field
		return []byte(`{"id":"did:web:x.example","verificationMethod":[]}`), nil
	}
	services, err := r.ResolveServices(context.Background(), "did:web:x.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 0 {
		t.Errorf("no service field should yield empty, got %d", len(services))
	}
}

func TestResolveServicesCancelled(t *testing.T) {
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.ResolveServices(ctx, "did:web:x.example")
	if err != context.Canceled {
		t.Errorf("cancelled context should return Canceled, got %v", err)
	}
}

// ============================================================================
// defaultHTTPFetch — coverage for the real HTTP fetcher paths
// ============================================================================

// testFetchClient has the same CheckRedirect policy as defaultClient but no
// custom DialContext, so it can reach an httptest.Server (always loopback).
// Used to test the request/redirect/body-limit mechanics in fetchWithClient
// in isolation from the SSRF dial restriction, which is covered separately
// by TestDefaultClientBlocksLoopback below (via the real defaultHTTPFetch).
func testFetchClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return ErrRedirectNotAllowed
		},
	}
}

func TestDefaultHTTPFetchNon200(t *testing.T) {
	// Use a real httptest server returning 404 to exercise the HTTP != 200 path.
	// fetchWithClient + testFetchClient (not defaultHTTPFetch) so the SSRF dial
	// guard doesn't short-circuit before the 404 is ever reached — that guard
	// has its own dedicated test (TestDefaultClientBlocksLoopback).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	_, err := fetchWithClient(context.Background(), ts.URL+"/did.json", testFetchClient())
	if err == nil {
		t.Fatal("non-200 response should return error")
	}
}

func TestDefaultHTTPFetchSuccess(t *testing.T) {
	body := `{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:web:example.com"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		w.Write([]byte(body))
	}))
	defer ts.Close()

	got, err := fetchWithClient(context.Background(), ts.URL+"/did.json", testFetchClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != body {
		t.Errorf("body mismatch: %q", got)
	}
}

func TestDefaultHTTPFetchBadURL(t *testing.T) {
	_, err := defaultHTTPFetch(context.Background(), "://not-a-valid-url")
	if err == nil {
		t.Fatal("bad URL should return error")
	}
}

// TestDefaultHTTPFetchRejectsRedirect verifies the SSRF guard on did:web
// resolution: a malicious DID document host that 302s to a private/loopback
// address must not be followed, because the W3C did:web spec defines the
// document path exactly and following a redirect would let an attacker pivot
// the fetch into 169.254.169.254 (cloud metadata), 127.0.0.1, etc.
func TestDefaultHTTPFetchRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Whatever the attacker wants to serve from the redirected destination.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"did:web:attacker.example"}`))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/did.json", http.StatusFound) // 302
	}))
	defer redirector.Close()

	_, err := fetchWithClient(context.Background(), redirector.URL+"/did.json", testFetchClient())
	if err == nil {
		t.Fatal("redirect should be refused, got no error")
	}
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Errorf("want ErrRedirectNotAllowed, got %v", err)
	}
}

// TestDefaultHTTPFetchRejectsRedirectChainToLoopback is the explicit SSRF
// scenario: a public-looking did:web host issues a 301 to a loopback target.
// We use the redirector itself as the "loopback" stand-in since httptest binds
// to 127.0.0.1 — Go's net/http would happily follow without the CheckRedirect
// guard, so this asserts the guard actually fires.
func TestDefaultHTTPFetchRejectsRedirectChainToLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/did.json" {
			http.Redirect(w, r, "/follow-me", http.StatusMovedPermanently) // 301
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"did:web:redirected.example"}`))
	}))
	defer ts.Close()

	_, err := fetchWithClient(context.Background(), ts.URL+"/did.json", testFetchClient())
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Errorf("want ErrRedirectNotAllowed, got %v", err)
	}
}

// ============================================================================
// SSRF: direct (non-redirect) resolution to a private/loopback address
// ============================================================================

// TestDefaultClientBlocksLoopback is the core regression test for the SSRF
// gap this axis fixes: a did:web identifier resolving *directly* (no redirect
// involved) to a loopback address must be refused by the real production
// fetcher (defaultHTTPFetch/defaultClient), not just by the CheckRedirect
// guard that only covers the redirect vector. Before the fix, this reached
// the local httptest.Server successfully — exactly the SSRF this closes.
func TestDefaultClientBlocksLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"did:web:should-not-be-reached.example"}`))
	}))
	defer ts.Close()

	_, err := defaultHTTPFetch(context.Background(), ts.URL+"/did.json")
	if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("want ErrBlockedTarget, got %v", err)
	}
}

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // cloud metadata service
		{"100.64.0.1", true},      // RFC 6598 carrier-grade NAT
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isBlockedIP(ip); got != c.blocked {
			t.Errorf("isBlockedIP(%s): got %v want %v", c.ip, got, c.blocked)
		}
	}
}

// ============================================================================
// InvalidateCache
// ============================================================================

func TestInvalidateCacheEvictsEntry(t *testing.T) {
	r := New()
	hit := 0
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		hit++
		return []byte(`{"id":"did:web:evict.example","@context":["https://www.w3.org/ns/did/v1"],"verificationMethod":[{"id":"did:web:evict.example#key-1","type":"JsonWebKey2020","controller":"did:web:evict.example","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"` + testEd25519X(t) + `"}}]}`), nil
	}
	ctx := context.Background()
	if _, err := r.Resolve(ctx, "did:web:evict.example"); err != nil {
		t.Fatal(err)
	}
	if hit != 1 {
		t.Fatalf("expected 1 fetch, got %d", hit)
	}
	// Second resolve should hit cache (no additional fetch)
	if _, err := r.Resolve(ctx, "did:web:evict.example"); err != nil {
		t.Fatal(err)
	}
	if hit != 1 {
		t.Fatalf("expected still 1 fetch (cached), got %d", hit)
	}
	// Invalidate and resolve again — must re-fetch
	r.InvalidateCache("did:web:evict.example")
	if _, err := r.Resolve(ctx, "did:web:evict.example"); err != nil {
		t.Fatal(err)
	}
	if hit != 2 {
		t.Fatalf("expected 2 fetches after invalidation, got %d", hit)
	}
}

// TestResolveAllReturnsPrivateCopy verifies the resolver does not hand out its
// internal cached key slice: mutating the returned slice (or its key bytes) must
// not corrupt what a later cache hit returns. Before the defensive copy, the
// returned slice aliased the cache, so a caller's append/reorder/byte-write
// silently poisoned the cached key material for every other goroutine.
func TestResolveAllReturnsPrivateCopy(t *testing.T) {
	x := testEd25519X(t)
	r := New()
	r.HTTPFetcher = func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`{"id":"did:web:copy.example","@context":["https://www.w3.org/ns/did/v1"],"verificationMethod":[{"id":"did:web:copy.example#k","type":"JsonWebKey2020","controller":"did:web:copy.example","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}]}`), nil
	}
	ctx := context.Background()

	first, err := r.ResolveAll(ctx, "did:web:copy.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(first[0]) != ed25519.PublicKeySize {
		t.Fatalf("unexpected first result: %v", first)
	}
	// Capture the legitimate key bytes, then vandalize the returned slice's key.
	want := append(ed25519.PublicKey(nil), first[0]...)
	for i := range first[0] {
		first[0][i] ^= 0xFF // mutate every byte of the returned key
	}

	// A second resolve hits the cache. It must return the ORIGINAL key, proving
	// the cache was not aliased by the first caller's mutation.
	second, err := r.ResolveAll(ctx, "did:web:copy.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second[0], want) {
		t.Errorf("cache corrupted by caller mutation:\n got  %x\n want %x", second[0], want)
	}
	// And the two returned slices must not share backing storage.
	if &first[0][0] == &second[0][0] {
		t.Error("ResolveAll returned an aliased key slice (same backing array)")
	}
}

// testEd25519X generates a valid base64url-encoded Ed25519 public key for use in DID documents.
func testEd25519X(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

// ============================================================================
// TrustAnchor
// ============================================================================

func TestTrustAnchorAddDIDNew(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AddDID("did:web:trusted2.example")
	if !ta.IsTrusted("did:web:trusted2.example", pub) {
		t.Error("AddDID: registered DID should be trusted")
	}
	if ta.IsTrusted("did:web:other2.example", pub) {
		t.Error("unregistered DID should not be trusted")
	}
}

func TestTrustAnchorAddKeyNew(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AddKey(pub)
	if !ta.IsTrusted("did:web:any2.example", pub) {
		t.Error("AddKey: registered key should be trusted for any DID")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if ta.IsTrusted("did:web:any2.example", otherPub) {
		t.Error("unregistered key should not be trusted")
	}
}

func TestTrustAnchorAllowAllNew(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ta.AllowAll()
	if !ta.IsTrusted("did:web:random2.example", pub) {
		t.Error("AllowAll: any DID/key combination should be trusted")
	}
}

func TestTrustAnchorEmptyNew(t *testing.T) {
	ta := NewTrustAnchor()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if ta.IsTrusted("did:web:any3.example", pub) {
		t.Error("empty TrustAnchor should not trust any DID/key")
	}
}

func TestResolveAndVerifyUntrustedNew(t *testing.T) {
	r := New()
	xB64 := testEd25519X(t)
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{"id":"did:web:untrusted2.example","@context":["https://www.w3.org/ns/did/v1"],"verificationMethod":[{"id":"did:web:untrusted2.example#key-1","type":"JsonWebKey2020","controller":"did:web:untrusted2.example","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"` + xB64 + `"}}]}`), nil
	}
	ta := NewTrustAnchor() // empty — nothing trusted
	_, err := ResolveAndVerify(context.Background(), r, ta, "did:web:untrusted2.example")
	if !errors.Is(err, ErrNotTrusted) {
		t.Errorf("untrusted DID: want ErrNotTrusted, got %v", err)
	}
}

func TestResolveAndVerifyTrustedNew(t *testing.T) {
	r := New()
	ta := NewTrustAnchor()
	ta.AllowAll()
	xB64 := testEd25519X(t)
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{"id":"did:web:ok2.example","@context":["https://www.w3.org/ns/did/v1"],"verificationMethod":[{"id":"did:web:ok2.example#key-1","type":"JsonWebKey2020","controller":"did:web:ok2.example","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"` + xB64 + `"}}]}`), nil
	}
	pub, err := ResolveAndVerify(context.Background(), r, ta, "did:web:ok2.example")
	if err != nil {
		t.Fatalf("AllowAll trust anchor: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("pub key size: %d", len(pub))
	}
}

// ============================================================================
// multibaseToEd25519 — 'm' multibase base64 path (previously uncovered)
// ============================================================================

// ============================================================================
// Targeted error-path coverage for uncovered branches
// ============================================================================

// TestResolveServicesDIDWebFetchError exercises the HTTPFetcher failure path
// inside ResolveServices (distinct from the context-cancelled path).
func TestResolveServicesDIDWebFetchError(t *testing.T) {
	r := New()
	fetchErr := errors.New("connection refused")
	r.HTTPFetcher = func(_ context.Context, _ string) ([]byte, error) {
		return nil, fetchErr
	}
	_, err := r.ResolveServices(context.Background(), "did:web:unreachable.example")
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("fetcher error in ResolveServices: want ErrFetchFailed, got %v", err)
	}
}

// TestResolveServicesInvalidJSON exercises the json.Unmarshal failure path
// inside ResolveServices when the fetched body is not valid JSON.
func TestResolveServicesInvalidJSON(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("not-valid-json{{{"), nil
	}
	_, err := r.ResolveServices(context.Background(), "did:web:badjson.example")
	if err == nil {
		t.Error("invalid JSON body in ResolveServices must return error")
	}
}

// TestParseDIDDocumentInvalidJSON exercises the json.Unmarshal failure inside
// parseDIDDocument when called via resolveDIDWeb.
func TestParseDIDDocumentInvalidJSON(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("{bad json"), nil
	}
	_, err := r.Resolve(context.Background(), "did:web:badjson2.example")
	if err == nil {
		t.Error("invalid DID document JSON must return error")
	}
}

// TestResolveDIDKeyBase58DecodeError exercises the base58Decode failure path in
// resolveDIDKey. The character '0' (zero) is not in the base58btc alphabet, so
// a did:key with 'z0...' causes base58Decode to return an error.
func TestResolveDIDKeyBase58DecodeError(t *testing.T) {
	// '0' is excluded from the base58 alphabet → decode error
	r := New()
	_, err := r.Resolve(context.Background(), "did:key:z0invalid")
	if !errors.Is(err, ErrMalformedDID) {
		t.Errorf("base58 decode error in did:key: want ErrMalformedDID, got %v", err)
	}
}

// TestResolveDIDKeyTooShort exercises the "decoded payload too short" check in
// resolveDIDKey. We encode a payload shorter than 2+ed25519.PublicKeySize bytes
// that starts with the correct multicodec prefix (0xed 0x01).
func TestResolveDIDKeyTooShort(t *testing.T) {
	short := append([]byte{0xed, 0x01}, make([]byte, 8)...) // only 10 bytes (need 34)
	did := "did:key:z" + base58Encode(short)
	r := New()
	_, err := r.Resolve(context.Background(), did)
	if !errors.Is(err, ErrMalformedDID) {
		t.Errorf("too-short did:key: want ErrMalformedDID, got %v", err)
	}
}

// TestResolveDIDKeyWrongMulticodec exercises the multicodec-prefix check in
// resolveDIDKey. We encode a 34-byte payload with a non-Ed25519 multicodec (0x00 0x00).
func TestResolveDIDKeyWrongMulticodec(t *testing.T) {
	payload := append([]byte{0x00, 0x00}, make([]byte, ed25519.PublicKeySize)...) // wrong prefix
	did := "did:key:z" + base58Encode(payload)
	r := New()
	_, err := r.Resolve(context.Background(), did)
	if !errors.Is(err, ErrMalformedDID) {
		t.Errorf("wrong multicodec did:key: want ErrMalformedDID, got %v", err)
	}
}

// TestResolveDIDKeyTrailingBytesRejected guards against did:key identifier
// malleability: a multicodec + 32-byte key with EXTRA trailing bytes must be
// rejected, not silently truncated to the same key. Otherwise one issuer key
// would be addressable by infinitely many distinct did:key strings.
func TestResolveDIDKeyTrailingBytesRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Canonical form (0xed 0x01 + 32 bytes) must resolve to pub.
	canonical := append([]byte{0xed, 0x01}, pub...)
	r := New()
	got, err := r.Resolve(context.Background(), "did:key:z"+base58Encode(canonical))
	if err != nil || !equalKeys(got, pub) {
		t.Fatalf("canonical did:key should resolve to pub: err=%v", err)
	}
	// Same key with trailing garbage MUST be rejected (no truncation).
	for _, extra := range [][]byte{{0x00}, {0xff, 0xff}, []byte("junk")} {
		malleable := append(append([]byte{0xed, 0x01}, pub...), extra...)
		did := "did:key:z" + base58Encode(malleable)
		if _, err := r.Resolve(context.Background(), did); !errors.Is(err, ErrMalformedDID) {
			t.Errorf("trailing %d bytes: want ErrMalformedDID, got %v", len(extra), err)
		}
	}
}

// TestBase58Ed25519DecodeTrailingBytesRejected is the multibase-level analog:
// a 34+ byte multicodec payload with trailing bytes must not be truncated.
func TestBase58Ed25519DecodeTrailingBytesRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	malleable := append(append([]byte{0xed, 0x01}, pub...), 0x00) // 35 bytes
	if _, err := base58Ed25519Decode(base58Encode(malleable)); err == nil {
		t.Error("35-byte multicodec payload should be rejected, not truncated")
	}
}

// TestResolveDIDJWKBadJSONBody exercises the json.Unmarshal failure inside
// resolveDIDJWK: valid base64url that decodes to non-JSON bytes.
func TestResolveDIDJWKBadJSONBody(t *testing.T) {
	badJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json-at-all"))
	r := New()
	_, err := r.Resolve(context.Background(), "did:jwk:"+badJSON)
	if !errors.Is(err, ErrMalformedDID) {
		t.Errorf("non-JSON JWK body: want ErrMalformedDID, got %v", err)
	}
}

// TestResolveAndVerifyResolveFails exercises the r.Resolve error path inside
// ResolveAndVerify (distinct from the "resolved but not trusted" path).
func TestResolveAndVerifyResolveFails(t *testing.T) {
	r := New()
	ta := NewTrustAnchor()
	ta.AllowAll()
	// An unsupported DID method will make r.Resolve return an error.
	_, err := ResolveAndVerify(context.Background(), r, ta, "did:unsupported:xyz")
	if err == nil {
		t.Error("Resolve failure in ResolveAndVerify must return error")
	}
}

// ============================================================================
// Cache size cap (DoS / memory exhaustion prevention)
// ============================================================================

// TestCacheSizeCap verifies that resolving more unique DIDs than MaxCacheSize
// never grows the internal cache map beyond that limit. Without the cap an
// attacker presenting credentials from many fabricated DID issuers would cause
// unbounded memory growth.
func TestCacheSizeCap(t *testing.T) {
	const cap = 3
	r := New()
	r.MaxCacheSize = cap
	r.CacheTTL = time.Hour // long TTL — entries won't expire during this test

	// Resolve cap+2 distinct did:key DIDs to drive the overflow path.
	for i := 0; i < cap+2; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		prefixed := append([]byte{0xed, 0x01}, pub...)
		did := "did:key:z" + base58Encode(prefixed)
		got, err := r.Resolve(context.Background(), did)
		if err != nil {
			t.Fatalf("resolve[%d]: %v", i, err)
		}
		if !equalKeys(got, pub) {
			t.Errorf("resolve[%d]: key mismatch", i)
		}
	}
	// The cache must not exceed the cap regardless of how many DIDs were resolved.
	r.mu.RLock()
	size := len(r.cache)
	r.mu.RUnlock()
	if size > cap {
		t.Errorf("cache grew to %d entries, exceeding cap %d", size, cap)
	}
}

// TestCacheSizeCapAllowsInsertAfterPurge verifies that once the cache is full
// of expired entries, the next write triggers a purge and caches the new entry.
func TestCacheSizeCapAllowsInsertAfterPurge(t *testing.T) {
	const cap = 2
	r := New()
	r.MaxCacheSize = cap
	r.CacheTTL = 10 * time.Millisecond // short TTL so entries expire quickly

	// Fill the cache to capacity.
	for i := 0; i < cap; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		prefixed := append([]byte{0xed, 0x01}, pub...)
		did := "did:key:z" + base58Encode(prefixed)
		if _, err := r.Resolve(context.Background(), did); err != nil {
			t.Fatal(err)
		}
	}
	// Wait for all cached entries to expire.
	time.Sleep(30 * time.Millisecond)

	// Resolving a new DID should purge expired entries and then cache the result.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	newDID := "did:key:z" + base58Encode(prefixed)
	got, err := r.Resolve(context.Background(), newDID)
	if err != nil {
		t.Fatal(err)
	}
	if !equalKeys(got, pub) {
		t.Error("key mismatch after cache purge")
	}
	r.mu.RLock()
	_, inCache := r.cache[newDID]
	r.mu.RUnlock()
	if !inCache {
		t.Error("new entry must be in cache after expired entries were purged")
	}
}

func TestMultibaseToEd25519Variants(t *testing.T) {
	// Generate a real Ed25519 public key for use in tests.
	rawPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 'm' prefix with bare 32-byte base64 key (RawStdEncoding).
	mBase64 := "m" + base64.RawStdEncoding.EncodeToString([]byte(rawPub))
	got, err := multibaseToEd25519(mBase64)
	if err != nil {
		t.Fatalf("'m' prefix base64: %v", err)
	}
	if !got.Equal(rawPub) {
		t.Error("'m' base64: decoded key mismatch")
	}

	// 'm' prefix with multicodec ed25519-pub header (0xed 0x01) prepended.
	withPrefix := append([]byte{0xed, 0x01}, []byte(rawPub)...)
	mWithPrefix := "m" + base64.RawStdEncoding.EncodeToString(withPrefix)
	got2, err := multibaseToEd25519(mWithPrefix)
	if err != nil {
		t.Fatalf("'m' with multicodec prefix: %v", err)
	}
	if !got2.Equal(rawPub) {
		t.Error("'m' with multicodec prefix: decoded key mismatch")
	}

	// 'm' prefix with invalid base64 — must fail.
	if _, err := multibaseToEd25519("m!!!"); err == nil {
		t.Error("invalid base64 after 'm' should fail")
	}

	// 'm' prefix with wrong-length key (too short).
	short := "m" + base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := multibaseToEd25519(short); err == nil {
		t.Error("short key after 'm' should fail")
	}

	// Too-short string (len < 2) — must fail.
	if _, err := multibaseToEd25519("x"); err == nil {
		t.Error("single-char string should fail")
	}
	if _, err := multibaseToEd25519(""); err == nil {
		t.Error("empty string should fail")
	}

	// Unsupported multibase prefix.
	if _, err := multibaseToEd25519("Xunsupported"); err == nil {
		t.Error("unsupported multibase prefix should fail")
	}
}
