package didresolver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func TestDefaultHTTPFetchNon200(t *testing.T) {
	// Use a real httptest server returning 404 to exercise the HTTP != 200 path.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	_, err := defaultHTTPFetch(context.Background(), ts.URL+"/did.json")
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

	got, err := defaultHTTPFetch(context.Background(), ts.URL+"/did.json")
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
