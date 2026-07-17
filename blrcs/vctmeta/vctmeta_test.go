package vctmeta

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

const vctURL = "https://schema.europa.eu/dpp/sd-jwt-vc/v1"

var sampleMeta = []byte(`{"vct":"https://schema.europa.eu/dpp/sd-jwt-vc/v1","name":"EU DPP","description":"Digital Product Passport","schema_uri":"https://schema.europa.eu/dpp/schema.json"}`)

func memFetcher(data []byte) FetchFunc {
	return func(_ context.Context, _ string) ([]byte, error) { return data, nil }
}

func errFetcher(err error) FetchFunc {
	return func(_ context.Context, _ string) ([]byte, error) { return nil, err }
}

// TestResolveFetchError propagates a fetch transport error.
func TestResolveFetchError(t *testing.T) {
	want := errors.New("network down")
	if _, err := Resolve(context.Background(), vctURL, "", errFetcher(want)); err != want {
		t.Errorf("fetch error not propagated: got %v", err)
	}
}

// TestResolveBadJSON exercises the json.Unmarshal error path in Resolve.
func TestResolveBadJSON(t *testing.T) {
	if _, err := Resolve(context.Background(), vctURL, "", memFetcher([]byte("{not json"))); err == nil {
		t.Error("malformed metadata JSON should error")
	}
}

func TestIntegrityRoundTrip(t *testing.T) {
	integ := Integrity(sampleMeta)
	if err := VerifyIntegrity(sampleMeta, integ); err != nil {
		t.Fatalf("matching integrity should verify: %v", err)
	}
	if err := VerifyIntegrity([]byte("tampered"), integ); err != ErrIntegrityMismatch {
		t.Fatalf("tampered data: want ErrIntegrityMismatch, got %v", err)
	}
}

func TestVerifyIntegrityBadFormat(t *testing.T) {
	for _, bad := range []string{"", "sha256", "md5-abc", "sha256-", "sha256-!!!notb64"} {
		if err := VerifyIntegrity(sampleMeta, bad); err == nil {
			t.Errorf("VerifyIntegrity(%q) should fail", bad)
		}
	}
}

func TestResolveRequiresHTTPS(t *testing.T) {
	if _, err := Resolve(context.Background(), "urn:example:type", "", memFetcher(sampleMeta)); err != ErrNotHTTPS {
		t.Fatalf("non-https vct: want ErrNotHTTPS, got %v", err)
	}
}

func TestResolveHappyPathWithIntegrity(t *testing.T) {
	integ := Integrity(sampleMeta)
	tm, err := Resolve(context.Background(), vctURL, integ, memFetcher(sampleMeta))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tm.Name != "EU DPP" || tm.SchemaURI == "" {
		t.Errorf("metadata not parsed: %+v", tm)
	}
	if len(tm.Raw) == 0 {
		t.Error("Raw bytes should be retained for caching/rehashing")
	}
}

func TestResolveIntegrityMismatch(t *testing.T) {
	// Credential pins an integrity for different bytes → fetched metadata rejected.
	wrong := Integrity([]byte(`{"vct":"x"}`))
	if _, err := Resolve(context.Background(), vctURL, wrong, memFetcher(sampleMeta)); err != ErrIntegrityMismatch {
		t.Fatalf("want ErrIntegrityMismatch, got %v", err)
	}
}

func TestResolveNoIntegritySkipsCheck(t *testing.T) {
	// Empty expectedIntegrity → fetch + parse without verification.
	tm, err := Resolve(context.Background(), vctURL, "", memFetcher(sampleMeta))
	if err != nil || tm.VCT != vctURL {
		t.Fatalf("resolve without integrity: tm=%+v err=%v", tm, err)
	}
}

// TestResolveVCTMismatch verifies that Resolve rejects metadata whose vct
// claim does not match the URL it was fetched from. Without this check a
// misconfigured CDN or type-confusion attack could cause claim validation to
// use the wrong JSON Schema: the server at https://a.example/type serves a
// document with "vct":"https://b.example/other-type", and the caller would
// silently validate claims against b's schema instead of a's.
func TestResolveVCTMismatch(t *testing.T) {
	wrongDoc := []byte(`{"vct":"https://other.example.com/type","name":"Wrong Type"}`)
	_, err := Resolve(context.Background(), vctURL, "", memFetcher(wrongDoc))
	if !errors.Is(err, ErrVCTMismatch) {
		t.Fatalf("metadata vct != requested URL: want ErrVCTMismatch, got %v", err)
	}
}

// TestResolveVCTEmptyInMetadata verifies that metadata lacking a vct claim
// (empty string after unmarshal) is also rejected via ErrVCTMismatch.
func TestResolveVCTEmptyInMetadata(t *testing.T) {
	noVCT := []byte(`{"name":"No VCT field"}`)
	_, err := Resolve(context.Background(), vctURL, "", memFetcher(noVCT))
	if !errors.Is(err, ErrVCTMismatch) {
		t.Fatalf("metadata with no vct: want ErrVCTMismatch, got %v", err)
	}
}

// ============================================================================
// Schema validation (jsonschema integration)
// ============================================================================

var metaWithSchema = []byte(`{
	"vct":"https://schema.europa.eu/dpp/sd-jwt-vc/v1",
	"name":"EU DPP",
	"schema":{
		"type":"object",
		"properties":{
			"vct":{"type":"string"},
			"product_id":{"type":"string","pattern":"^[0-9]{14}$"},
			"recyclability_pct":{"type":"integer","minimum":0,"maximum":100}
		},
		"required":["vct","product_id"]
	}
}`)

func TestValidateClaimsHappyPath(t *testing.T) {
	tm, err := Resolve(context.Background(), vctURL, "", memFetcher(metaWithSchema))
	if err != nil {
		t.Fatal(err)
	}
	if !tm.HasSchema() {
		t.Fatal("expected embedded schema")
	}
	claims := map[string]any{
		"vct":               vctURL,
		"product_id":        "04012345678901",
		"recyclability_pct": float64(82),
	}
	if err := tm.ValidateClaims(claims); err != nil {
		t.Errorf("valid claims should pass: %v", err)
	}
}

func TestValidateClaimsViolations(t *testing.T) {
	tm, _ := Resolve(context.Background(), vctURL, "", memFetcher(metaWithSchema))

	// Bad product_id pattern.
	if err := tm.ValidateClaims(map[string]any{"vct": "x", "product_id": "abc"}); err == nil {
		t.Error("bad product_id should fail")
	}
	// Missing required product_id.
	if err := tm.ValidateClaims(map[string]any{"vct": "x"}); err == nil {
		t.Error("missing required should fail")
	}
	// recyclability out of range.
	if err := tm.ValidateClaims(map[string]any{
		"vct": "x", "product_id": "04012345678901", "recyclability_pct": float64(150),
	}); err == nil {
		t.Error("out-of-range should fail")
	}
}

func TestValidateClaimsNoSchema(t *testing.T) {
	tm, _ := Resolve(context.Background(), vctURL, "", memFetcher(sampleMeta))
	if tm.HasSchema() {
		t.Fatal("sampleMeta has no embedded schema")
	}
	if err := tm.ValidateClaims(map[string]any{"vct": "x"}); err != ErrNoSchema {
		t.Errorf("want ErrNoSchema, got %v", err)
	}
}

// ============================================================================
// Remote schema_uri resolution
// ============================================================================

var schemaDoc = []byte(`{"type":"object","properties":{"vct":{"type":"string"},"product_id":{"type":"string","pattern":"^[0-9]{14}$"}},"required":["vct","product_id"]}`)

func TestResolveSchemaEmbeddedPreferred(t *testing.T) {
	tm, _ := Resolve(context.Background(), vctURL, "", memFetcher(metaWithSchema))
	// Even with a fetcher present, embedded schema wins (no fetch needed).
	got, err := tm.ResolveSchema(context.Background(), func(context.Context, string) ([]byte, error) {
		t.Fatal("fetch should not be called when schema is embedded")
		return nil, nil
	})
	if err != nil || len(got) == 0 {
		t.Fatalf("embedded schema: got=%d err=%v", len(got), err)
	}
}

func TestResolveSchemaViaURI(t *testing.T) {
	metaURIOnly := []byte(`{"vct":"` + vctURL + `","schema_uri":"https://schema.europa.eu/dpp/schema.json"}`)
	tm, _ := Resolve(context.Background(), vctURL, "", memFetcher(metaURIOnly))

	err := tm.ResolveAndValidate(context.Background(), map[string]any{
		"vct": "x", "product_id": "04012345678901",
	}, memFetcher(schemaDoc))
	if err != nil {
		t.Errorf("valid claims via schema_uri should pass: %v", err)
	}

	// Violation surfaces through the remote schema too.
	err = tm.ResolveAndValidate(context.Background(), map[string]any{"vct": "x"}, memFetcher(schemaDoc))
	if err == nil {
		t.Error("missing required product_id should fail")
	}
}

func TestResolveSchemaURIIntegrity(t *testing.T) {
	integ := Integrity(schemaDoc)
	metaWithIntegrity := []byte(`{"vct":"` + vctURL + `","schema_uri":"https://schema.europa.eu/dpp/schema.json","schema_uri#integrity":"` + integ + `"}`)
	tm, _ := Resolve(context.Background(), vctURL, "", memFetcher(metaWithIntegrity))

	// Correct bytes pass integrity.
	if _, err := tm.ResolveSchema(context.Background(), memFetcher(schemaDoc)); err != nil {
		t.Errorf("matching integrity should pass: %v", err)
	}
	// Tampered schema bytes are rejected.
	if _, err := tm.ResolveSchema(context.Background(), memFetcher([]byte(`{"type":"string"}`))); err != ErrIntegrityMismatch {
		t.Errorf("want ErrIntegrityMismatch, got %v", err)
	}
}

func TestResolveSchemaNone(t *testing.T) {
	tm, _ := Resolve(context.Background(), vctURL, "", memFetcher(sampleMeta))
	// sampleMeta has schema_uri but pointing at non-https? It is https. Override:
	tm.SchemaURI = ""
	if _, err := tm.ResolveSchema(context.Background(), memFetcher(nil)); err != ErrNoSchema {
		t.Errorf("want ErrNoSchema, got %v", err)
	}
}

func TestResolveSchemaURINotHTTPS(t *testing.T) {
	tm := &TypeMetadata{SchemaURI: "http://insecure.example/schema.json"}
	if _, err := tm.ResolveSchema(context.Background(), memFetcher(schemaDoc)); err != ErrNotHTTPS {
		t.Errorf("want ErrNotHTTPS, got %v", err)
	}
}

// ============================================================================
// ErrTooLarge — metadata and schema_uri body-size cap
// ============================================================================

func oversizedFetcher() FetchFunc {
	// maxMetadataBytes+1 bytes of printable ASCII so the check is clear.
	big := make([]byte, maxMetadataBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	return memFetcher(big)
}

func TestResolveTooLarge(t *testing.T) {
	if _, err := Resolve(context.Background(), vctURL, "", oversizedFetcher()); err != ErrTooLarge {
		t.Errorf("want ErrTooLarge, got %v", err)
	}
}

func TestResolveSchemaURITooLarge(t *testing.T) {
	tm := &TypeMetadata{SchemaURI: "https://schema.europa.eu/large.json"}
	if _, err := tm.ResolveSchema(context.Background(), oversizedFetcher()); err != ErrTooLarge {
		t.Errorf("want ErrTooLarge, got %v", err)
	}
}

// ============================================================================
// ResolveChain — extends chain resolution, depth limit, cycle detection
// ============================================================================

// chainFetcherWithIntegrity builds a FetchFunc for a linear extends chain
// where every hop includes a valid extends#integrity binding.
// urls[0] is the starting (leaf) URL; urls[last] is the root (no extends).
// Documents are built root-first so each node can embed the next node's hash.
func chainFetcherWithIntegrity(urls []string) FetchFunc {
	docs := make(map[string][]byte, len(urls))
	for i := len(urls) - 1; i >= 0; i-- {
		var extendsJSON string
		if i+1 < len(urls) {
			integ := Integrity(docs[urls[i+1]])
			extendsJSON = `,"extends":"` + urls[i+1] + `","extends#integrity":"` + integ + `"`
		}
		docs[urls[i]] = []byte(`{"vct":"` + urls[i] + `"` + extendsJSON + `}`)
	}
	return func(_ context.Context, url string) ([]byte, error) {
		if d, ok := docs[url]; ok {
			return d, nil
		}
		return nil, &notFoundErr{url}
	}
}

// chainFetcherNoIntegrity builds a FetchFunc like chainFetcherWithIntegrity
// but omits extends#integrity — used to exercise ErrExtendsIntegrityRequired.
func chainFetcherNoIntegrity(urls []string) FetchFunc {
	docs := make(map[string][]byte, len(urls))
	for i, u := range urls {
		var extends string
		if i+1 < len(urls) {
			extends = `,"extends":"` + urls[i+1] + `"`
		}
		docs[u] = []byte(`{"vct":"` + u + `"` + extends + `}`)
	}
	return func(_ context.Context, url string) ([]byte, error) {
		if d, ok := docs[url]; ok {
			return d, nil
		}
		return nil, &notFoundErr{url}
	}
}

type notFoundErr struct{ url string }

func (e *notFoundErr) Error() string { return "not found: " + e.url }

func TestResolveChainSingleNode(t *testing.T) {
	// No extends → chain of length 1.
	chain, err := ResolveChain(context.Background(), vctURL, "", memFetcher(sampleMeta))
	if err != nil {
		t.Fatalf("single-node chain: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("want 1, got %d", len(chain))
	}
	if chain[0].VCT != vctURL {
		t.Errorf("VCT: %s", chain[0].VCT)
	}
}

func TestResolveChainMultipleNodes(t *testing.T) {
	urls := []string{
		"https://eu.example/base",
		"https://eu.example/derived",
		"https://eu.example/leaf",
	}
	chain, err := ResolveChain(context.Background(), urls[0], "", chainFetcherWithIntegrity(urls))
	if err != nil {
		t.Fatalf("multi-node chain: %v", err)
	}
	if len(chain) != 3 {
		t.Errorf("want 3, got %d", len(chain))
	}
	// Chain returned root-first: urls[2] is root (no extends), urls[0] is leaf.
	if chain[0].VCT != urls[2] {
		t.Errorf("root should be %s, got %s", urls[2], chain[0].VCT)
	}
	if chain[len(chain)-1].VCT != urls[0] {
		t.Errorf("leaf should be %s, got %s", urls[0], chain[len(chain)-1].VCT)
	}
}

func TestResolveChainTooDeep(t *testing.T) {
	// Build a chain of maxExtendsDepth+1 nodes with proper integrity bindings.
	urls := make([]string, maxExtendsDepth+1)
	for i := range urls {
		urls[i] = "https://eu.example/type" + string(rune('0'+i))
	}
	_, err := ResolveChain(context.Background(), urls[0], "", chainFetcherWithIntegrity(urls))
	if err != ErrExtendsChainTooDeep {
		t.Fatalf("want ErrExtendsChainTooDeep, got %v", err)
	}
}

func TestResolveChainCycle(t *testing.T) {
	// A → B → A (cycle). A genuine cycle cannot carry consistent extends#integrity
	// values (sha256(A) depends on sha256(B) and vice-versa — circular), so in
	// practice the chain always fails with ErrExtendsIntegrityRequired before the
	// cycle detector fires. Both sentinels are valid: the chain is rejected.
	a := "https://eu.example/a"
	b := "https://eu.example/b"
	docs := map[string][]byte{
		a: []byte(`{"vct":"` + a + `","extends":"` + b + `"}`),
		b: []byte(`{"vct":"` + b + `","extends":"` + a + `"}`),
	}
	fetch := func(_ context.Context, url string) ([]byte, error) { return docs[url], nil }
	_, err := ResolveChain(context.Background(), a, "", fetch)
	if !errors.Is(err, ErrExtendsCycle) && !errors.Is(err, ErrExtendsIntegrityRequired) {
		t.Fatalf("want ErrExtendsCycle or ErrExtendsIntegrityRequired, got %v", err)
	}
}

// TestResolveChainMissingExtendsIntegrity verifies that a chain node with an
// `extends` link but no `extends#integrity` returns ErrExtendsIntegrityRequired.
// Without this guard every intermediate node is fetched on trust (TOFU), so a
// CDN misconfiguration or MITM can swap a parent schema without detection.
func TestResolveChainMissingExtendsIntegrity(t *testing.T) {
	urls := []string{
		"https://eu.example/leaf",
		"https://eu.example/root",
	}
	// chainFetcherNoIntegrity omits extends#integrity from every hop.
	_, err := ResolveChain(context.Background(), urls[0], "", chainFetcherNoIntegrity(urls))
	if !errors.Is(err, ErrExtendsIntegrityRequired) {
		t.Fatalf("want ErrExtendsIntegrityRequired, got %v", err)
	}
}

// TestResolveChainExtendsIntegrityMismatch verifies that a wrong extends#integrity
// value (pointing to different bytes than the parent actually serves) is rejected
// with ErrIntegrityMismatch. The root node is served with different content than
// the leaf's extends#integrity hash covers.
func TestResolveChainExtendsIntegrityMismatch(t *testing.T) {
	root := "https://eu.example/root"
	leaf := "https://eu.example/leaf"

	rootDoc := []byte(`{"vct":"` + root + `"}`)
	wrongInteg := Integrity([]byte(`{"vct":"` + root + `","tampered":true}`)) // hash of different bytes

	leafDoc := []byte(`{"vct":"` + leaf + `","extends":"` + root + `","extends#integrity":"` + wrongInteg + `"}`)

	fetch := func(_ context.Context, url string) ([]byte, error) {
		switch url {
		case leaf:
			return leafDoc, nil
		case root:
			return rootDoc, nil
		}
		return nil, &notFoundErr{url}
	}
	_, err := ResolveChain(context.Background(), leaf, "", fetch)
	if !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("want ErrIntegrityMismatch, got %v", err)
	}
}

// ============================================================================
// ValidateClaimsWithSchema — invalid schema compile path
// ============================================================================

func TestValidateClaimsWithSchemaBadSchema(t *testing.T) {
	badSchema := json.RawMessage(`{"type": "invalid-not-a-real-type"}`)
	// JSON Schema compile should either fail or produce a validator that rejects claims.
	// Either outcome is acceptable; what we verify is: no panic.
	_ = ValidateClaimsWithSchema(badSchema, map[string]any{"foo": "bar"})
}

func TestValidateClaimsWithSchemaInvalidJSON(t *testing.T) {
	malformed := json.RawMessage(`{not valid json`)
	if err := ValidateClaimsWithSchema(malformed, map[string]any{}); err == nil {
		t.Error("expected error for malformed JSON schema")
	}
}

// ============================================================================
// ResolveAndValidate — one-call happy path and error path
// ============================================================================

func TestResolveAndValidateHappy(t *testing.T) {
	schema := `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`
	tm := &TypeMetadata{
		VCT:    vctURL,
		Schema: json.RawMessage(schema),
	}
	if err := tm.ResolveAndValidate(context.Background(), map[string]any{"name": "Battery"}, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveAndValidateSchemaError(t *testing.T) {
	// No schema configured → ResolveSchema returns ErrNoSchema
	tm := &TypeMetadata{VCT: vctURL}
	if err := tm.ResolveAndValidate(context.Background(), map[string]any{}, nil); err != ErrNoSchema {
		t.Errorf("want ErrNoSchema, got %v", err)
	}
}

// ============================================================================
// HTTPFetcher — smoke test: constructs without panic, nil client gets default
// ============================================================================

func TestHTTPFetcherConstructor(t *testing.T) {
	f := HTTPFetcher(nil) // should not panic
	if f == nil {
		t.Error("HTTPFetcher(nil) returned nil")
	}
	// non-nil client
	f2 := HTTPFetcher(&http.Client{})
	if f2 == nil {
		t.Error("HTTPFetcher(client) returned nil")
	}
}

func TestHTTPFetcherHappy(t *testing.T) {
	body := []byte(`{"vct":"https://example.com/vc"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	f := HTTPFetcher(srv.Client())
	got, err := f(context.Background(), srv.URL+"/metadata")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("body: %q", got)
	}
}

func TestHTTPFetcherNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := HTTPFetcher(srv.Client())
	_, err := f(context.Background(), srv.URL+"/missing")
	if err == nil {
		t.Error("404 should return error")
	}
}

func TestHTTPFetcherCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	f := HTTPFetcher(srv.Client())
	_, err := f(ctx, srv.URL+"/metadata")
	if err == nil {
		t.Error("cancelled context should produce error")
	}
}

// TestHTTPFetcherBadURL covers vctmeta.go:68-70: http.NewRequestWithContext
// returns an error for URLs containing control characters such as null bytes.
func TestHTTPFetcherBadURL(t *testing.T) {
	f := HTTPFetcher(nil)
	_, err := f(context.Background(), "http://host\x00bad/path")
	if err == nil {
		t.Error("URL with null byte should fail NewRequestWithContext")
	}
}

// TestResolveSchemaFetchError covers vctmeta.go:183-185: fetch returns an
// error when schema_uri is present but the remote fetch fails.
func TestResolveSchemaFetchError(t *testing.T) {
	tm := &TypeMetadata{SchemaURI: "https://schema.example.com/v1.json"}
	want := errors.New("fetch failed")
	_, err := tm.ResolveSchema(context.Background(), errFetcher(want))
	if err != want {
		t.Errorf("ResolveSchema fetch error not propagated: got %v", err)
	}
}

// TestResolveChainFetchErrorOnExtends covers the mid-chain fetch error path:
// the child resolves OK but the parent fetch fails. The child must carry a
// non-empty extends#integrity so we reach the parent Resolve call (the
// integrity check happens after the fetch, so any placeholder hash works here
// — the fetch fails first).
func TestResolveChainFetchErrorOnExtends(t *testing.T) {
	parent := "https://eu.example/parent"
	child := "https://eu.example/child"
	// Any non-empty integrity string is fine: the fetch will fail before the
	// integrity bytes are compared.
	childDoc := []byte(`{"vct":"` + child + `","extends":"` + parent + `","extends#integrity":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)
	fetchErr := errors.New("parent unreachable")
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if url == child {
			return childDoc, nil
		}
		return nil, fetchErr
	}
	_, err := ResolveChain(context.Background(), child, "", fetch)
	if err == nil {
		t.Error("ResolveChain should return error when parent fetch fails")
	}
}

// TestHTTPFetcherRejectsRedirect verifies the default HTTPFetcher's
// CheckRedirect policy refuses 3xx responses. A malicious Type Metadata host
// that 302s could otherwise (a) silently violate the vct#integrity URL ->
// bytes binding (the SRI hash would guard a different URL than was issued)
// and (b) pivot the verifier into a private/loopback/metadata-IP target — an
// SSRF primitive. Uses a client with the same CheckRedirect policy as the
// real default but without its SSRF dial guard (see
// TestHTTPFetcherBlocksLoopback for that), so this test can still reach an
// httptest.Server (always loopback) to exercise the redirect-rejection path
// specifically.
func TestHTTPFetcherRejectsRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer ts.Close()
	fetcher := HTTPFetcher(&http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return ErrRedirectNotAllowed
		},
	})
	_, err := fetcher(context.Background(), ts.URL+"/metadata.json")
	if err == nil {
		t.Fatal("redirect should be refused")
	}
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Errorf("want ErrRedirectNotAllowed, got %v", err)
	}
}

// TestHTTPFetcherBlocksLoopback is the core regression test for the SSRF gap
// this axis fixes: a vct/schema_uri/extends URL resolving *directly* (no
// redirect involved) to a loopback address must be refused by the real
// default HTTPFetcher(nil) client, not just by the CheckRedirect guard that
// only covers the redirect vector. Before the fix, this reached the local
// httptest.Server successfully — exactly the SSRF this closes.
func TestHTTPFetcherBlocksLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vct":"should-not-be-reached"}`))
	}))
	defer ts.Close()
	fetcher := HTTPFetcher(nil) // real default SSRF-hardened client
	_, err := fetcher(context.Background(), ts.URL+"/metadata.json")
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

// TestHTTPFetcherCustomClientRespected verifies that when the caller supplies
// their own *http.Client, we use it as-is and do NOT override its redirect
// policy. The caller is in charge of whether to allow redirects.
func TestHTTPFetcherCustomClientRespected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vct":"https://eu.example/final"}`))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	// Caller-provided client with the default (follow-redirects) policy.
	fetcher := HTTPFetcher(&http.Client{})
	body, err := fetcher(context.Background(), redirector.URL+"/metadata.json")
	if err != nil {
		t.Fatalf("caller-provided client should follow redirects: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected body from redirected target")
	}
}
