package vctmeta

import (
	"context"
	"testing"
)

const vctURL = "https://schema.europa.eu/dpp/sd-jwt-vc/v1"

var sampleMeta = []byte(`{"vct":"https://schema.europa.eu/dpp/sd-jwt-vc/v1","name":"EU DPP","description":"Digital Product Passport","schema_uri":"https://schema.europa.eu/dpp/schema.json"}`)

func memFetcher(data []byte) FetchFunc {
	return func(_ context.Context, _ string) ([]byte, error) { return data, nil }
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
