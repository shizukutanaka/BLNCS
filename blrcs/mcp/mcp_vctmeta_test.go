package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// ============================================================================
// Axis 112: resolve_vct_metadata / validate_claims_against_vct
// ============================================================================

const testVCT = "https://schema.example/dpp/sd-jwt-vc/v1"

// mockVCTFetcher returns doc for any URL matching testVCT, avoiding a real
// network round-trip.
func mockVCTFetcher(doc []byte) func(ctx context.Context, url string) ([]byte, error) {
	return func(ctx context.Context, url string) ([]byte, error) {
		return doc, nil
	}
}

func TestResolveVCTMetadataHappyPath(t *testing.T) {
	srv, _, _ := setupServer(t)
	doc, _ := json.Marshal(map[string]any{
		"vct":         testVCT,
		"name":        "EU DPP",
		"description": "Digital Product Passport",
		"schema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
			"required":   []string{"name"},
		},
	})
	srv.vctFetcher = mockVCTFetcher(doc)

	result := toolCall(t, srv, 1, "resolve_vct_metadata", map[string]any{"vct": testVCT})
	text := toolCallText(t, result)
	var out struct {
		VCT       string `json:"vct"`
		Name      string `json:"name"`
		HasSchema bool   `json:"hasSchema"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.VCT != testVCT {
		t.Errorf("vct: got %s want %s", out.VCT, testVCT)
	}
	if out.Name != "EU DPP" {
		t.Errorf("name: got %s", out.Name)
	}
	if !out.HasSchema {
		t.Error("hasSchema should be true")
	}
}

func TestResolveVCTMetadataMissingVCT(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "resolve_vct_metadata", map[string]any{})
	if !result["isError"].(bool) {
		t.Fatal("missing vct should error")
	}
}

func TestResolveVCTMetadataVCTMismatchRejected(t *testing.T) {
	srv, _, _ := setupServer(t)
	// Document claims a different vct than the URL used to fetch it — the
	// IETF SD-JWT-VC §5 type-confusion guard inside vctmeta.Resolve itself.
	doc, _ := json.Marshal(map[string]any{"vct": "https://schema.example/other-type"})
	srv.vctFetcher = mockVCTFetcher(doc)

	result := toolCall(t, srv, 1, "resolve_vct_metadata", map[string]any{"vct": testVCT})
	if !result["isError"].(bool) {
		t.Fatal("vct mismatch should error")
	}
}

func TestValidateClaimsAgainstVCTHappyPath(t *testing.T) {
	srv, _, _ := setupServer(t)
	doc, _ := json.Marshal(map[string]any{
		"vct": testVCT,
		"schema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"category": map[string]any{"type": "string"}},
			"required":   []string{"category"},
		},
	})
	srv.vctFetcher = mockVCTFetcher(doc)

	result := toolCall(t, srv, 1, "validate_claims_against_vct", map[string]any{
		"vct":    testVCT,
		"claims": map[string]any{"category": "textile"},
	})
	text := toolCallText(t, result)
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Valid {
		t.Fatalf("expected valid=true, got %s", text)
	}
}

func TestValidateClaimsAgainstVCTMissingRequiredClaim(t *testing.T) {
	srv, _, _ := setupServer(t)
	doc, _ := json.Marshal(map[string]any{
		"vct": testVCT,
		"schema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"category": map[string]any{"type": "string"}},
			"required":   []string{"category"},
		},
	})
	srv.vctFetcher = mockVCTFetcher(doc)

	result := toolCall(t, srv, 1, "validate_claims_against_vct", map[string]any{
		"vct":    testVCT,
		"claims": map[string]any{"unrelated": "value"},
	})
	text := toolCallText(t, result)
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid {
		t.Fatal("claims missing a required field should not validate")
	}
}

func TestValidateClaimsAgainstVCTMissingVCT(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "validate_claims_against_vct", map[string]any{
		"claims": map[string]any{},
	})
	if !result["isError"].(bool) {
		t.Fatal("missing vct should error")
	}
}

// TestVCTMetaToolsNotAudited verifies these are pure/read-only tools with no
// ledger side effects.
func TestVCTMetaToolsNotAudited(t *testing.T) {
	srv, _, _ := setupServer(t)
	doc, _ := json.Marshal(map[string]any{"vct": testVCT, "name": "EU DPP"})
	srv.vctFetcher = mockVCTFetcher(doc)

	before := srv.Ledger().Size()
	toolCall(t, srv, 1, "resolve_vct_metadata", map[string]any{"vct": testVCT})
	after := srv.Ledger().Size()
	if after != before {
		t.Errorf("resolve_vct_metadata should not be audited: before=%d after=%d", before, after)
	}
}
