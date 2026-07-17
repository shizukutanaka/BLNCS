package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// ============================================================================
// Axis 108: resolve_did
// ============================================================================

// TestResolveDIDHappyPath verifies the MCP surface can resolve a self-contained
// did:jwk (no network involved) to its Ed25519 public key — previously only
// reachable via the didresolver package directly.
func TestResolveDIDHappyPath(t *testing.T) {
	srv, _, _ := setupServer(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	jwkBytes, _ := json.Marshal(jwk)
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	result := toolCall(t, srv, 1, "resolve_did", map[string]any{"did": did})
	text := toolCallText(t, result)
	var out struct {
		PublicKeysB64 []string `json:"publicKeysB64"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.PublicKeysB64) != 1 {
		t.Fatalf("expected 1 key, got %d", len(out.PublicKeysB64))
	}
	got, err := base64.StdEncoding.DecodeString(out.PublicKeysB64[0])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.PublicKey(got).Equal(pub) {
		t.Errorf("resolved key mismatch")
	}
}

// TestResolveDIDMissingDID verifies required-field validation.
func TestResolveDIDMissingDID(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "resolve_did", map[string]any{})
	if !result["isError"].(bool) {
		t.Fatal("missing did should error")
	}
}

// TestResolveDIDUnsupportedMethod verifies an unsupported DID method surfaces
// as a tool error rather than succeeding silently.
func TestResolveDIDUnsupportedMethod(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "resolve_did", map[string]any{"did": "did:example:not-a-real-method"})
	if !result["isError"].(bool) {
		t.Fatal("unsupported DID method should error")
	}
}

// TestResolveDIDNotAudited verifies this is a pure/read-only tool (no ledger
// side effects) — resolving a DID doesn't mutate server state.
func TestResolveDIDNotAudited(t *testing.T) {
	srv, _, _ := setupServer(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	jwkBytes, _ := json.Marshal(jwk)
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	before := srv.Ledger().Size()
	toolCall(t, srv, 1, "resolve_did", map[string]any{"did": did})
	after := srv.Ledger().Size()
	if after != before {
		t.Errorf("resolve_did should not be audited: before=%d after=%d", before, after)
	}
}

// ============================================================================
// discover_did_services
// ============================================================================

// TestDiscoverDIDServicesHappyPath verifies the MCP surface can fetch a
// did:web document's service endpoints — previously only reachable via the
// didresolver package directly. Injects a mock HTTPFetcher on the server's
// didResolver (same package, so the unexported field is accessible) to avoid
// a real network round-trip.
func TestDiscoverDIDServicesHappyPath(t *testing.T) {
	srv, _, _ := setupServer(t)
	srv.didResolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{
			"id": "did:web:factory.example",
			"verificationMethod": [],
			"service": [
				{"id":"did:web:factory.example#dpp","type":"DPPService","serviceEndpoint":"https://factory.example/dpp"}
			]
		}`), nil
	}

	result := toolCall(t, srv, 1, "discover_did_services", map[string]any{"did": "did:web:factory.example"})
	text := toolCallText(t, result)
	var out struct {
		Services []struct {
			ID              string `json:"id"`
			Type            string `json:"type"`
			ServiceEndpoint string `json:"serviceEndpoint"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(out.Services))
	}
	if out.Services[0].Type != "DPPService" {
		t.Errorf("type: got %s", out.Services[0].Type)
	}
	if out.Services[0].ServiceEndpoint != "https://factory.example/dpp" {
		t.Errorf("endpoint: got %s", out.Services[0].ServiceEndpoint)
	}
}

// TestDiscoverDIDServicesMissingDID verifies required-field validation.
func TestDiscoverDIDServicesMissingDID(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "discover_did_services", map[string]any{})
	if !result["isError"].(bool) {
		t.Fatal("missing did should error")
	}
}

// TestDiscoverDIDServicesEmptyResult verifies a DID document with no service
// field returns an empty (not nil-crashing) services list.
func TestDiscoverDIDServicesEmptyResult(t *testing.T) {
	srv, _, _ := setupServer(t)
	srv.didResolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{"id":"did:web:no-services.example","verificationMethod":[]}`), nil
	}
	result := toolCall(t, srv, 1, "discover_did_services", map[string]any{"did": "did:web:no-services.example"})
	text := toolCallText(t, result)
	var out struct {
		Services []any `json:"services"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(out.Services))
	}
}
