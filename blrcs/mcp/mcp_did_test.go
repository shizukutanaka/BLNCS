package mcp

import (
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
