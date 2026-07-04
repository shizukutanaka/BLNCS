package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// ============================================================================
// Axis 106: build_gs1_link / parse_gs1_link
// ============================================================================

// TestBuildGS1LinkHappyPath verifies the full MCP surface can build a GS1
// Digital Link URI — previously only reachable via the compliance package
// directly, despite README listing "GS1 Digital Link (ISO/IEC 18975) ✅".
func TestBuildGS1LinkHappyPath(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "build_gs1_link", map[string]any{
		"domain": "example.com",
		"gtin":   "04012345678901",
		"serial": "SN-1",
		"batch":  "LOT-42",
	})
	text := toolCallText(t, result)
	var out struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.URI, "https://example.com/01/04012345678901") {
		t.Errorf("bad URI: %s", out.URI)
	}
	if !strings.Contains(out.URI, "/21/SN-1") {
		t.Errorf("serial missing: %s", out.URI)
	}
	if !strings.Contains(out.URI, "/10/LOT-42") {
		t.Errorf("batch missing: %s", out.URI)
	}
}

// TestBuildGS1LinkInvalidGTIN verifies GTIN validation (8/12/13/14 digits)
// surfaces through the tool.
func TestBuildGS1LinkInvalidGTIN(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "build_gs1_link", map[string]any{
		"domain": "example.com",
		"gtin":   "not-digits",
	})
	if !result["isError"].(bool) {
		t.Fatal("non-digit GTIN should error")
	}
}

// TestBuildGS1LinkMissingDomain verifies required-field validation.
func TestBuildGS1LinkMissingDomain(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "build_gs1_link", map[string]any{
		"gtin": "04012345678901",
	})
	if !result["isError"].(bool) {
		t.Fatal("missing domain should error")
	}
}

// TestParseGS1LinkRoundTrip verifies build -> parse recovers the original
// domain/GTIN/serial.
func TestParseGS1LinkRoundTrip(t *testing.T) {
	srv, _, _ := setupServer(t)
	buildResult := toolCall(t, srv, 1, "build_gs1_link", map[string]any{
		"domain": "example.com",
		"gtin":   "04012345678901",
		"serial": "SN-1",
	})
	var buildOut struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, buildResult)), &buildOut); err != nil {
		t.Fatal(err)
	}

	parseResult := toolCall(t, srv, 2, "parse_gs1_link", map[string]any{"uri": buildOut.URI})
	var parseOut struct {
		Domain string `json:"domain"`
		GTIN   string `json:"gtin"`
		Serial string `json:"serial"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, parseResult)), &parseOut); err != nil {
		t.Fatal(err)
	}
	if parseOut.Domain != "example.com" {
		t.Errorf("domain: got %s", parseOut.Domain)
	}
	if parseOut.GTIN != "04012345678901" {
		t.Errorf("gtin: got %s", parseOut.GTIN)
	}
	if parseOut.Serial != "SN-1" {
		t.Errorf("serial: got %s", parseOut.Serial)
	}
}

// TestParseGS1LinkInvalid verifies malformed URIs are rejected.
func TestParseGS1LinkInvalid(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "parse_gs1_link", map[string]any{"uri": "not-a-uri"})
	if !result["isError"].(bool) {
		t.Fatal("malformed URI should error")
	}
}

// TestGS1LinkToolsAreNotAudited verifies these are pure/read-only tools with
// no ledger side effects — no state changes, so no audit trail entry.
func TestGS1LinkToolsAreNotAudited(t *testing.T) {
	srv, _, _ := setupServer(t)
	before := srv.Ledger().Size()
	toolCall(t, srv, 1, "build_gs1_link", map[string]any{"domain": "example.com", "gtin": "04012345678901"})
	toolCall(t, srv, 2, "parse_gs1_link", map[string]any{"uri": "https://example.com/01/04012345678901"})
	after := srv.Ledger().Size()
	if after != before {
		t.Errorf("GS1 link tools should not be audited: before=%d after=%d", before, after)
	}
}
