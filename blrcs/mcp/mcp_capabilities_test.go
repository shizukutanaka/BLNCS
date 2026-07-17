package mcp

import (
	"encoding/json"
	"testing"

	"blrcs/openid4vp"
)

// TestServerCapabilitiesDefault verifies an in-memory server reports the
// always-present functional capabilities as true and the config-dependent
// ones (VCI/VP/persistence) as false when nothing is registered.
func TestServerCapabilitiesDefault(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "get_server_capabilities", map[string]any{})
	text := toolCallText(t, result)

	var snap struct {
		Available map[string]bool `json:"available"`
		Sealed    bool            `json:"sealed"`
		Runtime   struct {
			GoVersion string `json:"goVersion"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal([]byte(text), &snap); err != nil {
		t.Fatal(err)
	}
	// Always-present.
	for _, cap := range []string{"crypto.ed25519", "compliance.dpp", "compliance.battery", "audit.scitt"} {
		if !snap.Available[cap] {
			t.Errorf("expected %s available, got false", cap)
		}
	}
	// Config-dependent, off by default (in-memory server, nothing registered).
	if snap.Available["protocol.openid4vci"] {
		t.Error("openid4vci should be false without a registered issuer")
	}
	if snap.Available["protocol.openid4vp"] {
		t.Error("openid4vp should be false without a registered verifier")
	}
	if !snap.Sealed {
		t.Error("snapshot should report the capability set as sealed")
	}
	if snap.Runtime.GoVersion == "" {
		t.Error("runtime.goVersion should be populated")
	}
}

// TestServerCapabilitiesReflectsRegistration verifies the report flips to true
// once an OpenID4VP verifier is registered — proving it reflects real server
// state, not a static list.
func TestServerCapabilitiesReflectsRegistration(t *testing.T) {
	srv, _, _ := setupServer(t)
	srv.RegisterVPVerifier(openid4vp.NewVerifier("https://verify.example", "https://verify.example/cb", nil))

	result := toolCall(t, srv, 1, "get_server_capabilities", map[string]any{})
	var snap struct {
		Available map[string]bool `json:"available"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, result)), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.Available["protocol.openid4vp"] {
		t.Error("openid4vp should be true after RegisterVPVerifier")
	}
	if snap.Available["protocol.openid4vci"] {
		t.Error("openid4vci should still be false (no issuer registered)")
	}
}

// TestServerCapabilitiesNotAudited verifies this read-only tool adds no ledger
// entry, matching the other get_* tools.
func TestServerCapabilitiesNotAudited(t *testing.T) {
	srv, _, _ := setupServer(t)
	before := srv.Ledger().Size()
	toolCall(t, srv, 1, "get_server_capabilities", map[string]any{})
	if after := srv.Ledger().Size(); after != before {
		t.Errorf("get_server_capabilities should not be audited: before=%d after=%d", before, after)
	}
}

// TestCapabilitiesSnapshotMatchesTool verifies the exported
// CapabilitiesSnapshot (used by cmd/blrcs-mcpd's
// /.well-known/blrcs-capabilities.json) returns the same capability data as the
// get_server_capabilities MCP tool — the whole point of a shared
// discovery document is that both transports agree.
func TestCapabilitiesSnapshotMatchesTool(t *testing.T) {
	srv, _, _ := setupServer(t)
	srv.RegisterVPVerifier(openid4vp.NewVerifier("https://verify.example", "https://verify.example/cb", nil))

	toolResult := toolCall(t, srv, 1, "get_server_capabilities", map[string]any{})
	toolJSON, err := json.Marshal(json.RawMessage(toolCallText(t, toolResult)))
	if err != nil {
		t.Fatal(err)
	}
	directJSON, err := json.Marshal(srv.CapabilitiesSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	// Compare via unmarshaled maps rather than raw bytes: detectedAt timestamps
	// are independently computed on each call, so byte-for-byte JSON would
	// differ even though the semantic content (available/sealed/runtime) agrees.
	var toolSnap, directSnap map[string]any
	_ = json.Unmarshal(toolJSON, &toolSnap)
	_ = json.Unmarshal(directJSON, &directSnap)
	if toolSnap["available"] == nil || directSnap["available"] == nil {
		t.Fatal("available field missing from one of the snapshots")
	}
	toolAvail, _ := json.Marshal(toolSnap["available"])
	directAvail, _ := json.Marshal(directSnap["available"])
	if string(toolAvail) != string(directAvail) {
		t.Errorf("available capabilities differ: tool=%s direct=%s", toolAvail, directAvail)
	}
}
