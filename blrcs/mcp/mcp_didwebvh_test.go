package mcp

import (
	"encoding/json"
	"testing"

	"blrcs/compliance"
	"blrcs/didwebvh"
)

// ============================================================================
// Axis 111: create_did_webvh / update_did_webvh / verify_did_webvh_log
// ============================================================================

// TestDIDWebVHFullLifecycleViaMCP exercises the complete real flow through
// the MCP surface: create a genesis entry, append a rotation entry, then
// verify the full log resolves correctly — previously only reachable via
// the didwebvh package directly, despite README listing
// "did:webvh (verifiable history + pre-rotation) ✅".
func TestDIDWebVHFullLifecycleViaMCP(t *testing.T) {
	srv, iss, _ := setupServer(t)

	createResult := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": iss.ID,
		"didPath":  "example.com:dids:org-1",
	})
	createText := toolCallText(t, createResult)
	var createOut struct {
		DID string              `json:"did"`
		Log []didwebvh.LogEntry `json:"log"`
	}
	if err := json.Unmarshal([]byte(createText), &createOut); err != nil {
		t.Fatal(err)
	}
	if createOut.DID == "" {
		t.Fatal("did missing")
	}
	if len(createOut.Log) != 1 {
		t.Fatalf("expected genesis log of length 1, got %d", len(createOut.Log))
	}

	updateResult := toolCall(t, srv, 2, "update_did_webvh", map[string]any{
		"signKeyIssuerId": iss.ID,
		"log":             createOut.Log,
		"newState":        map[string]any{"id": createOut.DID, "service": []any{"https://example.com/dpp"}},
	})
	updateText := toolCallText(t, updateResult)
	var updateOut struct {
		Log []didwebvh.LogEntry `json:"log"`
	}
	if err := json.Unmarshal([]byte(updateText), &updateOut); err != nil {
		t.Fatal(err)
	}
	if len(updateOut.Log) != 2 {
		t.Fatalf("expected log of length 2 after update, got %d", len(updateOut.Log))
	}

	verifyResult := toolCall(t, srv, 3, "verify_did_webvh_log", map[string]any{
		"log": updateOut.Log,
	})
	verifyText := toolCallText(t, verifyResult)
	var verifyOut struct {
		Valid       bool           `json:"valid"`
		DID         string         `json:"did"`
		SCID        string         `json:"scid"`
		Document    map[string]any `json:"document"`
		Deactivated bool           `json:"deactivated"`
	}
	if err := json.Unmarshal([]byte(verifyText), &verifyOut); err != nil {
		t.Fatal(err)
	}
	if !verifyOut.Valid {
		t.Fatalf("expected valid log: %s", verifyText)
	}
	if verifyOut.DID != createOut.DID {
		t.Errorf("did mismatch: got %s want %s", verifyOut.DID, createOut.DID)
	}
	if verifyOut.Deactivated {
		t.Error("should not be deactivated")
	}
}

// TestCreateDIDWebVHMissingDIDPath verifies required-field validation.
func TestCreateDIDWebVHMissingDIDPath(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "create_did_webvh", map[string]any{"issuerId": iss.ID})
	if !result["isError"].(bool) {
		t.Fatal("missing didPath should error")
	}
}

// TestCreateDIDWebVHUnknownIssuer verifies the same issuer-lookup guard as
// issue_passport applies.
func TestCreateDIDWebVHUnknownIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": "did:web:nonexistent",
		"didPath":  "example.com:dids:x",
	})
	if !result["isError"].(bool) {
		t.Fatal("unknown issuer should error")
	}
}

// TestUpdateDIDWebVHMissingLog verifies required-field validation.
func TestUpdateDIDWebVHMissingLog(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "update_did_webvh", map[string]any{
		"signKeyIssuerId": iss.ID,
		"newState":        map[string]any{},
	})
	if !result["isError"].(bool) {
		t.Fatal("missing log should error")
	}
}

// TestUpdateDIDWebVHWrongSignerFailsVerification verifies the security
// property end-to-end: update_did_webvh itself does not (and per
// didwebvh.Update's design cannot) reject an unauthorized signer — for an
// append-only verifiable log, authorization is checked at *verify* time
// against the log's own recorded update-key history, not at write time.
// A log entry signed by a key that never held update authority must
// therefore fail verify_did_webvh_log.
func TestUpdateDIDWebVHWrongSignerFailsVerification(t *testing.T) {
	srv, iss, _ := setupServer(t)
	otherIssuer, err := compliance.NewIssuer("did:web:not-the-genesis-key.example")
	if err != nil {
		t.Fatal(err)
	}
	srv.RegisterIssuer(otherIssuer)

	createResult := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": iss.ID,
		"didPath":  "example.com:dids:org-2",
	})
	var createOut struct {
		Log []didwebvh.LogEntry `json:"log"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, createResult)), &createOut)

	updateResult := toolCall(t, srv, 2, "update_did_webvh", map[string]any{
		"signKeyIssuerId": otherIssuer.ID,
		"log":             createOut.Log,
		"newState":        map[string]any{},
	})
	updateText := toolCallText(t, updateResult) // update itself succeeds
	var updateOut struct {
		Log []didwebvh.LogEntry `json:"log"`
	}
	if err := json.Unmarshal([]byte(updateText), &updateOut); err != nil {
		t.Fatal(err)
	}

	verifyResult := toolCall(t, srv, 3, "verify_did_webvh_log", map[string]any{"log": updateOut.Log})
	verifyText := toolCallText(t, verifyResult)
	var verifyOut struct {
		Valid bool `json:"valid"`
	}
	_ = json.Unmarshal([]byte(verifyText), &verifyOut)
	if verifyOut.Valid {
		t.Fatal("a log entry signed by an unauthorized key should fail verification")
	}
}

// TestVerifyDIDWebVHLogTamperedRejected verifies signature/hash-chain
// tampering is caught, returning a structured {valid:false} rather than a
// Go error, matching verify_passport's contract.
func TestVerifyDIDWebVHLogTamperedRejected(t *testing.T) {
	srv, iss, _ := setupServer(t)
	createResult := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": iss.ID,
		"didPath":  "example.com:dids:org-3",
	})
	var createOut struct {
		Log []didwebvh.LogEntry `json:"log"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, createResult)), &createOut)

	tampered := createOut.Log
	tampered[0].State["injected"] = "attacker-controlled"

	verifyResult := toolCall(t, srv, 2, "verify_did_webvh_log", map[string]any{"log": tampered})
	verifyText := toolCallText(t, verifyResult)
	var verifyOut struct {
		Valid bool `json:"valid"`
	}
	_ = json.Unmarshal([]byte(verifyText), &verifyOut)
	if verifyOut.Valid {
		t.Fatal("tampered log should not verify")
	}
}

// TestDIDWebVHToolsAuditedCorrectly verifies create/update mutate the ledger
// while verify does not, matching the issue_*/verify_* split elsewhere.
func TestDIDWebVHToolsAuditedCorrectly(t *testing.T) {
	srv, iss, _ := setupServer(t)
	before := srv.Ledger().Size()
	createResult := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": iss.ID,
		"didPath":  "example.com:dids:org-4",
	})
	afterCreate := srv.Ledger().Size()
	if afterCreate <= before {
		t.Errorf("create_did_webvh should add a ledger entry: before=%d after=%d", before, afterCreate)
	}

	var createOut struct {
		Log []didwebvh.LogEntry `json:"log"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, createResult)), &createOut)

	toolCall(t, srv, 2, "verify_did_webvh_log", map[string]any{"log": createOut.Log})
	afterVerify := srv.Ledger().Size()
	if afterVerify != afterCreate {
		t.Errorf("verify_did_webvh_log should not be audited: before=%d after=%d", afterCreate, afterVerify)
	}
}
