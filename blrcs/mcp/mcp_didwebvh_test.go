package mcp

import (
	"encoding/json"
	"testing"

	"blrcs/compliance"
	"blrcs/didwebvh"
	"blrcs/multiformats"
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

// registerWitnessIssuer generates a fresh keypair, derives its did:key DID,
// and registers it as an Issuer under that DID — the pattern an operator
// uses to make a witness identity's key retrievable via witnessIssuerId in
// sign_witness_proof (compliance.NewIssuer's id param is just a label
// unrelated to the generated key, so the did:key DID must be computed from
// the actual key afterward, not passed in upfront).
func registerWitnessIssuer(t *testing.T, srv *Server) (issuerID, didKeyDID string) {
	t.Helper()
	iss, err := compliance.NewIssuer("witness-placeholder")
	if err != nil {
		t.Fatal(err)
	}
	iss.ID = "did:key:" + multiformats.EncodeEd25519Multikey(iss.PublicKey())
	srv.RegisterIssuer(iss)
	return iss.ID, iss.ID
}

// TestDIDWebVHWitnessFullLifecycleViaMCP exercises the complete witness flow
// through the MCP surface: create a genesis entry declaring a 1-of-1 witness
// requirement, verify it fails without a witness proof, sign one via
// sign_witness_proof, then verify it succeeds with the assembled witnessLog.
func TestDIDWebVHWitnessFullLifecycleViaMCP(t *testing.T) {
	srv, iss, _ := setupServer(t)
	witnessID, witnessDID := registerWitnessIssuer(t, srv)

	createResult := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": iss.ID,
		"didPath":  "example.com:dids:witnessed-mcp",
		"witness": map[string]any{
			"threshold": 1,
			"witnesses": []map[string]any{{"id": witnessDID}},
		},
	})
	var createOut struct {
		DID string              `json:"did"`
		Log []didwebvh.LogEntry `json:"log"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, createResult)), &createOut); err != nil {
		t.Fatal(err)
	}

	// Without any witness proof, verification must fail.
	unwitnessedResult := toolCall(t, srv, 2, "verify_did_webvh_log", map[string]any{
		"log": createOut.Log,
	})
	var unwitnessedOut struct {
		Valid bool `json:"valid"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, unwitnessedResult)), &unwitnessedOut)
	if unwitnessedOut.Valid {
		t.Fatal("log with an unmet witness requirement should not verify")
	}

	// The witness signs the genesis entry (predecessorVersionId empty for genesis).
	signResult := toolCall(t, srv, 3, "sign_witness_proof", map[string]any{
		"witnessIssuerId": witnessID,
		"entry":           createOut.Log[0],
	})
	var signOut struct {
		Proof didwebvh.Proof `json:"proof"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, signResult)), &signOut); err != nil {
		t.Fatal(err)
	}

	// Verify again with the assembled witnessLog — must now succeed.
	witnessedResult := toolCall(t, srv, 4, "verify_did_webvh_log", map[string]any{
		"log": createOut.Log,
		"witnessLog": []map[string]any{
			{"versionId": createOut.Log[0].VersionID, "proof": []didwebvh.Proof{signOut.Proof}},
		},
	})
	witnessedText := toolCallText(t, witnessedResult)
	var witnessedOut struct {
		Valid bool   `json:"valid"`
		DID   string `json:"did"`
	}
	if err := json.Unmarshal([]byte(witnessedText), &witnessedOut); err != nil {
		t.Fatal(err)
	}
	if !witnessedOut.Valid {
		t.Fatalf("log with a satisfied witness requirement should verify: %s", witnessedText)
	}
	if witnessedOut.DID != createOut.DID {
		t.Errorf("did mismatch: %s vs %s", witnessedOut.DID, createOut.DID)
	}
}

// TestSignWitnessProofUnknownIssuer verifies the same issuer-lookup guard
// applies as elsewhere.
func TestSignWitnessProofUnknownIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "sign_witness_proof", map[string]any{
		"witnessIssuerId": "did:key:nonexistent",
		"entry":           map[string]any{"versionId": "1-x"},
	})
	if !result["isError"].(bool) {
		t.Fatal("unknown witness issuer should error")
	}
}

// TestSignWitnessProofMissingEntry verifies required-field validation.
func TestSignWitnessProofMissingEntry(t *testing.T) {
	srv, _, _ := setupServer(t)
	_, witnessDID := registerWitnessIssuer(t, srv)
	result := toolCall(t, srv, 1, "sign_witness_proof", map[string]any{
		"witnessIssuerId": witnessDID,
	})
	if !result["isError"].(bool) {
		t.Fatal("missing entry should error")
	}
}

// TestSignWitnessProofIsAudited verifies this signing tool is recorded to the
// transparency log, matching issue_mdoc/create_did_webvh.
func TestSignWitnessProofIsAudited(t *testing.T) {
	srv, iss, _ := setupServer(t)
	witnessID, witnessDID := registerWitnessIssuer(t, srv)

	createResult := toolCall(t, srv, 1, "create_did_webvh", map[string]any{
		"issuerId": iss.ID,
		"didPath":  "example.com:dids:audit-witness",
		"witness":  map[string]any{"threshold": 1, "witnesses": []map[string]any{{"id": witnessDID}}},
	})
	var createOut struct {
		Log []didwebvh.LogEntry `json:"log"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, createResult)), &createOut)

	before := srv.Ledger().Size()
	toolCall(t, srv, 2, "sign_witness_proof", map[string]any{
		"witnessIssuerId": witnessID,
		"entry":           createOut.Log[0],
	})
	after := srv.Ledger().Size()
	if after <= before {
		t.Errorf("sign_witness_proof should add a ledger entry: before=%d after=%d", before, after)
	}
}
