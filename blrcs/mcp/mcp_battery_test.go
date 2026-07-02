package mcp

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"blrcs/compliance"
)

// ============================================================================
// Axis 102: issue_battery_passport
// ============================================================================

// TestIssueBatteryPassportHappyPath verifies the full MCP surface can issue
// an EU Battery Passport (previously only reachable via the compliance
// package directly, not through the agent-facing tool surface at all).
func TestIssueBatteryPassportHappyPath(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId":                    iss.ID,
		"batteryId":                   "BAT-MCP-1",
		"category":                    "ev",
		"chemistry":                   "nmc",
		"capacityKWh":                 75.0,
		"carbonFootprintKgCO2ePerKWh": 48.5,
		"dueDiligenceReportUrl":       "https://factory.example/due-diligence/2026.pdf",
		"recycledContent": map[string]any{
			"cobalt": 16.0, "lithium": 6.0, "nickel": 6.0, "lead": 85.0,
		},
	})
	credJSON := toolCallText(t, result)

	var cred compliance.Credential
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		t.Fatal(err)
	}
	hasBattery := false
	for _, tp := range cred.Type {
		if tp == "BatteryPassport" {
			hasBattery = true
		}
	}
	if !hasBattery {
		t.Error("BatteryPassport type marker missing")
	}
	if cred.Status == nil {
		t.Fatal("issued battery passport should carry a credentialStatus, same as issue_passport")
	}

	// verify_passport must accept it — Credential is a generic W3C VC type,
	// so no battery-specific verification path is needed.
	verifyResult := toolCall(t, srv, 2, "verify_passport", map[string]any{
		"credentialJson":     credJSON,
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey()),
	})
	verifyText := toolCallText(t, verifyResult)
	var verifyOut struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(verifyText), &verifyOut); err != nil {
		t.Fatal(err)
	}
	if !verifyOut.Valid {
		t.Fatalf("issued battery passport should verify: %s", verifyText)
	}
}

// TestIssueBatteryPassportMissingBatteryID verifies the required-field
// validation from compliance.IssueBatteryPassport surfaces through the tool.
func TestIssueBatteryPassportMissingBatteryID(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId": iss.ID, "category": "portable",
	})
	if !result["isError"].(bool) {
		t.Fatal("missing batteryId should error")
	}
}

// TestIssueBatteryPassportEVWithoutDueDiligenceRejected verifies Art.52
// enforcement (EV/industrial >2kWh batteries require dueDiligenceReportUrl)
// is reachable through the MCP tool, not just the underlying compliance call.
func TestIssueBatteryPassportEVWithoutDueDiligenceRejected(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId": iss.ID, "batteryId": "BAT-NODD-1", "category": "ev", "capacityKWh": 75.0,
	})
	if !result["isError"].(bool) {
		t.Fatal("EV battery without dueDiligenceReportUrl should be rejected (Art.52)")
	}
}

// TestIssueBatteryPassportBadDateRejected verifies malformed RFC3339 date
// input is rejected with a clear error rather than silently defaulting.
func TestIssueBatteryPassportBadDateRejected(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId": iss.ID, "batteryId": "BAT-BADDATE-1", "category": "portable",
		"dateOfManufacture": "not-a-date",
	})
	if !result["isError"].(bool) {
		t.Fatal("malformed dateOfManufacture should error")
	}
}

// TestIssueBatteryPassportUnknownIssuer verifies the same issuer-lookup
// guard as issue_passport applies.
func TestIssueBatteryPassportUnknownIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId": "did:web:nonexistent", "batteryId": "BAT-X", "category": "portable",
	})
	if !result["isError"].(bool) {
		t.Fatal("unknown issuer should error")
	}
}

// TestIssueBatteryPassportRevocationLifecycle verifies a Battery Passport
// draws from the same shared status-list index space as issue_passport/
// issue_sdjwt, so the existing revoke_passport/check_revocation/
// get_revocation_list tools work unchanged for it too.
func TestIssueBatteryPassportRevocationLifecycle(t *testing.T) {
	srv, iss, _ := setupServer(t)
	issueResult := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId": iss.ID, "batteryId": "BAT-REVOKE-1", "category": "portable",
	})
	credJSON := toolCallText(t, issueResult)
	var cred compliance.Credential
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		t.Fatal(err)
	}
	index, err := jsonNumberToInt(cred.Status.StatusListIndex)
	if err != nil {
		t.Fatal(err)
	}

	revokeResult := toolCall(t, srv, 2, "revoke_passport", map[string]any{"statusListIndex": index})
	toolCallText(t, revokeResult) // asserts not isError

	listResult := toolCall(t, srv, 3, "get_revocation_list", map[string]any{})
	var listOut struct {
		StatusListTokenJWT     string `json:"statusListTokenJWT"`
		StatusListIssuerKeyB64 string `json:"statusListIssuerKeyB64"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, listResult)), &listOut); err != nil {
		t.Fatal(err)
	}
	checkResult := toolCall(t, srv, 4, "check_revocation", map[string]any{
		"statusListTokenJWT": listOut.StatusListTokenJWT, "statusListIssuerKeyB64": listOut.StatusListIssuerKeyB64, "statusIndex": index,
	})
	var checkOut struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, checkResult)), &checkOut); err != nil {
		t.Fatal(err)
	}
	if !checkOut.Revoked {
		t.Fatal("battery passport should be revoked after revoke_passport")
	}
}

// TestIssueBatteryPassportIsAudited verifies the tool is recorded to the
// transparency log like other mutating issuance tools.
func TestIssueBatteryPassportIsAudited(t *testing.T) {
	srv, iss, _ := setupServer(t)
	before := srv.Ledger().Size()
	result := toolCall(t, srv, 1, "issue_battery_passport", map[string]any{
		"issuerId": iss.ID, "batteryId": "BAT-AUDIT-1", "category": "portable",
	})
	toolCallText(t, result)
	after := srv.Ledger().Size()
	if after <= before {
		t.Errorf("issue_battery_passport should add a ledger entry: before=%d after=%d", before, after)
	}
}
