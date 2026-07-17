package mcp

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"blrcs/compliance"
)

// ============================================================================
// Axis 104: issue_mdoc / verify_mdoc
// ============================================================================

// TestIssueMdocHappyPath verifies the full MCP surface can issue an
// ISO 18013-5 mdoc — previously only reachable via the mdoc package directly
// (exercised only by doctor's self-check, never exposed as a tool).
func TestIssueMdocHappyPath(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_mdoc", map[string]any{
		"issuerId": iss.ID,
		"docType":  "org.iso.18013.5.1.mDL",
		"nameSpaces": map[string]any{
			"org.iso.18013.5.1": map[string]any{
				"family_name": "Tanaka",
				"given_name":  "Shizuku",
				"age_over_18": true,
			},
		},
	})
	text := toolCallText(t, result)
	var out struct {
		IssuerSignedB64 string `json:"issuerSignedB64"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.IssuerSignedB64 == "" {
		t.Fatal("issuerSignedB64 missing")
	}
	if _, err := base64.StdEncoding.DecodeString(out.IssuerSignedB64); err != nil {
		t.Fatalf("issuerSignedB64 should be valid base64: %v", err)
	}
}

// TestIssueMdocMissingDocType verifies required-field validation.
func TestIssueMdocMissingDocType(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_mdoc", map[string]any{
		"issuerId":   iss.ID,
		"nameSpaces": map[string]any{"ns": map[string]any{"a": "b"}},
	})
	if !result["isError"].(bool) {
		t.Fatal("missing docType should error")
	}
}

// TestIssueMdocUnknownIssuer verifies the same issuer-lookup guard as
// issue_passport applies.
func TestIssueMdocUnknownIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_mdoc", map[string]any{
		"issuerId":   "did:web:nonexistent",
		"docType":    "org.iso.18013.5.1.mDL",
		"nameSpaces": map[string]any{"ns": map[string]any{"a": "b"}},
	})
	if !result["isError"].(bool) {
		t.Fatal("unknown issuer should error")
	}
}

// TestIssueMdocIsAudited verifies the tool is recorded to the transparency
// log like other mutating issuance tools.
func TestIssueMdocIsAudited(t *testing.T) {
	srv, iss, _ := setupServer(t)
	before := srv.Ledger().Size()
	result := toolCall(t, srv, 1, "issue_mdoc", map[string]any{
		"issuerId":   iss.ID,
		"docType":    "org.iso.18013.5.1.mDL",
		"nameSpaces": map[string]any{"ns": map[string]any{"a": "b"}},
	})
	toolCallText(t, result)
	after := srv.Ledger().Size()
	if after <= before {
		t.Errorf("issue_mdoc should add a ledger entry: before=%d after=%d", before, after)
	}
}

// TestIssueAndVerifyMdocRoundTrip verifies the full issue -> verify lifecycle
// through the MCP surface, including that the revealed nameSpaces/values
// match what was issued.
func TestIssueAndVerifyMdocRoundTrip(t *testing.T) {
	srv, iss, _ := setupServer(t)
	issueResult := toolCall(t, srv, 1, "issue_mdoc", map[string]any{
		"issuerId": iss.ID,
		"docType":  "org.iso.18013.5.1.mDL",
		"nameSpaces": map[string]any{
			"org.iso.18013.5.1": map[string]any{
				"family_name": "Tanaka",
			},
		},
	})
	issueText := toolCallText(t, issueResult)
	var issueOut struct {
		IssuerSignedB64 string `json:"issuerSignedB64"`
	}
	if err := json.Unmarshal([]byte(issueText), &issueOut); err != nil {
		t.Fatal(err)
	}

	verifyResult := toolCall(t, srv, 2, "verify_mdoc", map[string]any{
		"issuerSignedB64":    issueOut.IssuerSignedB64,
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey()),
	})
	verifyText := toolCallText(t, verifyResult)
	var verifyOut struct {
		Valid      bool                      `json:"valid"`
		DocType    string                    `json:"docType"`
		NameSpaces map[string]map[string]any `json:"nameSpaces"`
	}
	if err := json.Unmarshal([]byte(verifyText), &verifyOut); err != nil {
		t.Fatal(err)
	}
	if !verifyOut.Valid {
		t.Fatalf("issued mdoc should verify: %s", verifyText)
	}
	if verifyOut.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType: got %s", verifyOut.DocType)
	}
	if verifyOut.NameSpaces["org.iso.18013.5.1"]["family_name"] != "Tanaka" {
		t.Errorf("revealed claim mismatch: %v", verifyOut.NameSpaces)
	}
}

// TestVerifyMdocWrongKeyRejected verifies signature verification actually
// checks the key rather than trusting any well-formed input.
func TestVerifyMdocWrongKeyRejected(t *testing.T) {
	srv, iss, _ := setupServer(t)
	issueResult := toolCall(t, srv, 1, "issue_mdoc", map[string]any{
		"issuerId":   iss.ID,
		"docType":    "org.iso.18013.5.1.mDL",
		"nameSpaces": map[string]any{"ns": map[string]any{"a": "b"}},
	})
	var issueOut struct {
		IssuerSignedB64 string `json:"issuerSignedB64"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, issueResult)), &issueOut)

	otherIssuer, err := compliance.NewIssuer("did:web:wrong-key.example")
	if err != nil {
		t.Fatal(err)
	}
	verifyResult := toolCall(t, srv, 2, "verify_mdoc", map[string]any{
		"issuerSignedB64":    issueOut.IssuerSignedB64,
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(otherIssuer.PublicKey()),
	})
	verifyText := toolCallText(t, verifyResult)
	var verifyOut struct {
		Valid bool `json:"valid"`
	}
	_ = json.Unmarshal([]byte(verifyText), &verifyOut)
	if verifyOut.Valid {
		t.Fatal("verifying with the wrong issuer key should not succeed")
	}
}

// TestVerifyMdocBadBase64Rejected verifies malformed input is rejected
// cleanly rather than panicking.
func TestVerifyMdocBadBase64Rejected(t *testing.T) {
	srv, iss, _ := setupServer(t)
	result := toolCall(t, srv, 1, "verify_mdoc", map[string]any{
		"issuerSignedB64":    "not-valid-base64!!!",
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey()),
	})
	if !result["isError"].(bool) {
		t.Fatal("malformed issuerSignedB64 should error")
	}
}
