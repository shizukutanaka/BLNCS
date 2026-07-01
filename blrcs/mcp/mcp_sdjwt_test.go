package mcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blrcs/revocation"
)

// toolResultText extracts the text payload from a JSON-RPC tools/call response.
func toolResultText(t *testing.T, rpcResp string) (text string, isError bool) {
	t.Helper()
	var outer struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(rpcResp), &outer); err != nil {
		t.Fatalf("parse rpc response: %v — %s", err, rpcResp)
	}
	if len(outer.Result.Content) == 0 {
		return "", outer.Result.IsError
	}
	return outer.Result.Content[0].Text, outer.Result.IsError
}

// ============================================================================
// toolIssueSDJWT — happy path
// ============================================================================

func TestToolIssueSDJWTHappyPath(t *testing.T) {
	srv, iss, _ := setupServer(t)
	rpcResp := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "did:example:holder",
		"sdClaims": map[string]any{
			"carbonKgCO2e": 42.5,
			"productId":    "PROD-001",
		},
		"clearClaims": map[string]any{
			"category": "battery",
		},
	})
	text, isError := toolResultText(t, rpcResp)
	if isError {
		t.Fatalf("issue_sdjwt failed: %s", text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("bad JSON: %v — %s", err, text)
	}
	sdjwt, _ := out["sdjwt"].(string)
	if sdjwt == "" {
		t.Error("sdjwt field missing")
	}
	// SD-JWT must have header.payload.sig~disc... format
	if !strings.Contains(sdjwt, "~") {
		t.Error("SD-JWT should contain disclosure delimiter '~'")
	}
	fields, _ := out["disclosableFields"].([]any)
	if len(fields) == 0 {
		t.Error("disclosableFields should be non-empty")
	}
}

// ============================================================================
// toolIssueSDJWT — error paths
// ============================================================================

func TestToolIssueSDJWTBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_sdjwt","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolIssueSDJWTUnknownIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": "did:web:nobody",
		"subject":  "sub",
		"sdClaims": map[string]any{"x": 1},
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("unknown issuer should fail: %s", resp)
	}
}

func TestToolIssueSDJWTEmptySubject(t *testing.T) {
	srv, iss, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "",
		"sdClaims": map[string]any{"x": 1},
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("empty subject should fail: %s", resp)
	}
}

// ============================================================================
// toolVerifySDJWT — happy path
// ============================================================================

func TestToolVerifySDJWTHappyPath(t *testing.T) {
	srv, iss, _ := setupServer(t)

	// First issue an SD-JWT
	issueRPC := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "did:example:holder",
		"sdClaims": map[string]any{"productId": "PROD-002"},
	})
	issueText, _ := toolResultText(t, issueRPC)
	var issued map[string]any
	if err := json.Unmarshal([]byte(issueText), &issued); err != nil {
		t.Fatalf("parse issue response: %v — %s", err, issueText)
	}
	sdjwt, _ := issued["sdjwt"].(string)
	if sdjwt == "" {
		t.Fatalf("no sdjwt in issue response: %s", issueText)
	}

	// Verify it
	pubB64 := base64.StdEncoding.EncodeToString(iss.PublicKey())
	verRPC := mcpToolCall(t, srv, "verify_sdjwt", map[string]any{
		"sdjwt":              sdjwt,
		"issuerPublicKeyB64": pubB64,
	})
	verText, isError := toolResultText(t, verRPC)
	if isError {
		t.Fatalf("verify_sdjwt errored: %s", verText)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(verText), &out); err != nil {
		t.Fatalf("bad JSON: %v — %s", err, verText)
	}
	if valid, _ := out["valid"].(bool); !valid {
		t.Errorf("expected valid=true: %s", verText)
	}
}

// ============================================================================
// toolVerifySDJWT — error paths
// ============================================================================

func TestToolVerifySDJWTBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_sdjwt","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolVerifySDJWTBadKey(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "verify_sdjwt", map[string]any{
		"sdjwt":              "a.b.c~",
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString([]byte("short")),
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("bad key should fail: %s", resp)
	}
}

func TestToolVerifySDJWTInvalidSig(t *testing.T) {
	srv, iss, _ := setupServer(t)
	// Issue with correct key, then verify with a different key
	issueRPC := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "sub",
		"sdClaims": map[string]any{"x": 1},
	})
	issueText, _ := toolResultText(t, issueRPC)
	var issued map[string]any
	json.Unmarshal([]byte(issueText), &issued)
	sdjwt, _ := issued["sdjwt"].(string)

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	verRPC := mcpToolCall(t, srv, "verify_sdjwt", map[string]any{
		"sdjwt":              sdjwt,
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString([]byte(otherPub)),
	})
	// Verification should fail but return valid=false (not isError)
	verText, isError := toolResultText(t, verRPC)
	if isError {
		t.Errorf("sig fail should be valid=false not isError: %s", verText)
	}
	var out map[string]any
	json.Unmarshal([]byte(verText), &out)
	if valid, _ := out["valid"].(bool); valid {
		t.Errorf("wrong key should give valid=false: %s", verText)
	}
}

// ============================================================================
// toolCheckRevocation — happy path
// ============================================================================

func TestToolCheckRevocationNotRevoked(t *testing.T) {
	srv, _, _ := setupServer(t)

	// Build a status list with index 5 revoked
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, 128)
	list.SetStatus(5, true)

	_, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub := issPriv.Public().(ed25519.PublicKey)
	token, err := list.IssueToken("did:web:status.example", "https://status.example/list", issPriv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Index 3 should NOT be revoked
	rpcResp := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     token,
		"statusListIssuerKeyB64": base64.StdEncoding.EncodeToString([]byte(pub)),
		"statusIndex":            3,
	})
	text, isError := toolResultText(t, rpcResp)
	if isError {
		t.Fatalf("check_revocation errored: %s", text)
	}
	var out map[string]any
	json.Unmarshal([]byte(text), &out)
	if revoked, _ := out["revoked"].(bool); revoked {
		t.Errorf("index 3 should not be revoked: %s", text)
	}
}

func TestToolCheckRevocationRevoked(t *testing.T) {
	srv, _, _ := setupServer(t)

	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, 128)
	list.SetStatus(7, true)

	_, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub := issPriv.Public().(ed25519.PublicKey)
	token, err := list.IssueToken("did:web:status.example", "https://status.example/list", issPriv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rpcResp := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     token,
		"statusListIssuerKeyB64": base64.StdEncoding.EncodeToString([]byte(pub)),
		"statusIndex":            7,
	})
	text, isError := toolResultText(t, rpcResp)
	if isError {
		t.Fatalf("check_revocation errored: %s", text)
	}
	var out map[string]any
	json.Unmarshal([]byte(text), &out)
	if revoked, _ := out["revoked"].(bool); !revoked {
		t.Errorf("index 7 should be revoked: %s", text)
	}
}

// ============================================================================
// toolCheckRevocation — error paths
// ============================================================================

func TestToolCheckRevocationBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_revocation","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolCheckRevocationBadKey(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     "x.y.z",
		"statusListIssuerKeyB64": base64.StdEncoding.EncodeToString([]byte("short")),
		"statusIndex":            0,
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("bad key should fail: %s", resp)
	}
}

func TestToolCheckRevocationNegativeIndex(t *testing.T) {
	srv, _, _ := setupServer(t)
	_, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub := issPriv.Public().(ed25519.PublicKey)
	resp := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     "x.y.z",
		"statusListIssuerKeyB64": base64.StdEncoding.EncodeToString([]byte(pub)),
		"statusIndex":            -1,
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("negative index should fail: %s", resp)
	}
}

func TestToolCheckRevocationInvalidToken(t *testing.T) {
	srv, _, _ := setupServer(t)
	_, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub := issPriv.Public().(ed25519.PublicKey)
	resp := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     "invalid.token.value",
		"statusListIssuerKeyB64": base64.StdEncoding.EncodeToString([]byte(pub)),
		"statusIndex":            0,
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("invalid token should fail: %s", resp)
	}
}

// ============================================================================
// Axis 101: issue_sdjwt now embeds status_list (revocable, same as
// issue_passport since Axis 100).
// ============================================================================

// TestIssueSDJWTReturnsStatusListIndex verifies issue_sdjwt's response now
// includes statusListIndex, so callers can revoke it without decoding the JWT.
func TestIssueSDJWTReturnsStatusListIndex(t *testing.T) {
	srv, iss, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "did:example:holder",
		"sdClaims": map[string]any{"productId": "PROD-STATUS-1"},
	})
	text, isError := toolResultText(t, resp)
	if isError {
		t.Fatalf("issue_sdjwt failed: %s", text)
	}
	var out struct {
		SDJWT           string `json:"sdjwt"`
		StatusListIndex *int   `json:"statusListIndex"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.StatusListIndex == nil {
		t.Fatal("response should include statusListIndex")
	}
}

// TestIssueSDJWTAndRevokePassportSharedIndexSpace verifies an SD-JWT VC
// issued via issue_sdjwt can be revoked via the SAME revoke_passport tool
// used for plain passports, and the revocation is visible through
// check_revocation/get_revocation_list — the two credential types share one
// status-list index space.
func TestIssueSDJWTAndRevokePassportSharedIndexSpace(t *testing.T) {
	srv, iss, _ := setupServer(t)

	issueResp := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "did:example:holder",
		"sdClaims": map[string]any{"productId": "PROD-REVOKE-SD-1"},
	})
	text, isError := toolResultText(t, issueResp)
	if isError {
		t.Fatalf("issue_sdjwt failed: %s", text)
	}
	var issued struct {
		StatusListIndex int `json:"statusListIndex"`
	}
	if err := json.Unmarshal([]byte(text), &issued); err != nil {
		t.Fatal(err)
	}

	// Not revoked yet.
	listResp := mcpToolCall(t, srv, "get_revocation_list", map[string]any{})
	listText, isError := toolResultText(t, listResp)
	if isError {
		t.Fatalf("get_revocation_list failed: %s", listText)
	}
	var listOut struct {
		StatusListTokenJWT     string `json:"statusListTokenJWT"`
		StatusListIssuerKeyB64 string `json:"statusListIssuerKeyB64"`
	}
	_ = json.Unmarshal([]byte(listText), &listOut)

	checkNotRevoked := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     listOut.StatusListTokenJWT,
		"statusListIssuerKeyB64": listOut.StatusListIssuerKeyB64,
		"statusIndex":            issued.StatusListIndex,
	})
	checkText, isError := toolResultText(t, checkNotRevoked)
	if isError {
		t.Fatalf("check_revocation failed: %s", checkText)
	}
	if strings.Contains(checkText, `"revoked":true`) {
		t.Fatal("freshly issued SD-JWT VC should not be revoked")
	}

	// Revoke via the shared revoke_passport tool.
	revokeResp := mcpToolCall(t, srv, "revoke_passport", map[string]any{
		"statusListIndex": issued.StatusListIndex,
	})
	revokeText, isError := toolResultText(t, revokeResp)
	if isError {
		t.Fatalf("revoke_passport failed: %s", revokeText)
	}

	// Now revoked.
	listResp2 := mcpToolCall(t, srv, "get_revocation_list", map[string]any{})
	listText2, _ := toolResultText(t, listResp2)
	var listOut2 struct {
		StatusListTokenJWT     string `json:"statusListTokenJWT"`
		StatusListIssuerKeyB64 string `json:"statusListIssuerKeyB64"`
	}
	_ = json.Unmarshal([]byte(listText2), &listOut2)
	checkRevoked := mcpToolCall(t, srv, "check_revocation", map[string]any{
		"statusListTokenJWT":     listOut2.StatusListTokenJWT,
		"statusListIssuerKeyB64": listOut2.StatusListIssuerKeyB64,
		"statusIndex":            issued.StatusListIndex,
	})
	checkText2, isError := toolResultText(t, checkRevoked)
	if isError {
		t.Fatalf("check_revocation failed: %s", checkText2)
	}
	if !strings.Contains(checkText2, `"revoked":true`) {
		t.Fatalf("SD-JWT VC should be revoked after revoke_passport: %s", checkText2)
	}
}

// TestIssuePassportAndIssueSDJWTGetDistinctIndices verifies the two
// issuance tools don't collide on the same index when interleaved.
func TestIssuePassportAndIssueSDJWTGetDistinctIndices(t *testing.T) {
	srv, iss, _ := setupServer(t)

	sdResp := mcpToolCall(t, srv, "issue_sdjwt", map[string]any{
		"issuerId": iss.ID, "subject": "did:example:holder",
		"sdClaims": map[string]any{"productId": "PROD-MIX-1"},
	})
	sdText, _ := toolResultText(t, sdResp)
	var sdOut struct {
		StatusListIndex int `json:"statusListIndex"`
	}
	_ = json.Unmarshal([]byte(sdText), &sdOut)

	passResp := mcpToolCall(t, srv, "issue_passport", map[string]any{
		"issuerId": iss.ID, "productId": "PROD-MIX-2",
	})
	passText, _ := toolResultText(t, passResp)
	var passOut struct {
		Status struct {
			StatusListIndex string `json:"statusListIndex"`
		} `json:"credentialStatus"`
	}
	_ = json.Unmarshal([]byte(passText), &passOut)

	if itoa(sdOut.StatusListIndex) == passOut.Status.StatusListIndex {
		t.Fatalf("issue_sdjwt and issue_passport should not collide on the same index: sd=%d passport=%s",
			sdOut.StatusListIndex, passOut.Status.StatusListIndex)
	}
}
