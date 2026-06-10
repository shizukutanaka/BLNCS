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
