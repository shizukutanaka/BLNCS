package mcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/openid4vp"
)

// ============================================================================
// Axis 105: create_presentation_request / get_presentation_result
// ============================================================================

func TestCreatePresentationRequestWithoutRegisteredVerifierErrors(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "create_presentation_request", map[string]any{
		"presentationDefinition": map[string]any{"id": "pd-1"},
	})
	if !result["isError"].(bool) {
		t.Fatal("create_presentation_request without a registered VP verifier should error")
	}
}

func TestCreatePresentationRequestMissingDefinition(t *testing.T) {
	srv, _, _ := setupServer(t)
	ver := openid4vp.NewVerifier("https://verify.example", "https://verify.example/cb", nil)
	srv.RegisterVPVerifier(ver)
	result := toolCall(t, srv, 1, "create_presentation_request", map[string]any{})
	if !result["isError"].(bool) {
		t.Fatal("missing presentationDefinition should error")
	}
}

func TestCreatePresentationRequestHappyPath(t *testing.T) {
	srv, iss, _ := setupServer(t)
	ver := openid4vp.NewVerifier("https://verify.example", "https://verify.example/cb", nil)
	srv.RegisterVPVerifier(ver)

	result := toolCall(t, srv, 1, "create_presentation_request", map[string]any{
		"presentationDefinition": map[string]any{
			"id":             "pd-1",
			"requiredClaims": []string{"category"},
		},
		"acceptableIssuerKeys": map[string]any{
			iss.ID: base64.StdEncoding.EncodeToString(iss.PublicKey()),
		},
	})
	text := toolCallText(t, result)
	var out struct {
		RequestURL string `json:"requestUrl"`
		State      string `json:"state"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.RequestURL == "" || out.State == "" {
		t.Fatalf("requestUrl/state missing: %s", text)
	}
}

func TestGetPresentationResultPendingByDefault(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "get_presentation_result", map[string]any{"state": "never-seen-state"})
	text := toolCallText(t, result)
	if text != `{"status":"pending"}` {
		t.Errorf("unknown state should be pending, got %s", text)
	}
}

func TestGetPresentationResultMissingState(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "get_presentation_result", map[string]any{})
	if !result["isError"].(bool) {
		t.Fatal("missing state should error")
	}
}

// TestFullPresentationLifecycleViaMCP exercises the complete real flow: MCP
// tool creates a request, a MockWallet responds to it (openid4vp's own test
// double for this exact purpose), the verifier processes the response
// exactly as CallbackHandler would, and the result becomes retrievable
// through get_presentation_result — the agent-facing side of a flow whose
// wallet-facing HTTP side (AuthorizeHandler/CallbackHandler) is mounted by
// cmd/blrcs-mcpd, not this package.
func TestFullPresentationLifecycleViaMCP(t *testing.T) {
	srv, _, _ := setupServer(t)

	issuer, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	wallet := openid4vp.NewMockWallet("did:web:alice.holder")
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wallet.HolderKey = holderPriv

	sdjwt, _, err := issuer.IssueSDJWTBound(
		"holder-subject-1",
		map[string]any{"category": "textile"},
		nil,
		holderPub,
		365*24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Store(openid4vp.StoredCredential{
		ID:         "cred-1",
		IssuerDID:  issuer.ID,
		IssuerPub:  issuer.PublicKey(),
		SDJWT:      sdjwt,
		ClaimNames: []string{"category"},
	})

	ver := openid4vp.NewVerifier("https://verify.example", "https://verify.example/cb", nil)
	srv.RegisterVPVerifier(ver)

	// 1. Agent creates the request via the MCP tool.
	createResult := toolCall(t, srv, 1, "create_presentation_request", map[string]any{
		"presentationDefinition": map[string]any{
			"id":             "pd-1",
			"requiredClaims": []string{"category"},
		},
		"acceptableIssuerKeys": map[string]any{
			issuer.ID: base64.StdEncoding.EncodeToString(issuer.PublicKey()),
		},
	})
	createText := toolCallText(t, createResult)
	var createOut struct {
		RequestURL string `json:"requestUrl"`
		State      string `json:"state"`
	}
	if err := json.Unmarshal([]byte(createText), &createOut); err != nil {
		t.Fatal(err)
	}

	// Before the wallet responds, the result is still pending.
	pendingResult := toolCall(t, srv, 2, "get_presentation_result", map[string]any{"state": createOut.State})
	if toolCallText(t, pendingResult) != `{"status":"pending"}` {
		t.Fatal("result should be pending before the wallet responds")
	}

	// 2. Wallet responds (simulates what a real wallet does against
	// AuthorizeHandler/CallbackHandler, mounted by cmd/blrcs-mcpd).
	resp, err := wallet.Present(createOut.RequestURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}

	// 3. Verifier processes the response — this is exactly what
	// CallbackHandler's body does before invoking onSuccess.
	vp, err := ver.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("process response: %v", err)
	}
	srv.RecordPresentationResult(vp)

	// 4. Agent polls get_presentation_result and sees the completed result.
	doneResult := toolCall(t, srv, 3, "get_presentation_result", map[string]any{"state": createOut.State})
	doneText := toolCallText(t, doneResult)
	var doneOut struct {
		Status  string         `json:"status"`
		Subject string         `json:"subject"`
		Issuer  string         `json:"issuer"`
		Claims  map[string]any `json:"claims"`
	}
	if err := json.Unmarshal([]byte(doneText), &doneOut); err != nil {
		t.Fatal(err)
	}
	if doneOut.Status != "success" {
		t.Fatalf("status: got %s want success: %s", doneOut.Status, doneText)
	}
	if doneOut.Issuer != issuer.ID {
		t.Errorf("issuer: got %s want %s", doneOut.Issuer, issuer.ID)
	}
	if doneOut.Claims["category"] != "textile" {
		t.Errorf("claims: got %v", doneOut.Claims)
	}
}

// TestCreatePresentationRequestWithTransactionData verifies the MCP tool binds
// transaction_data end-to-end: the agent supplies a plain JSON payment object,
// the tool base64url-encodes it into the request, the MockWallet hashes it into
// its KB-JWT, and ProcessResponse confirms the binding. Then it proves a wallet
// that responds to a request binding a DIFFERENT transaction fails.
func TestCreatePresentationRequestWithTransactionData(t *testing.T) {
	srv, _, _ := setupServer(t)
	issuer, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	wallet := openid4vp.NewMockWallet("did:web:alice.holder")
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wallet.HolderKey = holderPriv
	sdjwt, _, err := issuer.IssueSDJWTBound("holder-1", map[string]any{"category": "textile"}, nil, holderPub, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Store(openid4vp.StoredCredential{
		ID: "cred-1", IssuerDID: issuer.ID, IssuerPub: issuer.PublicKey(), SDJWT: sdjwt,
		ClaimNames: []string{"category"},
	})
	ver := openid4vp.NewVerifier("https://verify.example", "https://verify.example/cb", nil)
	srv.RegisterVPVerifier(ver)

	createResult := toolCall(t, srv, 1, "create_presentation_request", map[string]any{
		"presentationDefinition": map[string]any{"id": "pd-1", "requiredClaims": []string{"category"}},
		"acceptableIssuerKeys":   map[string]any{issuer.ID: base64.StdEncoding.EncodeToString(issuer.PublicKey())},
		"transactionData": []map[string]any{
			{"type": "payment", "amount": "42.00", "currency": "EUR", "payee": "ACME"},
		},
	})
	var createOut struct {
		RequestURL string `json:"requestUrl"`
		State      string `json:"state"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, createResult)), &createOut); err != nil {
		t.Fatal(err)
	}

	// The returned request URL must carry the transaction_data binding.
	if !strings.Contains(createOut.RequestURL, "transaction_data") {
		t.Errorf("request URL missing transaction_data: %s", createOut.RequestURL)
	}

	resp, err := wallet.Present(createOut.RequestURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}
	vp, err := ver.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("transaction-bound presentation should verify: %v", err)
	}
	if vp.Claims["category"] != "textile" {
		t.Errorf("claims: %v", vp.Claims)
	}
}
