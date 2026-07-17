package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"blrcs/compliance"
	"blrcs/openid4vci"
)

// ============================================================================
// Axis 103: create_credential_offer (openid4vci.Issuer wiring)
// ============================================================================

// setupVCIServer builds a Server with a registered OpenID4VCI issuer, mirroring
// how cmd/blrcs-mcpd wires it: srv.RegisterVCIIssuer(vciIssuer).
func setupVCIServer(t *testing.T) (*Server, *openid4vci.Issuer) {
	t.Helper()
	srv, _, _ := setupServer(t)
	signer, err := compliance.NewIssuer("did:web:vci.factory.example")
	if err != nil {
		t.Fatal(err)
	}
	vci := openid4vci.NewIssuer("https://issue.blrcs.example", signer)
	vci.RegisterConfiguration(openid4vci.CredentialConfiguration{
		ID:                "eu-dpp-v1",
		CredentialType:    "DigitalProductPassport",
		Format:            "vc+sd-jwt",
		DisclosableClaims: []string{"carbonKgCO2e"},
		ClearClaims:       []string{"productId"},
		ValidForDays:      365,
	})
	srv.RegisterVCIIssuer(vci)
	return srv, vci
}

// TestCreateCredentialOfferWithoutRegisteredIssuerErrors verifies the tool
// fails clearly when no VCI issuer has been registered — the default state
// for NewServer/NewServerWithStorage, matching how create_credential_offer
// is documented as requiring an explicit RegisterVCIIssuer call.
func TestCreateCredentialOfferWithoutRegisteredIssuerErrors(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "create_credential_offer", map[string]any{
		"configId": "eu-dpp-v1", "subject": "did:example:holder",
	})
	if !result["isError"].(bool) {
		t.Fatal("create_credential_offer without a registered VCI issuer should error")
	}
}

// TestCreateCredentialOfferHappyPath verifies a full offer can be minted and
// is redeemable end-to-end against the underlying openid4vci.Issuer — the
// offer is not just a well-formed string, it actually works.
func TestCreateCredentialOfferHappyPath(t *testing.T) {
	srv, vci := setupVCIServer(t)
	result := toolCall(t, srv, 1, "create_credential_offer", map[string]any{
		"configId": "eu-dpp-v1", "subject": "did:example:holder",
		"sdClaims":    map[string]any{"carbonKgCO2e": 12.5},
		"clearClaims": map[string]any{"productId": "P-VCI-1"},
	})
	text := toolCallText(t, result)
	var out struct {
		OfferURL          string `json:"offerUrl"`
		PreAuthorizedCode string `json:"preAuthorizedCode"`
		StatusListIndex   int    `json:"statusListIndex"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.OfferURL, "openid-credential-offer://") {
		t.Errorf("offerUrl should be an openid-credential-offer:// URI, got %s", out.OfferURL)
	}
	if out.PreAuthorizedCode == "" {
		t.Error("preAuthorizedCode missing")
	}

	// Redeem the code against the real underlying issuer, proving the offer
	// this tool minted is not just well-formed but actually functional.
	tok, err := vci.ExchangeCode(out.PreAuthorizedCode)
	if err != nil {
		t.Fatalf("offer's pre-authorized code should be redeemable: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("token exchange should return an access token")
	}
}

// TestCreateCredentialOfferMissingSubject verifies input validation.
func TestCreateCredentialOfferMissingSubject(t *testing.T) {
	srv, _ := setupVCIServer(t)
	result := toolCall(t, srv, 1, "create_credential_offer", map[string]any{
		"configId": "eu-dpp-v1",
	})
	if !result["isError"].(bool) {
		t.Fatal("missing subject should error")
	}
}

// TestCreateCredentialOfferUnknownConfig verifies an unregistered configId
// is rejected rather than silently issuing under some default.
func TestCreateCredentialOfferUnknownConfig(t *testing.T) {
	srv, _ := setupVCIServer(t)
	result := toolCall(t, srv, 1, "create_credential_offer", map[string]any{
		"configId": "does-not-exist", "subject": "did:example:holder",
	})
	if !result["isError"].(bool) {
		t.Fatal("unknown configId should error")
	}
}

// TestCreateCredentialOfferIsAudited verifies the tool is recorded to the
// transparency log, like other mutating issuance tools.
func TestCreateCredentialOfferIsAudited(t *testing.T) {
	srv, _ := setupVCIServer(t)
	before := srv.Ledger().Size()
	result := toolCall(t, srv, 1, "create_credential_offer", map[string]any{
		"configId": "eu-dpp-v1", "subject": "did:example:holder",
		"sdClaims": map[string]any{"carbonKgCO2e": 12.5},
	})
	toolCallText(t, result)
	after := srv.Ledger().Size()
	if after <= before {
		t.Errorf("create_credential_offer should add a ledger entry: before=%d after=%d", before, after)
	}
}
