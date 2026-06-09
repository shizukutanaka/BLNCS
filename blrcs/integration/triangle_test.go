// Triangle test — OpenID4VCI issuer → MockWallet → OpenID4VP verifier
//
// これはBLRCSの「実運用で動く」ことの決定的証明:
// Apple Wallet 相当が受領→選択提示→BLRCS verifier が検証 の完全E2E
package integration

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"blrcs/compliance"
	"blrcs/openid4vci"
	"blrcs/openid4vp"
)

func TestTriangle_IssuerWalletVerifier(t *testing.T) {
	// --- 1. Issuer side (factory) ---
	signer, _ := compliance.NewIssuer("did:web:factory.tri.example")
	issuer := openid4vci.NewIssuer("https://tri.example", signer)
	issuer.RegisterConfiguration(openid4vci.CredentialConfiguration{
		ID:                "battery-v1",
		CredentialType:    "BatteryPassport",
		DisclosableClaims: []string{"carbonKgCO2e", "supplierName"},
		ClearClaims:       []string{"batteryCategory"},
		ValidForDays:      3650,
	})
	issuerHTTP := httptest.NewServer(issuer.Handler())
	defer issuerHTTP.Close()
	issuer.URL = issuerHTTP.URL

	// --- 2. Issuer creates an offer for a specific battery ---
	_, preAuthCode, err := issuer.CreateOffer(
		"battery-v1",
		"battery-triangle-001",
		map[string]any{
			"carbonKgCO2e": 42.0,
			"supplierName": "SECRET-Cobalt-Co", // private SD claim
		},
		map[string]any{
			"batteryCategory": "ev",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// --- 3. Wallet fetches credential ---
	wallet := openid4vci.NewWalletClient(issuerHTTP.URL)
	sdjwt, err := wallet.FetchCredential(preAuthCode)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, err := wallet.FetchJWKS()
	if err != nil {
		t.Fatal(err)
	}

	// --- 4. Wallet stores credential locally (Apple Wallet / Google Wallet equivalent) ---
	mockWallet := openid4vp.NewMockWallet("did:web:holder.tri")
	mockWallet.Store(openid4vp.StoredCredential{
		ID:        "battery-cred",
		IssuerDID: signer.ID,
		IssuerPub: issuerPub,
		SDJWT:     sdjwt,
	})

	// --- 5. Verifier (retailer / regulator) creates presentation request ---
	verifier := openid4vp.NewVerifier(
		"https://verify.tri.example",
		"https://verify.tri.example/cb",
		nil,
	)
	// This triangle exercises the OpenID4VCI issuance path, which issues bearer
	// (unbound) SD-JWTs, so opt out of the secure-by-default key-binding
	// requirement. Anti-replay here relies on one-time state consumption.
	verifier.RequireKeyBinding = false
	def := openid4vp.PresentationDefinition{
		ID:      "eu-compliance-check",
		Purpose: "EU Regulation 2023/1542 Art.77 verification",
		RequiredClaims: []string{
			"batteryCategory", // clear claim
			"carbonKgCO2e",    // explicitly disclosed
		},
		AcceptableIssuers: map[string][]byte{signer.ID: issuerPub},
	}
	reqURL, _, err := verifier.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}

	// --- 6. Wallet presents selectively ---
	resp, err := mockWallet.Present(reqURL)
	if err != nil {
		t.Fatal(err)
	}

	// --- 7. Verifier validates and extracts claims ---
	vp, err := verifier.ProcessResponse(resp)
	if err != nil {
		t.Fatal(err)
	}

	// --- 8. Assertions: full disclosure contract honored ---
	if vp.Issuer != signer.ID {
		t.Errorf("issuer mismatch: %s", vp.Issuer)
	}
	if vp.Subject != "battery-triangle-001" {
		t.Errorf("subject: %s", vp.Subject)
	}
	if vp.Claims["batteryCategory"] != "ev" {
		t.Errorf("category: %v", vp.Claims["batteryCategory"])
	}
	carbon, ok := vp.Claims["carbonKgCO2e"].(float64)
	if !ok || carbon != 42.0 {
		t.Errorf("carbon: %v", vp.Claims["carbonKgCO2e"])
	}
	// PRIVACY CONTRACT — supplier must NOT leak
	if _, leaked := vp.Claims["supplierName"]; leaked {
		t.Error("CRITICAL: supplierName leaked in presentation")
	}

	_ = base64.RawURLEncoding // keep import for future key encoding tests
}
