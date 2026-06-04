package openid4vci

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
)

func setupIssuer(t *testing.T) (*Issuer, *compliance.Issuer) {
	t.Helper()
	signer, err := compliance.NewIssuer("did:web:issuer.vci.example")
	if err != nil {
		t.Fatal(err)
	}
	iss := NewIssuer("https://issue.blrcs.example", signer)
	iss.RegisterConfiguration(CredentialConfiguration{
		ID:                "eu-battery-passport-v1",
		CredentialType:    "BatteryPassport",
		Format:            "vc+sd-jwt",
		DisclosableClaims: []string{"carbonKgCO2ePerKWh", "recycledCoPct"},
		ClearClaims:       []string{"batteryCategory", "capacityKWh"},
		ValidForDays:      3650,
	})
	return iss, signer
}

// ============================================================================
// Configuration & Offer
// ============================================================================

func TestCreateOfferBasic(t *testing.T) {
	iss, _ := setupIssuer(t)
	offerURL, code, err := iss.CreateOffer(
		"eu-battery-passport-v1",
		"bat-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 75.0},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(offerURL, "openid-credential-offer://?credential_offer=") {
		t.Errorf("bad URL: %s", offerURL)
	}
	if code == "" {
		t.Fatal("code empty")
	}
	if !strings.Contains(offerURL, "eu-battery-passport-v1") {
		t.Errorf("config missing from URL: %s", offerURL)
	}
}

func TestCreateOfferUnknownConfig(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, _, err := iss.CreateOffer("unknown-config", "s", nil, nil)
	if err != ErrUnknownConfig {
		t.Fatalf("want ErrUnknownConfig, got %v", err)
	}
}

func TestCreateOfferMissingRequiredSDClaim(t *testing.T) {
	iss, _ := setupIssuer(t)
	// DisclosableClaims requires carbonKgCO2ePerKWh and recycledCoPct, omit one
	_, _, err := iss.CreateOffer(
		"eu-battery-passport-v1",
		"bat-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5}, // recycledCoPct missing
		nil,
	)
	if err == nil {
		t.Fatal("should fail strict check")
	}
}

// ============================================================================
// Token exchange
// ============================================================================

func TestExchangeCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil,
	)
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken == "" || tr.TokenType != "Bearer" {
		t.Error("bad token response")
	}
	if tr.CNonce == "" {
		t.Error("c_nonce missing")
	}
}

func TestExchangeCodeSingleUse(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil,
	)
	_, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	// 2回目は拒否されるはず
	if _, err := iss.ExchangeCode(code); err != ErrBadPreAuthCode {
		t.Fatalf("want ErrBadPreAuthCode, got %v", err)
	}
}

func TestExchangeCodeUnknown(t *testing.T) {
	iss, _ := setupIssuer(t)
	if _, err := iss.ExchangeCode("never-issued"); err != ErrBadPreAuthCode {
		t.Fatalf("want ErrBadPreAuthCode, got %v", err)
	}
}

func TestExchangeCodeExpired(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.preAuthTTL = 10 * time.Millisecond
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil,
	)
	time.Sleep(30 * time.Millisecond)
	if _, err := iss.ExchangeCode(code); err != ErrBadPreAuthCode {
		t.Fatalf("want expiry, got %v", err)
	}
}

// ============================================================================
// Credential issuance
// ============================================================================

func TestIssueCredential(t *testing.T) {
	iss, signer := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-123",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 75.0},
	)
	tr, _ := iss.ExchangeCode(code)
	cr, err := iss.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cr.Credential, "~") {
		t.Error("SD-JWT must contain disclosure separator")
	}
	// Verify the SD-JWT
	verified, err := compliance.VerifySDJWT(cr.Credential, signer.PublicKey())
	if err != nil {
		t.Fatalf("SD-JWT verify: %v", err)
	}
	if verified.Subject != "bat-123" {
		t.Errorf("subject: %s", verified.Subject)
	}
	// All claims present (full disclosure by default)
	for _, k := range []string{"carbonKgCO2ePerKWh", "recycledCoPct", "batteryCategory", "capacityKWh"} {
		if _, ok := verified.Claims[k]; !ok {
			t.Errorf("claim missing: %s", k)
		}
	}
}

func TestIssueCredentialTokenSingleUse(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil,
	)
	tr, _ := iss.ExchangeCode(code)
	if _, err := iss.IssueCredential(tr.AccessToken); err != nil {
		t.Fatal(err)
	}
	// 2回目は拒否
	if _, err := iss.IssueCredential(tr.AccessToken); err != ErrBadAccessToken {
		t.Fatalf("want ErrBadAccessToken, got %v", err)
	}
}

func TestIssueCredentialBadToken(t *testing.T) {
	iss, _ := setupIssuer(t)
	if _, err := iss.IssueCredential("bogus"); err != ErrBadAccessToken {
		t.Fatalf("want ErrBadAccessToken, got %v", err)
	}
}

// ============================================================================
// Metadata + JWKS
// ============================================================================

func TestMetadata(t *testing.T) {
	iss, _ := setupIssuer(t)
	m := iss.Metadata()
	if m["credential_issuer"] != "https://issue.blrcs.example" {
		t.Errorf("issuer URL: %v", m["credential_issuer"])
	}
	if m["token_endpoint"] != "https://issue.blrcs.example/token" {
		t.Errorf("token endpoint: %v", m["token_endpoint"])
	}
	configs := m["credential_configurations_supported"].(map[string]any)
	if _, ok := configs["eu-battery-passport-v1"]; !ok {
		t.Error("config missing from metadata")
	}
}

func TestJWKS(t *testing.T) {
	iss, signer := setupIssuer(t)
	jwks := iss.JWKS()
	keys := jwks["keys"].([]map[string]any)
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	k := keys[0]
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
		t.Errorf("wrong key type: kty=%v crv=%v", k["kty"], k["crv"])
	}
	// Decode the key and compare
	xb, err := base64.RawURLEncoding.DecodeString(k["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqualKeys(xb, signer.PublicKey()) {
		t.Error("JWKS key mismatch")
	}
}

func bytesEqualKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ============================================================================
// HTTP handler — full-stack test
// ============================================================================

func TestFullHTTPFlow(t *testing.T) {
	iss, signer := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	// Rebind issuer URL to test server
	iss.URL = ts.URL

	// 1. Create offer out-of-band (e.g. issuer's backend)
	_, code, err := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-http-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 75.0},
	)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Wallet fetches credential via WalletClient
	client := NewWalletClient(ts.URL)
	sdjwt, err := client.FetchCredential(code)
	if err != nil {
		t.Fatalf("wallet fetch: %v", err)
	}

	// 3. Wallet fetches JWKS and verifies
	pub, err := client.FetchJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqualKeys(pub, signer.PublicKey()) {
		t.Error("fetched JWKS key mismatch")
	}

	verified, err := compliance.VerifySDJWT(sdjwt, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Subject != "bat-http-001" {
		t.Errorf("subject: %s", verified.Subject)
	}
}

func TestHTTPInvalidTokenRequest(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()
	// GET on token endpoint
	resp, err := ts.Client().Get(ts.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

func TestHTTPMissingBearer(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()
	resp, err := ts.Client().Post(ts.URL+"/credential", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestHTTPMetadataDiscovery(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()
	iss.URL = ts.URL

	client := NewWalletClient(ts.URL)
	meta, err := client.FetchMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if meta["credential_issuer"] != ts.URL {
		t.Errorf("discovery URL: %v", meta["credential_issuer"])
	}
}
