package openid4vci

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// ============================================================================
// Proof-of-Possession (OpenID4VCI Draft 15 §5.1.2)
// ============================================================================

// buildProofJWT は Ed25519 holderKey で署名した openid4vci-proof+jwt を返す。
func buildProofJWT(t *testing.T, holderPriv ed25519.PrivateKey, nonce, aud string) string {
	t.Helper()
	pub := holderPriv.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := `{"alg":"EdDSA","typ":"openid4vci-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`
	pl := `{"nonce":"` + nonce + `","aud":"` + aud + `","iat":` + strconv.FormatInt(time.Now().Unix(), 10) + `}`
	h := base64.RawURLEncoding.EncodeToString([]byte(hdr))
	p := base64.RawURLEncoding.EncodeToString([]byte(pl))
	sig := ed25519.Sign(holderPriv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestIssueCredentialWithProofHappy(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-proof",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid proof JWT using a fresh holder key.
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, tr.CNonce, iss.URL)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": proofJWT})

	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != nil {
		t.Fatalf("valid proof should succeed: %v", err)
	}
	if cr.Credential == "" {
		t.Error("credential must not be empty")
	}
}

func TestIssueCredentialWithProofWrongNonce(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-proof2",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	tr, _ := iss.ExchangeCode(code)

	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, "wrong-nonce", iss.URL)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": proofJWT})

	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrProofNonceMismatch {
		t.Fatalf("want ErrProofNonceMismatch, got %v", err)
	}
}

func TestIssueCredentialRequireProof(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.RequireProof = true
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-proof3",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	tr, _ := iss.ExchangeCode(code)

	// No proof provided → must fail
	_, err := iss.IssueCredential(tr.AccessToken)
	if err != ErrInvalidProof {
		t.Fatalf("RequireProof=true with no proof: want ErrInvalidProof, got %v", err)
	}
}

func TestHTTPMethodNotAllowed(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	// GET on credential endpoint (requires POST)
	resp, err := ts.Client().Get(ts.URL + "/credential")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("credential GET: want 405, got %d", resp.StatusCode)
	}

	// POST on metadata endpoint (requires GET)
	resp2, err := ts.Client().Post(ts.URL+"/.well-known/openid-credential-issuer", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 405 {
		t.Fatalf("metadata POST: want 405, got %d", resp2.StatusCode)
	}

	// POST on JWKS endpoint (requires GET)
	resp3, err := ts.Client().Post(ts.URL+"/.well-known/jwks.json", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 405 {
		t.Fatalf("jwks POST: want 405, got %d", resp3.StatusCode)
	}
}

func TestSigner(t *testing.T) {
	iss, _ := setupIssuer(t)
	if iss.Signer() == nil {
		t.Error("Signer() must not be nil")
	}
}

func TestIssueCredentialProofBadSignature(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-proof4",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	tr, _ := iss.ExchangeCode(code)

	// Build JWT, then corrupt the signature.
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, tr.CNonce, iss.URL)
	// Overwrite last byte of sig (base64 last segment)
	parts := strings.Split(proofJWT, ".")
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	badJWT := strings.Join(parts, ".")
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": badJWT})

	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("bad sig: want ErrInvalidProof, got %v", err)
	}
}

// ============================================================================
// Token endpoint edge cases (handleToken coverage)
// ============================================================================

func TestHTTPTokenUnsupportedGrantType(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	form := strings.NewReader("grant_type=authorization_code&code=xyz")
	resp, err := ts.Client().Post(ts.URL+"/token", "application/x-www-form-urlencoded", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestHTTPTokenMissingCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	form := strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code")
	resp, err := ts.Client().Post(ts.URL+"/token", "application/x-www-form-urlencoded", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestRegisterConfigurationDefaults(t *testing.T) {
	signer, _ := compliance.NewIssuer("did:web:config.test")
	iss := NewIssuer("https://config.test", signer)
	// Empty format and zero ValidForDays → should get defaults
	iss.RegisterConfiguration(CredentialConfiguration{
		ID:             "test-cred",
		CredentialType: "TestType",
	})
	iss.mu.Lock()
	cfg, ok := iss.configs["test-cred"]
	iss.mu.Unlock()
	if !ok {
		t.Fatal("config not registered")
	}
	if cfg.Format != "vc+sd-jwt" {
		t.Errorf("default format: %s", cfg.Format)
	}
	if cfg.ValidForDays != 365 {
		t.Errorf("default validForDays: %d", cfg.ValidForDays)
	}
}

func TestFetchCredentialCtxCancelledBeforeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := NewWalletClient(ts.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := client.FetchCredentialCtx(ctx, "some-code")
	if err == nil {
		t.Fatal("cancelled context should produce error")
	}
}

func TestFetchMetadataCtxCancelled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := NewWalletClient(ts.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.FetchMetadataCtx(ctx)
	if err == nil {
		t.Fatal("cancelled context should produce error")
	}
}

func TestFetchJWKSCtxCancelled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := NewWalletClient(ts.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.FetchJWKSCtx(ctx)
	if err == nil {
		t.Fatal("cancelled context should produce error")
	}
}

// ============================================================================
// Coverage uplift: verifyProofJWT error paths
// ============================================================================

// buildBadProofJWT creates a proof JWT with controllable field values for
// negative testing of verifyProofJWT.
func buildCustomProofJWT(t *testing.T, holderPriv ed25519.PrivateKey, alg, typ, nonce, aud string, iatOffset time.Duration) string {
	t.Helper()
	pub := holderPriv.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := `{"alg":"` + alg + `","typ":"` + typ + `","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`
	iat := time.Now().Add(iatOffset).Unix()
	pl := `{"nonce":"` + nonce + `","aud":"` + aud + `","iat":` + strconv.FormatInt(iat, 10) + `}`
	h := base64.RawURLEncoding.EncodeToString([]byte(hdr))
	p := base64.RawURLEncoding.EncodeToString([]byte(pl))
	sig := ed25519.Sign(holderPriv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mustGetToken(t *testing.T, iss *Issuer) *TokenResponse {
	t.Helper()
	_, code, err := iss.CreateOffer(
		"eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 2.0}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestVerifyProofJWTWrongAud(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	jwt := buildCustomProofJWT(t, holderPriv, "EdDSA", "openid4vci-proof+jwt", tr.CNonce, "https://wrong.aud", 0)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": jwt})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("wrong aud: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTStaleIat(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	// iat = 10 minutes ago — outside the ±5 min window
	jwt := buildCustomProofJWT(t, holderPriv, "EdDSA", "openid4vci-proof+jwt", tr.CNonce, iss.URL, -10*time.Minute)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": jwt})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("stale iat: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTFutureIat(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	// iat = 10 minutes in the future
	jwt := buildCustomProofJWT(t, holderPriv, "EdDSA", "openid4vci-proof+jwt", tr.CNonce, iss.URL, 10*time.Minute)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": jwt})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("future iat: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadAlg(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	jwt := buildCustomProofJWT(t, holderPriv, "RS256", "openid4vci-proof+jwt", tr.CNonce, iss.URL, 0)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": jwt})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("bad alg: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadTyp(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	jwt := buildCustomProofJWT(t, holderPriv, "EdDSA", "JWT", tr.CNonce, iss.URL, 0)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": jwt})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("bad typ: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadHeaderBase64(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	proofJSON, _ := json.Marshal(map[string]string{
		"proof_type": "jwt",
		"jwt":        "!!!.validpayload.validsig",
	})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("bad header base64: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadSigBase64(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	pub := (ed25519.PublicKey)(make([]byte, ed25519.PublicKeySize))
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"openid4vci-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"x","aud":"y","iat":1}`))
	proofJSON, _ := json.Marshal(map[string]string{
		"proof_type": "jwt",
		"jwt":        hdr + "." + pl + ".!!!invalid-sig-base64",
	})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("bad sig base64: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTTruncatedSig(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	pub := (ed25519.PublicKey)(make([]byte, ed25519.PublicKeySize))
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"openid4vci-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"x","aud":"y","iat":1}`))
	// Only 16 bytes of sig, not 64
	shortSig := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	proofJSON, _ := json.Marshal(map[string]string{
		"proof_type": "jwt",
		"jwt":        hdr + "." + pl + "." + shortSig,
	})
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != ErrInvalidProof {
		t.Fatalf("truncated sig: want ErrInvalidProof, got %v", err)
	}
}

func TestIssueCredentialWithProofBadProofJSON(t *testing.T) {
	iss, _ := setupIssuer(t)
	tr := mustGetToken(t, iss)
	// proof field is invalid JSON
	_, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{
		Proof: []byte(`{"proof_type": "not-jwt", "jwt": ""}`),
	})
	if err != ErrInvalidProof {
		t.Fatalf("bad proof_type: want ErrInvalidProof, got %v", err)
	}
}

// ============================================================================
// Coverage uplift: handleCredential bad JSON body
// ============================================================================

func TestHTTPCredentialBadJSONBody(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	// Get a valid token first
	tr := mustGetToken(t, iss)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/credential", strings.NewReader("{bad json}"))
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad JSON body: want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// Coverage uplift: FetchCredentialCtx / FetchMetadataCtx / FetchJWKSCtx
// non-200 and decode-error paths
// ============================================================================

func TestFetchCredentialCtxTokenNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchCredentialCtx(context.Background(), "code")
	if err == nil {
		t.Fatal("non-200 token response should error")
	}
}

func TestFetchCredentialCtxTokenBadJSON(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json")) // token endpoint returns garbage
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchCredentialCtx(context.Background(), "code")
	if err == nil {
		t.Fatal("bad token JSON should error")
	}
}

func TestFetchCredentialCtxCredentialNon200(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// Return valid token response
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "tok",
				TokenType:   "Bearer",
				ExpiresIn:   300,
			})
			return
		}
		// Credential endpoint returns 500
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchCredentialCtx(context.Background(), "code")
	if err == nil {
		t.Fatal("non-200 credential response should error")
	}
}

func TestFetchCredentialCtxCredentialBadJSON(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "tok",
				TokenType:   "Bearer",
				ExpiresIn:   300,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json credential"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchCredentialCtx(context.Background(), "code")
	if err == nil {
		t.Fatal("bad credential JSON should error")
	}
}

func TestFetchMetadataCtxNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchMetadataCtx(context.Background())
	if err == nil {
		t.Fatal("non-200 metadata response should error")
	}
}

func TestFetchMetadataCtxBadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchMetadataCtx(context.Background())
	if err == nil {
		t.Fatal("bad JSON metadata should error")
	}
}

func TestFetchJWKSCtxNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unavailable"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchJWKSCtx(context.Background())
	if err == nil {
		t.Fatal("non-200 JWKS response should error")
	}
}

func TestFetchJWKSCtxBadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchJWKSCtx(context.Background())
	if err == nil {
		t.Fatal("bad JWKS JSON should error")
	}
}

// ============================================================================
// Coverage uplift: verifyProofJWT — remaining error branches
// These call verifyProofJWT directly (same package).
// ============================================================================

func TestVerifyProofJWTNotThreeParts(t *testing.T) {
	_, err := verifyProofJWT("no-dots-in-jwt", "n", "a")
	if err != ErrInvalidProof {
		t.Fatalf("want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadJWKKty(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"openid4vci-proof+jwt","jwk":{"kty":"RSA","crv":"Ed25519","x":"` + x + `"}}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"n","aud":"a","iat":1}`))
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(hdr+"."+pl)))
	_, err := verifyProofJWT(hdr+"."+pl+"."+sig, "n", "a")
	if err != ErrInvalidProof {
		t.Fatalf("bad JWK kty: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadPayloadBase64(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"openid4vci-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`))
	pl := "!!!" // invalid base64 — verifyProofJWT signs over it literally
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(hdr+"."+pl)))
	_, err := verifyProofJWT(hdr+"."+pl+"."+sig, "n", "a")
	if err != ErrInvalidProof {
		t.Fatalf("bad payload base64: want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyProofJWTBadPayloadJSON(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"openid4vci-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte("not-json-payload"))
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(hdr+"."+pl)))
	_, err := verifyProofJWT(hdr+"."+pl+"."+sig, "n", "a")
	if err != ErrInvalidProof {
		t.Fatalf("bad payload JSON: want ErrInvalidProof, got %v", err)
	}
}

// ============================================================================
// handleToken — uncovered HTTP paths
// ============================================================================

func TestHandleTokenMethodNotAllowed(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /token: want 405, got %d", resp.StatusCode)
	}
}

func TestHandleTokenMissingPreAuthCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/token", map[string][]string{
		"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		// pre-authorized_code intentionally omitted
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing code: want 400, got %d", resp.StatusCode)
	}
}

func TestHandleTokenUnsupportedGrantType(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/token", map[string][]string{
		"grant_type": {"authorization_code"},
		"code":       {"abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong grant_type: want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// handleCredential — uncovered HTTP paths
// ============================================================================

func TestHandleCredentialMethodNotAllowed(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/credential")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /credential: want 405, got %d", resp.StatusCode)
	}
}

func TestHandleCredentialMissingBearer(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/credential", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing Bearer: want 401, got %d", resp.StatusCode)
	}
}

func TestHandleCredentialBadJSON(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "bat-bad-json",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 10.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 50.0})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/credential", strings.NewReader(`{bad json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad JSON body: want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// IssueCredentialWithProof — RequireProof without proof in request
// ============================================================================

func TestIssueCredentialWithProofRequireProofMissing(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.RequireProof = true

	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "bat-require-proof",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 10.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 50.0})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}

	_, err = iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{})
	if err != ErrInvalidProof {
		t.Errorf("RequireProof without proof: want ErrInvalidProof, got %v", err)
	}
}
