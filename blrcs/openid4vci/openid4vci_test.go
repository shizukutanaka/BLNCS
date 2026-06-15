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

// TestExchangeCodeTxCodeRequired covers the tx_code (PIN) binding: an offer created
// with a transaction code cannot be redeemed without the exact code, defeating
// interception of the pre-authorized code alone.
func TestExchangeCodeTxCodeRequired(t *testing.T) {
	iss, _ := setupIssuer(t)
	const pin = "secret-pin-9173"
	_, code, err := iss.CreateOfferWithTxCode(
		"eu-battery-passport-v1", "bat-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		map[string]any{"batteryCategory": "ev"},
		pin, &TxCodeSpec{InputMode: "text", Length: len(pin)},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Plain ExchangeCode (no PIN) must fail when a tx_code is required.
	if _, err := iss.ExchangeCode(code); err != ErrBadTxCode {
		t.Fatalf("no PIN: want ErrBadTxCode, got %v", err)
	}
	// Wrong PIN must fail.
	if _, err := iss.ExchangeCodeWithTxCode(code, "wrong"); err != ErrBadTxCode {
		t.Fatalf("wrong PIN: want ErrBadTxCode, got %v", err)
	}
	// Failed attempts must NOT consume the code — the correct PIN still works.
	tr, err := iss.ExchangeCodeWithTxCode(code, pin)
	if err != nil {
		t.Fatalf("correct PIN should succeed: %v", err)
	}
	if tr.AccessToken == "" {
		t.Error("access token empty after correct PIN")
	}
	// And now the code is consumed.
	if _, err := iss.ExchangeCodeWithTxCode(code, pin); err != ErrBadPreAuthCode {
		t.Fatalf("redeemed code reuse: want ErrBadPreAuthCode, got %v", err)
	}
}

// TestCreateOfferAdvertisesTxCode confirms the offer advertises the tx_code
// requirement (metadata only) and never leaks the PIN value.
func TestCreateOfferAdvertisesTxCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	const pin = "distinctive-pin-55501"
	offerURL, _, err := iss.CreateOfferWithTxCode(
		"eu-battery-passport-v1", "bat-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		nil, pin, &TxCodeSpec{InputMode: "text", Length: len(pin), Description: "PIN from email"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(offerURL, "tx_code") {
		t.Errorf("offer should advertise tx_code requirement: %s", offerURL)
	}
	if !strings.Contains(offerURL, "input_mode") {
		t.Errorf("offer should advertise tx_code metadata: %s", offerURL)
	}
	if strings.Contains(offerURL, pin) {
		t.Errorf("offer MUST NOT contain the PIN value: %s", offerURL)
	}
}

// TestExchangeCodeNoTxCodeBackcompat confirms the plain flow is unchanged: an offer
// with no tx_code redeems via ExchangeCode, and an extraneous tx_code is ignored.
func TestExchangeCodeNoTxCodeBackcompat(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, err := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Extraneous tx_code on a no-tx offer is ignored (lenient, per spec).
	if _, err := iss.ExchangeCodeWithTxCode(code, "irrelevant"); err != nil {
		t.Fatalf("no-tx offer with extraneous PIN should still redeem: %v", err)
	}
}

// TestExchangeCodeTxCodeBruteForceLimit confirms the pre-authorized code is burned
// after too many wrong tx_code attempts, preventing PIN brute-force.
func TestExchangeCodeTxCodeBruteForceLimit(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.MaxTxCodeAttempts = 3
	const pin = "1234"
	_, code, err := iss.CreateOfferWithTxCode(
		"eu-battery-passport-v1", "bat-001",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		nil, pin, &TxCodeSpec{InputMode: "numeric", Length: 4},
	)
	if err != nil {
		t.Fatal(err)
	}
	// First (limit-1) wrong attempts return ErrBadTxCode and keep the code alive.
	for i := 0; i < 2; i++ {
		if _, err := iss.ExchangeCodeWithTxCode(code, "0000"); err != ErrBadTxCode {
			t.Fatalf("attempt %d: want ErrBadTxCode, got %v", i, err)
		}
	}
	// The attempt that reaches the limit still reports ErrBadTxCode but burns the code.
	if _, err := iss.ExchangeCodeWithTxCode(code, "0000"); err != ErrBadTxCode {
		t.Fatalf("limit attempt: want ErrBadTxCode, got %v", err)
	}
	// Even the CORRECT PIN now fails because the code was invalidated.
	if _, err := iss.ExchangeCodeWithTxCode(code, pin); err != ErrBadPreAuthCode {
		t.Fatalf("after limit, correct PIN: want ErrBadPreAuthCode, got %v", err)
	}
}

// TestTxCodeLockoutAuditHook pins the forensic-observability fix (Axis 12): the
// brute-force lockout fires OnTxCodeLockout exactly once, with the offer's
// subject/configID and never the secret code or PIN.
func TestTxCodeLockoutAuditHook(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.MaxTxCodeAttempts = 2
	var fires int
	var gotSubject, gotConfig string
	iss.OnTxCodeLockout = func(subject, configID string) {
		fires++
		gotSubject, gotConfig = subject, configID
	}
	const pin = "4242"
	_, code, err := iss.CreateOfferWithTxCode(
		"eu-battery-passport-v1", "bat-777",
		map[string]any{"carbonKgCO2ePerKWh": 48.5, "recycledCoPct": 16.0},
		nil, pin, &TxCodeSpec{InputMode: "numeric", Length: 4},
	)
	if err != nil {
		t.Fatal(err)
	}
	// First wrong attempt: under the limit, no lockout.
	if _, err := iss.ExchangeCodeWithTxCode(code, "0000"); err != ErrBadTxCode {
		t.Fatalf("attempt 1: want ErrBadTxCode, got %v", err)
	}
	if fires != 0 {
		t.Fatalf("hook must not fire before the limit, fired %d", fires)
	}
	// Second wrong attempt reaches the limit → burn → hook fires once.
	if _, err := iss.ExchangeCodeWithTxCode(code, "0000"); err != ErrBadTxCode {
		t.Fatalf("attempt 2: want ErrBadTxCode, got %v", err)
	}
	if fires != 1 {
		t.Fatalf("hook should fire exactly once on lockout, fired %d", fires)
	}
	if gotSubject != "bat-777" {
		t.Errorf("hook subject: want bat-777, got %q", gotSubject)
	}
	if gotConfig != "eu-battery-passport-v1" {
		t.Errorf("hook configID: want eu-battery-passport-v1, got %q", gotConfig)
	}
	// A no-tx_code offer must never trigger the hook.
	_, code2, _ := iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil)
	if _, err := iss.ExchangeCode(code2); err != nil {
		t.Fatal(err)
	}
	if fires != 1 {
		t.Errorf("no-tx_code flow must not fire the lockout hook, total fires %d", fires)
	}
}

// TestIssueCredentialBoundAndRevocable confirms an offer with a status reference and
// proof-of-possession yields a credential that is both holder-bound (cnf) AND
// revocable (status_list) — so VCI-issued credentials can be revoked.
func TestIssueCredentialBoundAndRevocable(t *testing.T) {
	iss, signer := setupIssuer(t)
	iss.RequireProof = true
	status := &compliance.StatusRef{URI: "https://status.example/list", Index: 9}
	_, code, err := iss.CreateOfferWithOptions(
		"eu-battery-passport-v1", "bat-rev",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
		OfferOptions{Status: status},
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, tr.CNonce, iss.URL)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": proofJWT})
	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != nil {
		t.Fatal(err)
	}
	// Holder-bound: plain verify must require a KB-JWT.
	if _, verr := compliance.VerifySDJWT(cr.Credential, signer.PublicKey()); verr != compliance.ErrKeyBindingMissing {
		t.Fatalf("want ErrKeyBindingMissing, got %v", verr)
	}
	// Present and verify: result must carry the status reference.
	pres, err := compliance.PresentWithKeyBinding(cr.Credential, []string{"carbonKgCO2ePerKWh"}, holderPriv, "n", "a", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := compliance.VerifySDJWTWithBinding(pres, signer.PublicKey(), compliance.VerifyOptions{
		ExpectedNonce: "n", ExpectedAudience: "a", RequireKeyBinding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !vc.KeyBound {
		t.Error("credential should be holder-bound")
	}
	if vc.Status == nil || vc.Status.Index != 9 || vc.Status.URI != status.URI {
		t.Fatalf("status reference not embedded: %+v", vc.Status)
	}
}

// TestIssueCredentialBearerRevocable covers the no-proof status path: a bearer
// credential can still carry a revocation reference.
func TestIssueCredentialBearerRevocable(t *testing.T) {
	iss, signer := setupIssuer(t)
	status := &compliance.StatusRef{URI: "https://status.example/list", Index: 3}
	_, code, err := iss.CreateOfferWithOptions(
		"eu-battery-passport-v1", "bat-bearer-rev",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
		OfferOptions{Status: status},
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := iss.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := compliance.VerifySDJWT(cr.Credential, signer.PublicKey())
	if err != nil {
		t.Fatalf("bearer credential should verify: %v", err)
	}
	if vc.Status == nil || vc.Status.Index != 3 {
		t.Fatalf("status reference not embedded on bearer credential: %+v", vc.Status)
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

// TestCNonceExpiresInMatchesTokenTTL pins that c_nonce_expires_in ≤ ExpiresIn
// (Axis 6: temporal integrity).
//
// A wallet that caches a c_nonce for up to c_nonce_expires_in seconds must be
// able to use it before the access token expires. Advertising a c_nonce window
// longer than the token lifetime creates a false expectation: the wallet would
// present a proof JWT referencing a c_nonce whose paired token is already gone.
func TestCNonceExpiresInMatchesTokenTTL(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, err := iss.CreateOffer(
		"eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if tr.CNonceExpiresIn > tr.ExpiresIn {
		t.Errorf("c_nonce_expires_in (%d) > access_token expires_in (%d): "+
			"wallet would receive a stale-nonce error before it can present the proof",
			tr.CNonceExpiresIn, tr.ExpiresIn)
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

// TestCreateOfferGCEvictsAbandonedOffer pins the resource-exhaustion fix: an
// offer created but never redeemed must not linger past its TTL. The time-gated
// sweep on CreateOffer evicts it (Axis 10: unbounded growth).
func TestCreateOfferGCEvictsAbandonedOffer(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.preAuthTTL = time.Millisecond

	_, code1, err := iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	iss.mu.Lock()
	_, present := iss.preAuths[code1]
	iss.mu.Unlock()
	if !present {
		t.Fatal("offer should be stored after CreateOffer")
	}

	// Let it expire and force the GC gate open (it was just set by CreateOffer).
	time.Sleep(5 * time.Millisecond)
	iss.mu.Lock()
	iss.lastGC = time.Now().Add(-time.Hour)
	iss.mu.Unlock()

	// A new offer triggers the gated sweep.
	if _, _, err = iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 2.0, "recycledCoPct": 6.0}, nil); err != nil {
		t.Fatal(err)
	}

	iss.mu.Lock()
	_, stillThere := iss.preAuths[code1]
	n := len(iss.preAuths)
	iss.mu.Unlock()
	if stillThere {
		t.Error("expired abandoned offer should have been evicted by GC")
	}
	if n != 1 {
		t.Errorf("preAuths should hold only the new offer, got %d entries", n)
	}
}

// TestCreateOfferGCEvictsAbandonedToken: a token created by an exchange but never
// used to issue a credential is also swept once expired.
func TestCreateOfferGCEvictsAbandonedToken(t *testing.T) {
	iss, _ := setupIssuer(t)
	iss.tokenTTL = time.Millisecond

	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	iss.mu.Lock()
	_, present := iss.tokens[tr.AccessToken]
	iss.mu.Unlock()
	if !present {
		t.Fatal("token should be stored after exchange")
	}

	time.Sleep(5 * time.Millisecond)
	iss.mu.Lock()
	iss.lastGC = time.Now().Add(-time.Hour)
	iss.mu.Unlock()

	if _, _, err = iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 2.0, "recycledCoPct": 6.0}, nil); err != nil {
		t.Fatal(err)
	}

	iss.mu.Lock()
	_, stillThere := iss.tokens[tr.AccessToken]
	iss.mu.Unlock()
	if stillThere {
		t.Error("expired abandoned access token should have been evicted by GC")
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

// TestIssueCredentialWithProofBindsHolderKey is the regression test for the
// proof-of-possession binding gap: a credential issued against a valid proof MUST
// be holder-bound (carry a cnf), otherwise it is a bearer credential that the
// secure-by-default OpenID4VP verifier (RequireKeyBinding=true) rejects, defeating
// the whole point of the proof step.
func TestIssueCredentialWithProofBindsHolderKey(t *testing.T) {
	iss, signer := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-bound",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, tr.CNonce, iss.URL)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": proofJWT})

	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{Proof: proofJSON})
	if err != nil {
		t.Fatalf("valid proof should succeed: %v", err)
	}

	// The credential must carry a cnf: plain (bearer) verification must now fail
	// with ErrKeyBindingMissing because a KB-JWT is required.
	if _, verr := compliance.VerifySDJWT(cr.Credential, signer.PublicKey()); verr != compliance.ErrKeyBindingMissing {
		t.Fatalf("proof-bound credential should require KB-JWT, got %v", verr)
	}

	// And it must be presentable through the secure holder-binding path using the
	// exact key the wallet proved possession of.
	nonce, aud := "vp-nonce-123", "https://verify.example"
	pres, err := compliance.PresentWithKeyBinding(cr.Credential, []string{"carbonKgCO2ePerKWh"}, holderPriv, nonce, aud, time.Time{})
	if err != nil {
		t.Fatalf("PresentWithKeyBinding: %v", err)
	}
	vc, err := compliance.VerifySDJWTWithBinding(pres, signer.PublicKey(), compliance.VerifyOptions{
		ExpectedNonce: nonce, ExpectedAudience: aud, RequireKeyBinding: true,
	})
	if err != nil {
		t.Fatalf("bound presentation should verify: %v", err)
	}
	if !vc.KeyBound {
		t.Error("verified presentation should be KeyBound")
	}
	if !bytesEqualKeys(vc.HolderKey, holderPub) {
		t.Error("credential bound to the wrong holder key")
	}
}

// TestIssueCredentialNoProofStaysBearer confirms the no-proof path is unchanged:
// when proof is not required and not supplied, a plain bearer SD-JWT is issued
// (verifiable without a KB-JWT) — backward compatibility.
func TestIssueCredentialNoProofStaysBearer(t *testing.T) {
	iss, signer := setupIssuer(t)
	_, code, _ := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-bearer",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := iss.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatalf("no-proof issuance: %v", err)
	}
	// Bearer credential: plain verification succeeds (no cnf, no KB-JWT required).
	if _, verr := compliance.VerifySDJWT(cr.Credential, signer.PublicKey()); verr != nil {
		t.Fatalf("bearer credential should verify without KB-JWT, got %v", verr)
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

// ============================================================================
// ExchangeCode — defensive guard: entry still in preAuths but accessToken set
// ============================================================================

func TestExchangeCodeAlreadyHasToken(t *testing.T) {
	iss, _ := setupIssuer(t)
	// Manually insert a pre-auth entry with accessToken already set.
	// This guard is defensive; the normal code path deletes the entry on exchange.
	iss.mu.Lock()
	iss.preAuths["phantom-code"] = &preAuthEntry{
		code:        "phantom-code",
		configID:    "eu-battery-passport-v1",
		expiresAt:   time.Now().Add(5 * time.Minute),
		accessToken: "already-set",
	}
	iss.mu.Unlock()
	_, err := iss.ExchangeCode("phantom-code")
	if err != ErrBadPreAuthCode {
		t.Fatalf("entry with accessToken set: want ErrBadPreAuthCode, got %v", err)
	}
}

// ============================================================================
// handleToken — ExchangeCode failure (invalid pre-authorized_code over HTTP)
// ============================================================================

func TestHandleTokenInvalidCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/token", map[string][]string{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {"this-code-was-never-issued"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid code: want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// handleCredential — body exceeds MaxBytesReader limit (1 MiB)
// ============================================================================

func TestHandleCredentialBodyTooLarge(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer("eu-battery-passport-v1", "big-body",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 10.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 50.0})
	tr, _ := iss.ExchangeCode(code)

	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	// Body is just over 1 MiB — triggers http.MaxBytesReader error.
	bigBody := strings.Repeat("A", (1<<20)+1)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/credential", strings.NewReader(bigBody))
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("oversized body: want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// IssueCredentialWithProof — ErrUnknownConfig when config deleted after code issued
// ============================================================================

func TestIssueCredentialUnknownConfig(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil)
	tr, _ := iss.ExchangeCode(code)

	// Delete the config that this token refers to.
	iss.mu.Lock()
	delete(iss.configs, "eu-battery-passport-v1")
	iss.mu.Unlock()

	_, err := iss.IssueCredential(tr.AccessToken)
	if err != ErrUnknownConfig {
		t.Fatalf("want ErrUnknownConfig, got %v", err)
	}
}

// ============================================================================
// FetchJWKSCtx — no Ed25519 key present in the JWKS response
// ============================================================================

func TestFetchJWKSCtxNoEd25519Key(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "crv": "", "x": ""},
			},
		})
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchJWKSCtx(context.Background())
	if err == nil {
		t.Fatal("JWKS with no Ed25519 key should error")
	}
}

// ============================================================================
// Coverage uplift: IssueSDJWT failure (reserved claim), handleCredential error
// path, WalletClient bad URL (NewRequestWithContext failures).
// ============================================================================

// TestIssueCredentialReservedClearClaim covers openid4vci.go:307-311: IssueSDJWT
// returns an error when a clear claim uses a reserved JWT claim name ("iss").
// The pre-auth code is un-consumed so a retry is possible.
func TestIssueCredentialReservedClearClaim(t *testing.T) {
	iss, _ := setupIssuer(t)
	// Register a config with no DisclosableClaims requirement so the offer
	// creation passes, but with a clear claim that collides with "iss".
	iss.RegisterConfiguration(CredentialConfiguration{
		ID:             "bad-clear-v1",
		CredentialType: "BadClear",
		Format:         "vc+sd-jwt",
		ValidForDays:   1,
	})
	_, code, err := iss.CreateOffer("bad-clear-v1", "s",
		nil,
		map[string]any{"iss": "injected"}, // "iss" is reserved → IssueSDJWT fails
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := iss.ExchangeCode(code)
	_, err = iss.IssueCredential(tr.AccessToken)
	if err == nil {
		t.Error("IssueSDJWT with reserved clear claim should fail")
	}
}

// TestHandleCredentialBadProof covers openid4vci.go:525-527: handleCredential
// calls IssueCredentialWithProof which returns ErrInvalidProof for a malformed
// proof JWT, exercising the error branch in the HTTP handler.
func TestHandleCredentialBadProof(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer("eu-battery-passport-v1", "s",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 5.0}, nil)
	tr, _ := iss.ExchangeCode(code)

	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"format": "vc+sd-jwt",
		"proof":  map[string]any{"proof_type": "jwt", "jwt": "invalid.proof.jwt"},
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/credential", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad proof JWT: want 400, got %d", resp.StatusCode)
	}
}

// TestFetchCredentialTokenOKCredentialFail covers openid4vci.go:634-635:
// c.HTTP.Do fails for the credential endpoint after the token endpoint
// succeeded — simulated by closing the connection on the credential request.
func TestFetchCredentialTokenOKCredentialFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "test-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		default:
			// Hijack and close the connection to force an HTTP client error.
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", 500)
				return
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer ts.Close()
	client := NewWalletClient(ts.URL)
	_, err := client.FetchCredentialCtx(context.Background(), "pre-auth-code")
	if err == nil {
		t.Error("credential endpoint connection reset should return error")
	}
}

// TestWalletClientBadURLToken covers openid4vci.go:608-609:
// http.NewRequestWithContext fails for the token endpoint when the base URL
// contains a null byte.
func TestWalletClientBadURLToken(t *testing.T) {
	client := &WalletClient{
		BaseURL: "http://host\x00bad",
		HTTP:    &http.Client{},
	}
	_, err := client.FetchCredentialCtx(context.Background(), "code")
	if err == nil {
		t.Error("null byte in base URL should fail NewRequestWithContext for token")
	}
}

// TestWalletClientBadURLMetadata covers openid4vci.go:657-658:
// http.NewRequestWithContext fails for the metadata endpoint.
func TestWalletClientBadURLMetadata(t *testing.T) {
	client := &WalletClient{
		BaseURL: "http://host\x00bad",
		HTTP:    &http.Client{},
	}
	_, err := client.FetchMetadataCtx(context.Background())
	if err == nil {
		t.Error("null byte in base URL should fail NewRequestWithContext for metadata")
	}
}

// TestWalletClientBadURLJWKS covers openid4vci.go:680-681:
// http.NewRequestWithContext fails for the JWKS endpoint.
func TestWalletClientBadURLJWKS(t *testing.T) {
	client := &WalletClient{
		BaseURL: "http://host\x00bad",
		HTTP:    &http.Client{},
	}
	_, err := client.FetchJWKSCtx(context.Background())
	if err == nil {
		t.Error("null byte in base URL should fail NewRequestWithContext for JWKS")
	}
}

// TestVerifyProofJWTBadXCoord covers openid4vci.go:353-354: the JWK X field
// decodes to fewer than 32 bytes (wrong length for Ed25519).
func TestVerifyProofJWTBadXCoord(t *testing.T) {
	// Build a proof JWT header with an OKP JWK whose X is only 16 bytes.
	shortX := base64.RawURLEncoding.EncodeToString(make([]byte, 16)) // too short
	hdr := map[string]any{
		"alg": "EdDSA",
		"typ": "openid4vci-proof+jwt",
		"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": shortX},
	}
	hdrBytes, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrBytes)
	// Use a real Ed25519 key to sign so the split-by-dots works.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	sigInput := hdrB64 + "." + payload
	sig := ed25519.Sign(priv, []byte(sigInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	proofJWT := sigInput + "." + sigB64

	_, err := verifyProofJWT(proofJWT, "nonce", "https://issuer.example")
	if err != ErrInvalidProof {
		t.Errorf("short X coordinate: want ErrInvalidProof, got %v", err)
	}
}
