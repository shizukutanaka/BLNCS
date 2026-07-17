package openid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
)

func TestBuildCredentialOfferURL(t *testing.T) {
	offer := CredentialOffer{
		CredentialIssuer:    "https://issue.blrcs.example",
		CredentialConfigIDs: []string{"eu-battery-passport-v1"},
		Grants: map[string]OfferGrant{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				PreAuthorizedCode: "abc123",
			},
		},
	}
	urlStr, err := BuildCredentialOfferURL(offer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(urlStr, "openid-credential-offer://?credential_offer=") {
		t.Errorf("bad URL: %s", urlStr)
	}
	if !strings.Contains(urlStr, "eu-battery-passport-v1") {
		t.Errorf("config missing: %s", urlStr)
	}
}

func TestBuildCredentialOfferValidation(t *testing.T) {
	cases := []CredentialOffer{
		{},
		{CredentialIssuer: "x"},
	}
	for i, c := range cases {
		if _, err := BuildCredentialOfferURL(c); err == nil {
			t.Errorf("case %d: should fail", i)
		}
	}
}

// ============================================================================
// Full E2E: Verifier ↔ MockWallet round-trip
// ============================================================================

func TestFullE2E_VerifierWalletRoundTrip(t *testing.T) {
	// --- Setup: issuer, wallet, verifier ---
	issuer, _ := compliance.NewIssuer("did:web:factory.example")
	wallet := NewMockWallet("did:web:alice.holder")
	// Holder key binds presentations to the request nonce/client_id (anti-replay).
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wallet.HolderKey = holderPriv
	verifier := NewVerifier(
		"https://verify.blrcs.example",
		"https://verify.blrcs.example/cb",
		nil,
	)

	// --- Step 1: Issuer creates a holder-bound SD-JWT for battery, wallet stores it ---
	sdjwt, _, err := issuer.IssueSDJWTBound(
		"battery-EV-001",
		map[string]any{
			"batteryCategory":       "ev",
			"chemistry":             "nmc",
			"capacityKWh":           75.0,
			"carbonKgCO2ePerKWh":    48.5,
			"supplierName":          "SECRET-Cobalt-Co", // wallet UIでは選択開示の選択肢
			"recycledContentCobalt": 16.0,
		},
		map[string]any{"productId": "BAT-2026-001"},
		holderPub,
		365*24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Store(StoredCredential{
		ID:         "battery-cred-1",
		IssuerDID:  issuer.ID,
		IssuerPub:  issuer.PublicKey(),
		SDJWT:      sdjwt,
		ClaimNames: []string{"batteryCategory", "chemistry", "capacityKWh", "carbonKgCO2ePerKWh", "supplierName", "recycledContentCobalt"},
	})

	// --- Step 2: Verifier creates Authorization Request ---
	def := PresentationDefinition{
		ID:      "eu-battery-compliance",
		Purpose: "EU Regulation 2023/1542 Article 77 verification",
		RequiredClaims: []string{
			"batteryCategory",
			"chemistry",
			"capacityKWh",
			"carbonKgCO2ePerKWh",
		},
		AcceptableIssuers: map[string][]byte{
			issuer.ID: issuer.PublicKey(),
		},
	}
	reqURL, state, err := verifier.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	_ = state // state は verifier 内部に保持、wallet には url 経由で伝わる

	// --- Step 3: Wallet responds ---
	resp, err := wallet.Present(reqURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}
	if resp.State == "" {
		t.Fatal("state not echoed")
	}

	// --- Step 4: Verifier processes response ---
	vp, err := verifier.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// --- Assertions: required claims disclosed, privacy preserved ---
	if vp.Issuer != issuer.ID {
		t.Errorf("issuer mismatch: %s", vp.Issuer)
	}
	for _, c := range def.RequiredClaims {
		if _, ok := vp.Claims[c]; !ok {
			t.Errorf("required claim missing: %s", c)
		}
	}
	// Privacy — supplierName / recycled must NOT appear
	if _, leaked := vp.Claims["supplierName"]; leaked {
		t.Error("CRITICAL: supplierName leaked")
	}
	if _, leaked := vp.Claims["recycledContentCobalt"]; leaked {
		t.Error("CRITICAL: recycled content leaked")
	}
	// Clear claim should always appear
	if vp.Claims["productId"] != "BAT-2026-001" {
		t.Errorf("clear claim missing: %v", vp.Claims["productId"])
	}
	// numeric claims come through as float64 from JSON
	if cat, ok := vp.Claims["batteryCategory"].(string); !ok || cat != "ev" {
		t.Errorf("category: %v", vp.Claims["batteryCategory"])
	}
	if f, ok := vp.Claims["capacityKWh"].(float64); !ok || f != 75.0 {
		t.Errorf("capacity: %v", vp.Claims["capacityKWh"])
	}
}

func TestMockWalletNoMatchingCredential(t *testing.T) {
	wallet := NewMockWallet("did:web:holder")
	// Wallet has nothing stored
	def := PresentationDefinition{
		ID: "x", RequiredClaims: []string{"foo"},
		AcceptableIssuers: map[string][]byte{"did:web:bogus": []byte("key")},
	}
	verifier := NewVerifier("https://v", "https://v/cb", nil)
	reqURL, _, _ := verifier.CreateRequest(def)
	if _, err := wallet.Present(reqURL); err == nil {
		t.Fatal("empty wallet should fail to present")
	}
}

func TestMockWalletMalformedRequest(t *testing.T) {
	wallet := NewMockWallet("x")
	if _, err := wallet.Present("not-a-url-%%"); err == nil {
		t.Fatal("malformed URL should fail")
	}
	if _, err := wallet.Present("openid4vp://authorize?state=x"); err == nil {
		t.Fatal("missing pd should fail")
	}
}

func TestWalletPresentMissingState(t *testing.T) {
	wallet := NewMockWallet("did:web:holder.example")
	// URL with presentation_definition but no state parameter.
	_, err := wallet.Present("openid4vp://authorize?presentation_definition=%7B%22id%22%3A%22x%22%7D")
	if err == nil {
		t.Fatal("missing state should fail")
	}
}

func TestWalletPresentBadPDJSON(t *testing.T) {
	wallet := NewMockWallet("did:web:holder.example")
	// URL has state and presentation_definition, but PD is not valid JSON.
	_, err := wallet.Present("openid4vp://authorize?state=abc&presentation_definition=%7Bnot+valid+json")
	if err == nil {
		t.Fatal("invalid PD JSON should fail")
	}
}

// ============================================================================
// JAR end-to-end: a JAR-aware wallet (VerifierKey set) trusts ONLY the signed
// request object, so a relay attacker who tampers the unsigned query params
// cannot redirect or rebind the presentation.
// ============================================================================

// jarE2ESetup builds a JAR-signing verifier, a JAR-aware wallet holding a
// matching holder-bound credential, and returns them plus a fresh request URL.
func jarE2ESetup(t *testing.T) (*Verifier, *MockWallet, string) {
	t.Helper()
	issuer, _ := compliance.NewIssuer("did:web:factory.example")

	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifier(
		"https://verify.blrcs.example",
		"https://verify.blrcs.example/cb",
		nil,
	)
	verifier.RequestSigningKey = signPriv

	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wallet := NewMockWallet("did:web:alice.holder")
	wallet.HolderKey = holderPriv
	wallet.VerifierKey = signPub // trust only the signed request object

	sdjwt, _, err := issuer.IssueSDJWTBound(
		"battery-EV-001",
		map[string]any{"batteryCategory": "ev", "capacityKWh": 75.0},
		map[string]any{"productId": "BAT-2026-001"},
		holderPub,
		365*24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Store(StoredCredential{
		ID:        "battery-cred-1",
		IssuerDID: issuer.ID,
		IssuerPub: issuer.PublicKey(),
		SDJWT:     sdjwt,
	})

	def := PresentationDefinition{
		ID:             "eu-battery-compliance",
		RequiredClaims: []string{"batteryCategory", "capacityKWh"},
		AcceptableIssuers: map[string][]byte{
			issuer.ID: issuer.PublicKey(),
		},
	}
	reqURL, _, err := verifier.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, wallet, reqURL
}

// TestJARE2E_HappyPath: signed request → JAR-aware wallet → verifier succeeds.
func TestJARE2E_HappyPath(t *testing.T) {
	verifier, wallet, reqURL := jarE2ESetup(t)
	resp, err := wallet.Present(reqURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}
	vp, err := verifier.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vp.Claims["batteryCategory"] != "ev" {
		t.Errorf("category: %v", vp.Claims["batteryCategory"])
	}
}

// TestJARE2E_RelayNonceTamperDefeated: the strongest demonstration of the JAR
// defense. An attacker rewrites the unsigned `nonce` (and `response_uri`) in the
// query. A legacy wallet would bind its KB-JWT to the wrong nonce and the
// verifier would reject it; the JAR-aware wallet binds to the AUTHENTICATED nonce
// from the signed object, so the genuine verifier still accepts the response.
func TestJARE2E_RelayNonceTamperDefeated(t *testing.T) {
	verifier, wallet, reqURL := jarE2ESetup(t)

	u, _ := url.Parse(reqURL)
	q := u.Query()
	q.Set("nonce", "attacker-substituted-nonce")
	q.Set("response_uri", "https://attacker.example/steal")
	u.RawQuery = q.Encode()
	tampered := u.String()

	resp, err := wallet.Present(tampered)
	if err != nil {
		t.Fatalf("JAR wallet should ignore tampered params and present: %v", err)
	}
	// The genuine verifier accepts: the KB-JWT was bound to the signed nonce.
	if _, err := verifier.ProcessResponse(resp); err != nil {
		t.Fatalf("verify after relay tamper: want success (signed nonce used), got %v", err)
	}
}

// TestJARE2E_LegacyWalletFooledByNonceTamper documents the contrast: a wallet
// WITHOUT VerifierKey trusts the tampered nonce, so the genuine verifier rejects
// the resulting presentation. This is exactly the exposure JAR closes.
func TestJARE2E_LegacyWalletFooledByNonceTamper(t *testing.T) {
	verifier, wallet, reqURL := jarE2ESetup(t)
	wallet.VerifierKey = nil // legacy: trust unsigned query params

	u, _ := url.Parse(reqURL)
	q := u.Query()
	q.Set("nonce", "attacker-substituted-nonce")
	u.RawQuery = q.Encode()

	resp, err := wallet.Present(u.String())
	if err != nil {
		t.Fatalf("legacy wallet present: %v", err)
	}
	// Bound to the wrong nonce → genuine verifier rejects.
	if _, err := verifier.ProcessResponse(resp); err == nil {
		t.Fatal("legacy wallet bound to tampered nonce should be rejected by verifier")
	}
}

// TestJARE2E_RequiresSignedRequest: a JAR-aware wallet given an UNSIGNED request
// (no `request` param) refuses rather than silently falling back to query params.
func TestJARE2E_RequiresSignedRequest(t *testing.T) {
	_, wallet, _ := jarE2ESetup(t)
	// Build an unsigned verifier's request and hand it to the JAR-aware wallet.
	plain := NewVerifier("https://verify.blrcs.example", "https://verify.blrcs.example/cb", nil)
	def := PresentationDefinition{
		ID: "x", RequiredClaims: []string{"batteryCategory"},
	}
	reqURL, _, err := plain.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wallet.Present(reqURL); err == nil {
		t.Fatal("JAR-aware wallet must refuse an unsigned request")
	}
}

// ============================================================================
// OpenID4VP 1.0 transaction_data — full verifier↔wallet round-trip (Axis 114)
// ============================================================================

func encodeTxData(t *testing.T, obj map[string]any) string {
	t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// txDataE2ESetup mirrors the E2E setup but returns the pieces needed to drive
// transaction_data through both the unsigned and JAR-signed paths.
func txDataE2ESetup(t *testing.T, jarSigned bool) (*Verifier, *MockWallet, PresentationDefinition) {
	t.Helper()
	issuer, _ := compliance.NewIssuer("did:web:factory.example")
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifier("https://verify.blrcs.example", "https://verify.blrcs.example/cb", nil)
	wallet := NewMockWallet("did:web:alice.holder")
	wallet.HolderKey = holderPriv
	if jarSigned {
		signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		verifier.RequestSigningKey = signPriv
		wallet.VerifierKey = signPub
	}
	sdjwt, _, err := issuer.IssueSDJWTBound("payment-authz",
		map[string]any{"accountHolder": "Alice"}, nil, holderPub, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Store(StoredCredential{
		ID: "c1", IssuerDID: issuer.ID, IssuerPub: issuer.PublicKey(), SDJWT: sdjwt,
		ClaimNames: []string{"accountHolder"},
	})
	def := PresentationDefinition{
		ID: "pay", RequiredClaims: []string{"accountHolder"},
		AcceptableIssuers: map[string][]byte{issuer.ID: issuer.PublicKey()},
	}
	return verifier, wallet, def
}

// TestTransactionDataE2EUnsigned drives transaction_data through the unsigned
// (query-param) request path: verifier binds a payment, wallet hashes it into
// the KB-JWT, verifier confirms the binding on ProcessResponse.
func TestTransactionDataE2EUnsigned(t *testing.T) {
	verifier, wallet, def := txDataE2ESetup(t, false)
	td := []string{encodeTxData(t, map[string]any{"type": "payment", "amount": "42.00", "currency": "EUR", "payee": "ACME"})}

	reqURL, _, err := verifier.CreateRequestTx(def, td)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := wallet.Present(reqURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}
	vp, err := verifier.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vp.Claims["accountHolder"] != "Alice" {
		t.Errorf("claim: %v", vp.Claims["accountHolder"])
	}
}

// TestTransactionDataE2ESigned drives the same flow through the JAR-signed
// request path, proving transaction_data survives the signed request object.
func TestTransactionDataE2ESigned(t *testing.T) {
	verifier, wallet, def := txDataE2ESetup(t, true)
	td := []string{encodeTxData(t, map[string]any{"type": "payment", "amount": "42.00"})}

	reqURL, _, err := verifier.CreateRequestTx(def, td)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := wallet.Present(reqURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}
	if _, err := verifier.ProcessResponse(resp); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestTransactionDataE2EReplayAgainstDifferentTxRejected is the security
// property end-to-end: a presentation bound to transaction A must not verify
// against a request that binds transaction B. This is exactly the "the holder
// approved a €42 payment, an attacker replays it for €4200" defense.
func TestTransactionDataE2EReplayAgainstDifferentTxRejected(t *testing.T) {
	verifier, wallet, def := txDataE2ESetup(t, false)

	// The holder responds to a request binding a €42 payment.
	tdReal := []string{encodeTxData(t, map[string]any{"amount": "42.00"})}
	reqURL, _, err := verifier.CreateRequestTx(def, tdReal)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := wallet.Present(reqURL)
	if err != nil {
		t.Fatalf("wallet present: %v", err)
	}

	// An attacker replays the SAME vp_token against a session that binds a
	// €4200 payment. Build that session directly on the verifier's store.
	tdAttack := []string{encodeTxData(t, map[string]any{"amount": "4200.00"})}
	attackReqURL, attackState, err := verifier.CreateRequestTx(def, tdAttack)
	if err != nil {
		t.Fatal(err)
	}
	_ = attackReqURL
	resp.State = attackState // point the stolen token at the attacker's session

	if _, err := verifier.ProcessResponse(resp); err == nil {
		t.Fatal("presentation bound to a different transaction must not verify")
	}
}
