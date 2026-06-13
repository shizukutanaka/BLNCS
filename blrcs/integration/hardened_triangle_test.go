// Hardened triangle — exercises the *secure-by-default* end-to-end pipeline that
// the per-package hardening built up:
//
//	OpenID4VCI offer WITH tx_code (PIN)              — offer-interception defense
//	  → exchange code+PIN                            — pre-auth + PIN binding
//	  → proof-of-possession → holder-BOUND credential (cnf)
//	OpenID4VP DCQL request (v1.0 §6)                 — sole v1.0 query language
//	  → present with KB-JWT bound to nonce+audience  — replay defense
//	  → verify with RequireKeyBinding=true (default) — secure-by-default
//
// Unlike TestTriangle_IssuerWalletVerifier (which opts out of key binding and uses
// the bearer path), this proves all the hardened pieces compose into one working
// flow, and that the permissive shortcuts are NOT required.
package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/openid4vci"
	"blrcs/openid4vp"
)

// buildProofJWT constructs an OpenID4VCI proof-of-possession JWT (Draft 15 §5.1.2)
// signed by the holder key, bound to the issuer-supplied c_nonce and issuer URL.
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

func TestHardenedTriangle_TxCodeProofBoundDCQLKeyBinding(t *testing.T) {
	// --- 1. Issuer requiring proof-of-possession ---
	signer, err := compliance.NewIssuer("did:web:factory.hardened.example")
	if err != nil {
		t.Fatal(err)
	}
	issuer := openid4vci.NewIssuer("https://issue.hardened.example", signer)
	issuer.RequireProof = true // reject unbound (bearer) issuance
	issuer.RegisterConfiguration(openid4vci.CredentialConfiguration{
		ID:                "battery-v1",
		CredentialType:    "BatteryPassport",
		DisclosableClaims: []string{"carbonKgCO2e", "supplierName"},
		ClearClaims:       []string{"batteryCategory"},
		ValidForDays:      3650,
	})

	// --- 2. Offer bound to a transaction code (PIN) ---
	const pin = "4821"
	_, code, err := issuer.CreateOfferWithTxCode(
		"battery-v1", "battery-hardened-001",
		map[string]any{"carbonKgCO2e": 42.0, "supplierName": "SECRET-Cobalt-Co"},
		map[string]any{"batteryCategory": "ev"},
		pin, &openid4vci.TxCodeSpec{InputMode: "numeric", Length: 4},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Redeeming without the PIN must fail (offer interception alone is useless).
	if _, err := issuer.ExchangeCode(code); err != openid4vci.ErrBadTxCode {
		t.Fatalf("redeem without PIN: want ErrBadTxCode, got %v", err)
	}

	// --- 3. Wallet redeems code + PIN, then proves possession of its holder key ---
	tr, err := issuer.ExchangeCodeWithTxCode(code, pin)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, tr.CNonce, issuer.URL)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": proofJWT})
	cr, err := issuer.IssueCredentialWithProof(tr.AccessToken, openid4vci.CredentialRequest{Proof: proofJSON})
	if err != nil {
		t.Fatalf("proof-bound issuance: %v", err)
	}
	sdjwt := cr.Credential

	// The issued credential must be holder-bound: a plain (bearer) verification must
	// require a KB-JWT, proving the cnf was embedded.
	if _, verr := compliance.VerifySDJWT(sdjwt, signer.PublicKey()); verr != compliance.ErrKeyBindingMissing {
		t.Fatalf("VCI credential should be holder-bound, got %v", verr)
	}

	// --- 4. Verifier issues a DCQL request (secure-by-default key binding) ---
	verifier := openid4vp.NewVerifier(
		"https://verify.hardened.example",
		"https://verify.hardened.example/cb",
		nil,
	)
	if !verifier.RequireKeyBinding {
		t.Fatal("verifier must require key binding by default")
	}
	verifier.TrustedIssuers = map[string][]byte{signer.ID: signer.PublicKey()}
	q := openid4vp.DCQLQuery{Credentials: []openid4vp.CredentialQuery{{
		ID:     "battery",
		Format: "dc+sd-jwt",
		Meta:   &openid4vp.CredentialQueryMeta{VCTValues: []string{compliance.VCTDigitalProductPassport}},
		Claims: []openid4vp.ClaimQuery{
			{Path: []string{"batteryCategory"}},
			{Path: []string{"carbonKgCO2e"}},
		},
	}}}
	reqURL, state, err := verifier.CreateRequestDCQL(q)
	if err != nil {
		t.Fatal(err)
	}

	// --- 5. Wallet presents with a KB-JWT bound to the request nonce + audience ---
	u, err := url.Parse(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	qv := u.Query()
	nonce, aud := qv.Get("nonce"), qv.Get("client_id")
	pres, err := compliance.PresentWithKeyBinding(sdjwt, []string{"carbonKgCO2e"}, holderPriv, nonce, aud, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	// --- 6. Verifier validates the full chain ---
	vp, err := verifier.ProcessResponse(&openid4vp.AuthorizationResponse{VPToken: pres, State: state})
	if err != nil {
		t.Fatalf("ProcessResponse: %v", err)
	}
	if vp.Subject != "battery-hardened-001" {
		t.Errorf("subject: %s", vp.Subject)
	}
	if vp.Claims["batteryCategory"] != "ev" {
		t.Errorf("category: %v", vp.Claims["batteryCategory"])
	}
	if carbon, ok := vp.Claims["carbonKgCO2e"].(float64); !ok || carbon != 42.0 {
		t.Errorf("carbon: %v", vp.Claims["carbonKgCO2e"])
	}
	// Privacy contract: undisclosed supplier must not leak.
	if _, leaked := vp.Claims["supplierName"]; leaked {
		t.Error("CRITICAL: supplierName leaked in presentation")
	}

	// --- 7. Replay defense: the one-time state is consumed ---
	if _, err := verifier.ProcessResponse(&openid4vp.AuthorizationResponse{VPToken: pres, State: state}); err == nil {
		t.Error("replay of consumed state should fail")
	}
}
