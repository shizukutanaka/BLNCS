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
	"errors"
	"net/url"
	"strconv"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/openid4vci"
	"blrcs/openid4vp"
	"blrcs/revocation"
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
		Meta:   &openid4vp.CredentialQueryMeta{VCTValues: []string{"BatteryPassport"}},
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

// TestHardenedTriangle_RevocationLifecycle proves the full credential lifecycle:
// a VCI-issued credential that is holder-bound AND revocable verifies while valid,
// and is rejected in-flow once the issuer flips its status-list bit.
func TestHardenedTriangle_RevocationLifecycle(t *testing.T) {
	signer, err := compliance.NewIssuer("did:web:factory.lifecycle.example")
	if err != nil {
		t.Fatal(err)
	}
	issuer := openid4vci.NewIssuer("https://issue.lifecycle.example", signer)
	issuer.RequireProof = true
	issuer.RegisterConfiguration(openid4vci.CredentialConfiguration{
		ID:                "battery-v1",
		CredentialType:    "BatteryPassport",
		DisclosableClaims: []string{"carbonKgCO2e"},
		ClearClaims:       []string{"batteryCategory"},
		ValidForDays:      3650,
	})

	// Issuer-owned revocation list; this credential occupies index 7.
	const statusIdx = 7
	statusList := revocation.NewBitstringStatusList(revocation.PurposeRevocation, 128)
	status := &compliance.StatusRef{URI: "https://issue.lifecycle.example/status/1", Index: statusIdx}

	// --- Issue a holder-bound + revocable credential via proof-of-possession ---
	_, code, err := issuer.CreateOfferWithOptions(
		"battery-v1", "battery-lifecycle-001",
		map[string]any{"carbonKgCO2e": 42.0},
		map[string]any{"batteryCategory": "ev"},
		openid4vci.OfferOptions{Status: status},
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := issuer.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	proofJWT := buildProofJWT(t, holderPriv, tr.CNonce, issuer.URL)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": proofJWT})
	cr, err := issuer.IssueCredentialWithProof(tr.AccessToken, openid4vci.CredentialRequest{Proof: proofJSON})
	if err != nil {
		t.Fatal(err)
	}
	sdjwt := cr.Credential

	// --- Verifier checks revocation against the issuer's list ---
	verifier := openid4vp.NewVerifier(
		"https://verify.lifecycle.example",
		"https://verify.lifecycle.example/cb",
		nil,
	)
	verifier.TrustedIssuers = map[string][]byte{signer.ID: signer.PublicKey()}
	verifier.RevocationChecker = func(s *compliance.StatusRef) (bool, error) {
		return statusList.GetStatus(s.Index)
	}

	// present runs one full DCQL request → KB-JWT presentation → ProcessResponse.
	present := func() error {
		q := openid4vp.DCQLQuery{Credentials: []openid4vp.CredentialQuery{{
			ID:     "battery",
			Format: "dc+sd-jwt",
			Meta:   &openid4vp.CredentialQueryMeta{VCTValues: []string{"BatteryPassport"}},
			Claims: []openid4vp.ClaimQuery{{Path: []string{"batteryCategory"}}},
		}}}
		reqURL, state, cerr := verifier.CreateRequestDCQL(q)
		if cerr != nil {
			return cerr
		}
		u, _ := url.Parse(reqURL)
		qv := u.Query()
		pres, perr := compliance.PresentWithKeyBinding(sdjwt, []string{"carbonKgCO2e"}, holderPriv, qv.Get("nonce"), qv.Get("client_id"), time.Time{})
		if perr != nil {
			return perr
		}
		_, verr := verifier.ProcessResponse(&openid4vp.AuthorizationResponse{VPToken: pres, State: state})
		return verr
	}

	// 1. While not revoked, the credential verifies.
	if err := present(); err != nil {
		t.Fatalf("valid credential should verify: %v", err)
	}

	// 2. Issuer revokes by flipping the status bit.
	if err := statusList.SetStatus(statusIdx, true); err != nil {
		t.Fatal(err)
	}

	// 3. The same credential is now rejected in-flow.
	if err := present(); !errors.Is(err, openid4vp.ErrCredentialRevoked) {
		t.Fatalf("revoked credential: want ErrCredentialRevoked, got %v", err)
	}
}

// TestBearerCredentialRejectedByKeyBindingVerifier — Axis 76
//
// Verifies the security contract: a bearer SD-JWT (issued without proof-of-
// possession, no `cnf` claim) MUST be rejected by a verifier with
// RequireKeyBinding=true. This integration test crosses openid4vci (bearer
// issuance) and openid4vp (secure verifier) to ensure neither package alone
// is responsible for enforcing the contract, and that they compose correctly.
func TestBearerCredentialRejectedByKeyBindingVerifier(t *testing.T) {
	// 1. Issue a bearer credential (no proof-of-possession, no cnf).
	signer, _ := compliance.NewIssuer("did:web:bearer.test.example")
	issuer := openid4vci.NewIssuer("https://bearer.test.example", signer)
	issuer.RequireProof = false // explicitly allow bearer issuance
	issuer.RegisterConfiguration(openid4vci.CredentialConfiguration{
		ID:                "battery-v1",
		CredentialType:    "BatteryPassport",
		DisclosableClaims: []string{"carbonKgCO2e"},
		ClearClaims:       []string{"batteryCategory"},
		ValidForDays:      365,
	})

	_, code, _ := issuer.CreateOffer(
		"battery-v1", "bat-bearer-test",
		map[string]any{"carbonKgCO2e": 55.0}, map[string]any{"batteryCategory": "ev"},
	)
	tr, err := issuer.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := issuer.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatalf("bearer issuance: %v", err)
	}
	bearerSDJWT := cr.Credential

	// 2. Bearer credential is valid in permissive mode (no KB required).
	if _, verr := compliance.VerifySDJWT(bearerSDJWT, signer.PublicKey()); verr != nil {
		t.Fatalf("bearer credential must verify without KB: %v", verr)
	}

	// 3. Set up a secure verifier with RequireKeyBinding=true (the default).
	verifier := openid4vp.NewVerifier("https://verifier.test.example", "https://verifier.test.example/cb", nil)
	verifier.TrustedIssuers = map[string][]byte{signer.ID: signer.PublicKey()}
	// RequireKeyBinding defaults to true — verify the secure-by-default contract.
	if !verifier.RequireKeyBinding {
		t.Fatal("verifier must require key binding by default")
	}

	// 4. Create a VP request so state/nonce tracking is initialized.
	_, state, _ := verifier.CreateRequest(openid4vp.PresentationDefinition{
		RequiredClaims: []string{"batteryCategory"},
	})

	// 5. Present the bearer SD-JWT (no KB-JWT suffix). The verifier must reject it
	// because it carries no `cnf` holder key and no KB-JWT, so RequireKeyBinding
	// cannot be satisfied — the bearer JWT is not equivalent to a key-bound one.
	_, err = verifier.ProcessResponse(&openid4vp.AuthorizationResponse{
		VPToken: bearerSDJWT,
		State:   state,
	})
	if err == nil {
		t.Fatal("bearer credential must be rejected by RequireKeyBinding=true verifier")
	}
}
