package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ============================================================================
// Axis 146: authorization code flow + PKCE
//
// The token endpoint previously accepted only the pre-authorized code grant, so
// an issuer that authenticates the user itself — the ordinary case, and what the
// EUDI ARF assumes — could not be expressed at all. These tests drive the whole
// flow and, more importantly, each binding that makes an intercepted code
// useless: PKCE, redirect_uri, client_id, and single use.
// ============================================================================

const (
	testRedirectURI = "https://wallet.example/cb"
	testClientID    = "wallet-client-1"
)

func authzClaims() (sd, clear map[string]any) {
	return map[string]any{"carbonKgCO2ePerKWh": 42.0, "recycledCoPct": 12.0},
		map[string]any{"batteryCategory": "ev", "capacityKWh": 75.0}
}

func newAuthzOffer(t *testing.T, iss *Issuer) (issuerState string) {
	t.Helper()
	sd, clear := authzClaims()
	_, issuerState, err := iss.CreateAuthorizationCodeOffer("eu-battery-passport-v1", "battery-1", sd, clear,
		AuthorizationCodeOfferOptions{RedirectURIs: []string{testRedirectURI}})
	if err != nil {
		t.Fatalf("create authz offer: %v", err)
	}
	return issuerState
}

func authzRequest(issuerState, challenge string) AuthorizationRequest {
	return AuthorizationRequest{
		ResponseType:        "code",
		ClientID:            testClientID,
		RedirectURI:         testRedirectURI,
		State:               "wallet-csrf-state",
		IssuerState:         issuerState,
		CodeChallenge:       challenge,
		CodeChallengeMethod: MethodS256,
	}
}

// TestAuthorizationCodeFlowRoundTrip is the happy path end to end.
func TestAuthorizationCodeFlowRoundTrip(t *testing.T) {
	iss, _ := setupIssuer(t)
	sd, clear := authzClaims()
	offerURL, issuerState, err := iss.CreateAuthorizationCodeOffer("eu-battery-passport-v1", "battery-1", sd, clear,
		AuthorizationCodeOfferOptions{RedirectURIs: []string{testRedirectURI}})
	if err != nil {
		t.Fatal(err)
	}
	// The offer must advertise the authorization_code grant and carry issuer_state.
	offer := decodeOffer(t, offerURL)
	grants := offer["grants"].(map[string]any)
	ac, ok := grants[GrantTypeAuthorizationCode].(map[string]any)
	if !ok {
		t.Fatalf("offer should carry an authorization_code grant, got %v", grants)
	}
	if ac["issuer_state"] != issuerState {
		t.Errorf("issuer_state mismatch: %v vs %s", ac["issuer_state"], issuerState)
	}
	// Claims must never appear in the front-channel offer. Asserted
	// STRUCTURALLY — the offer must carry exactly the members the spec defines
	// and nothing else — rather than by substring-matching the URL.
	//
	// The original form of this check was `strings.Contains(offerURL, "42")`,
	// looking for the carbon value. The offer URL also carries a random 43-char
	// base64 issuer_state, in which the two characters "42" occur by chance
	// roughly 1-2% of the time, so the test failed intermittently for a reason
	// unrelated to what it was testing. Searching a short literal in random
	// base64 is a false-positive generator, not an assertion.
	wantTop := map[string]bool{"credential_issuer": true, "credential_configuration_ids": true, "grants": true}
	for k := range offer {
		if !wantTop[k] {
			t.Errorf("unexpected member %q in the credential offer — claims must stay issuer-side", k)
		}
	}
	if len(ac) != 1 {
		t.Errorf("authorization_code grant should carry only issuer_state, got %v", ac)
	}
	if _, present := ac["issuer_state"]; !present {
		t.Error("authorization_code grant missing issuer_state")
	}

	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	res, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "authenticated-subject")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if res.State != "wallet-csrf-state" {
		t.Errorf("state must be echoed unchanged, got %q", res.State)
	}
	if !strings.HasPrefix(res.RedirectURI, testRedirectURI+"?") {
		t.Errorf("redirect target wrong: %s", res.RedirectURI)
	}
	u, err := url.Parse(res.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") != res.Code || u.Query().Get("state") != res.State {
		t.Errorf("redirect must carry code and state: %s", res.RedirectURI)
	}

	tr, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, testClientID)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tr.AccessToken == "" || tr.TokenType != "Bearer" || tr.CNonce == "" {
		t.Fatalf("token response incomplete: %+v", tr)
	}

	// The access token must actually work at the credential endpoint, proving the
	// grant record is the same shape the pre-authorized flow produces.
	cred, err := iss.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatalf("issue credential with authz-code token: %v", err)
	}
	if cred.Credential == "" {
		t.Fatal("empty credential")
	}
}

// TestPKCEMismatchRejected: an attacker who intercepts the code but not the
// verifier cannot redeem it. This is the whole point of PKCE.
func TestPKCEMismatchRejected(t *testing.T) {
	iss, _ := setupIssuer(t)
	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()
	attackerVerifier, _ := GenerateCodeVerifier()

	res, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ExchangeAuthorizationCode(res.Code, attackerVerifier, testRedirectURI, testClientID); !errors.Is(err, ErrBadAuthCode) {
		t.Fatalf("a wrong code_verifier must be refused, got %v", err)
	}
}

// TestAuthorizeRequiresPKCE: a request without a challenge, or with plain, must
// never mint a code.
func TestAuthorizeRequiresPKCE(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()

	noPKCE := authzRequest(newAuthzOffer(t, iss), "")
	if _, err := iss.Authorize(noPKCE, "s"); !errors.Is(err, ErrPKCERequired) {
		t.Errorf("a request without PKCE must be refused, got %v", err)
	}
	plain := authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier))
	plain.CodeChallengeMethod = "plain"
	if _, err := iss.Authorize(plain, "s"); !errors.Is(err, ErrPKCEMethodUnsupported) {
		t.Errorf("method=plain must be refused, got %v", err)
	}
	malformed := authzRequest(newAuthzOffer(t, iss), "short")
	if _, err := iss.Authorize(malformed, "s"); !errors.Is(err, ErrPKCEChallengeInvalid) {
		t.Errorf("a malformed challenge must be refused, got %v", err)
	}
}

// TestAuthorizationCodeIsSingleUse: RFC 6749 §4.1.2. A replayed code must fail
// even when every other binding is correct.
func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	iss, _ := setupIssuer(t)
	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()
	res, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, testClientID); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if _, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, testClientID); !errors.Is(err, ErrBadAuthCode) {
		t.Fatalf("a replayed code must be refused, got %v", err)
	}
}

// TestFailedRedemptionBurnsCode: an attacker racing the wallet with a guessed
// verifier must not leave the code usable for a second attempt.
func TestFailedRedemptionBurnsCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()
	wrong, _ := GenerateCodeVerifier()
	res, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ExchangeAuthorizationCode(res.Code, wrong, testRedirectURI, testClientID); !errors.Is(err, ErrBadAuthCode) {
		t.Fatal("wrong verifier should fail")
	}
	// Even the CORRECT verifier must now fail: the code was burned.
	if _, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, testClientID); !errors.Is(err, ErrBadAuthCode) {
		t.Fatalf("a code must be burned by a failed redemption, got %v", err)
	}
}

// TestRedirectURIBinding: RFC 6749 §4.1.3 requires the redemption redirect_uri
// to equal the authorized one, and §3.1.2.3 requires exact matching.
func TestRedirectURIBinding(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()

	// Authorize refuses an unregistered redirect_uri outright.
	req := authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier))
	req.RedirectURI = "https://attacker.example/cb"
	if _, err := iss.Authorize(req, "s"); !errors.Is(err, ErrRedirectURIMismatch) {
		t.Errorf("an unregistered redirect_uri must be refused, got %v", err)
	}
	// Prefix/suffix variants must not match a registered URI.
	for _, near := range []string{
		testRedirectURI + "/../evil",
		testRedirectURI + ".attacker.example",
		testRedirectURI + "?next=https://attacker.example",
		strings.TrimSuffix(testRedirectURI, "/cb"),
	} {
		r := authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier))
		r.RedirectURI = near
		if _, err := iss.Authorize(r, "s"); !errors.Is(err, ErrRedirectURIMismatch) {
			t.Errorf("near-miss redirect_uri %q must be refused, got %v", near, err)
		}
	}
	// And a mismatch at redemption fails too.
	res, err := iss.Authorize(authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ExchangeAuthorizationCode(res.Code, verifier, "https://attacker.example/cb", testClientID); !errors.Is(err, ErrBadAuthCode) {
		t.Fatalf("a redirect_uri mismatch at redemption must be refused, got %v", err)
	}
}

// TestClientIDBinding: a different client must not redeem another's code.
func TestClientIDBinding(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	res, err := iss.Authorize(authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, "other-client"); !errors.Is(err, ErrBadAuthCode) {
		t.Fatalf("a client_id mismatch must be refused, got %v", err)
	}
}

// TestIssuerStateIsSingleUse: one offer authorizes one code. Replaying the
// authorization request must not mint a second.
func TestIssuerStateIsSingleUse(t *testing.T) {
	iss, _ := setupIssuer(t)
	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()
	if _, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "s"); !errors.Is(err, ErrUnknownIssuerState) {
		t.Fatalf("a replayed issuer_state must be refused, got %v", err)
	}
}

// TestUnknownIssuerStateRejected: a wallet cannot invent a session.
func TestUnknownIssuerStateRejected(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	if _, err := iss.Authorize(authzRequest("not-a-real-state", S256Challenge(verifier)), "s"); !errors.Is(err, ErrUnknownIssuerState) {
		t.Fatalf("want ErrUnknownIssuerState, got %v", err)
	}
}

// TestOnlyResponseTypeCode: the implicit and hybrid flows return tokens through
// the front channel and are removed in OAuth 2.1.
func TestOnlyResponseTypeCode(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	for _, rt := range []string{"token", "id_token", "code token", ""} {
		req := authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier))
		req.ResponseType = rt
		if _, err := iss.Authorize(req, "s"); !errors.Is(err, ErrResponseTypeUnsupported) {
			t.Errorf("response_type %q must be refused, got %v", rt, err)
		}
	}
}

// TestAuthorizeRequiresClientAndRedirect covers the structural checks.
func TestAuthorizeRequiresClientAndRedirect(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	noClient := authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier))
	noClient.ClientID = ""
	if _, err := iss.Authorize(noClient, "s"); !errors.Is(err, ErrAuthzRequestInvalid) {
		t.Errorf("missing client_id must be refused, got %v", err)
	}
	noRedirect := authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier))
	noRedirect.RedirectURI = ""
	if _, err := iss.Authorize(noRedirect, "s"); !errors.Is(err, ErrAuthzRequestInvalid) {
		t.Errorf("missing redirect_uri must be refused, got %v", err)
	}
	// An offer with no registered redirect URI cannot be created.
	sd, clear := authzClaims()
	if _, _, err := iss.CreateAuthorizationCodeOffer("eu-battery-passport-v1", "b", sd, clear,
		AuthorizationCodeOfferOptions{}); !errors.Is(err, ErrAuthzRequestInvalid) {
		t.Errorf("an offer with no redirect URIs must be refused, got %v", err)
	}
}

// TestAuthenticatedSubjectOverrides: the subject the issuer authenticated wins
// over the one the offer was created for, so a credential is never minted for
// someone other than the person who just authenticated.
func TestAuthenticatedSubjectOverrides(t *testing.T) {
	iss, _ := setupIssuer(t)
	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()
	res, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "the-real-user")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, testClientID)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := iss.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if sub := decodeJWTSub(t, cred.Credential); sub != "the-real-user" {
		t.Errorf("credential subject should be the authenticated user, got %q", sub)
	}
}

// ============================================================================
// HTTP token endpoint
// ============================================================================

// TestTokenEndpointAuthorizationCodeGrant drives the flow over real HTTP.
func TestTokenEndpointAuthorizationCodeGrant(t *testing.T) {
	iss, _ := setupIssuer(t)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()
	res, err := iss.Authorize(authzRequest(issuerState, S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {res.Code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {testClientID},
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint returned %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("token responses must be no-store, got %q", cc)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken == "" {
		t.Fatal("no access token")
	}
}

// TestTokenEndpointCollapsesAuthCodeErrors: every failure mode must produce the
// same response, so the endpoint is not an oracle for which binding failed.
func TestTokenEndpointCollapsesAuthCodeErrors(t *testing.T) {
	iss, _ := setupIssuer(t)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	verifier, _ := GenerateCodeVerifier()
	wrong, _ := GenerateCodeVerifier()
	res, err := iss.Authorize(authzRequest(newAuthzOffer(t, iss), S256Challenge(verifier)), "s")
	if err != nil {
		t.Fatal(err)
	}

	var bodies []string
	for _, f := range []url.Values{
		{"grant_type": {GrantTypeAuthorizationCode}, "code": {"nonexistent"}, "code_verifier": {verifier}, "redirect_uri": {testRedirectURI}, "client_id": {testClientID}},
		{"grant_type": {GrantTypeAuthorizationCode}, "code": {res.Code}, "code_verifier": {wrong}, "redirect_uri": {testRedirectURI}, "client_id": {testClientID}},
		{"grant_type": {GrantTypeAuthorizationCode}, "code": {res.Code}, "code_verifier": {verifier}, "redirect_uri": {"https://attacker.example/cb"}, "client_id": {testClientID}},
		{"grant_type": {GrantTypeAuthorizationCode}, "code": {res.Code}, "code_verifier": {verifier}, "redirect_uri": {testRedirectURI}, "client_id": {"other"}},
	} {
		resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("want 400, got %d", resp.StatusCode)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodies = append(bodies, string(raw))
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("error responses must be indistinguishable:\n [0] %s\n [%d] %s", bodies[0], i, bodies[i])
		}
	}
}

// TestUnsupportedGrantStillRejected keeps the pre-authorized path working and
// refuses anything else.
func TestUnsupportedGrantStillRejected(t *testing.T) {
	iss, _ := setupIssuer(t)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	form := url.Values{"grant_type": {"client_credentials"}}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("want unsupported_grant_type, got %v", body["error"])
	}
}

// --- helpers ---

// decodeJWTSub pulls the `sub` claim out of an issued SD-JWT.
func decodeJWTSub(t *testing.T, sdjwt string) string {
	t.Helper()
	jwt := strings.SplitN(sdjwt, "~", 2)[0]
	segs := strings.Split(jwt, ".")
	if len(segs) != 3 {
		t.Fatalf("not a compact JWS: %s", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sub, _ := m["sub"].(string)
	return sub
}

func decodeOffer(t *testing.T, offerURL string) map[string]any {
	t.Helper()
	_, q, found := strings.Cut(offerURL, "credential_offer=")
	if !found {
		t.Fatalf("no credential_offer in %s", offerURL)
	}
	raw, err := url.QueryUnescape(q)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("offer JSON: %v (%s)", err, raw)
	}
	return m
}
