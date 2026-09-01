package openid4vci

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Axis 154: Pushed Authorization Requests (RFC 9126)
//
// PAR moves the authorization request off the front channel. The tests that
// matter are the bindings that make a leaked request_uri useless: single use,
// burn-on-failure, client_id binding, and expiry.
// ============================================================================

func parRequest(issuerState, challenge string) AuthorizationRequest {
	return AuthorizationRequest{
		ResponseType:        "code",
		ClientID:            testClientID,
		RedirectURI:         testRedirectURI,
		State:               "wallet-csrf",
		IssuerState:         issuerState,
		CodeChallenge:       challenge,
		CodeChallengeMethod: MethodS256,
	}
}

// TestPARFullFlow drives push → authorize → token → credential.
func TestPARFullFlow(t *testing.T) {
	iss, _ := setupIssuer(t)
	issuerState := newAuthzOffer(t, iss)
	verifier, _ := GenerateCodeVerifier()

	requestURI, expiresIn, err := iss.PushAuthorizationRequest(parRequest(issuerState, S256Challenge(verifier)))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if !strings.HasPrefix(requestURI, RequestURIPrefix) {
		t.Errorf("request_uri must use the RFC 9126 URN prefix, got %q", requestURI)
	}
	if expiresIn <= 0 {
		t.Errorf("expires_in should be positive, got %d", expiresIn)
	}

	res, err := iss.AuthorizeByRequestURI(requestURI, testClientID, "the-user")
	if err != nil {
		t.Fatalf("authorize by request_uri: %v", err)
	}
	if res.State != "wallet-csrf" {
		t.Errorf("state must survive the round trip, got %q", res.State)
	}

	tr, err := iss.ExchangeAuthorizationCode(res.Code, verifier, testRedirectURI, testClientID)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	cred, err := iss.IssueCredential(tr.AccessToken)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	if cred.Credential == "" {
		t.Fatal("empty credential")
	}
}

// TestPARRequestURIIsSingleUse: RFC 9126 §2.2.
func TestPARRequestURIIsSingleUse(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	requestURI, _, err := iss.PushAuthorizationRequest(parRequest(newAuthzOffer(t, iss), S256Challenge(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.AuthorizeByRequestURI(requestURI, testClientID, "u"); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if _, err := iss.AuthorizeByRequestURI(requestURI, testClientID, "u"); !errors.Is(err, ErrBadRequestURI) {
		t.Fatalf("a replayed request_uri must be refused, got %v", err)
	}
}

// TestPARBurnedByFailedRedemption: an attacker racing the client with a guessed
// client_id must not leave the reference usable.
func TestPARBurnedByFailedRedemption(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	requestURI, _, err := iss.PushAuthorizationRequest(parRequest(newAuthzOffer(t, iss), S256Challenge(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.AuthorizeByRequestURI(requestURI, "attacker-client", "u"); !errors.Is(err, ErrBadRequestURI) {
		t.Fatal("a wrong client_id must be refused")
	}
	// Even the CORRECT client must now fail: the reference was burned.
	if _, err := iss.AuthorizeByRequestURI(requestURI, testClientID, "u"); !errors.Is(err, ErrBadRequestURI) {
		t.Fatalf("a failed redemption must burn the request_uri, got %v", err)
	}
}

func TestPARUnknownRequestURI(t *testing.T) {
	iss, _ := setupIssuer(t)
	if _, err := iss.AuthorizeByRequestURI(RequestURIPrefix+"nonexistent", testClientID, "u"); !errors.Is(err, ErrBadRequestURI) {
		t.Fatalf("want ErrBadRequestURI, got %v", err)
	}
}

// TestPARValidatesAtPushTime: RFC 9126 §2.2 — an unusable request must fail on
// the back channel where the client can act on the error, not later in the
// browser where the user cannot.
func TestPARValidatesAtPushTime(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	good := S256Challenge(verifier)

	cases := map[string]AuthorizationRequest{
		"no PKCE":             {ResponseType: "code", ClientID: testClientID, RedirectURI: testRedirectURI},
		"no client_id":        {ResponseType: "code", RedirectURI: testRedirectURI, CodeChallenge: good, CodeChallengeMethod: MethodS256},
		"no redirect_uri":     {ResponseType: "code", ClientID: testClientID, CodeChallenge: good, CodeChallengeMethod: MethodS256},
		"wrong response_type": {ResponseType: "token", ClientID: testClientID, RedirectURI: testRedirectURI, CodeChallenge: good, CodeChallengeMethod: MethodS256},
		"plain PKCE":          {ResponseType: "code", ClientID: testClientID, RedirectURI: testRedirectURI, CodeChallenge: good, CodeChallengeMethod: "plain"},
	}
	for name, req := range cases {
		if _, _, err := iss.PushAuthorizationRequest(req); !errors.Is(err, ErrPARRequestInvalid) {
			t.Errorf("%s: must be refused at push time, got %v", name, err)
		}
	}
}

// TestPAREndpointHTTP covers the wire contract.
func TestPAREndpointHTTP(t *testing.T) {
	iss, _ := setupIssuer(t)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	verifier, _ := GenerateCodeVerifier()
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"issuer_state":          {newAuthzOffer(t, iss)},
		"code_challenge":        {S256Challenge(verifier)},
		"code_challenge_method": {MethodS256},
		"state":                 {"s"},
	}
	resp, err := http.Post(srv.URL+"/par", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// RFC 9126 §2.2: success is 201 Created.
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("PAR responses must be no-store, got %q", cc)
	}
	var body struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.RequestURI, RequestURIPrefix) || body.ExpiresIn <= 0 {
		t.Fatalf("bad response body: %+v", body)
	}
	// The reference is usable.
	if _, err := iss.AuthorizeByRequestURI(body.RequestURI, testClientID, "u"); err != nil {
		t.Errorf("the returned request_uri should redeem: %v", err)
	}
}

// TestPAREndpointRejectsNestedRequestURI: RFC 9126 §2.1 forbids a request_uri
// parameter AT the PAR endpoint — chaining would smuggle in a request the
// endpoint never validated.
func TestPAREndpointRejectsNestedRequestURI(t *testing.T) {
	iss, _ := setupIssuer(t)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	verifier, _ := GenerateCodeVerifier()
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {S256Challenge(verifier)},
		"code_challenge_method": {MethodS256},
		"request_uri":           {RequestURIPrefix + "smuggled"},
	}
	resp, err := http.Post(srv.URL+"/par", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a nested request_uri must be rejected, got %d", resp.StatusCode)
	}
}

func TestPAREndpointMethodAndErrors(t *testing.T) {
	iss, _ := setupIssuer(t)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/par")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET must be refused, got %d", resp.StatusCode)
	}

	// Every validation failure collapses to one identical body, so the endpoint
	// is not an oracle for which check a probe tripped.
	var bodies []string
	for _, f := range []url.Values{
		{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}}, // no PKCE
		{"response_type": {"token"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "code_challenge": {S256Challenge("x")}, "code_challenge_method": {MethodS256}},
		{"response_type": {"code"}, "redirect_uri": {testRedirectURI}, "code_challenge": {S256Challenge("x")}, "code_challenge_method": {MethodS256}}, // no client_id
	} {
		r, err := http.Post(srv.URL+"/par", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("want 400, got %d", r.StatusCode)
		}
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		bodies = append(bodies, string(raw))
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("PAR error bodies must be indistinguishable:\n [0] %s\n [%d] %s", bodies[0], i, bodies[i])
		}
	}
}

// TestPARMetadataAdvertised also regression-guards the two stale metadata
// fields corrected in this axis.
func TestPARMetadataAdvertised(t *testing.T) {
	iss, _ := setupIssuer(t)
	md := iss.Metadata()

	if md["pushed_authorization_request_endpoint"] != iss.URL+"/par" {
		t.Errorf("PAR endpoint not advertised: %v", md["pushed_authorization_request_endpoint"])
	}
	grants, _ := md["grant_types_supported"].([]string)
	var hasAuthCode bool
	for _, g := range grants {
		if g == GrantTypeAuthorizationCode {
			hasAuthCode = true
		}
	}
	if !hasAuthCode {
		t.Errorf("metadata must advertise the authorization_code grant the token endpoint accepts: %v", grants)
	}
	rts, _ := md["response_types_supported"].([]string)
	if len(rts) != 1 || rts[0] != "code" {
		t.Errorf(`response_types_supported should be ["code"], not an OpenID4VP value: %v`, rts)
	}
}

// TestPARExpiry: a parked request must not outlive its TTL.
func TestPARExpiry(t *testing.T) {
	iss, _ := setupIssuer(t)
	verifier, _ := GenerateCodeVerifier()
	requestURI, _, err := iss.PushAuthorizationRequest(parRequest(newAuthzOffer(t, iss), S256Challenge(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	// Age the parked entry past its TTL without sleeping.
	iss.mu.Lock()
	iss.parRequests[requestURI].expiresAt = time.Now().Add(-time.Second)
	iss.mu.Unlock()

	if _, err := iss.AuthorizeByRequestURI(requestURI, testClientID, "u"); !errors.Is(err, ErrBadRequestURI) {
		t.Fatalf("an expired request_uri must be refused, got %v", err)
	}
}
