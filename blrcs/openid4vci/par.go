package openid4vci

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ============================================================================
// Axis 154: Pushed Authorization Requests (RFC 9126)
//
// The authorization request previously reached the issuer only through the
// front channel — the browser address bar — carrying client_id, redirect_uri,
// scope, the PKCE challenge and potentially authorization_details. Everything
// in it is visible to the user agent, to browser history, to referrer headers
// and to anything else on that path, and nothing binds it to the client that
// composed it until the code is redeemed.
//
// PAR inverts that: the client POSTs the request DIRECTLY to the issuer over
// TLS, receives an opaque one-time `request_uri`, and the front channel then
// carries only that reference. The parameters never traverse the browser.
// Pairs naturally with the mandatory PKCE from Axis 146 — PKCE binds the code
// to its requester, PAR keeps the request itself off the front channel.
//
// # Why this shape
//
// This package deliberately has no HTTP authorization endpoint (see
// authcode.go): who the user is, and how they proved it, is the deploying
// issuer's decision, so authorization is the Go-level Authorize(). PAR
// therefore PARKS a validated request server-side, and the host application
// redeems it by request_uri after authenticating the user. The same seam, one
// step earlier.
//
// # Validation timing
//
// A pushed request is validated AT PUSH TIME with exactly the checks Authorize
// applies (response_type, client_id, redirect_uri, PKCE shape). RFC 9126 §2.2
// requires the endpoint to reject an invalid request rather than park it: a
// request that cannot succeed must fail on the back channel, where the client
// gets a usable error, not later in the browser where the user sees a failure
// they cannot act on.
// ============================================================================

// RequestURIPrefix is the URN namespace RFC 9126 §2.2 assigns to pushed
// request references.
const RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// parRequestTTL bounds how long a pushed request stays redeemable.
//
// RFC 9126 §2.2 suggests a lifetime "in the order of seconds to a few minutes"
// and its examples use 90s, which assumes the client redirects the browser
// immediately. Here the window must also span the user AUTHENTICATING at the
// issuer between the push and Authorize, so 90s would expire mid-login. Five
// minutes is the smallest value that accommodates a real login without leaving
// a parked request usable for meaningfully longer.
const parRequestTTL = 5 * time.Minute

var (
	// ErrPARRequestInvalid is returned when a pushed request fails the
	// validations Authorize would apply. Returned at PUSH time.
	ErrPARRequestInvalid = errors.New("vci: invalid pushed authorization request")
	// ErrBadRequestURI is returned when a request_uri is unknown, expired,
	// already redeemed, or presented by a different client. Deliberately one
	// error for all of those: distinguishing them tells an attacker which
	// binding to attack next, matching ErrBadAuthCode's treatment.
	ErrBadRequestURI = errors.New("vci: request_uri invalid or consumed")
)

// parkedRequest is a validated authorization request awaiting redemption.
type parkedRequest struct {
	req       AuthorizationRequest
	clientID  string
	expiresAt time.Time
}

// PushAuthorizationRequest validates an authorization request and parks it,
// returning the opaque request_uri that stands in for it on the front channel
// and the seconds until it expires.
//
// The request is validated here rather than at redemption so a client learns
// immediately, over the back channel, that it composed something unusable.
func (iss *Issuer) PushAuthorizationRequest(req AuthorizationRequest) (requestURI string, expiresIn int, err error) {
	// Exactly the checks Authorize runs before touching any state, so a pushed
	// request that would be refused later is refused now.
	if req.ResponseType != "code" {
		return "", 0, fmt.Errorf("%w: %w", ErrPARRequestInvalid, ErrResponseTypeUnsupported)
	}
	if req.ClientID == "" {
		return "", 0, fmt.Errorf("%w: client_id required", ErrPARRequestInvalid)
	}
	if req.RedirectURI == "" {
		return "", 0, fmt.Errorf("%w: redirect_uri required", ErrPARRequestInvalid)
	}
	if err := ValidateCodeChallenge(req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrPARRequestInvalid, err)
	}

	token, err := randomB64(32)
	if err != nil {
		return "", 0, err
	}
	requestURI = RequestURIPrefix + token

	now := time.Now()
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.gcAuthzLocked(now)
	if iss.parRequests == nil {
		iss.parRequests = make(map[string]*parkedRequest)
	}
	iss.parRequests[requestURI] = &parkedRequest{
		req:       req,
		clientID:  req.ClientID,
		expiresAt: now.Add(parRequestTTL),
	}
	return requestURI, int(parRequestTTL.Seconds()), nil
}

// AuthorizeByRequestURI redeems a pushed request and completes authorization
// for an already-authenticated user. It is PushAuthorizationRequest's
// counterpart to Authorize; the same caller responsibility applies — the host
// application authenticates the user first (see authcode.go).
//
// clientID must equal the one that pushed the request (RFC 9126 §2.2): the
// reference is opaque but not secret once it reaches the front channel, so the
// client binding is what stops another client redeeming it.
func (iss *Issuer) AuthorizeByRequestURI(requestURI, clientID, authenticatedSubject string) (*AuthorizationResult, error) {
	now := time.Now()
	iss.mu.Lock()
	parked, ok := iss.parRequests[requestURI]
	if ok {
		// Burn on ANY redemption attempt that finds it, not only on success —
		// an attacker racing the legitimate client must not get a second try at
		// the client_id. Same reasoning as the authorization code in Axis 146.
		delete(iss.parRequests, requestURI)
	}
	iss.mu.Unlock()

	if !ok || now.After(parked.expiresAt) {
		return nil, ErrBadRequestURI
	}
	if subtle.ConstantTimeCompare([]byte(parked.clientID), []byte(clientID)) != 1 {
		return nil, ErrBadRequestURI
	}
	return iss.Authorize(parked.req, authenticatedSubject)
}

// handlePAR is the RFC 9126 §2 pushed authorization request endpoint.
func (iss *Issuer) handlePAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if err := r.ParseForm(); err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	// RFC 9126 §2.1: the PAR endpoint MUST NOT accept a request_uri parameter.
	// Allowing one would let a client chain references and smuggle a request the
	// endpoint never validated.
	if r.Form.Get("request_uri") != "" {
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "request_uri is not permitted at the PAR endpoint")
		return
	}

	req := AuthorizationRequest{
		ResponseType:        r.Form.Get("response_type"),
		ClientID:            r.Form.Get("client_id"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		Scope:               r.Form.Get("scope"),
		State:               r.Form.Get("state"),
		IssuerState:         r.Form.Get("issuer_state"),
		CodeChallenge:       r.Form.Get("code_challenge"),
		CodeChallengeMethod: r.Form.Get("code_challenge_method"),
	}
	if ad := r.Form.Get("authorization_details"); ad != "" {
		if !json.Valid([]byte(ad)) {
			writeVCIError(w, http.StatusBadRequest, "invalid_request", "authorization_details must be JSON")
			return
		}
		req.AuthorizationDetails = json.RawMessage(ad)
	}

	requestURI, expiresIn, err := iss.PushAuthorizationRequest(req)
	if err != nil {
		// One collapsed description across every validation failure, so the
		// endpoint is not an oracle for which check a probe tripped.
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "the pushed authorization request is invalid")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// RFC 9126 §2.2: a successful response is 201 Created.
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_uri": requestURI,
		"expires_in":  expiresIn,
	})
}
