package openid4vci

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"blrcs/compliance"
)

// ============================================================================
// Axis 146: OpenID4VCI authorization code flow
//
// Until now the token endpoint accepted exactly one grant — the pre-authorized
// code — and rejected everything else with unsupported_grant_type. That flow
// only fits the case where the issuer already knows who the subject is and can
// hand them a code out of band (a QR on a printed document, say). It cannot
// express the ordinary case: a wallet that discovers an issuer and needs the
// user to authenticate AT the issuer before a credential is minted. OpenID4VCI
// 1.0 §4.1.1 defines the authorization code grant for exactly that, and the EUDI
// ARF assumes it for any issuer that authenticates the user itself.
//
// This implements the issuer half:
//
//	CreateAuthorizationCodeOffer -> offer carrying grants.authorization_code
//	                                with an issuer_state binding the session
//	Authorize                    -> after the issuer app authenticates the user,
//	                                mints a single-use code bound to the PKCE
//	                                challenge, redirect_uri and client_id
//	ExchangeAuthorizationCode    -> redeems it for an access token
//
// User authentication is deliberately NOT implemented here. Who the user is, and
// how they proved it, is the deploying issuer's decision (password, eID, an
// existing SSO). The issuer app authenticates however it likes and then calls
// Authorize with the resulting subject — the same seam the package already uses
// for revocation checks and audit hooks, and the reason this file stays free of
// any UI or session-cookie machinery.
//
// # Bindings enforced
//
//   - PKCE is REQUIRED and must be S256 (see pkce.go). A wallet is a public
//     client with no secret, so the code has no other binding to its requester.
//   - redirect_uri at redemption must exactly equal the one authorized
//     (RFC 6749 §4.1.3). Without this an attacker who substitutes their own
//     redirect_uri receives the code.
//   - client_id at redemption must match the one authorized.
//   - The code is single-use and short-lived; redeeming it twice fails, which is
//     what makes a replayed or leaked code useless after the wallet's own use.
//   - Every failure at the token endpoint collapses to one error, so redemption
//     is not an oracle telling an attacker which of these bindings they got
//     wrong (the same defence the pre-authorized/tx_code path already applies).
// ============================================================================

// GrantTypeAuthorizationCode is the OAuth 2.0 authorization code grant type.
const GrantTypeAuthorizationCode = "authorization_code"

var (
	// ErrUnknownIssuerState is returned when an authorization request carries an
	// issuer_state that does not match a live offer.
	ErrUnknownIssuerState = errors.New("vci: issuer_state unknown or expired")
	// ErrBadAuthCode is returned when an authorization code is unknown, expired,
	// already redeemed, or fails any of its bindings. It is deliberately the
	// single error for all of those: distinguishing them tells an attacker which
	// binding to attack next.
	ErrBadAuthCode = errors.New("vci: authorization code invalid or consumed")
	// ErrRedirectURIMismatch is returned by Authorize when the requested
	// redirect_uri is not one the offer registered. (At the TOKEN endpoint a
	// mismatch collapses into ErrBadAuthCode instead.)
	ErrRedirectURIMismatch = errors.New("vci: redirect_uri does not match the authorized value")
	// ErrResponseTypeUnsupported is returned for any response_type other than
	// "code". The implicit and hybrid flows return tokens through the front
	// channel and are removed in OAuth 2.1.
	ErrResponseTypeUnsupported = errors.New("vci: only response_type=code is supported")
	// ErrAuthzRequestInvalid is returned for a structurally invalid authorization
	// request (missing client_id, redirect_uri, and so on).
	ErrAuthzRequestInvalid = errors.New("vci: invalid authorization request")
)

// authzSession is the issuer-side state an authorization-code offer creates. It
// holds what will be minted once the user authenticates, so the claims never
// travel through the front channel.
type authzSession struct {
	issuerState  string
	configID     string
	subject      string
	sdClaims     map[string]any
	clearClaims  map[string]any
	status       *compliance.StatusRef
	redirectURIs []string
	expiresAt    time.Time
}

// authzCodeEntry is a minted authorization code and the bindings it carries.
type authzCodeEntry struct {
	session       *authzSession
	codeChallenge string
	redirectURI   string
	clientID      string
	subject       string
	expiresAt     time.Time
}

// AuthorizationRequest is the front-channel request a wallet makes to the
// issuer's authorization endpoint (OpenID4VCI 1.0 §4.1.1 / RFC 6749 §4.1.1).
type AuthorizationRequest struct {
	ResponseType         string // MUST be "code"
	ClientID             string
	RedirectURI          string
	Scope                string
	State                string // opaque wallet CSRF value, echoed back verbatim
	IssuerState          string // binds this request to a credential offer
	CodeChallenge        string
	CodeChallengeMethod  string // MUST be "S256"
	AuthorizationDetails json.RawMessage
}

// AuthorizationResult is what the issuer redirects back to the wallet with.
type AuthorizationResult struct {
	Code  string
	State string // the wallet's state, echoed unchanged
	// RedirectURI is the exact URI to redirect to, carrying Code and State.
	RedirectURI string
}

// AuthorizationCodeOfferOptions controls an authorization-code offer.
type AuthorizationCodeOfferOptions struct {
	// RedirectURIs is the set of redirect URIs this offer may be completed
	// against. Authorize refuses any other. Exact string matching is used, as
	// RFC 6749 §3.1.2.3 requires for URIs that are not simple.
	RedirectURIs []string
	// Status attaches a revocation reference to the credential this offer mints.
	Status *compliance.StatusRef
}

// CreateAuthorizationCodeOffer creates a credential offer that uses the
// authorization code grant. The returned issuer_state binds a later
// authorization request back to this offer, so the wallet cannot redirect the
// flow at a different credential than the one offered.
//
// The claims are held issuer-side and never appear in the offer or in any
// front-channel parameter.
func (iss *Issuer) CreateAuthorizationCodeOffer(configID, subject string, sdClaims, clearClaims map[string]any, opts AuthorizationCodeOfferOptions) (offerURL, issuerState string, err error) {
	iss.mu.Lock()
	cfg, ok := iss.configs[configID]
	iss.mu.Unlock()
	if !ok {
		return "", "", ErrUnknownConfig
	}
	for _, c := range cfg.DisclosableClaims {
		if _, has := sdClaims[c]; !has {
			return "", "", fmt.Errorf("%w: %s", ErrMissingClaims, c)
		}
	}
	if len(opts.RedirectURIs) == 0 {
		return "", "", fmt.Errorf("%w: at least one redirect URI must be registered", ErrAuthzRequestInvalid)
	}
	issuerState, err = randomB64(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	iss.mu.Lock()
	iss.gcExpiredLocked(now)
	iss.gcAuthzLocked(now)
	if iss.authzSessions == nil {
		iss.authzSessions = make(map[string]*authzSession)
	}
	iss.authzSessions[issuerState] = &authzSession{
		issuerState:  issuerState,
		configID:     configID,
		subject:      subject,
		sdClaims:     sdClaims,
		clearClaims:  clearClaims,
		status:       opts.Status,
		redirectURIs: append([]string(nil), opts.RedirectURIs...),
		expiresAt:    now.Add(iss.preAuthTTL),
	}
	iss.mu.Unlock()

	offer := map[string]any{
		"credential_issuer":            iss.URL,
		"credential_configuration_ids": []string{configID},
		"grants": map[string]any{
			GrantTypeAuthorizationCode: map[string]any{
				"issuer_state": issuerState,
			},
		},
	}
	b, err := json.Marshal(offer)
	if err != nil {
		return "", "", err
	}
	return "openid-credential-offer://?credential_offer=" + urlEscape(string(b)), issuerState, nil
}

// Authorize completes the authorization step for an already-authenticated user
// and mints a single-use authorization code.
//
// The caller is responsible for authenticating the user BEFORE calling this;
// see the package note above. Passing an empty authenticatedSubject uses the
// subject the offer was created for, which is the right behaviour when the
// issuer created the offer for a known subject and has just re-confirmed it.
func (iss *Issuer) Authorize(req AuthorizationRequest, authenticatedSubject string) (*AuthorizationResult, error) {
	if req.ResponseType != "code" {
		return nil, fmt.Errorf("%w: got %q", ErrResponseTypeUnsupported, req.ResponseType)
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("%w: client_id required", ErrAuthzRequestInvalid)
	}
	if req.RedirectURI == "" {
		return nil, fmt.Errorf("%w: redirect_uri required", ErrAuthzRequestInvalid)
	}
	// PKCE is mandatory, and only S256 is accepted. Checked before the session is
	// touched so a request without it can never mint a code.
	if err := ValidateCodeChallenge(req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return nil, err
	}

	now := time.Now()
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.gcAuthzLocked(now)

	session, ok := iss.authzSessions[req.IssuerState]
	if !ok || now.After(session.expiresAt) {
		return nil, ErrUnknownIssuerState
	}
	if !matchesRegisteredURI(session.redirectURIs, req.RedirectURI) {
		return nil, ErrRedirectURIMismatch
	}

	code, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	subject := authenticatedSubject
	if subject == "" {
		subject = session.subject
	}
	if iss.authzCodes == nil {
		iss.authzCodes = make(map[string]*authzCodeEntry)
	}
	iss.authzCodes[code] = &authzCodeEntry{
		session:       session,
		codeChallenge: req.CodeChallenge,
		redirectURI:   req.RedirectURI,
		clientID:      req.ClientID,
		subject:       subject,
		// An authorization code is redeemed immediately by the wallet; RFC 6749
		// §4.1.2 recommends a maximum lifetime of ten minutes and this is well
		// inside that, limiting the window in which a leaked code is usable.
		expiresAt: now.Add(authCodeTTL),
	}
	// The issuer_state is single-use: it authorized one code, and leaving it live
	// would let a replayed authorization request mint a second code for the same
	// offer.
	delete(iss.authzSessions, req.IssuerState)

	return &AuthorizationResult{
		Code:        code,
		State:       req.State,
		RedirectURI: appendCodeToRedirect(req.RedirectURI, code, req.State),
	}, nil
}

// ExchangeAuthorizationCode redeems an authorization code for an access token,
// enforcing the PKCE, redirect_uri and client_id bindings recorded at
// authorization time.
//
// Every failure returns ErrBadAuthCode so the endpoint cannot be used to probe
// which binding failed.
func (iss *Issuer) ExchangeAuthorizationCode(code, codeVerifier, redirectURI, clientID string) (*TokenResponse, error) {
	now := time.Now()
	iss.mu.Lock()
	defer iss.mu.Unlock()

	entry, ok := iss.authzCodes[code]
	if !ok || now.After(entry.expiresAt) {
		return nil, ErrBadAuthCode
	}
	// Burn the code on ANY redemption attempt that gets this far. RFC 6749
	// §4.1.2 requires a code be single-use, and §10.5 requires revoking the
	// grant if one is replayed — an attacker racing the legitimate wallet must
	// not get a second try at the PKCE verifier.
	delete(iss.authzCodes, code)

	if subtle.ConstantTimeCompare([]byte(entry.redirectURI), []byte(redirectURI)) != 1 {
		return nil, ErrBadAuthCode
	}
	if subtle.ConstantTimeCompare([]byte(entry.clientID), []byte(clientID)) != 1 {
		return nil, ErrBadAuthCode
	}
	if err := VerifyPKCE(codeVerifier, entry.codeChallenge); err != nil {
		return nil, ErrBadAuthCode
	}

	accessToken, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	cNonce, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	s := entry.session
	// Reuse the same grant record the pre-authorized flow produces, so the
	// credential endpoint needs no knowledge of which grant minted the token.
	granted := &preAuthEntry{
		configID:       s.configID,
		subject:        entry.subject,
		sdClaims:       s.sdClaims,
		clearClaims:    s.clearClaims,
		status:         s.status,
		accessToken:    accessToken,
		tokenExpiresAt: now.Add(iss.tokenTTL),
		cNonce:         cNonce,
		expiresAt:      now.Add(iss.tokenTTL),
	}
	if iss.tokens == nil {
		iss.tokens = make(map[string]*preAuthEntry)
	}
	iss.tokens[accessToken] = granted

	return &TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(iss.tokenTTL.Seconds()),
		CNonce:          cNonce,
		CNonceExpiresIn: int(iss.tokenTTL.Seconds()),
	}, nil
}

// authCodeTTL bounds how long a minted authorization code stays redeemable.
// RFC 6749 §4.1.2 recommends a maximum of ten minutes; a wallet redeems within
// seconds, so a tighter bound costs nothing and shrinks the leak window.
const authCodeTTL = 2 * time.Minute

// gcAuthzLocked drops expired authorization sessions and codes. Callers hold
// iss.mu. Without it, sessions that are never completed (the user abandons the
// flow) would accumulate for the process's lifetime.
func (iss *Issuer) gcAuthzLocked(now time.Time) {
	for k, s := range iss.authzSessions {
		if now.After(s.expiresAt) {
			delete(iss.authzSessions, k)
		}
	}
	for k, c := range iss.authzCodes {
		if now.After(c.expiresAt) {
			delete(iss.authzCodes, k)
		}
	}
}

// matchesRegisteredURI compares a requested redirect_uri against the registered
// set by exact string equality, which RFC 6749 §3.1.2.3 requires: prefix or
// substring matching lets an attacker append a path or query that redirects the
// code to a host they control.
func matchesRegisteredURI(registered []string, requested string) bool {
	for _, r := range registered {
		if subtle.ConstantTimeCompare([]byte(r), []byte(requested)) == 1 {
			return true
		}
	}
	return false
}

// appendCodeToRedirect builds the redirect target carrying the code and state.
func appendCodeToRedirect(redirectURI, code, state string) string {
	sep := "?"
	for i := 0; i < len(redirectURI); i++ {
		if redirectURI[i] == '?' {
			sep = "&"
			break
		}
	}
	out := redirectURI + sep + "code=" + urlEscape(code)
	if state != "" {
		out += "&state=" + urlEscape(state)
	}
	return out
}
