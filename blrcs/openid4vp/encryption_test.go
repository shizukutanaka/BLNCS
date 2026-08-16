package openid4vp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"blrcs/compliance"
)

// ============================================================================
// Axis 143: OpenID4VP §8.3 / HAIP encrypted Authorization Response wiring
//
// These tests exercise the OpenID4VP plumbing around the jwe package: request
// advertisement (client_metadata + direct_post.jwt), the wallet-side encrypt
// helper, the verifier-side decrypt, and the full encrypted round trip through
// ProcessResponse — proving a wallet can return its presentation encrypted and
// the verifier still verifies it.
// ============================================================================

func encVerifier(t *testing.T) (*Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier("did:web:verifier.example", "https://verifier.example/cb", nil)
	v.ResponseEncryptionKey = encKey
	t.Cleanup(func() { _ = v.Close() })
	return v, encKey
}

// TestCreateRequestAdvertisesEncryption: when a ResponseEncryptionKey is set the
// request switches to direct_post.jwt and carries the verifier's encryption JWK
// in client_metadata.
func TestCreateRequestAdvertisesEncryption(t *testing.T) {
	v, _ := encVerifier(t)
	reqURL, _, err := v.CreateRequest(PresentationDefinition{
		ID: "dpp", RequiredClaims: []string{"carbonKgCO2ePerKWh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_mode") != ResponseModeDirectPostJWT {
		t.Errorf("response_mode = %q, want %q", q.Get("response_mode"), ResponseModeDirectPostJWT)
	}
	var cm map[string]any
	if err := json.Unmarshal([]byte(q.Get("client_metadata")), &cm); err != nil {
		t.Fatalf("client_metadata: %v", err)
	}
	jwks := cm["jwks"].(map[string]any)["keys"].([]any)
	if len(jwks) != 1 {
		t.Fatalf("want 1 advertised key, got %d", len(jwks))
	}
	jwk := jwks[0].(map[string]any)
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["use"] != "enc" {
		t.Errorf("advertised JWK wrong: %v", jwk)
	}
}

// TestPlaintextRequestUnchangedWithoutKey is the back-compat guard: a verifier
// with no encryption key still produces a plaintext direct_post request.
func TestPlaintextRequestUnchangedWithoutKey(t *testing.T) {
	v := NewVerifier("did:web:v", "https://v/cb", nil)
	t.Cleanup(func() { _ = v.Close() })
	reqURL, _, err := v.CreateRequest(PresentationDefinition{ID: "d", RequiredClaims: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(reqURL)
	if got := q.Query().Get("response_mode"); got != "direct_post" {
		t.Errorf("response_mode = %q, want direct_post", got)
	}
	if q.Query().Get("client_metadata") != "" {
		t.Error("no client_metadata should be advertised without an encryption key")
	}
}

// TestEncryptedResponseRoundTrip is the full flow: issue a bound credential,
// present it, encrypt the response to the verifier's advertised JWK, and drive
// it through the verifier's decrypt + ProcessResponse.
func TestEncryptedResponseRoundTrip(t *testing.T) {
	v, encKey := encVerifier(t)

	// Issuer + holder.
	iss, err := compliance.NewIssuer("did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	v.TrustedIssuers = map[string][]byte{"did:web:issuer.example": iss.PublicKey()}
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Build a DCQL request (also exercises the advertisement path).
	reqURL, state, err := v.CreateRequestDCQL(DCQLQuery{Credentials: []CredentialQuery{{
		ID: "dpp", Format: FormatSDJWT,
		Meta:   &CredentialQueryMeta{VCTValues: []string{"DigitalProductPassport"}},
		Claims: []ClaimQuery{{Path: []any{"carbonKgCO2ePerKWh"}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	nonce := mustNonce(t, reqURL)

	sdjwt, _, err := iss.IssueSDJWTVCBound("DigitalProductPassport", "battery-1",
		map[string]any{"carbonKgCO2ePerKWh": 42.0}, nil, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := compliance.PresentWithKeyBindingTx(sdjwt, []string{"carbonKgCO2ePerKWh"},
		holderPriv, nonce, v.ClientID, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Wallet encrypts the response to the advertised JWK.
	jwk, err := jwkFromRequest(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := EncryptAuthorizationResponse(
		&AuthorizationResponse{VPToken: presented, State: state}, jwk, []byte("wallet"), nil)
	if err != nil {
		t.Fatalf("wallet encrypt: %v", err)
	}

	// Verifier decrypts and processes.
	resp, err := v.DecryptResponse(compact)
	if err != nil {
		t.Fatalf("verifier decrypt: %v", err)
	}
	if resp.State != state {
		t.Errorf("state mismatch after decrypt: %q", resp.State)
	}
	vp, err := v.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("process decrypted response: %v", err)
	}
	if vp.Claims["carbonKgCO2ePerKWh"] != 42.0 {
		t.Errorf("claim missing after encrypted round trip: %v", vp.Claims)
	}

	// Sanity: the plaintext must not be recoverable with a different key.
	_ = encKey
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v2 := NewVerifier("did:web:v2", "https://v2/cb", nil)
	v2.ResponseEncryptionKey = other
	t.Cleanup(func() { _ = v2.Close() })
	if _, err := v2.DecryptResponse(compact); err == nil {
		t.Error("a different verifier key must not decrypt the response")
	}
}

// TestParseSubmissionEncryptedForm proves the CallbackHandler's parse path
// recognises and decrypts an encrypted form submission (`response` parameter).
func TestParseSubmissionEncryptedForm(t *testing.T) {
	v, _ := encVerifier(t)
	jwk, err := jwe_PublicKeyJWK(t, v)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := EncryptAuthorizationResponse(
		&AuthorizationResponse{VPToken: "eyJ.fake.jwt~", State: "st"}, jwk, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"response": {compact}}.Encode()
	resp, err := v.parseSubmission("application/x-www-form-urlencoded", []byte(form))
	if err != nil {
		t.Fatalf("parse encrypted form: %v", err)
	}
	if resp.VPToken != "eyJ.fake.jwt~" || resp.State != "st" {
		t.Errorf("decrypted submission wrong: %+v", resp)
	}
}

// TestEncryptedResponseToUnconfiguredVerifierRejected: an encrypted `response`
// to a verifier without an encryption key must be refused, not mis-parsed.
func TestEncryptedResponseToUnconfiguredVerifierRejected(t *testing.T) {
	v := NewVerifier("did:web:v", "https://v/cb", nil)
	t.Cleanup(func() { _ = v.Close() })
	form := url.Values{"response": {"a.b.c.d.e"}}.Encode()
	if _, err := v.parseSubmission("application/x-www-form-urlencoded", []byte(form)); err != ErrEncryptedResponseUnsupported {
		t.Fatalf("want ErrEncryptedResponseUnsupported, got %v", err)
	}
}

// TestPlaintextSubmissionStillWorks: a verifier WITH an encryption key still
// accepts a plaintext vp_token form (encryption is offered, not forced here).
func TestPlaintextSubmissionStillWorks(t *testing.T) {
	v, _ := encVerifier(t)
	form := url.Values{"vp_token": {"eyJ.x~"}, "state": {"s"}}.Encode()
	resp, err := v.parseSubmission("application/x-www-form-urlencoded", []byte(form))
	if err != nil {
		t.Fatalf("plaintext submission: %v", err)
	}
	if resp.VPToken != "eyJ.x~" {
		t.Errorf("got %+v", resp)
	}
}

// --- helpers ---

func mustNonce(t *testing.T, reqURL string) string {
	t.Helper()
	u, err := url.Parse(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	n := u.Query().Get("nonce")
	if n == "" {
		t.Fatal("no nonce in request")
	}
	return n
}

func jwkFromRequest(reqURL string) (map[string]any, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
	}
	var cm map[string]any
	if err := json.Unmarshal([]byte(u.Query().Get("client_metadata")), &cm); err != nil {
		return nil, err
	}
	keys := cm["jwks"].(map[string]any)["keys"].([]any)
	return keys[0].(map[string]any), nil
}

func jwe_PublicKeyJWK(t *testing.T, v *Verifier) (map[string]any, error) {
	t.Helper()
	req := &AuthorizationRequest{}
	if err := v.applyResponseEncryption(req); err != nil {
		return nil, err
	}
	keys := req.ClientMetadata["jwks"].(map[string]any)["keys"].([]any)
	return keys[0].(map[string]any), nil
}
