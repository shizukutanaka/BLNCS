package openid4vci

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// Axis 130: batch issuance (OpenID4VCI 1.0 §8.2/§8.3)
// ============================================================================

// batchSetup creates an offer, exchanges it, and returns the issuer, the access
// token, and the token-bound c_nonce ready for a batch credential request.
func batchSetup(t *testing.T) (iss *Issuer, accessToken, cNonce string) {
	t.Helper()
	iss, _ = setupIssuer(t)
	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "bat-batch",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	return iss, tr.AccessToken, tr.CNonce
}

// sdjwtHolderCnf decodes the cnf.jwk x value (holder public key) embedded in an
// issued SD-JWT's JWT part, so a test can prove each batch credential is bound to
// a distinct holder key.
func sdjwtHolderCnf(t *testing.T, sdjwt string) string {
	t.Helper()
	jwtPart := strings.SplitN(sdjwt, "~", 2)[0]
	parts := strings.SplitN(jwtPart, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("malformed SD-JWT: %s", sdjwt)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Cnf struct {
			JWK struct {
				X string `json:"x"`
			} `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims.Cnf.JWK.X
}

func TestIssueBatchWithProofsHappy(t *testing.T) {
	iss, accessToken, cNonce := batchSetup(t)

	// Three distinct holder keys → three proofs → three distinct bound credentials.
	var jwts []string
	var wantX []string
	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		jwts = append(jwts, buildProofJWT(t, priv, cNonce, iss.URL))
		wantX = append(wantX, base64.RawURLEncoding.EncodeToString(pub))
	}

	resp, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{
		Proofs: &ProofsObject{JWT: jwts},
	})
	if err != nil {
		t.Fatalf("IssueBatchWithProofs: %v", err)
	}
	if len(resp.Credentials) != 3 {
		t.Fatalf("want 3 credentials, got %d", len(resp.Credentials))
	}
	if resp.NotificationID == "" {
		t.Error("batch response must carry a single notification_id")
	}
	// Each credential must be bound to its corresponding holder key (cnf), and all
	// three must be distinct (the unlinkability property batch issuance provides).
	seen := map[string]bool{}
	for i, c := range resp.Credentials {
		gotX := sdjwtHolderCnf(t, c.Credential)
		if gotX != wantX[i] {
			t.Errorf("credential %d bound to wrong holder key: got %s want %s", i, gotX, wantX[i])
		}
		if seen[gotX] {
			t.Errorf("credential %d duplicates an earlier holder binding", i)
		}
		seen[gotX] = true
	}
}

// TestIssueBatchSingleNotificationCovers proves one notification_id is issued for
// the whole batch and can be submitted with the same access token.
func TestIssueBatchSingleNotificationCovers(t *testing.T) {
	iss, accessToken, cNonce := batchSetup(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{
		Proofs: &ProofsObject{JWT: []string{buildProofJWT(t, priv, cNonce, iss.URL)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.HandleNotification(accessToken, NotificationRequest{
		NotificationID: resp.NotificationID, Event: NotificationEventAccepted,
	}); err != nil {
		t.Errorf("batch notification_id should be accepted: %v", err)
	}
}

// TestIssueBatchAllOrNothing proves that if any proof in the batch is invalid, no
// credentials are issued AND the access token is not consumed (a retry works).
func TestIssueBatchAllOrNothing(t *testing.T) {
	iss, accessToken, cNonce := batchSetup(t)
	_, good, _ := ed25519.GenerateKey(rand.Reader)

	// Second proof carries the wrong nonce → whole batch must fail.
	badJWT := buildProofJWT(t, good, "wrong-nonce", iss.URL)
	goodJWT := buildProofJWT(t, good, cNonce, iss.URL)

	_, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{
		Proofs: &ProofsObject{JWT: []string{goodJWT, badJWT}},
	})
	if err != ErrProofNonceMismatch {
		t.Fatalf("batch with one bad proof: want ErrProofNonceMismatch, got %v", err)
	}

	// The token must NOT have been consumed — a corrected batch succeeds.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{
		Proofs: &ProofsObject{JWT: []string{buildProofJWT(t, priv2, cNonce, iss.URL)}},
	})
	if err != nil {
		t.Fatalf("retry after failed batch should succeed (token not consumed): %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Errorf("want 1 credential on retry, got %d", len(resp.Credentials))
	}
}

func TestIssueBatchRejectsProofAndProofs(t *testing.T) {
	iss, accessToken, cNonce := batchSetup(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proofJSON, _ := json.Marshal(map[string]string{"proof_type": "jwt", "jwt": buildProofJWT(t, priv, cNonce, iss.URL)})
	_, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{
		Proof:  proofJSON,
		Proofs: &ProofsObject{JWT: []string{buildProofJWT(t, priv, cNonce, iss.URL)}},
	})
	if err != ErrInvalidProof {
		t.Fatalf("proof and proofs together: want ErrInvalidProof, got %v", err)
	}
}

func TestIssueBatchEmptyProofs(t *testing.T) {
	iss, accessToken, _ := batchSetup(t)
	if _, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{Proofs: &ProofsObject{}}); err != ErrInvalidProof {
		t.Fatalf("empty proofs.jwt: want ErrInvalidProof, got %v", err)
	}
}

func TestIssueBatchOverLimit(t *testing.T) {
	iss, accessToken, cNonce := batchSetup(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwts := make([]string, maxBatchProofs+1)
	for i := range jwts {
		jwts[i] = buildProofJWT(t, priv, cNonce, iss.URL)
	}
	_, err := iss.IssueBatchWithProofs(accessToken, CredentialRequest{Proofs: &ProofsObject{JWT: jwts}})
	if err == nil {
		t.Fatal("batch over maxBatchProofs should error")
	}
}

func TestIssueBatchBadAccessToken(t *testing.T) {
	iss, _, cNonce := batchSetup(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := iss.IssueBatchWithProofs("nope", CredentialRequest{Proofs: &ProofsObject{JWT: []string{buildProofJWT(t, priv, cNonce, iss.URL)}}})
	if err != ErrBadAccessToken {
		t.Fatalf("bad token: want ErrBadAccessToken, got %v", err)
	}
}

// ============================================================================
// HTTP layer — /credential dispatches batch vs single by request shape
// ============================================================================

func TestBatchCredentialEndpointHTTP(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()
	iss.URL = ts.URL

	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "bat-http",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 1.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	var jwts []string
	for i := 0; i < 2; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		jwts = append(jwts, buildProofJWT(t, priv, tr.CNonce, ts.URL))
	}
	body, _ := json.Marshal(CredentialRequest{Proofs: &ProofsObject{JWT: jwts}})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/credential", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var out BatchCredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Credentials) != 2 {
		t.Fatalf("want 2 credentials in HTTP batch response, got %d", len(out.Credentials))
	}
	if out.Credentials[0].Credential == "" {
		t.Error("empty credential in batch response")
	}
}
