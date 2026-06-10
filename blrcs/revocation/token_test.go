package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatusListTokenRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	if err := list.SetStatus(99, true); err != nil {
		t.Fatal(err)
	}
	token, err := list.IssueToken("did:web:issuer", "https://issuer.example/status/1", priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, meta, err := VerifyStatusListToken(token, pub, PurposeRevocation)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if meta.Subject != "https://issuer.example/status/1" {
		t.Errorf("subject: %s", meta.Subject)
	}
	on, err := got.GetStatus(99)
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Error("bit 99 should be set after round-trip")
	}
	if off, _ := got.GetStatus(100); off {
		t.Error("bit 100 should be unset")
	}
}

func TestStatusListTokenWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	token, _ := list.IssueToken("iss", "uri", priv, time.Hour)
	if _, _, err := VerifyStatusListToken(token, otherPub, PurposeRevocation); err != ErrTokenSigFailed {
		t.Fatalf("want ErrTokenSigFailed, got %v", err)
	}
}

func TestStatusListTokenExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	enc, _ := list.EncodedList()

	// Craft a token whose exp is well in the past (beyond the 60s leeway).
	var claims statusListClaims
	claims.Sub = "https://issuer.example/status/1"
	claims.Iat = time.Now().Add(-2 * time.Hour).Unix()
	claims.Exp = time.Now().Add(-1 * time.Hour).Unix()
	claims.StatusList.Bits = 1
	claims.StatusList.Lst = enc

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"statuslist+jwt"}`))
	plBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(plBytes)
	sig := ed25519.Sign(priv, []byte(header+"."+payload))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, _, err := VerifyStatusListToken(token, pub, PurposeRevocation); err != ErrTokenExpired {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestStatusListTokenMalformed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := VerifyStatusListToken("not-a-jwt", pub, PurposeRevocation); err != ErrTokenMalformed {
		t.Fatalf("want ErrTokenMalformed, got %v", err)
	}
}

func TestTokenHandlerServesContentType(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	token, _ := list.IssueToken("iss", "https://issuer.example/status/1", priv, time.Hour)

	srv := httptest.NewServer(TokenHandler(token, 5*time.Minute))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/statuslist+jwt" {
		t.Errorf("content-type: %s", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("cache-control: %s", cc)
	}
}

func TestVerifyStatusListTokenRejectsBadBits(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, 131072)
	tok, err := list.IssueToken("did:web:issuer", "https://issuer/status/1", priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Valid token verifies.
	if _, _, err := VerifyStatusListToken(tok, pub, PurposeRevocation); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	// Wrong key fails.
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := VerifyStatusListToken(tok, wrongPub, PurposeRevocation); err == nil {
		t.Error("wrong key should fail")
	}
}

// ============================================================================
// TokenMeta.IsStale — TTL freshness (draft-ietf-oauth-status-list)
// ============================================================================

func TestTokenMetaIsStale(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// Issued now, TTL=3600s → fresh at +30min, stale at +61min.
	m := &TokenMeta{IssuedAt: now.Unix(), TTL: 3600}
	if m.IsStaleAt(now.Add(30 * time.Minute)) {
		t.Error("token within TTL window must not be stale")
	}
	if !m.IsStaleAt(now.Add(61 * time.Minute)) {
		t.Error("token past TTL window must be stale")
	}
}

func TestTokenMetaIsStaleNoTTL(t *testing.T) {
	// No TTL advertised → never reported stale (caller falls back to exp/policy).
	m := &TokenMeta{IssuedAt: time.Now().Add(-100 * time.Hour).Unix(), TTL: 0}
	if m.IsStale() {
		t.Error("token without TTL must not be reported stale")
	}
}

func TestVerifyStatusListTokenPopulatesTTL(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	tok, err := list.IssueToken("did:web:issuer", "https://issuer/status/1", priv, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err := VerifyStatusListToken(tok, pub, PurposeRevocation)
	if err != nil {
		t.Fatal(err)
	}
	if meta.TTL != int64((2 * time.Hour).Seconds()) {
		t.Errorf("TTL not propagated: %d", meta.TTL)
	}
	if meta.IsStale() {
		t.Error("freshly issued token must not be stale")
	}
}
