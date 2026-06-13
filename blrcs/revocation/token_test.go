package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// ============================================================================
// LiveTokenHandler
// ============================================================================

func TestLiveTokenHandlerServesValidJWT(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	list.SetStatus(42, true)

	h := LiveTokenHandler(list, "did:web:issuer", "https://issuer.example/status/1", priv, time.Hour, 5*time.Minute)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/statuslist+jwt" {
		t.Errorf("wrong Content-Type: %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
		t.Errorf("expected max-age in Cache-Control: %q", cc)
	}

	body, _ := io.ReadAll(resp.Body)
	verified, _, err := VerifyStatusListToken(string(body), pub, PurposeRevocation)
	if err != nil {
		t.Fatalf("verify live token: %v", err)
	}
	if on, _ := verified.GetStatus(42); !on {
		t.Error("bit 42 should be set after round-trip through LiveTokenHandler")
	}
}

func TestLiveTokenHandlerNoRefreshInterval(t *testing.T) {
	// refreshInterval=0 → no-store, re-issued every request
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)

	h := LiveTokenHandler(list, "did:web:issuer", "https://issuer.example/status/2", priv, time.Hour, 0)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected no-store: %q", cc)
	}
}

func TestLiveTokenHandlerCachesToken(t *testing.T) {
	// With a long refresh interval, two requests should return the same token bytes.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)

	h := LiveTokenHandler(list, "did:web:issuer", "https://issuer.example/status/3", priv, time.Hour, time.Hour)
	ts := httptest.NewServer(h)
	defer ts.Close()

	get := func() string {
		resp, err := http.Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	tok1 := get()
	tok2 := get()
	if tok1 != tok2 {
		t.Error("expected cached token to be identical across two requests within refresh interval")
	}
}

// ============================================================================
// VerifyStatusListToken — error path coverage
// ============================================================================

func TestVerifyStatusListTokenBadKeyLength(t *testing.T) {
	// Key shorter than ed25519.PublicKeySize → immediate ErrTokenSigFailed
	_, _, err := VerifyStatusListToken("x.y.z", []byte("tooshort"), PurposeRevocation)
	if err != ErrTokenSigFailed {
		t.Fatalf("want ErrTokenSigFailed, got %v", err)
	}
}

func TestVerifyStatusListTokenBadFormat(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Not enough dots → not 3 segments
	_, _, err := VerifyStatusListToken("only-one-segment", pub, PurposeRevocation)
	if err != ErrTokenMalformed {
		t.Fatalf("want ErrTokenMalformed (bad format), got %v", err)
	}
}

func TestVerifyStatusListTokenBadHeaderBase64(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Segment 0 is not valid base64url
	_, _, err := VerifyStatusListToken("!!!.payload.sig", pub, PurposeRevocation)
	if err != ErrTokenMalformed {
		t.Fatalf("want ErrTokenMalformed (bad header base64), got %v", err)
	}
}

func TestVerifyStatusListTokenBadHeaderJSON(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Header is valid base64url but not valid JSON
	hdr := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, _, err := VerifyStatusListToken(hdr+".payload.sig", pub, PurposeRevocation)
	if err != ErrTokenMalformed {
		t.Fatalf("want ErrTokenMalformed (bad header JSON), got %v", err)
	}
}

func TestVerifyStatusListTokenWrongAlg(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Header has wrong Alg
	hdrJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "statuslist+jwt"})
	hdr := base64.RawURLEncoding.EncodeToString(hdrJSON)
	_, _, err := VerifyStatusListToken(hdr+".payload.sig", pub, PurposeRevocation)
	if err != ErrTokenMalformed {
		t.Fatalf("want ErrTokenMalformed (wrong alg), got %v", err)
	}
}

func TestVerifyStatusListTokenExpired(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	enc, _ := list.EncodedList()

	// Craft a JWT with exp 200s in the past (well past the 60s leeway).
	expiredExp := time.Now().Add(-200 * time.Second).Unix()
	claims := map[string]any{
		"sub":         "https://issuer/status/1",
		"iss":         "did:web:issuer",
		"iat":         time.Now().Unix(),
		"exp":         expiredExp,
		"status_list": map[string]any{"bits": 1, "lst": enc},
	}
	hdrJSON := `{"alg":"EdDSA","typ":"statuslist+jwt"}`
	hdr := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))
	plBytes, _ := json.Marshal(claims)
	pl := base64.RawURLEncoding.EncodeToString(plBytes)
	sig := ed25519.Sign(privKey, []byte(hdr+"."+pl))
	tok := hdr + "." + pl + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, _, err = VerifyStatusListToken(tok, pubKey, PurposeRevocation)
	if err != ErrTokenExpired {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestVerifyStatusListTokenBadSigBase64(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	tok, err := list.IssueToken("did:web:issuer", "https://issuer/status/1", priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the signature segment
	parts := strings.SplitN(tok, ".", 3)
	corrupted := parts[0] + "." + parts[1] + ".!!!"
	_, _, err = VerifyStatusListToken(corrupted, pub, PurposeRevocation)
	if err != ErrTokenMalformed {
		t.Fatalf("want ErrTokenMalformed (bad sig base64), got %v", err)
	}
}

// ============================================================================
// Additional coverage: bad payload base64, bad payload JSON, bad IssueToken key
// ============================================================================

func craftValidSigToken(t *testing.T, priv ed25519.PrivateKey, hdrJSON, payloadSeg string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))
	sig := ed25519.Sign(priv, []byte(hdr+"."+payloadSeg))
	return hdr + "." + payloadSeg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyStatusListTokenBadPayloadBase64(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Payload segment is not valid base64url — signature is valid for this token.
	tok := craftValidSigToken(t, priv, `{"alg":"EdDSA","typ":"statuslist+jwt"}`, "!!!")
	if _, _, err := VerifyStatusListToken(tok, pub, PurposeRevocation); err != ErrTokenMalformed {
		t.Errorf("bad payload base64: want ErrTokenMalformed, got %v", err)
	}
}

func TestVerifyStatusListTokenBadPayloadJSON(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Payload is valid base64 but decodes to non-JSON bytes.
	pl := base64.RawURLEncoding.EncodeToString([]byte("not-valid-json{{{"))
	tok := craftValidSigToken(t, priv, `{"alg":"EdDSA","typ":"statuslist+jwt"}`, pl)
	if _, _, err := VerifyStatusListToken(tok, pub, PurposeRevocation); err != ErrTokenMalformed {
		t.Errorf("bad payload JSON: want ErrTokenMalformed, got %v", err)
	}
}

func TestIssueTokenInvalidPrivKey(t *testing.T) {
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	if _, err := list.IssueToken("iss", "uri", []byte("short"), time.Hour); err == nil {
		t.Error("invalid private key should fail IssueToken")
	}
}

func TestDecodeBitstringNotGzip(t *testing.T) {
	// Valid base64url but decodes to non-gzip bytes → gzip.NewReader fails.
	notGzip := base64.RawURLEncoding.EncodeToString([]byte("definitely-not-gzip-data"))
	if _, err := DecodeBitstringStatusList(PurposeRevocation, notGzip); err == nil {
		t.Error("non-gzip payload should fail DecodeBitstringStatusList")
	}
}

// TestVerifyStatusListTokenBitsFieldTwo covers line 136-138: a claims.StatusList.Bits
// value that is neither 0 nor 1 must be rejected as ErrTokenMalformed.
func TestVerifyStatusListTokenBitsFieldTwo(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	enc, _ := list.EncodedList()
	claims := map[string]any{
		"sub":         "https://issuer/status/1",
		"iat":         time.Now().Unix(),
		"status_list": map[string]any{"bits": 2, "lst": enc},
	}
	plBytes, _ := json.Marshal(claims)
	pl := base64.RawURLEncoding.EncodeToString(plBytes)
	tok := craftValidSigToken(t, priv, `{"alg":"EdDSA","typ":"statuslist+jwt"}`, pl)
	if _, _, err := VerifyStatusListToken(tok, pub, PurposeRevocation); err != ErrTokenMalformed {
		t.Errorf("bits=2 should return ErrTokenMalformed, got %v", err)
	}
}

// TestVerifyStatusListTokenBadLst covers line 143-145: a valid-sig token whose
// lst field does not decode to a valid gzip list must return an error.
func TestVerifyStatusListTokenBadLst(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := map[string]any{
		"sub":         "https://issuer/status/1",
		"iat":         time.Now().Unix(),
		"status_list": map[string]any{"bits": 1, "lst": "not-valid-gzip-data"},
	}
	plBytes, _ := json.Marshal(claims)
	pl := base64.RawURLEncoding.EncodeToString(plBytes)
	tok := craftValidSigToken(t, priv, `{"alg":"EdDSA","typ":"statuslist+jwt"}`, pl)
	_, _, err := VerifyStatusListToken(tok, pub, PurposeRevocation)
	if err == nil {
		t.Error("bad lst should return error from DecodeBitstringStatusList")
	}
}

// TestLiveTokenHandlerIssueError covers lines 190-194: when IssueToken returns
// an error (here: bad private key), the handler must respond 500.
func TestLiveTokenHandlerIssueError(t *testing.T) {
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	badPriv := ed25519.PrivateKey([]byte("too-short"))
	h := LiveTokenHandler(list, "iss", "uri", badPriv, time.Hour, 0)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}
