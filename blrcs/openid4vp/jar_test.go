package openid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// signedVerifier returns a Verifier whose requests are JAR-signed, plus the
// matching public key a wallet would use to verify them.
func signedVerifier(t *testing.T) (*Verifier, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ver := NewVerifier(
		"https://verify.blrcs.example",
		"https://verify.blrcs.example/openid4vp/callback",
		nil,
	)
	ver.RequestSigningKey = priv
	return ver, pub
}

func simplePD() PresentationDefinition {
	return PresentationDefinition{
		ID:             "pd-jar",
		RequiredClaims: []string{"category"},
	}
}

// TestJAR_RoundTrip: a JAR-signed request verifies and yields the authenticated
// response_uri / nonce / client_id.
func TestJAR_RoundTrip(t *testing.T) {
	ver, pub := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	authReq, err := VerifyRequestObject(reqURL, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if authReq.ClientID != ver.ClientID {
		t.Errorf("client_id: got %q", authReq.ClientID)
	}
	if authReq.ResponseURI != ver.ResponseURI {
		t.Errorf("response_uri: got %q", authReq.ResponseURI)
	}
	if authReq.Nonce == "" {
		t.Error("nonce missing from authenticated request")
	}
}

// TestJAR_TamperedResponseURIDetected is the core defense: a relay attacker keeps
// the genuine client_id but rewrites response_uri to its own endpoint. Because
// response_uri is inside the signed object, the wallet's verification fails.
func TestJAR_TamperedResponseURIDetected(t *testing.T) {
	ver, pub := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}

	// Attacker rewrites the (unsigned) response_uri query param. A non-JAR wallet
	// would POST to the attacker; a JAR-aware wallet reads response_uri from the
	// *signed* object, so the tamper has no effect on where it sends the response.
	u, _ := url.Parse(reqURL)
	q := u.Query()
	q.Set("response_uri", "https://attacker.example/steal")
	u.RawQuery = q.Encode()

	authReq, err := VerifyRequestObject(u.String(), pub)
	if err != nil {
		t.Fatalf("verify of (param-tampered) request: %v", err)
	}
	// The authenticated response_uri is the verifier's, NOT the attacker's.
	if authReq.ResponseURI != ver.ResponseURI {
		t.Fatalf("authenticated response_uri must come from the signed object, got %q",
			authReq.ResponseURI)
	}
	if strings.Contains(authReq.ResponseURI, "attacker") {
		t.Fatal("attacker response_uri leaked into authenticated request")
	}
}

// TestJAR_TamperedSignedPayloadRejected: mutating a byte inside the signed JWT
// payload breaks the signature.
func TestJAR_TamperedSignedPayloadRejected(t *testing.T) {
	ver, pub := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(reqURL)
	q := u.Query()
	jwt := q.Get("request")
	parts := strings.Split(jwt, ".")
	// Flip a character in the payload segment.
	pl := []byte(parts[1])
	pl[len(pl)/2] ^= 0x01
	parts[1] = string(pl)
	q.Set("request", strings.Join(parts, "."))
	u.RawQuery = q.Encode()

	if _, err := VerifyRequestObject(u.String(), pub); !errors.Is(err, ErrRequestObjectInvalid) {
		t.Fatalf("tampered payload: want ErrRequestObjectInvalid, got %v", err)
	}
}

// TestJAR_WrongVerifierKeyRejected: a request signed by one verifier does not
// verify under a different verifier's key.
func TestJAR_WrongVerifierKeyRejected(t *testing.T) {
	ver, _ := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyRequestObject(reqURL, otherPub); !errors.Is(err, ErrRequestObjectInvalid) {
		t.Fatalf("wrong key: want ErrRequestObjectInvalid, got %v", err)
	}
}

// TestJAR_ClientIDMismatchRejected: an attacker presents a genuinely-signed
// request object but under a different top-level client_id context.
func TestJAR_ClientIDMismatchRejected(t *testing.T) {
	ver, pub := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(reqURL)
	q := u.Query()
	q.Set("client_id", "https://different-verifier.example")
	u.RawQuery = q.Encode()
	if _, err := VerifyRequestObject(u.String(), pub); !errors.Is(err, ErrRequestObjectInvalid) {
		t.Fatalf("client_id mismatch: want ErrRequestObjectInvalid, got %v", err)
	}
}

// TestJAR_AlgConfusionRejected: header alg/typ are pinned; a "none"/HS256 header
// must not be accepted (no header-dispatched verifier).
func TestJAR_AlgConfusionRejected(t *testing.T) {
	ver, pub := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(reqURL)
	q := u.Query()
	jwt := q.Get("request")
	parts := strings.Split(jwt, ".")
	for _, badHdr := range []string{
		`{"alg":"none","typ":"oauth-authz-req+jwt"}`,
		`{"alg":"HS256","typ":"oauth-authz-req+jwt"}`,
		`{"alg":"EdDSA","typ":"JWT"}`,
	} {
		parts[0] = base64.RawURLEncoding.EncodeToString([]byte(badHdr))
		q.Set("request", strings.Join(parts, "."))
		u.RawQuery = q.Encode()
		if _, err := VerifyRequestObject(u.String(), pub); !errors.Is(err, ErrRequestObjectInvalid) {
			t.Fatalf("alg/typ=%s: want ErrRequestObjectInvalid, got %v", badHdr, err)
		}
	}
}

// TestJAR_MissingRequestObject: a plain (unsigned) request URL has no `request`
// param; VerifyRequestObject reports it distinctly so callers can decide policy.
func TestJAR_MissingRequestObject(t *testing.T) {
	ver, _ := setupFlow(t) // unsigned verifier (no RequestSigningKey)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequestObject(reqURL, pub); !errors.Is(err, ErrRequestObjectMissing) {
		t.Fatalf("unsigned request: want ErrRequestObjectMissing, got %v", err)
	}
}

// TestJAR_BackCompatUnsigned: when no signing key is set, CreateRequest still
// produces a working unsigned request (no `request` param).
func TestJAR_BackCompatUnsigned(t *testing.T) {
	ver, _ := setupFlow(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(reqURL)
	if u.Query().Get("request") != "" {
		t.Error("unsigned verifier must not emit a request object")
	}
}

// TestJAR_ExpiredRequestObjectRejected verifies that a JAR whose `exp` is in the
// past (beyond the 60s leeway) is rejected. Without this, a stolen signed
// Authorization Request remains valid forever — defeating the short-lived JAR
// anti-replay property.
func TestJAR_ExpiredRequestObjectRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Build a JAR manually with exp in the far past (> 60s leeway).
	pastExp := time.Now().UTC().Add(-10 * time.Minute).Unix()
	payload := map[string]any{
		"iss":           "https://v.example",
		"client_id":     "https://v.example",
		"response_type": "vp_token",
		"response_uri":  "https://v.example/cb",
		"nonce":         "n",
		"state":         "s",
		"exp":           pastExp,
	}
	payloadBytes, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"oauth-authz-req+jwt"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(sigInput))
	jwt := sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	reqURL := "https://v.example/openid4vp?client_id=https%3A%2F%2Fv.example&request=" + url.QueryEscape(jwt)
	if _, err := VerifyRequestObject(reqURL, pub); !errors.Is(err, ErrRequestObjectInvalid) {
		t.Fatalf("expired JAR should fail, got: %v", err)
	}
}

// TestJAR_BadVerifierKeyRejected verifies that passing an empty/nil verifier pub
// key to VerifyRequestObject fails fast with ErrRequestObjectInvalid rather than
// a silent accept or a panic.
func TestJAR_BadVerifierKeyRejected(t *testing.T) {
	ver, _ := signedVerifier(t)
	reqURL, _, err := ver.CreateRequest(simplePD())
	if err != nil {
		t.Fatal(err)
	}
	// zero-length key
	if _, err := VerifyRequestObject(reqURL, ed25519.PublicKey{}); !errors.Is(err, ErrRequestObjectInvalid) {
		t.Fatalf("zero-length pub key: want ErrRequestObjectInvalid, got %v", err)
	}
}

// TestJAR_SignRequestObjectBadPrivateKey verifies signRequestObject returns an
// error when handed a short/invalid private key, not a panic or silent success.
func TestJAR_SignRequestObjectBadPrivateKey(t *testing.T) {
	req := &AuthorizationRequest{ClientID: "https://v.example"}
	_, err := signRequestObject(req, ed25519.PrivateKey{}, time.Minute)
	if !errors.Is(err, ErrRequestObjectInvalid) {
		t.Fatalf("bad private key: want ErrRequestObjectInvalid, got %v", err)
	}
}
