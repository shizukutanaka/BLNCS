package compliance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 135: ES256 (P-256) SD-JWT verification
//
// The EUDI ARF and OpenID4VC HAIP mandate P-256, so these tests stand in for
// "a credential issued by a real EUDI wallet ecosystem verifies here".
// ============================================================================

// mintES256SDJWT hand-builds an SD-JWT signed with ES256, using the fixed-width
// R‖S signature form of RFC 7518 §3.4 (NOT ASN.1 DER).
func mintES256SDJWT(t *testing.T, priv *ecdsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	hdr, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, ecdsakey.ES256SignatureSize)
	r.FillBytes(raw[:ecdsakey.P256CoordSize])
	s.FillBytes(raw[ecdsakey.P256CoordSize:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(raw) + "~"
}

func es256Key(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsakey.MarshalP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// TestVerifyES256SDJWT proves an ES256-signed SD-JWT verifies through the
// ordinary verification path — the capability that was previously absent.
func TestVerifyES256SDJWT(t *testing.T) {
	priv, pub := es256Key(t)
	sdjwt := mintES256SDJWT(t, priv, map[string]any{
		"iss": "did:web:eudi-issuer.example",
		"sub": "battery-001",
		"vct": "DigitalProductPassport",
	})
	vc, err := VerifySDJWTWithBinding(sdjwt, pub, VerifyOptions{})
	if err != nil {
		t.Fatalf("ES256 SD-JWT should verify: %v", err)
	}
	if vc.Subject != "battery-001" || vc.Issuer != "did:web:eudi-issuer.example" {
		t.Errorf("claims not recovered: %+v", vc)
	}
}

func TestES256SDJWTTamperRejected(t *testing.T) {
	priv, pub := es256Key(t)
	sdjwt := mintES256SDJWT(t, priv, map[string]any{"iss": "i", "sub": "battery-001"})
	parts := strings.SplitN(sdjwt, ".", 3)
	// Re-encode a different payload while keeping the original signature.
	forged, err := json.Marshal(map[string]any{"iss": "i", "sub": "battery-EVIL"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if _, err := VerifySDJWTWithBinding(tampered, pub, VerifyOptions{}); err == nil {
		t.Fatal("tampered ES256 SD-JWT must not verify")
	}
}

func TestES256SDJWTWrongKeyRejected(t *testing.T) {
	priv, _ := es256Key(t)
	_, otherPub := es256Key(t)
	sdjwt := mintES256SDJWT(t, priv, map[string]any{"iss": "i", "sub": "s"})
	if _, err := VerifySDJWTWithBinding(sdjwt, otherPub, VerifyOptions{}); err == nil {
		t.Fatal("ES256 SD-JWT must not verify under a different key")
	}
}

// TestES256RespectsAllowedAlgs proves the new algorithm still honours the
// downgrade-defence allowlist: pinning EdDSA must reject an ES256 credential,
// and vice versa.
func TestES256RespectsAllowedAlgs(t *testing.T) {
	priv, pub := es256Key(t)
	// vct is required by the SD-JWT-VC checks that run after signature
	// verification; include it so this test isolates the allowlist behaviour.
	sdjwt := mintES256SDJWT(t, priv, map[string]any{"iss": "i", "sub": "s", "vct": "DigitalProductPassport"})

	if _, err := VerifySDJWTWithBinding(sdjwt, pub, VerifyOptions{AllowedAlgs: []string{"EdDSA"}}); err == nil {
		t.Error("ES256 credential must be rejected when only EdDSA is allowed")
	}
	if _, err := VerifySDJWTWithBinding(sdjwt, pub, VerifyOptions{AllowedAlgs: []string{"ES256"}}); err != nil {
		t.Errorf("ES256 credential should pass an ES256 allowlist: %v", err)
	}
}

// TestES256DERSignatureRejectedEndToEnd confirms the encoding-confusion guard
// survives through the full SD-JWT path, not just the unit level.
func TestES256DERSignatureRejectedEndToEnd(t *testing.T) {
	priv, pub := es256Key(t)
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	pl, _ := json.Marshal(map[string]any{"iss": "i", "sub": "s"})
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	digest := sha256.Sum256([]byte(signingInput))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sdjwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(der) + "~"
	if _, err := VerifySDJWTWithBinding(sdjwt, pub, VerifyOptions{}); err == nil {
		t.Fatal("DER-encoded ES256 signature must be rejected end to end")
	}
}

// TestEd25519StillWorksAlongsideES256 guards against the new registration
// disturbing the existing default path.
func TestEd25519StillWorksAlongsideES256(t *testing.T) {
	iss, err := NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	sdjwt, _, err := iss.IssueSDJWT("battery-9", map[string]any{"a": 1.0}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); err != nil {
		t.Fatalf("EdDSA path must be unaffected: %v", err)
	}
}
