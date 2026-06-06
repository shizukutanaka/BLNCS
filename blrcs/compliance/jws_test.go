package compliance

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// reHeaderAlg replaces the JOSE header of an issued SD-JWT with one carrying the
// given alg, re-signing the issuer JWT with priv so the signature stays valid.
func reHeaderAlg(t *testing.T, sdjwt string, priv ed25519.PrivateKey, alg string) string {
	t.Helper()
	tilde := strings.IndexByte(sdjwt, '~')
	jwt := sdjwt
	tail := ""
	if tilde >= 0 {
		jwt, tail = sdjwt[:tilde], sdjwt[tilde:]
	}
	segs := strings.SplitN(jwt, ".", 3)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"vc+sd-jwt"}`))
	sigInput := header + "." + segs[1]
	sig := ed25519.Sign(priv, []byte(sigInput))
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig) + tail
}

func TestVerifyRejectsUnsupportedAlg(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	// "none" is not registered → must be rejected before signature handling.
	forged := reHeaderAlg(t, sdjwt, iss.PrivateKey(), "none")
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != ErrSDJWTUnsupportedAlg {
		t.Fatalf("alg=none: want ErrSDJWTUnsupportedAlg, got %v", err)
	}
}

func TestRegisterJWSVerifierEnablesAlg(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)

	const alg = "EdDSA-test"
	// Before registration the custom alg is rejected.
	forged := reHeaderAlg(t, sdjwt, iss.PrivateKey(), alg)
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != ErrSDJWTUnsupportedAlg {
		t.Fatalf("pre-register: want ErrSDJWTUnsupportedAlg, got %v", err)
	}
	// Register an Ed25519-backed verifier under the custom alg name → now verifies.
	RegisterJWSVerifier(alg, func(pub, msg, sig []byte) bool {
		return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
	})
	vc, err := VerifySDJWT(forged, iss.PublicKey())
	if err != nil {
		t.Fatalf("post-register verify: %v", err)
	}
	if vc.Claims["a"] == nil {
		t.Error("claim not extracted after custom-alg verify")
	}
	// A wrong key must still fail signature verification (registry doesn't bypass it).
	other, _ := NewIssuer("did:web:other")
	if _, err := VerifySDJWT(forged, other.PublicKey()); err != ErrSDJWTSigFailed {
		t.Fatalf("wrong key: want ErrSDJWTSigFailed, got %v", err)
	}
}

func TestEdDSAStillDefault(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	if _, err := VerifySDJWT(sdjwt, iss.PublicKey()); err != nil {
		t.Fatalf("built-in EdDSA must verify: %v", err)
	}
}
