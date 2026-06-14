package compliance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// resignPayload rebuilds an SD-JWT's issuer JWT from a mutated payload map,
// re-signing with priv so the signature stays valid. Disclosures/tail preserved.
func resignPayload(t *testing.T, sdjwt string, priv ed25519.PrivateKey, mutate func(map[string]any)) string {
	t.Helper()
	tilde := strings.IndexByte(sdjwt, '~')
	jwt, tail := sdjwt, ""
	if tilde >= 0 {
		jwt, tail = sdjwt[:tilde], sdjwt[tilde:]
	}
	segs := strings.SplitN(jwt, ".", 3)
	plBytes, _ := base64.RawURLEncoding.DecodeString(segs[1])
	var pl map[string]any
	if err := json.Unmarshal(plBytes, &pl); err != nil {
		t.Fatal(err)
	}
	mutate(pl)
	newPl, _ := json.Marshal(pl)
	sigInput := segs[0] + "." + base64.RawURLEncoding.EncodeToString(newPl)
	sig := ed25519.Sign(priv, []byte(sigInput))
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig) + tail
}

func TestVerifyRejectsUnsupportedHashAlg(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		pl["_sd_alg"] = "sha-512" // unsupported
	})
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != ErrSDJWTUnsupportedHashAlg {
		t.Fatalf("want ErrSDJWTUnsupportedHashAlg, got %v", err)
	}
}

func TestVerifyRequiresVCT(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		delete(pl, "vct")
	})
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != ErrSDJWTMissingVCT {
		t.Fatalf("want ErrSDJWTMissingVCT, got %v", err)
	}
}

func TestVerifyRejectsDuplicateDigest(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1, "b": 2}, nil, time.Hour)
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		sd, _ := pl["_sd"].([]any)
		if len(sd) > 0 {
			pl["_sd"] = append(sd, sd[0]) // duplicate the first digest
		}
	})
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != ErrSDJWTDuplicateDigest {
		t.Fatalf("want ErrSDJWTDuplicateDigest, got %v", err)
	}
}

func TestVerifyAcceptsDefaultSdAlgAbsent(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	// Absent _sd_alg defaults to sha-256 → must still verify.
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		delete(pl, "_sd_alg")
	})
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != nil {
		t.Fatalf("absent _sd_alg should default to sha-256: %v", err)
	}
}

// ============================================================================
// nbf (not-before) — RFC 9901 §4.2.1
// ============================================================================

func TestVerifyRejectsFutureNbf(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	// Set nbf 1 hour in the future — credential must not be accepted yet.
	future := float64(time.Now().Add(time.Hour).Unix())
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		pl["nbf"] = future
	})
	if _, err := VerifySDJWT(forged, iss.PublicKey()); err != ErrSDJWTNotYetValid {
		t.Fatalf("future nbf: want ErrSDJWTNotYetValid, got %v", err)
	}
}

func TestVerifyAcceptsPastNbf(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	// nbf in the past — credential is valid.
	past := float64(time.Now().Add(-time.Hour).Unix())
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		pl["nbf"] = past
	})
	vc, err := VerifySDJWT(forged, iss.PublicKey())
	if err != nil {
		t.Fatalf("past nbf should verify: %v", err)
	}
	if vc.NotBefore == 0 {
		t.Error("NotBefore field should be populated from nbf claim")
	}
}

func TestVerifyNbfNotInClaims(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	past := float64(time.Now().Add(-time.Minute).Unix())
	forged := resignPayload(t, sdjwt, iss.PrivateKey(), func(pl map[string]any) {
		pl["nbf"] = past
	})
	vc, err := VerifySDJWT(forged, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// nbf is a reserved claim and must not appear in vc.Claims.
	if _, ok := vc.Claims["nbf"]; ok {
		t.Error("nbf must be stripped from vc.Claims (reserved)")
	}
}

// TestCrossCredentialDisclosureRejected pins the disclosure-transplant defense
// (domain separation at the credential level): a disclosure minted for credential A
// cannot be grafted onto a presentation of credential B. B's _sd digest set is
// signed by the issuer, so A's disclosure (whose digest is absent from B's _sd) must
// be rejected outright — never silently dropped, which would mask tampering.
func TestCrossCredentialDisclosureRejected(t *testing.T) {
	iss, err := NewIssuer("did:web:issuer")
	if err != nil {
		t.Fatal(err)
	}
	// Credential A carries a "secretA" selectively-disclosable claim.
	aFull, _, err := iss.IssueSDJWT("subA", map[string]any{"secretA": "valueA"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	aParts := strings.Split(aFull, "~")
	if len(aParts) < 2 || aParts[1] == "" {
		t.Fatal("expected a disclosure segment in credential A")
	}
	aDisclosure := aParts[1]

	// Credential B is a distinct credential (its own _sd set), signed by the same key.
	bFull, _, err := iss.IssueSDJWT("subB", map[string]any{"claimB": "valueB"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Graft A's disclosure onto B's presentation.
	grafted := strings.TrimSuffix(bFull, "~") + "~" + aDisclosure + "~"
	vc, err := VerifySDJWT(grafted, iss.PublicKey())
	if err == nil {
		if _, leaked := vc.Claims["secretA"]; leaked {
			t.Fatal("CRITICAL: transplanted disclosure from another credential was accepted")
		}
		t.Fatal("grafted foreign disclosure must be rejected, not silently dropped")
	}
}
