package compliance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blrcs/ecdsakey"
)

// kbSegment returns the KB-JWT appended to a presentation.
func kbSegment(t *testing.T, presentation string) string {
	t.Helper()
	i := strings.LastIndex(presentation, "~")
	if i < 0 || i == len(presentation)-1 {
		t.Fatalf("presentation carries no KB-JWT: %q", presentation)
	}
	return presentation[i+1:]
}

// kbHeader decodes the KB-JWT protected header.
func kbHeader(t *testing.T, kb string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(kb, ".", 2)[0])
	if err != nil {
		t.Fatalf("decode KB-JWT header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("parse KB-JWT header: %v", err)
	}
	return h
}

// TestKBJWTHeaderAlgIsTheAlgorithmThatSigned is the label-matches-act assertion
// for holder binding: the KB-JWT header must name the algorithm whose key
// actually produced the signature. Until the signer carried its own algorithm,
// the header string and the signing function were independent arguments to
// presentWithKB, so a caller could emit `alg: EdDSA` over an ES256 signature —
// the same defect that made mdoc COSE headers lie. This asserts the observable
// consequence for both holder key types.
func TestKBJWTHeaderAlgIsTheAlgorithmThatSigned(t *testing.T) {
	iss := newES256Issuer(t)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	esPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esPub, err := ecdsakey.MarshalP256PublicKey(&esPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sdjwt, _, err := iss.IssueSDJWT("battery-001", map[string]any{"a": 1.0}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("EdDSA holder key", func(t *testing.T) {
		pres, err := PresentWithKeyBindingTx(sdjwt, nil, edPriv, "n0nce", "https://verifier.example", nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		kb := kbSegment(t, pres)
		if got := kbHeader(t, kb)["alg"]; got != "EdDSA" {
			t.Fatalf("header alg = %v, want EdDSA", got)
		}
		signingInput, sig := splitKB(t, kb)
		if !ed25519.Verify(edPub, signingInput, sig) {
			t.Fatal("header says EdDSA but the Ed25519 holder key does not verify it")
		}
	})

	t.Run("ES256 holder key", func(t *testing.T) {
		pres, err := PresentWithKeyBindingES256(sdjwt, nil, esPriv, "n0nce", "https://verifier.example", nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		kb := kbSegment(t, pres)
		if got := kbHeader(t, kb)["alg"]; got != "ES256" {
			t.Fatalf("header alg = %v, want ES256", got)
		}
		signingInput, sig := splitKB(t, kb)
		if len(sig) != ecdsakey.ES256SignatureSize {
			t.Fatalf("ES256 signature is %d bytes, want %d (raw R||S, not DER)", len(sig), ecdsakey.ES256SignatureSize)
		}
		if !ecdsakey.VerifyES256(esPub, signingInput, sig) {
			t.Fatal("header says ES256 but the P-256 holder key does not verify it")
		}
	})
}

// splitKB returns the KB-JWT signing input (header.payload) and the raw signature.
func splitKB(t *testing.T, kb string) ([]byte, []byte) {
	t.Helper()
	parts := strings.Split(kb, ".")
	if len(parts) != 3 {
		t.Fatalf("KB-JWT has %d segments, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return []byte(parts[0] + "." + parts[1]), sig
}
