package cbor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 135: ES256 (P-256) COSE_Sign1 verification — the mdoc / SCITT path.
// Real mDLs are ES256-signed, so this is what an ISO 18013-5 credential from a
// production issuing authority looks like on the wire.
// ============================================================================

// signES256Sign1 builds a COSE_Sign1 whose signature is the fixed-width R‖S
// form of RFC 9053 §2.1 (Signature = I2OSP(R,n) | I2OSP(S,n)), not DER.
func signES256Sign1(t *testing.T, priv *ecdsa.PrivateKey, payload, externalAAD []byte) []byte {
	t.Helper()
	protectedBytes, err := Marshal(map[int]any{HeaderAlg: AlgES256})
	if err != nil {
		t.Fatal(err)
	}
	sigStructure, err := Marshal([]any{"Signature1", protectedBytes, externalAAD, payload})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, ecdsakey.ES256SignatureSize)
	r.FillBytes(sig[:ecdsakey.P256CoordSize])
	s.FillBytes(sig[ecdsakey.P256CoordSize:])

	out, err := Marshal(Tag{Number: TagCOSESign1, Content: []any{protectedBytes, map[int]any{}, payload, sig}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func es256Pair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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

func TestCOSEVerifyES256(t *testing.T) {
	priv, pub := es256Pair(t)
	payload := []byte("mdoc MSO payload")
	data := signES256Sign1(t, priv, payload, nil)

	res, err := Verify1(data, pub, nil)
	if err != nil {
		t.Fatalf("ES256 COSE_Sign1 should verify: %v", err)
	}
	if string(res.Payload) != string(payload) {
		t.Errorf("payload mismatch: %q", res.Payload)
	}
}

func TestCOSEES256TamperRejected(t *testing.T) {
	priv, pub := es256Pair(t)
	data := signES256Sign1(t, priv, []byte("original"), nil)
	// Flip a byte inside the encoded structure.
	data[len(data)-1] ^= 0x01
	if _, err := Verify1(data, pub, nil); err == nil {
		t.Fatal("tampered ES256 COSE_Sign1 must not verify")
	}
}

func TestCOSEES256WrongKeyRejected(t *testing.T) {
	priv, _ := es256Pair(t)
	_, otherPub := es256Pair(t)
	data := signES256Sign1(t, priv, []byte("p"), nil)
	if _, err := Verify1(data, otherPub, nil); err == nil {
		t.Fatal("ES256 COSE_Sign1 must not verify under a different key")
	}
}

// TestCOSEES256AlgAllowlist proves the Axis 124 downgrade defence still governs
// the newly-registered algorithm.
func TestCOSEES256AlgAllowlist(t *testing.T) {
	priv, pub := es256Pair(t)
	data := signES256Sign1(t, priv, []byte("p"), nil)

	if _, err := Verify1WithAlgs(data, pub, nil, []int{AlgEdDSA}); err == nil {
		t.Error("ES256 must be rejected when only EdDSA is allowed")
	}
	if _, err := Verify1WithAlgs(data, pub, nil, []int{AlgES256}); err != nil {
		t.Errorf("ES256 should pass an ES256 allowlist: %v", err)
	}
}

// TestCOSEES256ExternalAADBound proves the Sig_structure binding still holds for
// the new algorithm: verifying with different external AAD must fail.
func TestCOSEES256ExternalAADBound(t *testing.T) {
	priv, pub := es256Pair(t)
	data := signES256Sign1(t, priv, []byte("p"), []byte("session-transcript"))
	if _, err := Verify1(data, pub, []byte("session-transcript")); err != nil {
		t.Fatalf("matching external AAD should verify: %v", err)
	}
	if _, err := Verify1(data, pub, []byte("different")); err == nil {
		t.Error("mismatched external AAD must be rejected")
	}
}
