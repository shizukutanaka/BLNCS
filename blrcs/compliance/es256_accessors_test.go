package compliance

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"blrcs/ecdsakey"
)

// TestES256IssuerAlgMatchesWhatItSigns is the label-matches-act assertion applied
// to the issuer's own advertised algorithm: Alg() is what a caller publishes in
// metadata, so it must equal the `alg` that actually appears in the header of a
// credential this issuer produces. A drift between the two is the same defect as
// the mdoc COSE header that named EdDSA over an ES256 signature.
func TestES256IssuerAlgMatchesWhatItSigns(t *testing.T) {
	iss := newES256Issuer(t)
	sdjwt, _, err := iss.IssueSDJWT("battery-001", map[string]any{"a": 1.0}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := sdjwtHeader(t, sdjwt)["alg"]; got != iss.Alg() {
		t.Fatalf("issuer advertises Alg()=%q but signs with alg=%v", iss.Alg(), got)
	}
}

// TestES256IssuerPublicKeyECDSAVerifiesItsOwnSignature proves the accessor hands
// back the key that actually corresponds to the signing key, rather than merely
// returning a non-nil pointer.
func TestES256IssuerPublicKeyECDSAVerifiesItsOwnSignature(t *testing.T) {
	iss := newES256Issuer(t)

	pub := iss.PublicKeyECDSA()
	if pub == nil {
		t.Fatal("PublicKeyECDSA returned nil")
	}
	sec1, err := ecdsakey.MarshalP256PublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The SEC1 encoding must equal what PublicKey() reports, so the two
	// accessors cannot describe different keys.
	if !bytesEqualES256(sec1, iss.PublicKey()) {
		t.Fatal("PublicKeyECDSA and PublicKey describe different keys")
	}

	// And it must verify a signature made by the private half.
	msg := []byte("attested payload")
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, iss.privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, ecdsakey.ES256SignatureSize)
	r.FillBytes(sig[:ecdsakey.P256CoordSize])
	s.FillBytes(sig[ecdsakey.P256CoordSize:])
	if !ecdsakey.VerifyES256(sec1, msg, sig) {
		t.Fatal("key from PublicKeyECDSA does not verify the issuer's own signature")
	}
}

func bytesEqualES256(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
