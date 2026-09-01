package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"blrcs/cbor"
	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 148: mdoc x5chain / IACA→DSC validation
//
// The property under test is that the embedded chain is EVIDENCE, never
// authority: a self-signed certificate an attacker attaches must not validate,
// and a genuine DSC attached to a document signed by some other key must not
// verify either.
// ============================================================================

type testCA struct {
	cert *x509.Certificate
	priv *ecdsa.PrivateKey
}

func newIACA(t *testing.T, cn string) *testCA {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		// ISO 18013-5 Annex B: an IACA root is long-lived (years), a DSC short.
		// The wide window also lets a test validate at a historical instant.
		NotBefore:             time.Now().Add(-90 * 24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte("iaca-ski-" + cn),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, priv: priv}
}

// newDSC issues a Document Signer Certificate under an IACA.
func newDSC(t *testing.T, ca *testCA, cn string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte("dsc-ski-" + cn),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &priv.PublicKey, ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

// issueWithChain issues an mdoc signed by dscPriv carrying chain in x5chain.
func issueWithChain(t *testing.T, dscPriv *ecdsa.PrivateKey, chain []*x509.Certificate) []byte {
	t.Helper()
	hdr, err := X5ChainHeader(chain)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := Issue(IssueParams{
		DocType:               "org.iso.18013.5.1.mDL",
		NameSpaces:            testNS(),
		Validity:              testValidity(),
		IssuerPrivES256:       dscPriv,
		IssuerAuthUnprotected: hdr,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return cred
}

func TestVerifyChainRoundTrip(t *testing.T) {
	ca := newIACA(t, "IACA JP")
	dsc, dscPriv := newDSC(t, ca, "DSC JP 1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cred := issueWithChain(t, dscPriv, []*x509.Certificate{dsc})

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	doc, chain, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if doc.NameSpaces["org.iso.18013.5.1"]["family_name"] != "Tanaka" {
		t.Errorf("claims wrong: %v", doc.NameSpaces)
	}
	if len(chain) < 2 || chain[0].Subject.CommonName != "DSC JP 1" {
		t.Fatalf("chain should be leaf-first and reach the root: %v", chain)
	}
	if chain[len(chain)-1].Subject.CommonName != "IACA JP" {
		t.Errorf("chain should terminate at the IACA, got %v", chain[len(chain)-1].Subject)
	}
}

// TestSelfSignedChainRejected is the core attack: an attacker mints their own
// certificate for a key they control and attaches it. It must not validate.
func TestSelfSignedChainRejected(t *testing.T) {
	realCA := newIACA(t, "IACA JP")
	attacker := newIACA(t, "Attacker Root")
	evilDSC, evilPriv := newDSC(t, attacker, "Evil DSC", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cred := issueWithChain(t, evilPriv, []*x509.Certificate{evilDSC, attacker.cert})

	roots := x509.NewCertPool()
	roots.AddCert(realCA.cert) // only the REAL IACA is trusted

	if _, _, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("an attacker-rooted chain must be rejected, got %v", err)
	}
}

// TestGenuineDSCWithForeignSignatureRejected: attaching someone else's valid DSC
// to a document you signed yourself must fail. Without the key-binding check the
// chain would be purely decorative.
func TestGenuineDSCWithForeignSignatureRejected(t *testing.T) {
	ca := newIACA(t, "IACA JP")
	genuineDSC, _ := newDSC(t, ca, "Genuine DSC", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	attackerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Sign with the attacker's key but present the genuine, properly-chained DSC.
	cred := issueWithChain(t, attackerPriv, []*x509.Certificate{genuineDSC})

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	_, _, err = VerifyChain(cred, ChainVerifyOptions{Roots: roots})
	if !errors.Is(err, ErrDSCKeyMismatch) {
		t.Fatalf("want ErrDSCKeyMismatch, got %v", err)
	}
}

// TestNoRootsFailsClosed: with no configured anchors the embedded chain must not
// be trusted by default.
func TestNoRootsFailsClosed(t *testing.T) {
	ca := newIACA(t, "IACA")
	dsc, priv := newDSC(t, ca, "DSC", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cred := issueWithChain(t, priv, []*x509.Certificate{dsc})
	if _, _, err := VerifyChain(cred, ChainVerifyOptions{}); !errors.Is(err, ErrNoTrustAnchors) {
		t.Fatalf("want ErrNoTrustAnchors, got %v", err)
	}
}

// TestExpiredDSCRejected: ISO 18013-5 Annex B requires the DSC to be valid at
// signing time. It must be rejected once expired — but a verifier checking an
// ARCHIVED document must still be able to validate it as of when it was signed,
// which is why ChainVerifyOptions.Now exists.
func TestExpiredDSCRejected(t *testing.T) {
	ca := newIACA(t, "IACA")
	dsc, priv := newDSC(t, ca, "Expired DSC", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	hdr, err := X5ChainHeader([]*x509.Certificate{dsc})
	if err != nil {
		t.Fatal(err)
	}
	// The document's own validity window must also cover the historical instant,
	// or the MSO check would fail for an unrelated reason and the test would not
	// be exercising certificate validity at all.
	signed := time.Now().Add(-36 * time.Hour)
	cred, err := Issue(IssueParams{
		DocType:    "org.iso.18013.5.1.mDL",
		NameSpaces: testNS(),
		Validity: ValidityInfo{
			Signed:     signed,
			ValidFrom:  signed,
			ValidUntil: time.Now().Add(-12 * time.Hour),
		},
		IssuerPrivES256:       priv,
		IssuerAuthUnprotected: hdr,
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	if _, _, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots}); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("an expired DSC must be rejected now, got %v", err)
	}
	if _, _, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots, Now: signed}); err != nil {
		t.Fatalf("validating as of signing time should succeed: %v", err)
	}
}

// TestMissingX5ChainRejected: a bare-key document must not silently pass a
// chain-verifying call.
func TestMissingX5ChainRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := Issue(IssueParams{
		DocType: "org.iso.18013.5.1.mDL", NameSpaces: testNS(),
		Validity: testValidity(), IssuerPrivES256: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	ca := newIACA(t, "IACA")
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, _, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots}); !errors.Is(err, ErrX5ChainMissing) {
		t.Fatalf("want ErrX5ChainMissing, got %v", err)
	}
}

// TestX5ChainEncodingForms: RFC 9360 §2 — one certificate is a bstr, several are
// an array of bstr.
func TestX5ChainEncodingForms(t *testing.T) {
	ca := newIACA(t, "IACA")
	dsc, _ := newDSC(t, ca, "DSC", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	single, err := X5ChainHeader([]*x509.Certificate{dsc})
	if err != nil {
		t.Fatal(err)
	}
	if _, isBytes := single[HeaderX5Chain].([]byte); !isBytes {
		t.Errorf("a single certificate must encode as a bstr, got %T", single[HeaderX5Chain])
	}
	multi, err := X5ChainHeader([]*x509.Certificate{dsc, ca.cert})
	if err != nil {
		t.Fatal(err)
	}
	arr, isArr := multi[HeaderX5Chain].([]any)
	if !isArr || len(arr) != 2 {
		t.Errorf("a chain must encode as an array of bstr, got %T", multi[HeaderX5Chain])
	}
	if _, err := X5ChainHeader(nil); !errors.Is(err, ErrX5ChainMalformed) {
		t.Errorf("an empty chain must be refused, got %v", err)
	}
}

// TestMalformedX5ChainRejected: junk in the header must be an error, never
// silently treated as absent.
func TestMalformedX5ChainRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newIACA(t, "IACA")
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	for name, hdr := range map[string]cbor.Header{
		"not a cert":    {HeaderX5Chain: []byte("not-der")},
		"wrong type":    {HeaderX5Chain: "a string"},
		"empty array":   {HeaderX5Chain: []any{}},
		"array of junk": {HeaderX5Chain: []any{"not bytes"}},
	} {
		cred, err := Issue(IssueParams{
			DocType: "org.iso.18013.5.1.mDL", NameSpaces: testNS(),
			Validity: testValidity(), IssuerPrivES256: priv,
			IssuerAuthUnprotected: hdr,
		})
		if err != nil {
			t.Fatalf("%s: issue: %v", name, err)
		}
		if _, _, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots}); !errors.Is(err, ErrX5ChainMalformed) {
			t.Errorf("%s: want ErrX5ChainMalformed, got %v", name, err)
		}
	}
}

// TestAKIMatching supports OpenID4VP §6.1.1's `aki` trusted-authority type
// against a validated chain.
func TestAKIMatching(t *testing.T) {
	ca := newIACA(t, "IACA JP")
	dsc, priv := newDSC(t, ca, "DSC", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cred := issueWithChain(t, priv, []*x509.Certificate{dsc})
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	_, chain, err := VerifyChain(cred, ChainVerifyOptions{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	caAKI := AuthorityKeyIdentifier(ca.cert)
	if !ChainMatchesAKI(chain, caAKI) {
		t.Error("the validated chain should match its own IACA's key identifier")
	}
	other := newIACA(t, "Other IACA")
	if ChainMatchesAKI(chain, AuthorityKeyIdentifier(other.cert)) {
		t.Error("an unrelated authority must not match")
	}
	if ChainMatchesAKI(chain, "not-base64!!") || ChainMatchesAKI(chain, "") {
		t.Error("a malformed aki value must not match")
	}
}

// TestBareKeyVerifyStillWorks is the back-compat guard: the existing bare-key
// Verify path is untouched.
func TestBareKeyVerifyStillWorks(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := Issue(IssueParams{
		DocType: "org.iso.18013.5.1.mDL", NameSpaces: testNS(),
		Validity: testValidity(), IssuerPrivES256: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsakey.MarshalP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Verify(cred, pub, time.Now())
	if err != nil {
		t.Fatalf("bare-key verify must still work: %v", err)
	}
	if doc.NameSpaces["org.iso.18013.5.1"]["family_name"] != "Tanaka" {
		t.Errorf("claims wrong: %v", doc.NameSpaces)
	}
}

// --- helpers ---

func testNS() map[string][]Element {
	return map[string][]Element{"org.iso.18013.5.1": {
		{Identifier: "family_name", Value: "Tanaka"},
		{Identifier: "age_over_18", Value: true},
	}}
}

func testValidity() ValidityInfo {
	now := time.Now()
	return ValidityInfo{Signed: now, ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
}
