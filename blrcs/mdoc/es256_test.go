package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"blrcs/cbor"
	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 141: ES256 (P-256) mdoc issuance and device auth
//
// Real mDLs are ES256-signed with a P-256 device key. Verification of AlgES256
// landed in Axis 135; this covers the signing half, so BLRCS can produce a
// credential a P-256-only ecosystem accepts rather than only consume one.
// ============================================================================

func p256Pair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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

func es256Params(t *testing.T, issuerPriv *ecdsa.PrivateKey, devicePub *ecdsa.PublicKey) IssueParams {
	t.Helper()
	now := time.Now().UTC()
	return IssueParams{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]Element{
			"org.iso.18013.5.1": {
				{Identifier: "family_name", Value: "Tanaka"},
				{Identifier: "age_over_18", Value: true},
			},
		},
		Validity: ValidityInfo{
			Signed: now, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
		},
		DeviceKeyES256:  devicePub,
		IssuerPrivES256: issuerPriv,
	}
}

// TestES256IssueAndVerify is the headline: an mdoc signed with ES256 and bound
// to a P-256 device key issues and verifies.
func TestES256IssueAndVerify(t *testing.T) {
	issuerPriv, issuerPub := p256Pair(t)
	devicePriv, _ := p256Pair(t)

	cred, err := Issue(es256Params(t, issuerPriv, &devicePriv.PublicKey))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	vd, err := Verify(cred, issuerPub, time.Now())
	if err != nil {
		t.Fatalf("ES256 mdoc should verify: %v", err)
	}
	if vd.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType: %q", vd.DocType)
	}
	if vd.NameSpaces["org.iso.18013.5.1"]["family_name"] != "Tanaka" {
		t.Errorf("claims: %+v", vd.NameSpaces)
	}
	// The device binding must come back as a P-256 key, not an Ed25519 one.
	if vd.DeviceKey != nil {
		t.Error("a P-256-bound credential must not report an Ed25519 device key")
	}
	if len(vd.DeviceKeyES256) != ecdsakey.P256UncompressedSize {
		t.Fatalf("device key should be a 65-byte SEC1 point, got %d", len(vd.DeviceKeyES256))
	}
	if _, err := ecdsakey.ParseP256PublicKey(vd.DeviceKeyES256); err != nil {
		t.Errorf("recovered device key is not a valid P-256 point: %v", err)
	}
}

// TestES256IssuerAuthSignatureIsFixedWidth proves the COSE signature is the raw
// R‖S form RFC 9053 §2.1 mandates, not ASN.1 DER.
func TestES256IssuerAuthSignatureIsFixedWidth(t *testing.T) {
	issuerPriv, _ := p256Pair(t)
	devicePriv, _ := p256Pair(t)
	// Repeat: a short encoding only appears when a coordinate has a leading zero
	// byte (~1 in 256), so one sample would miss it.
	for n := 0; n < 200; n++ {
		cred, err := Issue(es256Params(t, issuerPriv, &devicePriv.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		sig := issuerAuthSignature(t, cred)
		if len(sig) != ecdsakey.ES256SignatureSize {
			t.Fatalf("iteration %d: issuerAuth signature is %d bytes, want %d (raw R||S)",
				n, len(sig), ecdsakey.ES256SignatureSize)
		}
	}
}

// issuerAuthSignature digs the COSE_Sign1 signature out of an IssuerSigned.
func issuerAuthSignature(t *testing.T, cred []byte) []byte {
	t.Helper()
	top, err := cbor.Unmarshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := top.(map[any]any)
	if !ok {
		t.Fatal("IssuerSigned not a map")
	}
	tag, ok := m[isIssuerAuth].(cbor.Tag)
	if !ok {
		t.Fatalf("issuerAuth not a COSE tag: %T", m[isIssuerAuth])
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		t.Fatal("malformed COSE_Sign1")
	}
	sig, ok := arr[3].([]byte)
	if !ok {
		t.Fatal("signature not bstr")
	}
	return sig
}

func TestES256WrongIssuerKeyRejected(t *testing.T) {
	issuerPriv, _ := p256Pair(t)
	_, otherPub := p256Pair(t)
	devicePriv, _ := p256Pair(t)

	cred, err := Issue(es256Params(t, issuerPriv, &devicePriv.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(cred, otherPub, time.Now()); err == nil {
		t.Fatal("must not verify under a different issuer key")
	}
}

// TestES256DeviceAuthRoundTrip exercises the full presentation path with P-256
// on both sides, including the session-transcript binding.
func TestES256DeviceAuthRoundTrip(t *testing.T) {
	issuerPriv, issuerPub := p256Pair(t)
	devicePriv, _ := p256Pair(t)
	transcript := []byte("session-transcript-abc")

	cred, err := Issue(es256Params(t, issuerPriv, &devicePriv.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignDeviceAuthES256("org.iso.18013.5.1.mDL", transcript, devicePriv)
	if err != nil {
		t.Fatalf("device auth sign: %v", err)
	}
	vd, err := Verify(cred, issuerPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceAuth(sig, "org.iso.18013.5.1.mDL", transcript, vd.DeviceKeyES256); err != nil {
		t.Fatalf("ES256 device auth should verify: %v", err)
	}
	// Binding: a different transcript must fail.
	if err := VerifyDeviceAuth(sig, "org.iso.18013.5.1.mDL", []byte("other-session"), vd.DeviceKeyES256); err == nil {
		t.Error("device auth must be bound to the session transcript")
	}
	// And a different docType must fail.
	if err := VerifyDeviceAuth(sig, "org.iso.23220.photoid.1", transcript, vd.DeviceKeyES256); err == nil {
		t.Error("device auth must be bound to the docType")
	}
}

// TestES256FullDocumentVerify runs the whole document path (issuerAuth + device
// auth together) as VerifyDocument does in a real presentation.
func TestES256FullDocumentVerify(t *testing.T) {
	issuerPriv, issuerPub := p256Pair(t)
	devicePriv, _ := p256Pair(t)
	transcript := []byte("transcript")

	cred, err := Issue(es256Params(t, issuerPriv, &devicePriv.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := presentWithES256DeviceAuth(t, cred, transcript, devicePriv)
	if err != nil {
		t.Fatal(err)
	}
	vd, err := VerifyDocument(doc, issuerPub, transcript, time.Now())
	if err != nil {
		t.Fatalf("full ES256 document should verify: %v", err)
	}
	if vd.NameSpaces["org.iso.18013.5.1"]["age_over_18"] != true {
		t.Errorf("disclosed claims: %+v", vd.NameSpaces)
	}
	// Wrong transcript must be refused by the device-auth step.
	if _, err := VerifyDocument(doc, issuerPub, []byte("other"), time.Now()); err == nil {
		t.Error("a document bound to another session must not verify")
	}
}

// presentWithES256DeviceAuth mirrors PresentWithDeviceAuth for a P-256 device
// key: filter the disclosed elements, then attach an ES256 deviceSignature.
func presentWithES256DeviceAuth(t *testing.T, cred []byte, transcript []byte, devicePriv *ecdsa.PrivateKey) ([]byte, error) {
	t.Helper()
	filtered, err := Present(cred, map[string][]string{
		"org.iso.18013.5.1": {"family_name", "age_over_18"},
	})
	if err != nil {
		return nil, err
	}
	sig, err := SignDeviceAuthES256("org.iso.18013.5.1.mDL", transcript, devicePriv)
	if err != nil {
		return nil, err
	}
	sigDecoded, err := cbor.Unmarshal(sig)
	if err != nil {
		return nil, err
	}
	filteredDecoded, err := cbor.Unmarshal(filtered)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(map[string]any{
		docDocType:      "org.iso.18013.5.1.mDL",
		docIssuerSigned: filteredDecoded,
		docDeviceSigned: map[string]any{
			dsNameSpaces: map[string]any{},
			dsDeviceAuth: map[string]any{daDeviceSignature: sigDecoded},
		},
	})
}

// TestEd25519MdocUnchanged is the regression guard for the existing path.
func TestEd25519MdocUnchanged(t *testing.T) {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cred, err := Issue(IssueParams{
		DocType:    "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]Element{"ns": {{Identifier: "a", Value: "b"}}},
		Validity:   ValidityInfo{Signed: now, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)},
		DeviceKey:  devicePub,
		IssuerPriv: issuerPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	vd, err := Verify(cred, issuerPub, time.Now())
	if err != nil {
		t.Fatalf("Ed25519 mdoc must still verify: %v", err)
	}
	if len(vd.DeviceKey) != ed25519.PublicKeySize {
		t.Error("Ed25519 device key should still come back as such")
	}
	if vd.DeviceKeyES256 != nil {
		t.Error("an Ed25519-bound credential must not report a P-256 device key")
	}
}

// TestSign1ES256RejectsBadKey covers the primitive's guard.
func TestSign1ES256RejectsBadKey(t *testing.T) {
	if _, err := cbor.Sign1ES256(cbor.Header{}, nil, []byte("p"), nil, nil); err == nil {
		t.Error("nil key should be rejected")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cbor.Sign1ES256(cbor.Header{}, nil, []byte("p"), nil, p384); err == nil {
		t.Error("a P-384 key must be rejected for ES256")
	}
}

// TestAlgHeaderMismatchRejected pins the guard added after this axis hit the bug
// itself: signing under a protected header that declares a different algorithm
// produced a COSE_Sign1 whose header sent verifiers to the wrong code, so the
// credential was well-formed but unverifiable.
func TestAlgHeaderMismatchRejected(t *testing.T) {
	priv, _ := p256Pair(t)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = edPub

	// ES256 signer, header says EdDSA.
	if _, err := cbor.Sign1ES256(cbor.Header{cbor.HeaderAlg: cbor.AlgEdDSA}, nil, []byte("p"), nil, priv); err == nil {
		t.Error("ES256 signing under an EdDSA header must be rejected")
	}
	// EdDSA signer, header says ES256.
	if _, err := cbor.Sign1(cbor.Header{cbor.HeaderAlg: cbor.AlgES256}, nil, []byte("p"), nil, edPriv); err == nil {
		t.Error("EdDSA signing under an ES256 header must be rejected")
	}
	// The matching headers, and an empty header, are both fine.
	if _, err := cbor.Sign1ES256(cbor.Header{cbor.HeaderAlg: cbor.AlgES256}, nil, []byte("p"), nil, priv); err != nil {
		t.Errorf("matching ES256 header should sign: %v", err)
	}
	if _, err := cbor.Sign1(cbor.Header{}, nil, []byte("p"), nil, edPriv); err != nil {
		t.Errorf("empty header should default correctly: %v", err)
	}
}
