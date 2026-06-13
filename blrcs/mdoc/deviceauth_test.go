package mdoc

import (
	"errors"
	"testing"
	"time"

	"blrcs/cbor"
)

// marshalDocNoDeviceAuth builds a Document containing issuerSigned but no
// deviceSigned, for the missing-deviceAuth rejection test.
func marshalDocNoDeviceAuth(docType string, issuerSigned []byte) ([]byte, error) {
	return cbor.Marshal(map[string]any{
		docDocType:      docType,
		docIssuerSigned: rawCBOR(issuerSigned),
	})
}

// TestDeviceAuthRoundtrip is the happy path: a credential issued with a device key
// is presented with device authentication bound to a session transcript, and the
// verifier accepts it and recovers the disclosed claims.
func TestDeviceAuthRoundtrip(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	devicePriv, devicePub := testKeys(t)

	cred, err := Issue(sampleParams(issuerPriv, devicePub))
	if err != nil {
		t.Fatal(err)
	}
	transcript := []byte("session-transcript-verifier-nonce-abc")
	doc, err := PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name", "age_over_18"}},
		"org.iso.18013.5.1.mDL", devicePriv, transcript)
	if err != nil {
		t.Fatal(err)
	}

	vd, err := VerifyDocument(doc, issuerPub, transcript, time.Now())
	if err != nil {
		t.Fatalf("VerifyDocument: %v", err)
	}
	got := vd.NameSpaces["org.iso.18013.5.1"]
	if got["family_name"] != "Tanaka" {
		t.Errorf("family_name: %v", got["family_name"])
	}
	if got["age_over_18"] != true {
		t.Errorf("age_over_18: %v", got["age_over_18"])
	}
	if _, leaked := got["given_name"]; leaked {
		t.Error("given_name should not be disclosed")
	}
}

// TestDeviceAuthWrongTranscript rejects a presentation replayed against a different
// session transcript (the core anti-replay property).
func TestDeviceAuthWrongTranscript(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	devicePriv, devicePub := testKeys(t)
	cred, err := Issue(sampleParams(issuerPriv, devicePub))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name"}},
		"org.iso.18013.5.1.mDL", devicePriv, []byte("transcript-A"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(doc, issuerPub, []byte("transcript-B"), time.Now()); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("replay against different transcript: want ErrDeviceAuth, got %v", err)
	}
}

// TestDeviceAuthWrongDeviceKey rejects a presentation signed by a key other than
// the one the issuer committed to in the MSO.
func TestDeviceAuthWrongDeviceKey(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	_, devicePub := testKeys(t)    // committed device key
	attackerPriv, _ := testKeys(t) // different key
	cred, err := Issue(sampleParams(issuerPriv, devicePub))
	if err != nil {
		t.Fatal(err)
	}
	transcript := []byte("transcript")
	doc, err := PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name"}},
		"org.iso.18013.5.1.mDL", attackerPriv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(doc, issuerPub, transcript, time.Now()); !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("wrong device key: want ErrDeviceAuth, got %v", err)
	}
}

// TestDeviceAuthNoDeviceKey rejects a Document whose credential was issued without
// a device key (cannot be bound; must not be accepted as a device-authenticated
// presentation).
func TestDeviceAuthNoDeviceKey(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	devicePriv, _ := testKeys(t)
	cred, err := Issue(sampleParams(issuerPriv, nil)) // no device key
	if err != nil {
		t.Fatal(err)
	}
	transcript := []byte("transcript")
	doc, err := PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name"}},
		"org.iso.18013.5.1.mDL", devicePriv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(doc, issuerPub, transcript, time.Now()); !errors.Is(err, ErrNoDeviceKey) {
		t.Fatalf("no device key: want ErrNoDeviceKey, got %v", err)
	}
}

// TestVerifyDocumentMissingDeviceAuth rejects a Document with no deviceAuth.
func TestVerifyDocumentMissingDeviceAuth(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	_, devicePub := testKeys(t)
	cred, err := Issue(sampleParams(issuerPriv, devicePub))
	if err != nil {
		t.Fatal(err)
	}
	// Hand-build a Document with issuerSigned but no deviceSigned.
	filtered, err := Present(cred, map[string][]string{"org.iso.18013.5.1": {"family_name"}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := marshalDocNoDeviceAuth("org.iso.18013.5.1.mDL", filtered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(doc, issuerPub, []byte("t"), time.Now()); !errors.Is(err, ErrDeviceAuthMissing) {
		t.Fatalf("missing deviceAuth: want ErrDeviceAuthMissing, got %v", err)
	}
}

// TestVerifyDocumentExpired confirms issuerSigned validity is still enforced inside
// VerifyDocument (the device-auth wrapper does not bypass credential expiry).
func TestVerifyDocumentExpired(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	devicePriv, devicePub := testKeys(t)
	now := time.Now().UTC()
	p := sampleParams(issuerPriv, devicePub)
	p.Validity = ValidityInfo{Signed: now.Add(-48 * time.Hour), ValidFrom: now.Add(-48 * time.Hour), ValidUntil: now.Add(-24 * time.Hour)}
	cred, err := Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	transcript := []byte("t")
	doc, err := PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name"}},
		"org.iso.18013.5.1.mDL", devicePriv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(doc, issuerPub, transcript, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired credential: want ErrExpired, got %v", err)
	}
}
