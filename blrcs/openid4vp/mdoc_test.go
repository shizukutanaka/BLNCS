package openid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"blrcs/cbor"
	"blrcs/mdoc"
)

// ============================================================================
// Axis 138: mso_mdoc verification dispatch
// ============================================================================

const testDoctype = "org.iso.18013.5.1.mDL"

func mdocKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// buildMdocPresentation issues an mdoc bound to a device key and presents it
// with DeviceAuth over the given transcript, wrapped in a DeviceResponse and
// base64url-encoded exactly as an OpenID4VP vp_token carries it.
func buildMdocPresentation(t *testing.T, issuerPriv ed25519.PrivateKey, devicePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, docType string, transcript []byte) string {
	t.Helper()
	now := time.Now().UTC()
	cred, err := mdoc.Issue(mdoc.IssueParams{
		DocType: docType,
		NameSpaces: map[string][]mdoc.Element{
			"org.iso.18013.5.1": {
				{Identifier: "family_name", Value: "Tanaka"},
				{Identifier: "age_over_18", Value: true},
			},
		},
		Validity: mdoc.ValidityInfo{
			Signed: now, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
		},
		DeviceKey:  devicePub,
		IssuerPriv: issuerPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mdoc.PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name", "age_over_18"}},
		docType, devicePriv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	return wrapDeviceResponse(t, doc)
}

// wrapDeviceResponse puts one Document into a DeviceResponse and base64url-encodes it.
func wrapDeviceResponse(t *testing.T, doc []byte) string {
	t.Helper()
	decoded, err := cbor.Unmarshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := cbor.Marshal(map[string]any{
		"version":   "1.0",
		"documents": []any{decoded},
		"status":    0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(dr)
}

// mdocVerifier builds a verifier configured for an mso_mdoc DCQL flow.
func mdocVerifier(t *testing.T, issuerPub ed25519.PublicKey, transcript []byte, doctype string) (*Verifier, string) {
	t.Helper()
	v := NewVerifier("https://verifier.example", "https://verifier.example/cb", NewMemoryStore())
	v.TrustedIssuers = map[string][]byte{"did:web:issuer.example": issuerPub}
	v.MdocSessionTranscript = transcript

	_, state, err := v.CreateRequestDCQL(DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "mdl",
			Format: FormatMsoMdoc,
			Meta:   &CredentialQueryMeta{DoctypeValue: doctype},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, state
}

// TestMdocPresentationVerifies is the capability this axis adds: an mso_mdoc
// vp_token is now actually verified, instead of being pushed through the SD-JWT
// verifier and failing with a misleading error.
func TestMdocPresentationVerifies(t *testing.T) {
	issuerPriv, issuerPub := mdocKeys(t)
	devicePriv, devicePub := mdocKeys(t)
	transcript := []byte("agreed-session-transcript-bytes")

	v, state := mdocVerifier(t, issuerPub, transcript, testDoctype)
	vpToken := buildMdocPresentation(t, issuerPriv, devicePriv, devicePub, testDoctype, transcript)

	vp, err := v.ProcessResponse(&AuthorizationResponse{VPToken: vpToken, State: state})
	if err != nil {
		t.Fatalf("mdoc presentation should verify: %v", err)
	}
	if vp.Issuer != "did:web:issuer.example" {
		t.Errorf("issuer: %q", vp.Issuer)
	}
	if vp.Subject != testDoctype {
		t.Errorf("subject should be the doctype: %q", vp.Subject)
	}
	if vp.Claims["org.iso.18013.5.1:family_name"] != "Tanaka" {
		t.Errorf("namespaced claim missing: %+v", vp.Claims)
	}
	if vp.Claims["org.iso.18013.5.1:age_over_18"] != true {
		t.Errorf("age_over_18 not disclosed: %+v", vp.Claims)
	}
}

// TestMdocWrongSessionTranscriptRejected is the replay defence: a presentation
// bound to one session must not verify in another.
func TestMdocWrongSessionTranscriptRejected(t *testing.T) {
	issuerPriv, issuerPub := mdocKeys(t)
	devicePriv, devicePub := mdocKeys(t)

	// Wallet binds to session A; verifier is in session B.
	vpToken := buildMdocPresentation(t, issuerPriv, devicePriv, devicePub, testDoctype, []byte("session-A"))
	v, state := mdocVerifier(t, issuerPub, []byte("session-B"), testDoctype)

	if _, err := v.ProcessResponse(&AuthorizationResponse{VPToken: vpToken, State: state}); err == nil {
		t.Fatal("a presentation bound to a different session must not verify (replay)")
	}
}

// TestMdocWithoutSessionTranscriptFailsClosed proves the verifier refuses rather
// than silently skipping device binding — an unbound mdoc is replayable.
func TestMdocWithoutSessionTranscriptFailsClosed(t *testing.T) {
	issuerPriv, issuerPub := mdocKeys(t)
	devicePriv, devicePub := mdocKeys(t)
	transcript := []byte("transcript")

	v, state := mdocVerifier(t, issuerPub, transcript, testDoctype)
	v.MdocSessionTranscript = nil // operator forgot to configure it
	vpToken := buildMdocPresentation(t, issuerPriv, devicePriv, devicePub, testDoctype, transcript)

	_, err := v.ProcessResponse(&AuthorizationResponse{VPToken: vpToken, State: state})
	if !errors.Is(err, ErrMdocSessionTranscriptMissing) {
		t.Fatalf("want ErrMdocSessionTranscriptMissing, got %v", err)
	}
}

// TestMdocDoctypeEnforced closes the gap where DoctypeValue was declared but
// never read: a wallet returning a different doctype must be rejected.
func TestMdocDoctypeEnforced(t *testing.T) {
	issuerPriv, issuerPub := mdocKeys(t)
	devicePriv, devicePub := mdocKeys(t)
	transcript := []byte("transcript")

	// Query asks for an mDL; the wallet returns a photo ID.
	v, state := mdocVerifier(t, issuerPub, transcript, testDoctype)
	vpToken := buildMdocPresentation(t, issuerPriv, devicePriv, devicePub,
		"org.iso.23220.photoid.1", transcript)

	_, err := v.ProcessResponse(&AuthorizationResponse{VPToken: vpToken, State: state})
	if !errors.Is(err, ErrMdocDoctypeMismatch) {
		t.Fatalf("want ErrMdocDoctypeMismatch, got %v", err)
	}
}

// TestMdocUntrustedIssuerRejected proves the issuer signature is really checked.
func TestMdocUntrustedIssuerRejected(t *testing.T) {
	issuerPriv, _ := mdocKeys(t)
	_, otherPub := mdocKeys(t)
	devicePriv, devicePub := mdocKeys(t)
	transcript := []byte("transcript")

	v, state := mdocVerifier(t, otherPub, transcript, testDoctype) // trusts a different key
	vpToken := buildMdocPresentation(t, issuerPriv, devicePriv, devicePub, testDoctype, transcript)

	if _, err := v.ProcessResponse(&AuthorizationResponse{VPToken: vpToken, State: state}); err == nil {
		t.Fatal("a credential from an untrusted issuer must not verify")
	}
}

// TestMdocMalformedTokenRejected covers the decode/parse boundary.
func TestMdocMalformedTokenRejected(t *testing.T) {
	_, issuerPub := mdocKeys(t)
	v, state := mdocVerifier(t, issuerPub, []byte("t"), testDoctype)

	for name, token := range map[string]string{
		"not base64":        "!!!not base64!!!",
		"not CBOR":          base64.RawURLEncoding.EncodeToString([]byte("plain text")),
		"empty":             "",
		"CBOR but no docs":  base64.RawURLEncoding.EncodeToString(mustCBOR(t, map[string]any{"version": "1.0"})),
		"documents not arr": base64.RawURLEncoding.EncodeToString(mustCBOR(t, map[string]any{"documents": "nope"})),
	} {
		if _, err := v.ProcessResponse(&AuthorizationResponse{VPToken: token, State: state}); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSDJWTFlowUnaffectedByDispatch is the regression guard: a DCQL query for
// dc+sd-jwt must still take the SD-JWT path unchanged.
func TestSDJWTFlowUnaffectedByDispatch(t *testing.T) {
	q := &DCQLQuery{Credentials: []CredentialQuery{{
		ID: "dpp", Format: FormatSDJWT,
		Meta: &CredentialQueryMeta{VCTValues: []string{"DigitalProductPassport"}},
	}}}
	if isMdoc, _ := mdocQueryFromDCQL(q); isMdoc {
		t.Fatal("an SD-JWT query must not be routed to the mdoc branch")
	}
	if isMdoc, _ := mdocQueryFromDCQL(nil); isMdoc {
		t.Fatal("a nil DCQL query must not be routed to the mdoc branch")
	}
	mixed := &DCQLQuery{Credentials: []CredentialQuery{
		{ID: "a", Format: FormatSDJWT},
		{ID: "b", Format: FormatMsoMdoc, Meta: &CredentialQueryMeta{DoctypeValue: testDoctype}},
	}}
	isMdoc, dt := mdocQueryFromDCQL(mixed)
	if !isMdoc || dt != testDoctype {
		t.Errorf("a query containing an mso_mdoc entry should route to the mdoc branch: %v %q", isMdoc, dt)
	}
}
