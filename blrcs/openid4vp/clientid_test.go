package openid4vp

import "testing"

func TestValidateClientID(t *testing.T) {
	valid := []string{
		"https://verify.blrcs.example",           // bare pre-registered URL
		"verifier.example",                       // bare pre-registered
		"redirect_uri:https://verify.example/cb", // redirect_uri scheme
		"origin:https://verify.example",          // DC-API origin (OpenID4VP v1.0 §5.10)
		"decentralized_identifier:did:web:v.ex",  // DID
		"x509_san_dns:verify.example",            // DNS SAN
		"x509_hash:abc123",                       // hash
		"verifier_attestation:tokenvalue",        // attestation
		"openid_federation:https://fed.example",  // federation entity
	}
	for _, c := range valid {
		if err := ValidateClientID(c); err != nil {
			t.Errorf("ValidateClientID(%q) = %v, want nil", c, err)
		}
	}

	invalid := []string{
		"",                                 // empty
		"  ",                               // whitespace
		"has space",                        // embedded space
		"redirect_uri:ftp://x",             // redirect_uri not https
		"redirect_uri:not-a-url",           // redirect_uri not absolute
		"redirect_uri:",                    // empty value
		"decentralized_identifier:notadid", // not a DID
		"decentralized_identifier:did:",    // empty DID body
		"x509_san_dns:has/slash",           // DNS name with path
		"x509_san_dns:",                    // empty DNS
		"x509_hash:",                       // empty hash
		"verifier_attestation:",            // empty attestation
		"openid_federation:not-a-url",      // federation not absolute https
		"redirect_uri:https://%zz",         // invalid percent-encoding → url.Parse error
		"origin:not-a-url",                 // origin not absolute https
		"origin:ftp://x",                   // origin not https
	}
	for _, c := range invalid {
		if err := ValidateClientID(c); err != ErrClientIDInvalid {
			t.Errorf("ValidateClientID(%q) = %v, want ErrClientIDInvalid", c, err)
		}
	}
}

// TestValidateClientIDOriginPrefixIsSpecLiteral proves the DC-API prefix uses the
// exact OpenID4VP v1.0 §5.10 wire string "origin", not the retired "web-origin".
// A spec-conformant wallet/browser checking the literal "origin:" prefix would not
// recognize a "web-origin:"-prefixed client_id, so the old string must no longer be
// scheme-validated as the DC-API prefix — it degrades to a bare pre-registered
// identifier (still accepted, since any non-empty unknown-prefix string is treated
// as pre-registered, but no longer https-URL-validated as an origin).
func TestValidateClientIDOriginPrefixIsSpecLiteral(t *testing.T) {
	if err := ValidateClientID("origin:https://verify.example"); err != nil {
		t.Errorf("origin: prefix must validate as DC-API origin, got %v", err)
	}
	// The old "web-origin:" string is no longer a known scheme, so an invalid-origin
	// value under it must NOT be rejected as a malformed origin (it just isn't
	// recognized as that prefix at all).
	if err := ValidateClientID("web-origin:not-a-url"); err != nil {
		t.Errorf("web-origin: is no longer a known prefix, should pass through as bare pre-registered, got %v", err)
	}
}

func TestCreateRequestRejectsBadClientID(t *testing.T) {
	_, iss := setupFlow(t)
	bad := NewVerifier("redirect_uri:not-a-url", "https://verify.example/cb", nil)
	def := PresentationDefinition{
		ID:                "x",
		RequiredClaims:    []string{"a"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	if _, _, err := bad.CreateRequest(def); err != ErrClientIDInvalid {
		t.Fatalf("CreateRequest with bad client_id: want ErrClientIDInvalid, got %v", err)
	}
}
