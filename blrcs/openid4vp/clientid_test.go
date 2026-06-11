package openid4vp

import "testing"

func TestValidateClientID(t *testing.T) {
	valid := []string{
		"https://verify.blrcs.example",           // bare pre-registered URL
		"verifier.example",                       // bare pre-registered
		"redirect_uri:https://verify.example/cb", // redirect_uri scheme
		"web-origin:https://verify.example",      // DC-API origin
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
	}
	for _, c := range invalid {
		if err := ValidateClientID(c); err != ErrClientIDInvalid {
			t.Errorf("ValidateClientID(%q) = %v, want ErrClientIDInvalid", c, err)
		}
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
