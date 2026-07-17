package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"blrcs/revocation"
)

// TestCheckRevokedTokenEndToEnd — issue a credential with a status ref, publish
// the list as a signed Status List Token, then verify the credential's status
// against the token (authenticity + subject binding + bit check).
func TestCheckRevokedTokenEndToEnd(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	statusPub, statusPriv, _ := ed25519.GenerateKey(rand.Reader)
	uri := "https://issuer.example/status/1"
	ref := &StatusRef{URI: uri, Index: 5}

	sdjwt, _, _ := iss.IssueSDJWTStatus("s", map[string]any{"a": 1}, nil, ref, time.Hour)
	vc, _ := VerifySDJWT(sdjwt, iss.PublicKey())

	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	token, _ := list.IssueToken("did:web:issuer", uri, statusPriv, time.Hour)
	revoked, err := CheckRevokedToken(vc, token, statusPub)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("should not be revoked before bit is set")
	}

	// Revoke and re-publish.
	_ = list.SetStatus(5, true)
	token2, _ := list.IssueToken("did:web:issuer", uri, statusPriv, time.Hour)
	revoked, err = CheckRevokedToken(vc, token2, statusPub)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("should be revoked after bit is set")
	}
}

// TestCheckRevokedTokenSubjectMismatch — a token whose subject differs from the
// credential's status.uri (a substituted list) must be rejected.
func TestCheckRevokedTokenSubjectMismatch(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	statusPub, statusPriv, _ := ed25519.GenerateKey(rand.Reader)
	ref := &StatusRef{URI: "https://issuer.example/status/1", Index: 5}
	sdjwt, _, _ := iss.IssueSDJWTStatus("s", map[string]any{"a": 1}, nil, ref, time.Hour)
	vc, _ := VerifySDJWT(sdjwt, iss.PublicKey())

	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	// Token published under a DIFFERENT subject URI.
	token, _ := list.IssueToken("did:web:issuer", "https://evil.example/status/9", statusPriv, time.Hour)
	if _, err := CheckRevokedToken(vc, token, statusPub); err != ErrStatusListMismatch {
		t.Fatalf("want ErrStatusListMismatch, got %v", err)
	}
}

// TestStatusClaimRoundTrip — an issued credential carries a resolvable status
// reference, and CheckRevoked reflects the bit in the status list.
func TestStatusClaimRoundTrip(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	ref := &StatusRef{URI: "https://issuer.example/status/1", Index: 42}

	sdjwt, _, err := iss.IssueSDJWTStatus("subject-1",
		map[string]any{"carbon": 2.5}, nil, ref, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	vc, err := VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vc.Status == nil {
		t.Fatal("status reference not extracted from credential")
	}
	if vc.Status.URI != ref.URI || vc.Status.Index != ref.Index {
		t.Fatalf("status mismatch: got %+v want %+v", vc.Status, ref)
	}

	// Status list with bit 42 not yet set → not revoked.
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	revoked, err := CheckRevoked(vc, list)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("credential should not be revoked before its bit is set")
	}

	// Issuer revokes index 42 → CheckRevoked must report true.
	if err := list.SetStatus(42, true); err != nil {
		t.Fatal(err)
	}
	revoked, err = CheckRevoked(vc, list)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("credential should be revoked after its bit is set")
	}
}

// TestStatusClaimSurvivesEncodedListRoundTrip — the status check works against a
// list that was published (gzip+base64url) and decoded by the verifier.
func TestStatusClaimSurvivesEncodedListRoundTrip(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	ref := &StatusRef{URI: "https://issuer.example/status/1", Index: 7}
	sdjwt, _, _ := iss.IssueSDJWTStatus("s", map[string]any{"a": 1}, nil, ref, time.Hour)
	vc, _ := VerifySDJWT(sdjwt, iss.PublicKey())

	src := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	_ = src.SetStatus(7, true)
	encoded, err := src.EncodedList()
	if err != nil {
		t.Fatal(err)
	}
	// Verifier side: fetch + decode the published list, then check.
	list, err := revocation.DecodeBitstringStatusList(revocation.PurposeRevocation, encoded)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := CheckRevoked(vc, list)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("expected revoked=true after decoding published status list")
	}
}

// TestCheckRevokedNoStatus — a credential without a status claim is never revoked.
func TestCheckRevokedNoStatus(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	vc, _ := VerifySDJWT(sdjwt, iss.PublicKey())
	if vc.Status != nil {
		t.Fatal("unbound credential should have no status reference")
	}
	revoked, err := CheckRevoked(vc, nil)
	if err != nil {
		t.Fatalf("no-status credential should not require a list: %v", err)
	}
	if revoked {
		t.Error("no-status credential must never be revoked")
	}
}

// TestCheckRevokedMissingList — a status-bearing credential with no list errors.
func TestCheckRevokedMissingList(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	ref := &StatusRef{URI: "https://issuer.example/s/1", Index: 1}
	sdjwt, _, _ := iss.IssueSDJWTStatus("s", map[string]any{"a": 1}, nil, ref, time.Hour)
	vc, _ := VerifySDJWT(sdjwt, iss.PublicKey())
	if _, err := CheckRevoked(vc, nil); err != ErrStatusListRequired {
		t.Fatalf("want ErrStatusListRequired, got %v", err)
	}
}

// TestCheckRevokedTokenBadToken — a malformed status list token must propagate the error.
func TestCheckRevokedTokenBadToken(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	_, statusPriv, _ := ed25519.GenerateKey(rand.Reader)
	statusPub := statusPriv.Public().(ed25519.PublicKey)
	ref := &StatusRef{URI: "https://issuer.example/s/1", Index: 0}
	sdjwt, _, _ := iss.IssueSDJWTStatus("s", map[string]any{"a": 1}, nil, ref, time.Hour)
	vc, _ := VerifySDJWT(sdjwt, iss.PublicKey())
	if _, err := CheckRevokedToken(vc, "not-a-valid-token", statusPub); err == nil {
		t.Error("invalid token should return an error")
	}
}

// ============================================================================
// extractStatus edge cases — status_list not a map, missing idx/uri
// ============================================================================

func TestExtractStatusStatusListNotMap(t *testing.T) {
	// status is a map but status_list is not a map (it's a string)
	payload := map[string]any{
		"status": map[string]any{
			"status_list": "not-a-map",
		},
	}
	if got := extractStatus(payload); got != nil {
		t.Errorf("non-map status_list: want nil, got %+v", got)
	}
}

func TestExtractStatusEmptyURI(t *testing.T) {
	// status_list is a map but uri is empty
	payload := map[string]any{
		"status": map[string]any{
			"status_list": map[string]any{
				"uri": "",
				"idx": float64(5),
			},
		},
	}
	if got := extractStatus(payload); got != nil {
		t.Errorf("empty URI: want nil, got %+v", got)
	}
}

func TestExtractStatusMissingIdx(t *testing.T) {
	// status_list has a uri but no idx field
	payload := map[string]any{
		"status": map[string]any{
			"status_list": map[string]any{
				"uri": "https://issuer.example/status/1",
				// no idx
			},
		},
	}
	if got := extractStatus(payload); got != nil {
		t.Errorf("missing idx: want nil, got %+v", got)
	}
}

// TestCheckRevokedTokenNilVC — nil vc and nil Status must return (false, nil).
func TestCheckRevokedTokenNilVC(t *testing.T) {
	_, statusPriv, _ := ed25519.GenerateKey(rand.Reader)
	statusPub := statusPriv.Public().(ed25519.PublicKey)
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	token, _ := list.IssueToken("did:web:iss", "https://issuer.example/status/1", statusPriv, time.Hour)

	if revoked, err := CheckRevokedToken(nil, token, statusPub); revoked || err != nil {
		t.Errorf("nil vc: want (false,nil), got (%v,%v)", revoked, err)
	}
	noStatus := &VerifiedClaims{}
	if revoked, err := CheckRevokedToken(noStatus, token, statusPub); revoked || err != nil {
		t.Errorf("nil status: want (false,nil), got (%v,%v)", revoked, err)
	}
}
