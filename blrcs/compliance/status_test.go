package compliance

import (
	"testing"
	"time"

	"blrcs/revocation"
)

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
