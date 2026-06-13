package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"blrcs/revocation"
)

// TestIssueSDJWTBoundStatus proves a credential can be both holder-bound (cnf, for
// anti-replay) AND revocable (status_list) at once — the combination a regulated DPP
// needs. Before this method the public API forced an either/or choice.
func TestIssueSDJWTBoundStatus(t *testing.T) {
	iss, err := NewIssuer("did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	const idx = 5
	status := &StatusRef{URI: "https://status.example/list", Index: idx}

	sdjwt, _, err := iss.IssueSDJWTBoundStatus("subj",
		map[string]any{"carbon": 2.5}, map[string]any{"public": "v"},
		holderPub, status, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Holder-bound: a plain (bearer) verify must require a KB-JWT.
	if _, verr := VerifySDJWT(sdjwt, iss.PublicKey()); verr != ErrKeyBindingMissing {
		t.Fatalf("bound+status credential should require KB-JWT, got %v", verr)
	}

	// Present with KB-JWT and verify; the result must carry BOTH key binding and status.
	nonce, aud := "n-123", "https://verify.example"
	pres, err := PresentWithKeyBinding(sdjwt, []string{"carbon"}, holderPriv, nonce, aud, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce: nonce, ExpectedAudience: aud, RequireKeyBinding: true,
	})
	if err != nil {
		t.Fatalf("bound presentation should verify: %v", err)
	}
	if !vc.KeyBound {
		t.Error("verified presentation should be KeyBound")
	}
	if vc.Status == nil || vc.Status.Index != idx || vc.Status.URI != status.URI {
		t.Fatalf("status reference not preserved: %+v", vc.Status)
	}

	// Revocation works against the embedded status reference.
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, 64)
	if err := list.SetStatus(idx, true); err != nil { // mark this credential revoked
		t.Fatal(err)
	}
	revoked, err := CheckRevoked(vc, list)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("credential with its status bit set should be revoked")
	}

	// A list where the bit is clear reports not-revoked.
	clear := revocation.NewBitstringStatusList(revocation.PurposeRevocation, 64)
	if revoked, err := CheckRevoked(vc, clear); err != nil || revoked {
		t.Errorf("clear list should report not-revoked: revoked=%v err=%v", revoked, err)
	}
}

// TestIssueSDJWTBoundStatusRequiresHolderKey covers the holder-key guard.
func TestIssueSDJWTBoundStatusRequiresHolderKey(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer.example")
	_, _, err := iss.IssueSDJWTBoundStatus("subj", nil, nil, []byte("short"),
		&StatusRef{URI: "u", Index: 1}, time.Hour)
	if err != ErrHolderKeyRequired {
		t.Fatalf("want ErrHolderKeyRequired, got %v", err)
	}
}
