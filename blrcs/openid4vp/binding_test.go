package openid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// TestE2EKeyBoundFlow — full verifier→wallet→verifier flow with holder key
// binding enforced. The wallet signs a KB-JWT over the request nonce/client_id.
func TestE2EKeyBoundFlow(t *testing.T) {
	ver, iss := setupFlow(t)
	ver.RequireKeyBinding = true

	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)

	def := PresentationDefinition{
		ID:             "dpp-bound",
		RequiredClaims: []string{"batteryCategory"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}

	sdjwt, _, err := iss.IssueSDJWTBound("battery-1",
		map[string]any{"batteryCategory": "ev"}, nil, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	w := NewMockWallet("did:holder:1")
	w.HolderKey = holderPriv
	w.Store(StoredCredential{ID: "c1", IssuerDID: iss.ID, IssuerPub: iss.PublicKey(), SDJWT: sdjwt})

	resp, err := w.Present(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.State != state {
		t.Fatalf("state mismatch: %s != %s", resp.State, state)
	}
	vp, err := ver.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("process bound response: %v", err)
	}
	if vp.Claims["batteryCategory"] != "ev" {
		t.Errorf("batteryCategory: %v", vp.Claims["batteryCategory"])
	}
}

// TestRequireKeyBindingRejectsUnbound — with RequireKeyBinding, a credential
// lacking holder binding (cnf) must be rejected even if otherwise valid.
func TestVerifierRejectsUnboundWhenRequired(t *testing.T) {
	ver, iss := setupFlow(t)
	ver.RequireKeyBinding = true

	def := PresentationDefinition{
		ID:             "x",
		RequiredClaims: []string{"a"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	_, state, _ := ver.CreateRequest(def)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour) // no cnf
	if _, err := ver.ProcessResponse(&AuthorizationResponse{VPToken: sdjwt, State: state}); err == nil {
		t.Fatal("unbound credential must be rejected when RequireKeyBinding is set")
	}
}

// TestKeyBoundCrossSessionReplayRejected — the central anti-replay guarantee.
// A presentation bound to request A's nonce must NOT verify under a fresh
// request B (different nonce), even though B's state is valid and unconsumed.
// Before nonce binding, this forged replay would have succeeded.
func TestKeyBoundCrossSessionReplayRejected(t *testing.T) {
	ver, iss := setupFlow(t)
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)

	def := PresentationDefinition{
		ID:             "x",
		RequiredClaims: []string{"a"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURLA, _, _ := ver.CreateRequest(def)
	sdjwt, _, _ := iss.IssueSDJWTBound("s", map[string]any{"a": 1}, nil, holderPub, time.Hour)

	w := NewMockWallet("h")
	w.HolderKey = holderPriv
	w.Store(StoredCredential{ID: "c", IssuerDID: iss.ID, SDJWT: sdjwt})

	// Holder builds a presentation bound to request A's nonce.
	respA, err := w.Present(reqURLA)
	if err != nil {
		t.Fatal(err)
	}

	// A fresh, independent request B is created.
	_, stateB, _ := ver.CreateRequest(def)

	// Attacker replays A's vp_token under session B → must be rejected.
	forged := &AuthorizationResponse{VPToken: respA.VPToken, State: stateB}
	if _, err := ver.ProcessResponse(forged); err == nil {
		t.Fatal("cross-session replay with stale nonce must be rejected")
	}
}
