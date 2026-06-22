package didresolver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustAuthority(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func keyHashHex(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func sampleList(t *testing.T) *TrustList {
	t.Helper()
	return &TrustList{
		Authority: "did:web:registry.europa.eu",
		Version:   1,
		IssuedAt:  time.Now().Unix(),
		Expires:   time.Now().Add(24 * time.Hour).Unix(),
		Entries: []TrustListEntry{
			{DID: "did:web:factory.example", Status: IssuerActive, Scope: "battery"},
			{DID: "did:web:revoked.example", Status: IssuerRevoked},
			{DID: "did:web:suspended.example", Status: IssuerSuspended},
		},
	}
}

func TestTrustListSignVerifyRoundTrip(t *testing.T) {
	pub, priv := mustAuthority(t)
	tl := sampleList(t)

	signed, err := SignTrustList(tl, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyTrustList(signed, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Authority != tl.Authority || got.Version != 1 || len(got.Entries) != 3 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestTrustListRejectsWrongKey(t *testing.T) {
	_, priv := mustAuthority(t)
	otherPub, _ := mustAuthority(t)
	signed, _ := SignTrustList(sampleList(t), priv)
	if _, err := VerifyTrustList(signed, otherPub); !errors.Is(err, ErrTrustListSig) {
		t.Errorf("wrong key: want ErrTrustListSig, got %v", err)
	}
}

func TestTrustListRejectsTamper(t *testing.T) {
	pub, priv := mustAuthority(t)
	signed, _ := SignTrustList(sampleList(t), priv)
	// Flip a character in the payload segment.
	payloadB64, sigB64, _ := strings.Cut(signed, ".")
	tampered := payloadB64[:len(payloadB64)-1] + "A" + "." + sigB64
	if _, err := VerifyTrustList(tampered, pub); err == nil {
		t.Error("tampered payload should fail verification")
	}
}

func TestTrustListExpiry(t *testing.T) {
	pub, priv := mustAuthority(t)
	tl := sampleList(t)
	tl.Expires = time.Now().Add(-2 * time.Hour).Unix() // already expired
	signed, _ := SignTrustList(tl, priv)
	if _, err := VerifyTrustList(signed, pub); !errors.Is(err, ErrTrustListExpired) {
		t.Errorf("expired list: want ErrTrustListExpired, got %v", err)
	}
	// Within leeway it still verifies at a time before expiry.
	if _, err := VerifyTrustListAt(signed, pub, time.Now().Add(-3*time.Hour)); err != nil {
		t.Errorf("not-yet-expired at past time: %v", err)
	}
}

func TestTrustListMalformed(t *testing.T) {
	_, priv := mustAuthority(t)
	// Missing authority.
	if _, err := SignTrustList(&TrustList{Version: 1}, priv); !errors.Is(err, ErrTrustListMalformed) {
		t.Errorf("missing authority: want ErrTrustListMalformed, got %v", err)
	}
	// Invalid status.
	bad := &TrustList{Authority: "did:web:a", Entries: []TrustListEntry{{DID: "did:web:x", Status: "bogus"}}}
	if _, err := SignTrustList(bad, priv); !errors.Is(err, ErrTrustListMalformed) {
		t.Errorf("bad status: want ErrTrustListMalformed, got %v", err)
	}
	// Duplicate DID.
	dup := &TrustList{Authority: "did:web:a", Entries: []TrustListEntry{
		{DID: "did:web:x", Status: IssuerActive},
		{DID: "did:web:x", Status: IssuerActive},
	}}
	if _, err := SignTrustList(dup, priv); !errors.Is(err, ErrTrustListMalformed) {
		t.Errorf("duplicate DID: want ErrTrustListMalformed, got %v", err)
	}
	// Invalid keyHash.
	badHash := &TrustList{Authority: "did:web:a", Entries: []TrustListEntry{
		{DID: "did:web:x", Status: IssuerActive, KeyHash: "not-hex"},
	}}
	if _, err := SignTrustList(badHash, priv); !errors.Is(err, ErrTrustListMalformed) {
		t.Errorf("bad keyHash: want ErrTrustListMalformed, got %v", err)
	}
}

func TestTrustListToTrustAnchorActiveOnly(t *testing.T) {
	issuerPub, _ := mustAuthority(t)
	tl := &TrustList{
		Authority: "did:web:reg",
		Version:   1,
		Entries: []TrustListEntry{
			{DID: "did:web:active.example", Status: IssuerActive},
			{DID: "did:web:revoked.example", Status: IssuerRevoked},
			{DID: "did:web:pinned.example", Status: IssuerActive, KeyHash: keyHashHex(issuerPub)},
		},
	}
	ta := tl.ToTrustAnchor()

	if !ta.IsTrusted("did:web:active.example", nil) {
		t.Error("active DID should be trusted")
	}
	if ta.IsTrusted("did:web:revoked.example", nil) {
		t.Error("revoked DID must NOT be trusted (fail-closed)")
	}
	// The pinned entry is trusted by its DID...
	if !ta.IsTrusted("did:web:pinned.example", issuerPub) {
		t.Error("pinned active DID should be trusted via its DID")
	}
	// ...but the pinned key must NOT become trusted under a DIFFERENT DID: the
	// per-DID binding of a keyHash pin must not leak into a global key allow-list.
	if ta.IsTrusted("did:web:counterfeit.example", issuerPub) {
		t.Error("a key pinned for one DID must not be trusted under another DID")
	}
}

func TestTrustListAuthorizes(t *testing.T) {
	issuerPub, _ := mustAuthority(t)
	otherPub, _ := mustAuthority(t)
	tl := &TrustList{
		Authority: "did:web:reg",
		Entries: []TrustListEntry{
			{DID: "did:web:open.example", Status: IssuerActive},
			{DID: "did:web:pinned.example", Status: IssuerActive, KeyHash: keyHashHex(issuerPub)},
			{DID: "did:web:revoked.example", Status: IssuerRevoked},
		},
	}
	// Open entry: any key accepted.
	if !tl.Authorizes("did:web:open.example", otherPub) {
		t.Error("open active entry should authorize any key")
	}
	// Pinned entry: only the pinned key.
	if !tl.Authorizes("did:web:pinned.example", issuerPub) {
		t.Error("pinned entry should authorize the pinned key")
	}
	if tl.Authorizes("did:web:pinned.example", otherPub) {
		t.Error("pinned entry must reject a different key")
	}
	// Revoked entry: never.
	if tl.Authorizes("did:web:revoked.example", issuerPub) {
		t.Error("revoked entry must not authorize")
	}
	// Unlisted DID: never.
	if tl.Authorizes("did:web:unlisted.example", issuerPub) {
		t.Error("unlisted DID must not authorize")
	}
}

func TestTrustListVerifierRollback(t *testing.T) {
	pub, priv := mustAuthority(t)
	mk := func(version uint64) string {
		tl := sampleList(t)
		tl.Version = version
		s, err := SignTrustList(tl, priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	v := NewTrustListVerifier(pub)

	// Accept v2.
	if _, err := v.Verify(mk(2)); err != nil {
		t.Fatalf("v2: %v", err)
	}
	if v.CurrentVersion() != 2 {
		t.Fatalf("current version: want 2, got %d", v.CurrentVersion())
	}
	// Rollback to v1 must be rejected.
	if _, err := v.Verify(mk(1)); !errors.Is(err, ErrTrustListRollback) {
		t.Errorf("rollback to v1: want ErrTrustListRollback, got %v", err)
	}
	// Same version (v2) is idempotently accepted.
	if _, err := v.Verify(mk(2)); err != nil {
		t.Errorf("same version refresh: %v", err)
	}
	// Forward to v3 accepted and advances the bar.
	if _, err := v.Verify(mk(3)); err != nil {
		t.Errorf("v3: %v", err)
	}
	if v.CurrentVersion() != 3 {
		t.Errorf("current version: want 3, got %d", v.CurrentVersion())
	}
}

// TestTrustListVerifierRejectsBadSigBeforeVersion ensures a forged list never
// advances the version counter (signature is checked before the rollback gate).
func TestTrustListVerifierRejectsBadSig(t *testing.T) {
	pub, priv := mustAuthority(t)
	_, otherPriv := mustAuthority(t)
	v := NewTrustListVerifier(pub)

	tl := sampleList(t)
	tl.Version = 5
	forged, _ := SignTrustList(tl, otherPriv) // signed by the wrong key
	if _, err := v.Verify(forged); !errors.Is(err, ErrTrustListSig) {
		t.Errorf("forged: want ErrTrustListSig, got %v", err)
	}
	if v.CurrentVersion() != 0 {
		t.Errorf("forged list must not advance version, got %d", v.CurrentVersion())
	}
	// A genuine v1 is still accepted afterward (counter wasn't poisoned).
	genuine, _ := SignTrustList(func() *TrustList { l := sampleList(t); l.Version = 1; return l }(), priv)
	if _, err := v.Verify(genuine); err != nil {
		t.Errorf("genuine v1 after forged: %v", err)
	}
}

// TestTrustListEndToEnd wires a verified trust list into ResolveAndVerify: an
// issuer listed as active is accepted; one not on the list is rejected.
func TestTrustListEndToEnd(t *testing.T) {
	authPub, authPriv := mustAuthority(t)
	issuerPub, _ := mustAuthority(t)

	tl := &TrustList{
		Authority: "did:web:registry",
		Version:   1,
		Expires:   time.Now().Add(time.Hour).Unix(),
		Entries: []TrustListEntry{
			{DID: "did:web:authorized.example", Status: IssuerActive, KeyHash: keyHashHex(issuerPub)},
		},
	}
	signed, _ := SignTrustList(tl, authPriv)

	verified, err := VerifyTrustList(signed, authPub)
	if err != nil {
		t.Fatalf("verify list: %v", err)
	}
	ta := verified.ToTrustAnchor()

	if !ta.IsTrusted("did:web:authorized.example", issuerPub) {
		t.Error("authorized issuer should be trusted")
	}
	if ta.IsTrusted("did:web:counterfeit.example", issuerPub) {
		t.Error("counterfeit issuer must not be trusted")
	}
}
