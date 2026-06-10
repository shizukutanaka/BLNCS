package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func makeKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// ============================================================================
// Reason validation
// ============================================================================

func TestReasonValidity(t *testing.T) {
	valid := []Reason{
		ReasonRecall, ReasonError, ReasonExpired, ReasonSuperseded,
		ReasonSecurity, ReasonCompliance, ReasonOther,
	}
	for _, r := range valid {
		if !r.IsValid() {
			t.Errorf("%s should be valid", r)
		}
	}
	if Reason("custom-reason").IsValid() {
		t.Error("unknown reason should be invalid")
	}
}

// ============================================================================
// Revoke + Lookup
// ============================================================================

func TestRevokeAndLookup(t *testing.T) {
	l := New("did:web:issuer.test")
	entry, err := l.Revoke("cred-001", ReasonRecall, "Battery defect — risk of fire")
	if err != nil {
		t.Fatal(err)
	}
	if entry.CredentialID != "cred-001" {
		t.Errorf("id: %s", entry.CredentialID)
	}
	if entry.Reason != ReasonRecall {
		t.Errorf("reason: %s", entry.Reason)
	}
	if !l.IsRevoked("cred-001") {
		t.Error("should be revoked")
	}
	if l.IsRevoked("cred-002") {
		t.Error("non-revoked should report false")
	}
	got, err := l.Lookup("cred-001")
	if err != nil {
		t.Fatal(err)
	}
	if got.Detail != "Battery defect — risk of fire" {
		t.Errorf("detail: %s", got.Detail)
	}
}

func TestRevokeRejectsInvalidReason(t *testing.T) {
	l := New("did:web:issuer.test")
	_, err := l.Revoke("cred-1", Reason("custom"), "")
	if err == nil {
		t.Fatal("invalid reason should fail")
	}
}

func TestDoubleRevokeRejected(t *testing.T) {
	l := New("did:web:issuer.test")
	l.Revoke("cred-X", ReasonRecall, "")
	_, err := l.Revoke("cred-X", ReasonError, "")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("want ErrAlreadyRevoked, got %v", err)
	}
}

func TestLookupNonRevoked(t *testing.T) {
	l := New("did:web:issuer.test")
	_, err := l.Lookup("never-revoked")
	if !errors.Is(err, ErrNotRevoked) {
		t.Errorf("want ErrNotRevoked, got %v", err)
	}
}

// ============================================================================
// Size + Entries
// ============================================================================

func TestSizeReflectsRevocations(t *testing.T) {
	l := New("did:web:issuer.test")
	if l.Size() != 0 {
		t.Errorf("initial: %d", l.Size())
	}
	for i := 0; i < 10; i++ {
		l.Revoke(fmtID(i), ReasonRecall, "")
	}
	if l.Size() != 10 {
		t.Errorf("after 10: %d", l.Size())
	}
}

func TestEntriesSortedDeterministic(t *testing.T) {
	l := New("did:web:issuer.test")
	// Insert out of order
	l.Revoke("cred-z", ReasonRecall, "")
	l.Revoke("cred-a", ReasonRecall, "")
	l.Revoke("cred-m", ReasonRecall, "")

	entries := l.Entries()
	if len(entries) != 3 {
		t.Fatal("count")
	}
	// Sorted by CredentialID
	if entries[0].CredentialID != "cred-a" ||
		entries[1].CredentialID != "cred-m" ||
		entries[2].CredentialID != "cred-z" {
		t.Errorf("not sorted: %v", entries)
	}
}

// ============================================================================
// Sign / Verify roundtrip
// ============================================================================

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv := makeKeyPair(t)
	l := New("did:web:issuer.test")
	l.Revoke("cred-1", ReasonRecall, "production defect")
	l.Revoke("cred-2", ReasonError, "wrong product ID")

	signed, err := l.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature == "" {
		t.Error("no signature")
	}
	if len(signed.Entries) != 2 {
		t.Errorf("entries: %d", len(signed.Entries))
	}
	if err := Verify(signed, pub); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestVerifyDetectsTamperedEntries(t *testing.T) {
	pub, priv := makeKeyPair(t)
	l := New("did:web:issuer.test")
	l.Revoke("cred-1", ReasonRecall, "real reason")

	signed, _ := l.Sign(priv)
	// Tamper with entries
	signed.Entries[0].Detail = "tampered detail"

	err := Verify(signed, pub)
	if !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("tamper should fail: %v", err)
	}
}

func TestVerifyDetectsTamperedIssuer(t *testing.T) {
	pub, priv := makeKeyPair(t)
	l := New("did:web:legitimate.test")
	l.Revoke("cred-1", ReasonRecall, "")
	signed, _ := l.Sign(priv)

	signed.Issuer = "did:web:evil.test"
	err := Verify(signed, pub)
	if !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("tamper should fail: %v", err)
	}
}

func TestVerifyWrongPublicKey(t *testing.T) {
	_, priv1 := makeKeyPair(t)
	pub2, _ := makeKeyPair(t)
	l := New("did:web:issuer.test")
	l.Revoke("cred-1", ReasonRecall, "")
	signed, _ := l.Sign(priv1)

	if err := Verify(signed, pub2); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("wrong pub key: %v", err)
	}
}

func TestVerifyMalformedSignature(t *testing.T) {
	pub, priv := makeKeyPair(t)
	_ = priv
	signed := &SignedList{
		Issuer:    "did:web:test",
		Entries:   []Entry{},
		Signature: "not-hex",
	}
	if err := Verify(signed, pub); !errors.Is(err, ErrInvalidSig) {
		t.Errorf("malformed sig: %v", err)
	}
}

// ============================================================================
// Load from SignedList
// ============================================================================

func TestLoadFromSignedList(t *testing.T) {
	pub, priv := makeKeyPair(t)
	original := New("did:web:issuer.test")
	original.Revoke("cred-A", ReasonRecall, "test")
	original.Revoke("cred-B", ReasonError, "")

	signed, _ := original.Sign(priv)
	if err := Verify(signed, pub); err != nil {
		t.Fatal(err)
	}

	// Reconstitute
	loaded := Load(signed)
	if loaded.Size() != 2 {
		t.Errorf("loaded size: %d", loaded.Size())
	}
	if !loaded.IsRevoked("cred-A") || !loaded.IsRevoked("cred-B") {
		t.Error("entries not loaded")
	}
	entry, _ := loaded.Lookup("cred-A")
	if entry.Reason != ReasonRecall {
		t.Errorf("reason: %s", entry.Reason)
	}
}

// ============================================================================
// JSON serialization
// ============================================================================

func TestSignedListJSONRoundtrip(t *testing.T) {
	_, priv := makeKeyPair(t)
	l := New("did:web:test")
	l.Revoke("cred-1", ReasonRecall, "detail")
	signed, _ := l.Sign(priv)

	body, err := signed.MarshalToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "cred-1") {
		t.Errorf("missing entry: %s", body)
	}
	parsed, err := UnmarshalSignedList(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Issuer != "did:web:test" {
		t.Errorf("issuer roundtrip: %s", parsed.Issuer)
	}
	if len(parsed.Entries) != 1 {
		t.Errorf("entries: %d", len(parsed.Entries))
	}
}

// ============================================================================
// Issuer attribute
// ============================================================================

func TestIssuer(t *testing.T) {
	l := New("did:web:test.issuer")
	if l.Issuer() != "did:web:test.issuer" {
		t.Errorf("issuer: %s", l.Issuer())
	}
}

// ============================================================================
// Concurrent revocation
// ============================================================================

func TestConcurrentRevocations(t *testing.T) {
	l := New("did:web:test")
	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func() {
			l.Revoke(fmtID(i), ReasonRecall, "")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	if l.Size() != 100 {
		t.Errorf("expected 100, got %d", l.Size())
	}
}

// TestUnmarshalSignedListBadJSON covers the json.Unmarshal error path.
func TestUnmarshalSignedListBadJSON(t *testing.T) {
	_, err := UnmarshalSignedList([]byte("not valid json {{{"))
	if err == nil {
		t.Fatal("invalid JSON should return an error from UnmarshalSignedList")
	}
}

// ============================================================================
// helpers
// ============================================================================

func fmtID(i int) string {
	return "cred-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
}
