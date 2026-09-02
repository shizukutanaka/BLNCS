package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// TestComputeDigestFailsClosed pins the same fix as scitt's signing payload, in
// the revocation list's signature digest.
//
// computeDigest discarded its json.Marshal error and hashed nil on failure.
// Marshal fails on a time.Time outside [0,9999], and Entry.RevokedAt is one —
// so two lists with different issuers and different entries produced the SAME
// digest, and a signature over one would verify for the other. Both Sign and
// Verify now fail closed.
func TestComputeDigestFailsClosed(t *testing.T) {
	far := time.Now().UTC().AddDate(100000, 0, 0)

	a := &SignedList{Issuer: "did:web:a", UpdatedAt: time.Now().UTC(),
		Entries: []Entry{{CredentialID: "AAA", RevokedAt: far}}}
	b := &SignedList{Issuer: "did:web:b", UpdatedAt: time.Now().UTC(),
		Entries: []Entry{{CredentialID: "BBB", RevokedAt: far}}}

	da, errA := computeDigest(a)
	db, errB := computeDigest(b)
	if errA == nil || errB == nil {
		t.Fatalf("want an error for an unencodable timestamp, got %v / %v", errA, errB)
	}
	if da != nil || db != nil {
		t.Fatal("a failed digest must be nil, never a hash of empty input")
	}
}

// TestNoCrossListSignatureReuse is the test that actually captures the
// vulnerability, rather than merely observing that verification errors.
//
// The original computeDigest hashed nil when json.Marshal failed, so EVERY list
// with an out-of-range timestamp digested to sha256("") — one signature over
// that constant verified any such list, whatever its issuer and entries. Here
// that exact forgery is constructed and must be rejected.
//
// An earlier version of this test only asserted that Verify returned
// ErrInvalidSig, which a broken implementation also does by accident; mutation
// testing caught that, and this is the replacement.
func TestNoCrossListSignatureReuse(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	far := time.Now().UTC().AddDate(100000, 0, 0)

	// The digest the discarded-error form produced for every such list.
	emptyDigest := sha256.Sum256(nil)
	forged := hex.EncodeToString(ed25519.Sign(priv, emptyDigest[:]))

	victim := &SignedList{
		Issuer:    "did:web:attacker",
		UpdatedAt: time.Now().UTC(),
		Entries:   []Entry{{CredentialID: "not-really-revoked", RevokedAt: far}},
		Signature: forged,
	}
	if err := Verify(victim, pub); err == nil {
		t.Fatal("a signature over the empty digest verified a list it never covered")
	}
}

// TestSignRefusesUnencodableTimestamp: the forgery above cannot even be minted
// through the public API, because Sign fails closed too.
func TestSignRefusesUnencodableTimestamp(t *testing.T) {
	far := time.Now().UTC().AddDate(100000, 0, 0)
	l := &SignedList{Issuer: "did:web:a", UpdatedAt: time.Now().UTC(),
		Entries: []Entry{{CredentialID: "AAA", RevokedAt: far}}}
	if _, err := computeDigest(l); err == nil {
		t.Fatal("computeDigest must refuse an unencodable timestamp")
	}
}
