package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// farFutureTime is past the year 9999 that RFC 3339 (and so encoding/json) can
// represent. It is reachable in-process — time.Now().AddDate(100000, 0, 0)
// produces it — though not over the wire, since Go's RFC 3339 parser rejects
// expanded years on the way in.
func farFutureTime() time.Time { return time.Now().UTC().AddDate(100000, 0, 0) }

// TestStatementSigPayloadFailsClosed pins the fix for a signature-integrity bug.
//
// statementSigPayload discarded its json.Marshal error and returned nil on
// failure. Marshal fails on a time.Time outside [0,9999], so every statement
// carrying such a timestamp produced the SAME empty signing payload — one
// signature would then verify for any of them, leaving issuer, subject and
// payloadHash unauthenticated. The payload builder now reports the error and
// both signing and verification fail closed.
func TestStatementSigPayloadFailsClosed(t *testing.T) {
	far := farFutureTime()
	a := &Statement{Issuer: "did:web:a", Subject: "AAA", ContentType: "x", PayloadHash: "aa", IssuedAt: far, IssuerKey: "k1"}
	b := &Statement{Issuer: "did:web:b", Subject: "BBB", ContentType: "y", PayloadHash: "bb", IssuedAt: far, IssuerKey: "k2"}

	pa, errA := statementSigPayload(a)
	pb, errB := statementSigPayload(b)
	if errA == nil || errB == nil {
		t.Fatalf("want an error for an unencodable timestamp, got %v / %v", errA, errB)
	}
	if len(pa) != 0 || len(pb) != 0 {
		t.Fatalf("a failed payload must be empty, got %d / %d bytes", len(pa), len(pb))
	}
	// The bug was that these two DIFFERENT statements shared one signing
	// payload. They still share the empty one — the fix is that no signature is
	// ever produced or accepted over it.
}

// TestVerifyStatementRejectsUnencodableTimestamp is the fail-closed half: a
// statement whose signing payload cannot be built must never verify, whatever
// signature it carries.
func TestVerifyStatementRejectsUnencodableTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good, err := SignStatement(priv, "did:web:issuer", "subject", "application/vc+json", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatement(&good); err != nil {
		t.Fatalf("a well-formed statement must verify: %v", err)
	}
	_ = pub

	// Same signature, timestamp pushed out of encodable range.
	tampered := good
	tampered.IssuedAt = farFutureTime()
	err = VerifyStatement(&tampered)
	if err == nil {
		t.Fatal("a statement with an unencodable timestamp must not verify")
	}
	if !errors.Is(err, ErrStatementMalformed) {
		t.Fatalf("want ErrStatementMalformed, got %v", err)
	}
}

// TestSignStatementCannotProduceUnverifiableStatement: SignStatement sets
// IssuedAt itself, so it must always yield something VerifyStatement accepts.
func TestSignStatementCannotProduceUnverifiableStatement(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := SignStatement(priv, "did:web:issuer", "subject", "application/vc+json", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatement(&stmt); err != nil {
		t.Fatalf("SignStatement produced a statement it cannot verify: %v", err)
	}
}

// TestNoCrossStatementSignatureReuse captures the vulnerability directly rather
// than merely observing that verification errors.
//
// The original statementSigPayload returned nil when json.Marshal failed, so
// every statement with an out-of-range timestamp was signed and verified over
// the SAME empty payload — one signature covered any of them, whatever the
// issuer, subject or payloadHash claimed. Here that forgery is constructed and
// must be rejected.
func TestNoCrossStatementSignatureReuse(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The signature the discarded-error form accepted for every such statement.
	forged := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, nil))

	victim := &Statement{
		Issuer:      "did:web:attacker",
		Subject:     "a-product-the-attacker-never-attested",
		ContentType: "application/vc+json",
		PayloadHash: "00",
		IssuedAt:    farFutureTime(),
		Signature:   forged,
		IssuerKey:   base64.StdEncoding.EncodeToString(pub),
	}
	if err := VerifyStatement(victim); err == nil {
		t.Fatal("a signature over the empty payload verified a statement it never covered")
	}
}
