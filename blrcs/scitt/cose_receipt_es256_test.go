package scitt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"blrcs/cbor"
	"blrcs/ecdsakey"
)

// es256Fixture registers one statement on a fresh ledger and returns the
// statement, its receipt, and a P-256 transparency-service key pair (SEC1
// public encoding, as a relying party would hold it).
func es256Fixture(t *testing.T) (Statement, *Receipt, *ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	ledger, err := NewLedger("did:web:ts.blrcs.example")
	if err != nil {
		t.Fatal(err)
	}
	_, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	stmt, err := SignStatement(issuerPriv, "did:web:issuer", "product-1", "application/vc+json", []byte("dpp-payload"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ledger.Register(stmt)
	if err != nil {
		t.Fatal(err)
	}
	tsPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := ecdsakey.MarshalP256PublicKey(&tsPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return stmt, receipt, tsPriv, sec1, ledger.tsID
}

func TestCOSEReceiptES256Roundtrip(t *testing.T) {
	stmt, receipt, tsPriv, sec1, tsID := es256Fixture(t)

	data, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatalf("IssueCOSEReceiptES256: %v", err)
	}
	if len(data) == 0 || data[0] != 0xd2 {
		t.Fatalf("want COSE_Sign1 tag 18 (0xd2), got % x", data[:1])
	}
	if err := VerifyCOSEReceipt(data, stmt, sec1); err != nil {
		t.Fatalf("VerifyCOSEReceipt (ES256): %v", err)
	}
	// The compressed SEC1 encoding of the same key must work identically.
	compressed := elliptic.MarshalCompressed(elliptic.P256(), tsPriv.X, tsPriv.Y)
	if err := VerifyCOSEReceipt(data, stmt, compressed); err != nil {
		t.Fatalf("VerifyCOSEReceipt with compressed SEC1 key: %v", err)
	}
}

// TestCOSEReceiptES256HeaderDeclaresES256 is the label-matches-act assertion:
// the protected header must name the algorithm that actually signed. A header
// naming EdDSA over an ECDSA signature is exactly the defect class fixed in the
// mdoc path, so it is asserted here rather than assumed.
func TestCOSEReceiptES256HeaderDeclaresES256(t *testing.T) {
	_, receipt, tsPriv, sec1, tsID := es256Fixture(t)

	data, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cbor.Verify1WithAlgs(data, sec1, nil, nil)
	if err != nil {
		t.Fatalf("Verify1WithAlgs: %v", err)
	}
	alg, ok := cbor.GetInt(res.Protected[cbor.HeaderAlg])
	if !ok {
		t.Fatalf("protected header alg is %T, want an integer", res.Protected[cbor.HeaderAlg])
	}
	if alg != int64(cbor.AlgES256) {
		t.Fatalf("protected header declares alg %d, want ES256 (%d)", alg, cbor.AlgES256)
	}
	if kid, ok := res.Protected[cbor.HeaderKid].([]byte); !ok || string(kid) != tsID {
		t.Fatalf("protected header kid = %q, want %q", kid, tsID)
	}
}

func TestCOSEReceiptES256Tampered(t *testing.T) {
	stmt, receipt, tsPriv, sec1, tsID := es256Fixture(t)

	data, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"first byte of the signature region", len(data) - 1},
		{"middle of the structure", len(data) / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := make([]byte, len(data))
			copy(bad, data)
			bad[tc.at] ^= 0xff
			if err := VerifyCOSEReceipt(bad, stmt, sec1); err == nil {
				t.Fatal("tampered COSE receipt verified")
			}
		})
	}
}

func TestCOSEReceiptES256WrongKey(t *testing.T) {
	stmt, receipt, tsPriv, _, tsID := es256Fixture(t)

	data, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ecdsakey.MarshalP256PublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCOSEReceipt(data, stmt, wrong); err == nil {
		t.Fatal("receipt verified under a different P-256 key")
	}
}

// TestCOSEReceiptES256InclusionStillEnforced proves the ES256 path checks the
// Merkle proof too, not just the signature: a validly signed receipt must not
// vouch for a statement that is not in the tree.
func TestCOSEReceiptES256InclusionStillEnforced(t *testing.T) {
	_, receipt, tsPriv, sec1, tsID := es256Fixture(t)

	data, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	unregistered, err := SignStatement(otherPriv, "did:web:issuer", "product-2", "application/vc+json", []byte("never-registered"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCOSEReceipt(data, unregistered, sec1); err == nil {
		t.Fatal("receipt vouched for a statement that was never registered")
	}
}

// TestCOSEReceiptCrossAlgConfusion checks both directions: a receipt of one
// algorithm must not pass when the relying party pins the other. The allowlist
// is the mechanism an RP uses to refuse algorithm substitution.
func TestCOSEReceiptCrossAlgConfusion(t *testing.T) {
	stmt, receipt, tsPriv, sec1, tsID := es256Fixture(t)

	esData, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edData, err := IssueCOSEReceipt(receipt, edPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCOSEReceiptWithAlgs(esData, stmt, sec1, []int{cbor.AlgEdDSA}); err == nil {
		t.Fatal("ES256 receipt accepted while pinning EdDSA")
	}
	if err := VerifyCOSEReceiptWithAlgs(edData, stmt, edPub, []int{cbor.AlgES256}); err == nil {
		t.Fatal("EdDSA receipt accepted while pinning ES256")
	}
	// Each still passes under its own pinned algorithm — the allowlist rejects
	// substitution, not the feature.
	if err := VerifyCOSEReceiptWithAlgs(esData, stmt, sec1, []int{cbor.AlgES256}); err != nil {
		t.Fatalf("ES256 receipt pinned to ES256: %v", err)
	}
	if err := VerifyCOSEReceiptWithAlgs(edData, stmt, edPub, []int{cbor.AlgEdDSA}); err != nil {
		t.Fatalf("EdDSA receipt pinned to EdDSA: %v", err)
	}
	// And a key of the wrong kind for the declared alg fails rather than
	// verifying: an Ed25519 key against an ES256 receipt and vice versa.
	if err := VerifyCOSEReceipt(esData, stmt, edPub); err == nil {
		t.Fatal("ES256 receipt verified with an Ed25519 key")
	}
	if err := VerifyCOSEReceipt(edData, stmt, sec1); err == nil {
		t.Fatal("EdDSA receipt verified with a P-256 key")
	}
}

// TestCOSEReceiptWrongLengthKeyDoesNotPanic pins the fix from the ed25519.Verify
// panic class: a caller-supplied key of any shape must produce an error, never
// a crash, on both receipt algorithms.
func TestCOSEReceiptWrongLengthKeyDoesNotPanic(t *testing.T) {
	stmt, receipt, tsPriv, _, tsID := es256Fixture(t)

	esData, err := IssueCOSEReceiptES256(receipt, tsPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edData, err := IssueCOSEReceipt(receipt, edPriv, tsID)
	if err != nil {
		t.Fatal(err)
	}

	badKeys := map[string][]byte{
		"nil":                 nil,
		"empty":               {},
		"one byte":            {0x04},
		"16 bytes":            make([]byte, 16),
		"31 bytes":            make([]byte, 31),
		"33 bytes, bad tag":   make([]byte, 33),
		"64 bytes":            make([]byte, 64),
		"65 bytes, bad tag":   make([]byte, 65),
		"65 bytes, off curve": append([]byte{0x04}, make([]byte, 64)...),
	}
	for _, receiptData := range [][]byte{esData, edData} {
		for name, key := range badKeys {
			t.Run(name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on malformed key %q: %v", name, r)
					}
				}()
				if err := VerifyCOSEReceipt(receiptData, stmt, key); err == nil {
					t.Fatalf("malformed key %q verified a receipt", name)
				}
			})
		}
	}
}
