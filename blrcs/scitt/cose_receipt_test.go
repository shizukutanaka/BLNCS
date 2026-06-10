package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCOSEReceiptRoundtrip(t *testing.T) {
	ledger, err := NewLedger("did:web:ts.blrcs.example")
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	stmt, err := SignStatement(priv, "did:web:issuer", "product-1", "application/vc+json", []byte("dpp-payload"))
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := ledger.Register(stmt)
	if err != nil {
		t.Fatal(err)
	}

	// Issue a COSE_Sign1 receipt
	tsPriv := ledger.tsPriv
	coseData, err := IssueCOSEReceipt(receipt, tsPriv, ledger.tsID)
	if err != nil {
		t.Fatalf("IssueCOSEReceipt: %v", err)
	}
	if len(coseData) == 0 {
		t.Fatal("COSE receipt is empty")
	}

	// First byte must be tag 18 (0xd2)
	if coseData[0] != 0xd2 {
		t.Errorf("first byte: got %02x, want 0xd2 (tag 18)", coseData[0])
	}

	// Verify with TS public key
	if err := VerifyCOSEReceipt(coseData, stmt, ledger.PublicKey()); err != nil {
		t.Fatalf("VerifyCOSEReceipt: %v", err)
	}
	_ = pub
}

func TestCOSEReceiptMultipleEntries(t *testing.T) {
	ledger, err := NewLedger("ts-multi")
	if err != nil {
		t.Fatal(err)
	}

	priv, _ := mustIssuer(t, "iss")

	// Register 50 entries
	var receipts []*Receipt
	var stmts []Statement
	for i := 0; i < 50; i++ {
		stmt, _ := SignStatement(priv, "iss", string(rune('a'+i)), "c", []byte{byte(i + 1)})
		r, err := ledger.Register(stmt)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, r)
		stmts = append(stmts, stmt)
	}

	// Verify COSE receipt for every entry
	for i, r := range receipts {
		cose, err := IssueCOSEReceipt(r, ledger.tsPriv, ledger.tsID)
		if err != nil {
			t.Fatalf("entry %d IssueCOSEReceipt: %v", i, err)
		}
		if err := VerifyCOSEReceipt(cose, stmts[i], ledger.PublicKey()); err != nil {
			t.Errorf("entry %d VerifyCOSEReceipt: %v", i, err)
		}
	}
}

func TestCOSEReceiptTamperedPayload(t *testing.T) {
	ledger, _ := NewLedger("ts-tamper")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)

	cose, _ := IssueCOSEReceipt(receipt, ledger.tsPriv, ledger.tsID)

	// Flip a byte in the COSE structure
	tampered := make([]byte, len(cose))
	copy(tampered, cose)
	tampered[len(tampered)-10] ^= 0xff

	if err := VerifyCOSEReceipt(tampered, stmt, ledger.PublicKey()); err == nil {
		t.Error("tampered COSE receipt should fail")
	}
}

func TestCOSEReceiptWrongStatement(t *testing.T) {
	ledger, _ := NewLedger("ts-wrong")
	priv, _ := mustIssuer(t, "iss")

	stmt1, _ := SignStatement(priv, "iss", "s1", "c", []byte("p1"))
	stmt2, _ := SignStatement(priv, "iss", "s2", "c", []byte("p2"))
	receipt1, _ := ledger.Register(stmt1)
	ledger.Register(stmt2)

	cose, _ := IssueCOSEReceipt(receipt1, ledger.tsPriv, ledger.tsID)

	// Verify against wrong statement
	if err := VerifyCOSEReceipt(cose, stmt2, ledger.PublicKey()); err == nil {
		t.Error("wrong statement should fail inclusion proof")
	}
}

func TestCOSEReceiptWrongKey(t *testing.T) {
	ledger, _ := NewLedger("ts-wk")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)

	cose, _ := IssueCOSEReceipt(receipt, ledger.tsPriv, ledger.tsID)

	// Verify with a different key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyCOSEReceipt(cose, stmt, wrongPub); err == nil {
		t.Error("wrong key should fail")
	}
}
