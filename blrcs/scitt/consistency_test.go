package scitt

import (
	"bytes"
	"fmt"
	"testing"

	"blrcs/compliance"
)

// buildLedger registers n statements and returns the ledger.
func buildLedger(t *testing.T, n int) (*Ledger, *compliance.Issuer) {
	t.Helper()
	iss, _ := compliance.NewIssuer("did:web:consistency.test")
	ledger, _ := NewLedger("did:web:ts.consistency.test")
	for i := 0; i < n; i++ {
		stmt, _ := SignStatement(iss.PrivateKey(), iss.ID, fmt.Sprintf("s%d", i), "text/plain", []byte{byte(i), byte(i >> 8)})
		if _, err := ledger.Register(stmt); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	return ledger, iss
}

// rootAt returns the signed checkpoint root for the current tree.
func rootAt(t *testing.T, ledger *Ledger) []byte {
	t.Helper()
	ckpt := ledger.SignedCheckpoint()
	root, err := hexDecode(ckpt.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestConsistencyProofAcrossSizes(t *testing.T) {
	// Build a 1-leaf ledger, capture root, grow to n, prove consistency each step.
	for n := 2; n <= 16; n++ {
		ledgerM, iss := buildLedger(t, 1)
		oldRoot := rootAt(t, ledgerM)
		// grow same ledger to n
		for i := 1; i < n; i++ {
			stmt, _ := SignStatement(iss.PrivateKey(), iss.ID, fmt.Sprintf("g%d", i), "text/plain", []byte{byte(i)})
			ledgerM.Register(stmt)
		}
		newRoot := rootAt(t, ledgerM)
		proof, err := ledgerM.ConsistencyProof(1, uint64(n))
		if err != nil {
			t.Fatalf("n=%d proof: %v", n, err)
		}
		if err := VerifyConsistency(1, uint64(n), oldRoot, newRoot, proof); err != nil {
			t.Errorf("n=%d: consistency verify failed: %v", n, err)
		}
		ledgerM.Close()
	}
}

func TestConsistencyProofManyTransitions(t *testing.T) {
	// For a 20-leaf tree, prove consistency from every m to every n>m.
	const total = 20
	ledger, _ := buildLedger(t, total)
	defer ledger.Close()

	// Capture intermediate roots by rebuilding sub-trees from leafHashes.
	ledger.mu.RLock()
	leaves := make([][]byte, len(ledger.leafHashes))
	copy(leaves, ledger.leafHashes)
	ledger.mu.RUnlock()

	rootOf := func(size int) []byte { return merkleRoot(leaves[:size]) }

	for m := 1; m < total; m++ {
		for n := m + 1; n <= total; n++ {
			proof, err := ledger.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatalf("m=%d n=%d proof: %v", m, n, err)
			}
			err = VerifyConsistency(uint64(m), uint64(n), rootOf(m), rootOf(n), proof)
			if err != nil {
				t.Errorf("m=%d n=%d: verify failed: %v", m, n, err)
			}
		}
	}
}

func TestConsistencyProofEqualSize(t *testing.T) {
	ledger, _ := buildLedger(t, 5)
	defer ledger.Close()
	root := rootAt(t, ledger)
	proof, err := ledger.ConsistencyProof(5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(5, 5, root, root, proof); err != nil {
		t.Errorf("equal-size consistency should pass: %v", err)
	}
}

func TestConsistencyProofEmptyOld(t *testing.T) {
	ledger, _ := buildLedger(t, 8)
	defer ledger.Close()
	newRoot := rootAt(t, ledger)
	proof, err := ledger.ConsistencyProof(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	// m=0: empty tree is prefix of anything
	if err := VerifyConsistency(0, 8, nil, newRoot, proof); err != nil {
		t.Errorf("empty old tree should be consistent: %v", err)
	}
}

func TestConsistencyProofInvalidRange(t *testing.T) {
	ledger, _ := buildLedger(t, 5)
	defer ledger.Close()
	// m > n
	if _, err := ledger.ConsistencyProof(6, 3); err == nil {
		t.Error("m>n should error")
	}
	// n beyond tree size
	if _, err := ledger.ConsistencyProof(2, 99); err == nil {
		t.Error("n>size should error")
	}
}

func TestVerifyConsistencyTamperedRoot(t *testing.T) {
	ledger, _ := buildLedger(t, 10)
	defer ledger.Close()
	ledger.mu.RLock()
	leaves := make([][]byte, len(ledger.leafHashes))
	copy(leaves, ledger.leafHashes)
	ledger.mu.RUnlock()

	proof, _ := ledger.ConsistencyProof(4, 10)
	oldRoot := merkleRoot(leaves[:4])
	newRoot := merkleRoot(leaves[:10])

	// Tamper newRoot
	bad := make([]byte, len(newRoot))
	copy(bad, newRoot)
	bad[0] ^= 0xFF
	if err := VerifyConsistency(4, 10, oldRoot, bad, proof); err == nil {
		t.Error("tampered new root should fail consistency")
	}
	// Tamper oldRoot
	badOld := make([]byte, len(oldRoot))
	copy(badOld, oldRoot)
	badOld[0] ^= 0xFF
	if err := VerifyConsistency(4, 10, badOld, newRoot, proof); err == nil {
		t.Error("tampered old root should fail consistency")
	}
}

func TestVerifyConsistencyMGreaterN(t *testing.T) {
	if err := VerifyConsistency(10, 5, nil, nil, nil); err == nil {
		t.Error("m>n should fail verification")
	}
}

func TestVerifyConsistencyEqualMismatch(t *testing.T) {
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	if err := VerifyConsistency(3, 3, a, b, nil); err == nil {
		t.Error("equal size with different roots should fail")
	}
}

func TestLedgerRoot(t *testing.T) {
	ledger, _ := buildLedger(t, 3)
	defer ledger.Close()
	root := ledger.Root()
	ckpt := ledger.SignedCheckpoint()
	want, _ := hexDecode(ckpt.RootHash)
	if !bytes.Equal(root, want) {
		t.Error("Root() should match checkpoint root")
	}
}
