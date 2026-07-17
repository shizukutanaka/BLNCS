package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

func growLedger(t *testing.T, l *Ledger, n int) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < n; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d-%d", l.Size(), i), "c", []byte(fmt.Sprintf("p%d", i)))
		if _, err := l.Register(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWitnessCosignHappyPath(t *testing.T) {
	ledger, _ := NewLedger("ts-w1")
	growLedger(t, ledger, 3)
	cp := ledger.SignedCheckpoint()

	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("witness-A", wPriv)

	cs, err := w.Cosign(cp, ledger.PublicKey(), nil) // first sighting: no proof needed
	if err != nil {
		t.Fatalf("cosign: %v", err)
	}
	if err := VerifyCosignature(cp, cs, w.PublicKey()); err != nil {
		t.Fatalf("verify cosignature: %v", err)
	}
	// Wrong witness key must fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyCosignature(cp, cs, otherPub); err != ErrCheckpointSig {
		t.Fatalf("wrong witness key: want ErrCheckpointSig, got %v", err)
	}
}

func TestWitnessCosignAppendOnly(t *testing.T) {
	ledger, _ := NewLedger("ts-w2")
	growLedger(t, ledger, 2)
	cp1 := ledger.SignedCheckpoint()

	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("witness-A", wPriv)
	if _, err := w.Cosign(cp1, ledger.PublicKey(), nil); err != nil {
		t.Fatal(err)
	}

	growLedger(t, ledger, 2) // size 2 → 4
	cp2 := ledger.SignedCheckpoint()
	proof, err := ledger.ConsistencyProof(cp1.TreeSize, cp2.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Cosign(cp2, ledger.PublicKey(), proof); err != nil {
		t.Fatalf("append-only cosign: %v", err)
	}
}

func TestWitnessRejectsBadConsistencyProof(t *testing.T) {
	ledger, _ := NewLedger("ts-w3")
	growLedger(t, ledger, 2)
	cp1 := ledger.SignedCheckpoint()
	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("witness-A", wPriv)
	_, _ = w.Cosign(cp1, ledger.PublicKey(), nil)

	growLedger(t, ledger, 2)
	cp2 := ledger.SignedCheckpoint()
	// Supply an empty/wrong proof for a real size increase → split-view refusal.
	if _, err := w.Cosign(cp2, ledger.PublicKey(), nil); err != ErrSplitView {
		t.Fatalf("bad consistency proof: want ErrSplitView, got %v", err)
	}
}

func TestWitnessRejectsRegression(t *testing.T) {
	ledger, _ := NewLedger("ts-w4")
	growLedger(t, ledger, 2)
	cpSmall := ledger.SignedCheckpoint() // size 2
	growLedger(t, ledger, 2)
	cpBig := ledger.SignedCheckpoint() // size 4
	proof, _ := ledger.ConsistencyProof(cpSmall.TreeSize, cpBig.TreeSize)

	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("witness-A", wPriv)
	if _, err := w.Cosign(cpBig, ledger.PublicKey(), proof); err != nil {
		t.Fatal(err)
	}
	// Presenting the older (smaller) checkpoint now must be rejected.
	if _, err := w.Cosign(cpSmall, ledger.PublicKey(), nil); err != ErrCheckpointRegression {
		t.Fatalf("regression: want ErrCheckpointRegression, got %v", err)
	}
}

func TestVerifyCheckpointTamperDetected(t *testing.T) {
	ledger, _ := NewLedger("ts-w5")
	growLedger(t, ledger, 3)
	cp := ledger.SignedCheckpoint()
	if err := VerifyCheckpoint(cp, ledger.PublicKey()); err != nil {
		t.Fatalf("valid checkpoint: %v", err)
	}
	cp.RootHash = "deadbeef" // tamper
	if err := VerifyCheckpoint(cp, ledger.PublicKey()); err != ErrCheckpointSig {
		t.Fatalf("tampered checkpoint: want ErrCheckpointSig, got %v", err)
	}
}
