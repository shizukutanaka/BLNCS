package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func mustIssuer(t *testing.T, id string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSignVerifyStatement(t *testing.T) {
	priv, _ := mustIssuer(t, "did:web:issuer")
	stmt, err := SignStatement(priv, "did:web:issuer", "product-123", "application/vc+json", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatement(&stmt); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// tamper subject
	stmt.Subject = "different"
	if err := VerifyStatement(&stmt); err == nil {
		t.Fatal("tamper undetected")
	}
}

func TestRegisterAndVerifyReceipt(t *testing.T) {
	ledger, err := NewLedger("did:web:ts.blrcs.example")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "issuer")
	stmt, _ := SignStatement(priv, "did:web:iss", "dpp-1", "application/vc+json", []byte("dpp-payload"))
	receipt, err := ledger.Register(stmt)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(receipt, stmt, ledger.PublicKey()); err != nil {
		t.Fatalf("receipt verify: %v", err)
	}
	if receipt.LeafIndex != 0 || receipt.TreeSize != 1 {
		t.Fatalf("unexpected receipt: idx=%d size=%d", receipt.LeafIndex, receipt.TreeSize)
	}
}

func TestInclusionProofsAcrossGrowth(t *testing.T) {
	// leaf 0 を登録した後、100個追加してから leaf 0 を再検証
	// 最初のreceiptはtree size=1のroot、後の検証はlive tree: 別経路
	ledger, _ := NewLedger("ts1")
	priv, _ := mustIssuer(t, "iss")
	stmt0, _ := SignStatement(priv, "iss", "s0", "c", []byte("p0"))
	_, err := ledger.Register(stmt0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 100; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("p%d", i)))
		if _, err := ledger.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	// ledger.Get で最新のreceipt (新しいroot下) を取り直す
	gotStmt, fresh, err := ledger.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(fresh, gotStmt, ledger.PublicKey()); err != nil {
		t.Fatalf("fresh receipt for leaf 0 in size=101 tree should verify: %v", err)
	}
	if fresh.TreeSize != 101 {
		t.Fatalf("tree size mismatch: %d", fresh.TreeSize)
	}
}

func TestTamperedStatementBreaksInclusion(t *testing.T) {
	ledger, _ := NewLedger("ts1")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)
	stmt.Subject = "tampered" // 改ざん — leaf hash 変化
	err := VerifyReceipt(receipt, stmt, ledger.PublicKey())
	if err == nil {
		t.Fatal("tampered stmt verified wrongly")
	}
	if !errors.Is(err, ErrBadProof) {
		t.Errorf("want ErrBadProof, got %v", err)
	}
}

func TestVerifyReceiptBadTSSignature(t *testing.T) {
	ledger, _ := NewLedger("ts-btsig")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)

	bad := *receipt
	// All-zero bytes: valid base64 but wrong ed25519 signature.
	bad.TSSignature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := VerifyReceipt(&bad, stmt, ledger.PublicKey()); !errors.Is(err, ErrBadReceipt) {
		t.Errorf("want ErrBadReceipt, got %v", err)
	}
}

func TestVerifyReceiptBadAuditPath(t *testing.T) {
	ledger, _ := NewLedger("ts-bap")
	priv, _ := mustIssuer(t, "iss")

	// Register 3 statements so leaf 0 has a non-empty audit path.
	var stmt0 Statement
	for i := 0; i < 3; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("p%d", i)))
		if _, err := ledger.Register(s); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			stmt0 = s
		}
	}

	_, receipt, err := ledger.Get(0) // fresh receipt in size-3 tree
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.AuditPath) == 0 {
		t.Fatal("expected non-empty audit path for leaf 0 in size-3 tree")
	}

	bad := *receipt
	bad.AuditPath = make([]string, len(receipt.AuditPath))
	copy(bad.AuditPath, receipt.AuditPath)
	// Corrupt first sibling hash: flip the first byte (00→ff or ff→00).
	h := bad.AuditPath[0]
	if len(h) >= 2 && h[:2] == "ff" {
		bad.AuditPath[0] = "00" + h[2:]
	} else {
		bad.AuditPath[0] = "ff" + h[2:]
	}

	if err := VerifyReceipt(&bad, stmt0, ledger.PublicKey()); !errors.Is(err, ErrBadProof) {
		t.Errorf("want ErrBadProof, got %v", err)
	}
}

func TestConcurrentRegistration(t *testing.T) {
	ledger, _ := NewLedger("ts-conc")
	priv, _ := mustIssuer(t, "iss")
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			s, _ := SignStatement(priv, "iss", fmt.Sprintf("sub-%d", i), "c", []byte(fmt.Sprintf("p-%d", i)))
			if _, err := ledger.Register(s); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if sz := ledger.Size(); sz != N {
		t.Fatalf("size want %d got %d", N, sz)
	}
	// ランダムleafの包含証明検証
	for _, idx := range []uint64{0, 1, 50, 100, 199} {
		stmt, receipt, err := ledger.Get(idx)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyReceipt(receipt, stmt, ledger.PublicKey()); err != nil {
			t.Fatalf("idx=%d: %v", idx, err)
		}
	}
}

func TestCheckpoint(t *testing.T) {
	ledger, _ := NewLedger("ts-cp")
	priv, _ := mustIssuer(t, "iss")
	for i := 0; i < 10; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("%d", i)))
		ledger.Register(s)
	}
	cp := ledger.SignedCheckpoint()
	if cp.TreeSize != 10 {
		t.Fatal("checkpoint size wrong")
	}
	if cp.Signature == "" {
		t.Fatal("checkpoint not signed")
	}
}

func BenchmarkRegister(b *testing.B) {
	ledger, _ := NewLedger("ts-b")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	stmts := make([]Statement, b.N)
	for i := 0; i < b.N; i++ {
		stmts[i], _ = SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte("payload"))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ledger.Register(stmts[i])
	}
}

// TestCachedMerkleMatchesReference verifies the memoized perfect-subtree root
// and audit path are byte-identical to the reference merkleRoot/auditPath for
// every tree size and leaf index (the cache must not change any hash).
func TestCachedMerkleMatchesReference(t *testing.T) {
	l := &Ledger{}
	for n := 1; n <= 130; n++ {
		leaf := make([]byte, 32)
		leaf[0] = byte(n)
		leaf[1] = byte(n >> 8)
		l.leafHashes = append(l.leafHashes, hashLeaf(leaf))

		wantRoot := merkleRoot(l.leafHashes)
		gotRoot := l.cachedRoot(n)
		if !equalBytes(wantRoot, gotRoot) {
			t.Fatalf("n=%d root mismatch:\n ref %x\n got %x", n, wantRoot, gotRoot)
		}
		for idx := 0; idx < n; idx++ {
			want := auditPath(l.leafHashes, idx)
			got := l.cachedAuditPath(idx, n)
			if len(want) != len(got) {
				t.Fatalf("n=%d idx=%d path len: ref=%d got=%d", n, idx, len(want), len(got))
			}
			for i := range want {
				if !equalBytes(want[i], got[i]) {
					t.Fatalf("n=%d idx=%d path[%d] mismatch", n, idx, i)
				}
			}
			// And the cached path must verify against the cached root.
			if !VerifyInclusion(l.leafHashes[idx], gotRoot, uint64(idx), uint64(n), got) {
				t.Fatalf("n=%d idx=%d cached path fails inclusion", n, idx)
			}
		}
	}
}
