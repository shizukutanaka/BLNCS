package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"

	"blrcs/cbor"
	"blrcs/storage"
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

func TestExportedMerkleHelpers(t *testing.T) {
	leaf := HashLeaf([]byte("data"))
	if len(leaf) != 32 {
		t.Errorf("HashLeaf: len=%d", len(leaf))
	}
	node := HashNode(leaf, leaf)
	if len(node) != 32 {
		t.Errorf("HashNode: len=%d", len(node))
	}
	root := MerkleRootForTest([][]byte{leaf, leaf})
	if len(root) == 0 {
		t.Error("MerkleRootForTest: empty root")
	}
}

func TestLedgerTSID(t *testing.T) {
	l, err := NewLedger("did:web:ts.example")
	if err != nil {
		t.Fatal(err)
	}
	if l.TSID() != "did:web:ts.example" {
		t.Errorf("TSID: %q", l.TSID())
	}
	if len(l.PublicKey()) != ed25519.PublicKeySize {
		t.Errorf("PublicKey: len=%d", len(l.PublicKey()))
	}
}

func TestWitnessID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	w := NewWitness("did:web:witness.example", priv)
	if w.ID() != "did:web:witness.example" {
		t.Errorf("Witness.ID: %q", w.ID())
	}
	if len(w.PublicKey()) != ed25519.PublicKeySize {
		t.Errorf("Witness.PublicKey: len=%d", len(w.PublicKey()))
	}
}

// ============================================================================
// Internal helpers — hexDecode / hexChar / cachedRoot(0)
// ============================================================================

func TestHexDecodeValid(t *testing.T) {
	b, err := hexDecode("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 || b[0] != 0xDE || b[3] != 0xEF {
		t.Errorf("hexDecode: %x", b)
	}
}

func TestHexDecodeUppercase(t *testing.T) {
	b, err := hexDecode("DEADBEEF")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Errorf("hexDecode uppercase: %x", b)
	}
}

func TestHexDecodeOddLength(t *testing.T) {
	_, err := hexDecode("abc")
	if err == nil {
		t.Error("odd-length hex should fail")
	}
}

func TestHexDecodeInvalidChar(t *testing.T) {
	_, err := hexDecode("zz")
	if err == nil {
		t.Error("invalid hex char should fail")
	}
}

func TestCachedRootEmptyTree(t *testing.T) {
	l := &Ledger{}
	root := l.cachedRoot(0)
	// empty tree root = SHA-256 of empty input
	if len(root) != 32 {
		t.Errorf("empty root len: %d", len(root))
	}
}

// ============================================================================
// Coverage uplift: error paths in NewLedgerWithStorage, VerifyReceipt,
// VerifyCheckpoint, Cosign, VerifyCosignature, IssueCOSEReceipt,
// decodeReceiptPayload, equalBytes
// ============================================================================

// errLoadKPStore wraps MemoryStorage and returns an error from LoadKeyPair.
type errLoadKPStore struct {
	*storage.MemoryStorage
}

func (e *errLoadKPStore) LoadKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return nil, nil, errors.New("simulated keypair load error")
}

func TestNewLedgerWithStorageEmptyID(t *testing.T) {
	_, err := NewLedgerWithStorage("", storage.NewMemoryStorage())
	if err == nil {
		t.Error("empty tsID should fail NewLedgerWithStorage")
	}
}

func TestNewLedgerWithStorageLoadKeyPairError(t *testing.T) {
	_, err := NewLedgerWithStorage("ts-x", &errLoadKPStore{storage.NewMemoryStorage()})
	if err == nil {
		t.Error("LoadKeyPair error should propagate from NewLedgerWithStorage")
	}
}

func TestEqualBytesLengthMismatch(t *testing.T) {
	if equalBytes([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Error("different-length slices should not be equal")
	}
}

func TestVerifyReceiptBadRootHashHex(t *testing.T) {
	ledger, _ := NewLedger("ts")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)
	bad := *receipt
	bad.RootHash = "not-valid-hex!!"
	if err := VerifyReceipt(&bad, stmt, ledger.PublicKey()); err != ErrBadReceipt {
		t.Errorf("bad root hash hex: want ErrBadReceipt, got %v", err)
	}
}

func TestVerifyReceiptBadAuditPathHex(t *testing.T) {
	// Register 3 entries so leaf 0 has a non-empty audit path.
	ledger, _ := NewLedger("ts-ap")
	priv, _ := mustIssuer(t, "iss")
	var s0 Statement
	for i := 0; i < 3; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("p%d", i)))
		ledger.Register(s)
		if i == 0 {
			s0 = s
		}
	}
	_, receipt, _ := ledger.Get(0)
	bad := *receipt
	if len(bad.AuditPath) == 0 {
		t.Skip("audit path is empty (only 1 leaf)")
	}
	bad.AuditPath = append([]string{}, bad.AuditPath...)
	bad.AuditPath[0] = "!!"
	if err := VerifyReceipt(&bad, s0, ledger.PublicKey()); err != ErrBadReceipt {
		t.Errorf("bad audit path hex: want ErrBadReceipt, got %v", err)
	}
}

func TestVerifyCheckpointBadBase64Sig(t *testing.T) {
	cp := Checkpoint{Signature: "!!not-base64!!"}
	if err := VerifyCheckpoint(cp, make(ed25519.PublicKey, ed25519.PublicKeySize)); err != ErrCheckpointSig {
		t.Errorf("bad base64 sig: want ErrCheckpointSig, got %v", err)
	}
}

func TestVerifyCheckpointShortPubKey(t *testing.T) {
	ledger, _ := NewLedger("ts-spk")
	growLedger(t, ledger, 1)
	cp := ledger.SignedCheckpoint()
	shortKey := ed25519.PublicKey(make([]byte, 16)) // 16 bytes, not 32
	if err := VerifyCheckpoint(cp, shortKey); err != ErrCheckpointSig {
		t.Errorf("short pub key: want ErrCheckpointSig, got %v", err)
	}
}

func TestCosignVerifyCheckpointFails(t *testing.T) {
	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("witness", wPriv)
	// A checkpoint with bad base64 signature fails VerifyCheckpoint before any
	// witness state is consulted.
	bad := Checkpoint{Signature: "!!bad!!"}
	if _, err := w.Cosign(bad, make(ed25519.PublicKey, ed25519.PublicKeySize), nil); err == nil {
		t.Error("Cosign with invalid checkpoint should fail")
	}
}

func TestCosignSameSizeDifferentRoot(t *testing.T) {
	_, tsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("witness", wPriv)

	// Build a first valid checkpoint at tree size 5 with root "aaaa..."
	cp1 := Checkpoint{TreeSize: 5, RootHash: "aabbccdd", TSID: "ts-split"}
	cp1.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(tsPriv, checkpointSigPayload(cp1)))
	tsPub := tsPriv.Public().(ed25519.PublicKey)
	if _, err := w.Cosign(cp1, tsPub, nil); err != nil {
		t.Fatalf("first cosign: %v", err)
	}

	// Second checkpoint: SAME tree size but DIFFERENT root → split view.
	cp2 := Checkpoint{TreeSize: 5, RootHash: "11223344", TSID: "ts-split"}
	cp2.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(tsPriv, checkpointSigPayload(cp2)))
	if _, err := w.Cosign(cp2, tsPub, nil); err != ErrSplitView {
		t.Errorf("same size different root: want ErrSplitView, got %v", err)
	}
}

func TestVerifyCosignatureBadBase64(t *testing.T) {
	cp := Checkpoint{TreeSize: 1, RootHash: "aabb", TSID: "ts"}
	cs := Cosignature{Signature: "!!bad-base64!!"}
	if err := VerifyCosignature(cp, cs, make(ed25519.PublicKey, ed25519.PublicKeySize)); err != ErrCheckpointSig {
		t.Errorf("bad base64: want ErrCheckpointSig, got %v", err)
	}
}

func TestIssueCOSEReceiptBadRootHash(t *testing.T) {
	ledger, _ := NewLedger("ts")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)
	bad := *receipt
	bad.RootHash = "!!"
	if _, err := IssueCOSEReceipt(&bad, ledger.tsPriv, ledger.tsID); err == nil {
		t.Error("bad root hash should fail IssueCOSEReceipt")
	}
}

func TestIssueCOSEReceiptBadAuditPath(t *testing.T) {
	ledger, _ := NewLedger("ts-ap2")
	priv, _ := mustIssuer(t, "iss")
	for i := 0; i < 3; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte("p"))
		ledger.Register(s)
	}
	_, receipt, _ := ledger.Get(0)
	if len(receipt.AuditPath) == 0 {
		t.Skip("no audit path to corrupt")
	}
	bad := *receipt
	bad.AuditPath = append([]string{}, bad.AuditPath...)
	bad.AuditPath[0] = "!!"
	if _, err := IssueCOSEReceipt(&bad, ledger.tsPriv, ledger.tsID); err == nil {
		t.Error("bad audit path entry should fail IssueCOSEReceipt")
	}
}

func TestDecodeReceiptPayloadNotMap(t *testing.T) {
	b, _ := cbor.Marshal("not-a-map")
	if _, err := decodeReceiptPayload(b); err == nil {
		t.Error("non-map payload should fail")
	}
}

func TestDecodeReceiptPayloadMissingLeafIndex(t *testing.T) {
	b, _ := cbor.Marshal(map[int]any{})
	if _, err := decodeReceiptPayload(b); err == nil {
		t.Error("missing leaf_index should fail")
	}
}

func TestDecodeReceiptPayloadMissingTreeSize(t *testing.T) {
	b, _ := cbor.Marshal(map[int]any{cbrLeafIndex: uint64(0)})
	if _, err := decodeReceiptPayload(b); err == nil {
		t.Error("missing tree_size should fail")
	}
}

func TestDecodeReceiptPayloadMissingRootHash(t *testing.T) {
	b, _ := cbor.Marshal(map[int]any{cbrLeafIndex: uint64(0), cbrTreeSize: uint64(1)})
	if _, err := decodeReceiptPayload(b); err == nil {
		t.Error("missing root_hash should fail")
	}
}

func TestDecodeReceiptPayloadMissingAuditPath(t *testing.T) {
	b, _ := cbor.Marshal(map[int]any{
		cbrLeafIndex: uint64(0),
		cbrTreeSize:  uint64(1),
		cbrRootHash:  make([]byte, 32),
	})
	if _, err := decodeReceiptPayload(b); err == nil {
		t.Error("missing audit_path should fail")
	}
}

func TestDecodeReceiptPayloadBadAuditPathElem(t *testing.T) {
	b, _ := cbor.Marshal(map[int]any{
		cbrLeafIndex: uint64(0),
		cbrTreeSize:  uint64(2),
		cbrRootHash:  make([]byte, 32),
		cbrAuditPath: []any{"not-bstr"},
	})
	if _, err := decodeReceiptPayload(b); err == nil {
		t.Error("non-bstr audit_path elem should fail")
	}
}

func TestVerifyStatementBadBase64Sig(t *testing.T) {
	s := Statement{
		IssuerKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		Signature: "!!not-base64!!",
	}
	if err := VerifyStatement(&s); err == nil {
		t.Error("bad base64 signature should fail VerifyStatement")
	}
}
