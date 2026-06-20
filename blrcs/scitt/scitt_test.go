package scitt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
		if !bytes.Equal(wantRoot, gotRoot) {
			t.Fatalf("n=%d root mismatch:\n ref %x\n got %x", n, wantRoot, gotRoot)
		}
		for idx := 0; idx < n; idx++ {
			want := auditPath(l.leafHashes, idx)
			got := l.cachedAuditPath(idx, n)
			if len(want) != len(got) {
				t.Fatalf("n=%d idx=%d path len: ref=%d got=%d", n, idx, len(want), len(got))
			}
			for i := range want {
				if !bytes.Equal(want[i], got[i]) {
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
// decodeReceiptPayload
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
	if bytes.Equal([]byte{1, 2, 3}, []byte{1, 2}) {
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

// TestCheckpointSignatureBindsTSID proves the checkpoint signature covers the
// log identity (TSID / origin). A validly-signed checkpoint whose TSID is
// relabeled to a different log MUST fail verification — otherwise an attacker
// could move a signed tree head between logs and defeat the witness's per-log
// (w.seen[cp.TSID]) split-view tracking.
func TestCheckpointSignatureBindsTSID(t *testing.T) {
	ledger, _ := NewLedger("did:web:log-a.example")
	growLedger(t, ledger, 3)
	cp := ledger.SignedCheckpoint()
	tsPub := ledger.PublicKey()

	// Sanity: the genuine checkpoint verifies.
	if err := VerifyCheckpoint(cp, tsPub); err != nil {
		t.Fatalf("genuine checkpoint should verify: %v", err)
	}

	// Relabel the log identity; signature must no longer verify.
	forged := cp
	forged.TSID = "did:web:log-b.example"
	if err := VerifyCheckpoint(forged, tsPub); err != ErrCheckpointSig {
		t.Errorf("TSID-relabeled checkpoint must fail: want ErrCheckpointSig, got %v", err)
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

// ============================================================================
// Additional coverage: SignStatement empty payload, VerifyInclusion out-of-bounds,
// hexDecode invalid lo nibble, VerifyReceipt bad base64 TS sig, Get out-of-bounds,
// merkleRoot empty, VerifyConsistency edge cases.
// ============================================================================

func TestSignStatementEmptyPayload(t *testing.T) {
	priv, _ := mustIssuer(t, "iss")
	if _, err := SignStatement(priv, "iss", "s", "c", nil); err != ErrEmptyStmt {
		t.Errorf("empty payload: want ErrEmptyStmt, got %v", err)
	}
}

func TestVerifyInclusionIdxGESize(t *testing.T) {
	leaf := HashLeaf([]byte("x"))
	if VerifyInclusion(leaf, leaf, 5, 3, nil) {
		t.Error("idx>=size should return false")
	}
}

// TestVerifyInclusionTamperedLastByte verifies that a root hash differing only
// in the last byte is rejected. The inclusion proof now uses
// subtle.ConstantTimeCompare, which (unlike the former timing-variable
// equalBytes) always inspects every byte — so this also guards against a
// timing oracle that would let an attacker learn the expected root hash one byte
// at a time via response-latency measurements.
func TestVerifyInclusionTamperedLastByte(t *testing.T) {
	ledger, err := NewLedger("ts-timing")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "iss")
	stmt, err := SignStatement(priv, "iss", "s0", "c", []byte("pay"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ledger.Register(stmt)
	if err != nil {
		t.Fatal(err)
	}
	// Decode root hash and audit path from the receipt.
	correctRoot, err := hexDecodeString(receipt.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	path := make([][]byte, len(receipt.AuditPath))
	for i, h := range receipt.AuditPath {
		path[i], err = hexDecodeString(h)
		if err != nil {
			t.Fatalf("AuditPath[%d] decode: %v", i, err)
		}
	}
	leaf := ledger.leafHashes[0]
	// Correct root must verify.
	if !VerifyInclusion(leaf, correctRoot, 0, uint64(receipt.TreeSize), path) {
		t.Fatal("valid inclusion proof rejected")
	}
	// Tamper only the last byte of the root hash — must be rejected.
	tampered := bytes.Clone(correctRoot)
	tampered[len(tampered)-1] ^= 0xFF
	if VerifyInclusion(leaf, tampered, 0, uint64(receipt.TreeSize), path) {
		t.Fatal("tampered root (last byte) should be rejected")
	}
}

func TestHexDecodeInvalidLoNibble(t *testing.T) {
	// 'a' is valid hi nibble, 'z' is invalid lo nibble
	if _, err := hexDecode("az"); err == nil {
		t.Error("invalid lo nibble should fail hexDecode")
	}
}

func TestVerifyReceiptBadBase64TSSig(t *testing.T) {
	ledger, _ := NewLedger("ts-b64")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)
	bad := *receipt
	bad.TSSignature = "!!not-valid-base64!!"
	if err := VerifyReceipt(&bad, stmt, ledger.PublicKey()); err != ErrBadReceipt {
		t.Errorf("bad base64 TSSignature: want ErrBadReceipt, got %v", err)
	}
}

func TestGetOutOfBounds(t *testing.T) {
	ledger, _ := NewLedger("ts-oob")
	if _, _, err := ledger.Get(0); err != ErrNotFound {
		t.Errorf("empty ledger Get(0): want ErrNotFound, got %v", err)
	}
}

func TestMerkleRootEmptyLeaves(t *testing.T) {
	root := merkleRoot(nil)
	if len(root) != 32 {
		t.Errorf("merkleRoot(nil): want 32 bytes, got %d", len(root))
	}
}

func TestVerifyConsistencyEqualSizeNonNilProof(t *testing.T) {
	// m==n but proof is non-empty → should fail
	root := HashLeaf([]byte("r"))
	proof := [][]byte{root}
	if err := VerifyConsistency(5, 5, root, root, proof); err == nil {
		t.Error("equal size with non-nil proof should fail")
	}
}

func TestVerifyConsistencyEmptyProofNonTrivial(t *testing.T) {
	// m!=n, m!=0, but proof is empty (and m is not a power of 2 to keep proofArr empty)
	// m=3 (not pow2), n=5, proof=nil → proofArr still nil → len=0 → ErrConsistency
	root := HashLeaf([]byte("r"))
	if err := VerifyConsistency(3, 5, root, root, nil); err == nil {
		t.Error("empty proof for non-trivial consistency should fail")
	}
}

// ============================================================================
// Mock stores for Register / NewLedgerWithStorage error paths
// ============================================================================

type failAppendStore struct {
	*storage.MemoryStorage
}

func (f *failAppendStore) AppendStatement(_ storage.StatementBlob) (uint64, error) {
	return 0, errors.New("simulated append failure")
}

func TestRegisterAppendFailure(t *testing.T) {
	l, err := NewLedgerWithStorage("ts-fa", &failAppendStore{storage.NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("payload"))
	if _, err := l.Register(stmt); err == nil {
		t.Error("AppendStatement failure should propagate from Register")
	}
}

// wrongIdxStore always returns idx=99, causing a storage/memory desync in Register.
type wrongIdxStore struct {
	*storage.MemoryStorage
}

func (w *wrongIdxStore) AppendStatement(_ storage.StatementBlob) (uint64, error) {
	return 99, nil
}

// TestRegisterDesyncDetected covers `return nil, fmt.Errorf("ledger: storage/memory desync …")`
// in Register when AppendStatement returns an idx that doesn't match the in-memory leaf count.
func TestRegisterDesyncDetected(t *testing.T) {
	l, err := NewLedgerWithStorage("ts-desync", &wrongIdxStore{storage.NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "subj", "c", []byte("payload"))
	if _, err := l.Register(stmt); err == nil {
		t.Error("desync should be detected and returned as error")
	}
}

// failLoadKPStore returns a non-ErrNotFound error from LoadKeyPair.
type failLoadKPStore struct {
	*storage.MemoryStorage
}

func (f *failLoadKPStore) LoadKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return nil, nil, errors.New("simulated load failure")
}

// TestNewLedgerLoadKeyPairFails covers `return nil, fmt.Errorf("load keypair: %w", err)`
// in NewLedgerWithStorage when LoadKeyPair returns a non-ErrNotFound error.
func TestNewLedgerLoadKeyPairFails(t *testing.T) {
	_, err := NewLedgerWithStorage("ts-lkpfail", &failLoadKPStore{storage.NewMemoryStorage()})
	if err == nil {
		t.Fatal("LoadKeyPair failure should propagate from NewLedgerWithStorage")
	}
}

// replayBadSigStore wraps MemoryStorage and serves a valid-JSON statement with a bad signature.
type replayBadSigStore struct {
	*storage.MemoryStorage
	blob []byte
}

func (r *replayBadSigStore) IterateStatements(fn func(uint64, storage.StatementBlob) error) error {
	return fn(0, storage.StatementBlob(r.blob))
}

// TestNewLedgerReplayBadSig covers `return fmt.Errorf("replay bad sig at idx %d")` in
// NewLedgerWithStorage when a replayed statement has an invalid signature.
func TestNewLedgerReplayBadSig(t *testing.T) {
	priv, _ := mustIssuer(t, "iss-replay")
	goodStmt, _ := SignStatement(priv, "iss-replay", "s", "c", []byte("payload"))

	// Build a statement with a tampered signature so VerifyStatement fails.
	badStmt := goodStmt
	decoded, err := base64.StdEncoding.DecodeString(goodStmt.Signature)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0] ^= 0xff
	badStmt.Signature = base64.StdEncoding.EncodeToString(decoded)

	blob, _ := json.Marshal(badStmt)

	mem := storage.NewMemoryStorage()
	// Pre-populate a key pair so LoadKeyPair succeeds.
	pub, priv2, _ := ed25519.GenerateKey(rand.Reader)
	if err := mem.SaveKeyPair(pub, priv2); err != nil {
		t.Fatal(err)
	}
	store := &replayBadSigStore{MemoryStorage: mem, blob: blob}
	_, err = NewLedgerWithStorage("ts-badsigreplay", store)
	if err == nil {
		t.Fatal("bad-sig replay should propagate from NewLedgerWithStorage")
	}
}

// TestVerifyReceiptWrongTSKey covers `!ed25519.Verify → return ErrBadReceipt` in VerifyReceipt.
func TestVerifyReceiptWrongTSKey(t *testing.T) {
	ledger, _ := NewLedger("ts-wrongkey")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("payload"))
	receipt, _ := ledger.Register(stmt)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyReceipt(receipt, stmt, wrongPub); err != ErrBadReceipt {
		t.Errorf("wrong TS key: want ErrBadReceipt, got %v", err)
	}
}

// TestVerifyReceiptInvalidHexRootResigned covers the `hexDecode(r.RootHash) → return ErrBadReceipt`
// path.  The receipt is re-signed with the actual tsPriv so signature verification passes,
// but the root hash contains a non-hex character so hexDecode fails.
func TestVerifyReceiptInvalidHexRootResigned(t *testing.T) {
	ledger, _ := NewLedger("ts-hexroot")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	receipt, _ := ledger.Register(stmt)

	// Tamper the root hash to contain invalid hex, then re-sign so !Verify passes.
	bad := *receipt
	bad.RootHash = "GG" // "GG" has even length but 'G' is not a valid hex nibble
	bad.TSSignature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(ledger.tsPriv, receiptSigPayload(&bad)),
	)
	if err := VerifyReceipt(&bad, stmt, ledger.PublicKey()); err != ErrBadReceipt {
		t.Errorf("invalid hex root: want ErrBadReceipt, got %v", err)
	}
}

// TestDecodeReceiptPayloadBadCBOR covers `return nil, err` when cbor.Unmarshal fails.
func TestDecodeReceiptPayloadBadCBOR(t *testing.T) {
	_, err := decodeReceiptPayload([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("invalid CBOR should fail decodeReceiptPayload")
	}
}

// ============================================================================
// Cosign paths: hexDecode(prev.RootHash) error and hexDecode(cp.RootHash) error
// ============================================================================

func makeSignedCheckpoint(tsID string, treeSize uint64, rootHash string, tsPriv ed25519.PrivateKey) Checkpoint {
	cp := Checkpoint{TSID: tsID, TreeSize: treeSize, RootHash: rootHash}
	cp.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(tsPriv, checkpointSigPayload(cp)))
	return cp
}

func TestCosignPrevRootHashBadHex(t *testing.T) {
	_, tsPriv, _ := ed25519.GenerateKey(rand.Reader)
	tsPub := tsPriv.Public().(ed25519.PublicKey)
	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("w", wPriv)

	// First checkpoint: root hash is invalid hex (not parseable by hexDecode) but
	// the signature is valid, so VerifyCheckpoint passes and it gets stored.
	cp1 := makeSignedCheckpoint("ts-bad1", 1, "GGGG", tsPriv)
	if _, err := w.Cosign(cp1, tsPub, nil); err != nil {
		t.Fatalf("first cosign should succeed: %v", err)
	}

	// Second checkpoint: larger tree size → enters default branch, tries
	// hexDecode(prev.RootHash) = hexDecode("GGGG") → error → ErrSplitView.
	cp2 := makeSignedCheckpoint("ts-bad1", 2, "aabbccdd", tsPriv)
	if _, err := w.Cosign(cp2, tsPub, nil); err != ErrSplitView {
		t.Errorf("bad prev root hex: want ErrSplitView, got %v", err)
	}
}

func TestCosignCPRootHashBadHex(t *testing.T) {
	_, tsPriv, _ := ed25519.GenerateKey(rand.Reader)
	tsPub := tsPriv.Public().(ed25519.PublicKey)
	_, wPriv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewWitness("w", wPriv)

	// First checkpoint: valid hex root hash (44 chars = 22 bytes, arbitrary).
	cp1 := makeSignedCheckpoint("ts-bad2", 1, "aabb", tsPriv)
	if _, err := w.Cosign(cp1, tsPub, nil); err != nil {
		t.Fatalf("first cosign should succeed: %v", err)
	}

	// Second checkpoint: tree size grows, but cp.RootHash is invalid hex
	// → hexDecode(prev.RootHash) succeeds, hexDecode(cp.RootHash) fails → ErrSplitView.
	cp2 := makeSignedCheckpoint("ts-bad2", 2, "GGGG", tsPriv)
	if _, err := w.Cosign(cp2, tsPub, nil); err != ErrSplitView {
		t.Errorf("bad cp root hex: want ErrSplitView, got %v", err)
	}
}

func TestVerifyCOSEReceiptBadPayload(t *testing.T) {
	// Build a COSE_Sign1 with a valid TS signature but payload that fails decodeReceiptPayload.
	ledger, _ := NewLedger("ts-badpay")
	// Payload is just a CBOR string — not a map → decodeReceiptPayload will error.
	badPayload, _ := cbor.Marshal("not-a-map")
	protected := cbor.Header{
		cbor.HeaderAlg: cbor.AlgEdDSA,
		cbor.HeaderKid: []byte("ts-badpay"),
	}
	data, err := cbor.Sign1(protected, nil, badPayload, nil, ledger.tsPriv)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("p"))
	if err := VerifyCOSEReceipt(data, stmt, ledger.PublicKey()); err == nil {
		t.Error("COSE receipt with bad payload should fail VerifyCOSEReceipt")
	}
}

// ============================================================================
// Coverage uplift: NewLedgerWithStorage error paths, VerifyConsistency inner
// loop error paths
// ============================================================================

// failSaveKeyPairStore fails only on SaveKeyPair.
type failSaveKeyPairStore struct {
	*storage.MemoryStorage
}

func (f *failSaveKeyPairStore) SaveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	return errors.New("disk full")
}

// TestNewLedgerSaveKeyPairFails covers the `if err := store.SaveKeyPair(...); err != nil`
// path in NewLedgerWithStorage (new key generated, then save fails).
func TestNewLedgerSaveKeyPairFails(t *testing.T) {
	_, err := NewLedgerWithStorage("ts-savefail", &failSaveKeyPairStore{storage.NewMemoryStorage()})
	if err == nil {
		t.Fatal("SaveKeyPair failure should propagate from NewLedgerWithStorage")
	}
}

// replayBadJSONStore returns a valid key pair but serves corrupt JSON from IterateStatements.
type replayBadJSONStore struct {
	*storage.MemoryStorage
}

func (r *replayBadJSONStore) IterateStatements(fn func(uint64, storage.StatementBlob) error) error {
	return fn(0, storage.StatementBlob("not-valid-json"))
}

// TestNewLedgerReplayUnmarshalError covers `fmt.Errorf("replay at idx %d: %w", ...)` in
// NewLedgerWithStorage when IterateStatements returns malformed JSON.
func TestNewLedgerReplayUnmarshalError(t *testing.T) {
	mem := storage.NewMemoryStorage()
	// Pre-populate a key pair so the load path succeeds.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := mem.SaveKeyPair(pub, priv); err != nil {
		t.Fatal(err)
	}
	store := &replayBadJSONStore{mem}
	_, err := NewLedgerWithStorage("ts-replay", store)
	if err == nil {
		t.Fatal("corrupt replay JSON should propagate from NewLedgerWithStorage")
	}
}

// TestVerifyConsistencyCorruptedProof covers the `!bytes.Equal(fr, oldRoot)`,
// `!bytes.Equal(sr, newRoot)`, and `sn != 0` paths in VerifyConsistency.
// We build a real 5-entry ledger, obtain a valid proof, verify it (must pass),
// then corrupt individual proof elements to hit each error path.
func TestVerifyConsistencyCorruptedProof(t *testing.T) {
	ledger, err := NewLedger("ts-consist")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "iss")

	roots := make([][]byte, 0, 6)
	roots = append(roots, nil) // placeholder for index 0 (no tree)
	for i := 1; i <= 5; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("pay%d", i)))
		r, err := ledger.Register(s)
		if err != nil {
			t.Fatalf("Register %d: %v", i, err)
		}
		b, err := hexDecodeString(r.RootHash)
		if err != nil {
			t.Fatalf("rootHash decode: %v", err)
		}
		roots = append(roots, b)
	}

	// Get a valid proof from m=3 to n=5.
	proof, err := ledger.ConsistencyProof(3, 5)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}

	// Happy path must pass.
	if err := VerifyConsistency(3, 5, roots[3], roots[5], proof); err != nil {
		t.Fatalf("valid consistency proof rejected: %v", err)
	}

	if len(proof) < 2 {
		t.Skip("need at least 2 proof elements for corruption tests")
	}

	// Corrupt first proof element → wrong fr/sr seed → !bytes.Equal(fr, oldRoot)
	corrupt := make([][]byte, len(proof))
	copy(corrupt, proof)
	bad := make([]byte, len(corrupt[0]))
	copy(bad, corrupt[0])
	bad[0] ^= 0xff
	corrupt[0] = bad
	if err := VerifyConsistency(3, 5, roots[3], roots[5], corrupt); err == nil {
		t.Error("corrupted first element should fail VerifyConsistency")
	}

	// Corrupt last proof element → intermediate correct but final root wrong.
	corrupt2 := make([][]byte, len(proof))
	copy(corrupt2, proof)
	bad2 := make([]byte, len(corrupt2[len(corrupt2)-1]))
	copy(bad2, corrupt2[len(corrupt2)-1])
	bad2[0] ^= 0xff
	corrupt2[len(corrupt2)-1] = bad2
	if err := VerifyConsistency(3, 5, roots[3], roots[5], corrupt2); err == nil {
		t.Error("corrupted last element should fail VerifyConsistency")
	}
}

// hexDecodeString is a helper for TestVerifyConsistencyCorruptedProof.
func hexDecodeString(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, err := hexChar(s[i])
		if err != nil {
			return nil, err
		}
		lo, err := hexChar(s[i+1])
		if err != nil {
			return nil, err
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

// TestVerifyConsistencySnZeroInLoop covers `if sn == 0 { return ErrConsistency }`
// inside the inner loop, triggered by appending an extra element to a valid proof
// so that the loop continues when sn has already been reduced to zero.
func TestVerifyConsistencySnZeroInLoop(t *testing.T) {
	ledger, err := NewLedger("ts-sn0")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "iss")

	roots := make([][]byte, 3)
	for i := 1; i <= 2; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("p%d", i)))
		r, err := ledger.Register(s)
		if err != nil {
			t.Fatalf("Register %d: %v", i, err)
		}
		b, err := hexDecodeString(r.RootHash)
		if err != nil {
			t.Fatalf("rootHash decode: %v", err)
		}
		roots[i] = b
	}

	// Valid proof for m=1 → n=2 has exactly 1 element.
	proof, err := ledger.ConsistencyProof(1, 2)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	if err := VerifyConsistency(1, 2, roots[1], roots[2], proof); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// Append one extra element — after processing the real element sn reaches 0;
	// the next iteration hits `if sn == 0 { return ErrConsistency }`.
	extra := append(proof, HashLeaf([]byte("extra")))
	if err := VerifyConsistency(1, 2, roots[1], roots[2], extra); err == nil {
		t.Error("extended proof should fail with sn==0 guard")
	}
}

// TestRegisterInvalidStatementRejected covers scitt.go:350-352: Register must
// return an error (without modifying the ledger) when VerifyStatement fails.
// A tampered Signature makes the statement's ed25519 signature invalid.
func TestRegisterInvalidStatementRejected(t *testing.T) {
	ledger, _ := NewLedger("ts")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "sub", "text/plain", []byte("payload"))
	// Tamper the signature so VerifyStatement rejects it.
	stmt.Signature = "aW52YWxpZA" // base64 of "invalid" — wrong signature
	if _, err := ledger.Register(stmt); err == nil {
		t.Error("Register should reject statement with invalid signature")
	}
	// Ledger must remain empty.
	if sz := ledger.Size(); sz != 0 {
		t.Errorf("ledger size after rejected register: %d, want 0", sz)
	}
}

// TestVerifyConsistencySnNonZeroAtEnd covers consistency.go:121-123: when the
// consistency proof is shorter than expected (truncated), sn > 0 after the loop
// but fr still matches oldRoot, triggering the final sn != 0 guard.
//
// With m=1 (power of 2), n=4: VerifyConsistency prepends oldRoot to proof
// (proofArr=[oldRoot,p1,p2]).  If we pass only [p1] (no p2), after processing
// p1 we have sn=1 ≠ 0.  Because fr stays as oldRoot (fn never reaches the
// left-branch update), the first two checks pass and line 121 is what fires.
func TestVerifyConsistencySnNonZeroAtEnd(t *testing.T) {
	ledger, _ := NewLedger("ts")
	priv, _ := mustIssuer(t, "iss")
	for i := 0; i < 4; i++ {
		stmt, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte{byte(i)})
		ledger.Register(stmt) //nolint:errcheck
	}
	root1 := ledger.leafHashes[:1]
	oldRoot := merkleRoot(root1)
	newRoot := ledger.Root()
	proof, _ := ledger.ConsistencyProof(1, 4) // 2-element proof for m=1 → n=4
	// Drop the last element to make a 1-element (truncated) proof.
	truncated := proof[:len(proof)-1]
	err := VerifyConsistency(1, 4, oldRoot, newRoot, truncated)
	if err == nil {
		t.Error("truncated consistency proof should fail")
	}
}

// TestReceiptCheckpointSigNotTransferable pins domain separation between the two
// structures the Transparency Service key signs: receipts and checkpoints. They
// share a RootHash prefix, so a missing domain tag could in principle let one
// signature be replayed as the other. This asserts the signatures are not
// transferable — a checkpoint signature must not verify a receipt and vice versa.
func TestReceiptCheckpointSigNotTransferable(t *testing.T) {
	ledger, err := NewLedger("did:web:ts.example")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ledger.Close() }()
	priv, _ := mustIssuer(t, "did:web:iss")
	stmt, err := SignStatement(priv, "did:web:iss", "sub", "text/plain", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ledger.Register(stmt)
	if err != nil {
		t.Fatal(err)
	}
	cp := ledger.SignedCheckpoint()
	tsPub := ledger.PublicKey()

	// Sanity: each verifies in its own context.
	if err := VerifyReceipt(receipt, stmt, tsPub); err != nil {
		t.Fatalf("receipt should verify: %v", err)
	}
	if err := VerifyCheckpoint(cp, tsPub); err != nil {
		t.Fatalf("checkpoint should verify: %v", err)
	}

	// A checkpoint signature must NOT verify a receipt.
	forgedReceipt := *receipt
	forgedReceipt.TSSignature = cp.Signature
	if err := VerifyReceipt(&forgedReceipt, stmt, tsPub); err == nil {
		t.Fatal("checkpoint signature must not verify as a receipt signature")
	}

	// A receipt signature must NOT verify a checkpoint.
	forgedCP := cp
	forgedCP.Signature = receipt.TSSignature
	if err := VerifyCheckpoint(forgedCP, tsPub); err == nil {
		t.Fatal("receipt signature must not verify as a checkpoint signature")
	}
}

// ============================================================================
// Axis-13 (Merkle complexity + receipt audit path bounds)
// ============================================================================

// TestSignedCheckpointMatchesCachedRoot asserts that SignedCheckpoint (now using
// cachedRoot) produces exactly the same root hash as the reference merkleRoot.
// This proves the O(n)→O(log n) substitution is correct and not a silent regression.
func TestSignedCheckpointMatchesCachedRoot(t *testing.T) {
	ledger, _ := NewLedger("ts-cp-cached")
	priv, _ := mustIssuer(t, "iss")

	for n := 1; n <= 50; n++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", n), "c", []byte(fmt.Sprintf("%d", n)))
		if _, err := ledger.Register(s); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}

		cp := ledger.SignedCheckpoint()

		// Reference: the slow uncached path
		ledger.mu.RLock()
		refRoot := fmt.Sprintf("%x", merkleRoot(ledger.leafHashes))
		ledger.mu.RUnlock()

		if cp.RootHash != refRoot {
			t.Fatalf("n=%d: checkpoint root %q != ref %q", n, cp.RootHash, refRoot)
		}
		if err := VerifyCheckpoint(cp, ledger.PublicKey()); err != nil {
			t.Fatalf("n=%d: checkpoint signature invalid: %v", n, err)
		}
	}
}

// TestVerifyReceiptOversizedAuditPathRejected asserts that a receipt whose
// AuditPath has more than 64 entries is rejected before any allocation. A
// legitimate tree of any conceivable size (up to 2^63 leaves) requires at most
// 63 path elements, so 65 is unambiguously malformed.
func TestVerifyReceiptOversizedAuditPathRejected(t *testing.T) {
	ledger, _ := NewLedger("ts-bigpath")
	priv, _ := mustIssuer(t, "iss")
	stmt, _ := SignStatement(priv, "iss", "s", "c", []byte("payload"))
	receipt, _ := ledger.Register(stmt)

	bad := *receipt
	// Build a 65-element audit path of zero-hash hex strings; TS signature is
	// copied from the original (validation must fail before it's re-checked).
	bad.AuditPath = make([]string, 65)
	for i := range bad.AuditPath {
		bad.AuditPath[i] = fmt.Sprintf("%064x", 0) // 32 zero bytes as hex
	}

	if err := VerifyReceipt(&bad, stmt, ledger.PublicKey()); err != ErrBadReceipt {
		t.Fatalf("oversized AuditPath: want ErrBadReceipt, got %v", err)
	}
}

// TestRootMatchesCachedRoot asserts that Root() (now using cachedRoot) matches
// the reference merkleRoot for every tree size 1..50.
func TestRootMatchesCachedRoot(t *testing.T) {
	ledger, _ := NewLedger("ts-root-cached")
	priv, _ := mustIssuer(t, "iss")

	for n := 1; n <= 50; n++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", n), "c", []byte(fmt.Sprintf("%d", n)))
		if _, err := ledger.Register(s); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}

		got := ledger.Root()

		ledger.mu.RLock()
		want := merkleRoot(ledger.leafHashes)
		ledger.mu.RUnlock()

		if !bytes.Equal(got, want) {
			t.Fatalf("n=%d: Root()=%x != ref=%x", n, got, want)
		}
	}
}
