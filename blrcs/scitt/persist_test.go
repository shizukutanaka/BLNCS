package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"blrcs/storage"
)

func TestLedgerPersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-scitt-*")
	defer os.RemoveAll(dir)

	// Session 1: 10 statements 書込み
	store1, err := storage.NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	ledger1, err := NewLedgerWithStorage("did:web:ts.persist", store1)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	receipts := make([]*Receipt, 10)
	statements := make([]Statement, 10)
	for i := 0; i < 10; i++ {
		stmt, _ := SignStatement(priv, "did:web:iss", fmt.Sprintf("subject-%d", i), "text/plain", []byte(fmt.Sprintf("payload-%d", i)))
		rec, err := ledger1.Register(stmt)
		if err != nil {
			t.Fatal(err)
		}
		receipts[i] = rec
		statements[i] = stmt
	}
	tsKey1 := ledger1.PublicKey()
	ledger1.Close()

	// Session 2: 再オープンして全receipt verify
	store2, err := storage.NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	ledger2, err := NewLedgerWithStorage("did:web:ts.persist", store2)
	if err != nil {
		t.Fatal(err)
	}
	if ledger2.Size() != 10 {
		t.Fatalf("size after restart: %d", ledger2.Size())
	}
	// Keypair は同じはず
	tsKey2 := ledger2.PublicKey()
	if !bytesEq(tsKey1, tsKey2) {
		t.Fatal("ts keypair not persisted")
	}
	// session-1 で取得した receipts が session-2 の公開鍵で検証できる
	for i, rec := range receipts {
		if err := VerifyReceipt(rec, statements[i], tsKey2); err != nil {
			t.Fatalf("receipt %d cross-session verify: %v", i, err)
		}
	}
}

func TestLedgerAppendAfterRestart(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-append-restart-*")
	defer os.RemoveAll(dir)

	// 3つ書く
	store, _ := storage.NewFileStorage(dir)
	ledger, _ := NewLedgerWithStorage("ts", store)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < 3; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("p%d", i)))
		ledger.Register(s)
	}
	ledger.Close()

	// 再オープン + 追記
	store2, _ := storage.NewFileStorage(dir)
	defer store2.Close()
	ledger2, _ := NewLedgerWithStorage("ts", store2)

	s, _ := SignStatement(priv, "iss", "s3", "c", []byte("p3"))
	rec, err := ledger2.Register(s)
	if err != nil {
		t.Fatal(err)
	}
	if rec.LeafIndex != 3 || rec.TreeSize != 4 {
		t.Fatalf("continuation wrong: idx=%d size=%d", rec.LeafIndex, rec.TreeSize)
	}
	// 旧leaf (idx=0) の包含証明が 新tree (size=4) で検証可能
	oldStmt, oldRec, err := ledger2.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(oldRec, oldStmt, ledger2.PublicKey()); err != nil {
		t.Fatalf("old leaf in grown tree: %v", err)
	}
}

func TestLedgerReplayDetectsTamperedLog(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-tamper-*")
	defer os.RemoveAll(dir)

	store, _ := storage.NewFileStorage(dir)
	ledger, _ := NewLedgerWithStorage("ts", store)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < 3; i++ {
		s, _ := SignStatement(priv, "iss", fmt.Sprintf("s%d", i), "c", []byte(fmt.Sprintf("p%d", i)))
		ledger.Register(s)
	}
	ledger.Close()

	// ログファイル中身を改ざん (1バイト flip)
	p := dir + "/ledger.log"
	b, _ := os.ReadFile(p)
	if len(b) < 50 {
		t.Skip("log too small to tamper predictably")
	}
	b[len(b)-10] ^= 0xFF // 最後のstatement内部の何かを壊す
	os.WriteFile(p, b, 0o600)

	// 再オープンはstatement署名検証で失敗するはず
	store2, err := storage.NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	_, err = NewLedgerWithStorage("ts", store2)
	if err == nil {
		t.Fatal("tampered log should fail replay")
	}
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
