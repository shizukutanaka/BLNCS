package storage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// 共通テスト: 両実装が同じ契約を満たすことを保証
func testStorageContract(t *testing.T, name string, newStorage func() Storage) {
	t.Run(name+"/EmptyIterate", func(t *testing.T) {
		s := newStorage()
		defer s.Close()
		count := 0
		if err := s.IterateStatements(func(idx uint64, b StatementBlob) error {
			count++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("empty storage iter count: %d", count)
		}
	})

	t.Run(name+"/AppendAndIterate", func(t *testing.T) {
		s := newStorage()
		defer s.Close()
		blobs := []string{`{"a":1}`, `{"b":"hello"}`, `{"c":[1,2,3]}`}
		for _, b := range blobs {
			idx, err := s.AppendStatement([]byte(b))
			if err != nil {
				t.Fatal(err)
			}
			_ = idx
		}
		sz, _ := s.Size()
		if sz != uint64(len(blobs)) {
			t.Fatalf("size got %d want %d", sz, len(blobs))
		}
		var got []string
		if err := s.IterateStatements(func(idx uint64, b StatementBlob) error {
			if idx != uint64(len(got)) {
				return fmt.Errorf("idx out of order: %d", idx)
			}
			got = append(got, string(b))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for i, b := range blobs {
			if got[i] != b {
				t.Errorf("blob %d: got %q want %q", i, got[i], b)
			}
		}
	})

	t.Run(name+"/KeyPairRoundTrip", func(t *testing.T) {
		s := newStorage()
		defer s.Close()
		_, _, err := s.LoadKeyPair()
		if err != ErrNotFound {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := s.SaveKeyPair(pub, priv); err != nil {
			t.Fatal(err)
		}
		gotPub, gotPriv, err := s.LoadKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if !bytesEqual(pub, gotPub) || !bytesEqual(priv, gotPriv) {
			t.Fatal("keypair mismatch")
		}
	})

	t.Run(name+"/Concurrent", func(t *testing.T) {
		s := newStorage()
		defer s.Close()
		const N = 50
		var wg sync.WaitGroup
		wg.Add(N)
		for i := 0; i < N; i++ {
			go func(i int) {
				defer wg.Done()
				blob, _ := json.Marshal(map[string]int{"n": i})
				if _, err := s.AppendStatement(blob); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		sz, _ := s.Size()
		if sz != N {
			t.Fatalf("size got %d want %d", sz, N)
		}
	})
}

func TestMemoryStorage(t *testing.T) {
	testStorageContract(t, "mem", func() Storage { return NewMemoryStorage() })
}

func TestFileStorage(t *testing.T) {
	testStorageContract(t, "file", func() Storage {
		dir, err := os.MkdirTemp("", "blrcs-storage-*")
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewFileStorage(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		return s
	})
}

func TestFileStorage_CrashRecovery(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-crash-*")
	defer os.RemoveAll(dir)

	// 書込みセッション
	s, err := NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s.SaveKeyPair(pub, priv)
	wroteBlobs := make([]string, 100)
	for i := 0; i < 100; i++ {
		blob := fmt.Sprintf(`{"n":%d,"msg":"hello-%d"}`, i, i)
		wroteBlobs[i] = blob
		if _, err := s.AppendStatement([]byte(blob)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	// 「クラッシュ」後の再オープン
	s2, err := NewFileStorage(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	sz, _ := s2.Size()
	if sz != 100 {
		t.Fatalf("recovered size: got %d want 100", sz)
	}

	gotPub, gotPriv, err := s2.LoadKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(pub, gotPub) || !bytesEqual(priv, gotPriv) {
		t.Fatal("keypair lost across restart")
	}

	count := 0
	if err := s2.IterateStatements(func(idx uint64, b StatementBlob) error {
		if string(b) != wroteBlobs[idx] {
			return fmt.Errorf("blob %d mismatch: got %q want %q", idx, string(b), wroteBlobs[idx])
		}
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 100 {
		t.Fatalf("replay count: %d", count)
	}
}

func TestFileStorage_AppendAfterReopen(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-reopen-*")
	defer os.RemoveAll(dir)

	s1, _ := NewFileStorage(dir)
	s1.AppendStatement([]byte(`{"a":1}`))
	s1.AppendStatement([]byte(`{"a":2}`))
	s1.Close()

	s2, err := NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	// index should continue from 2
	idx, err := s2.AppendStatement([]byte(`{"a":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if idx != 2 {
		t.Fatalf("post-reopen idx: got %d want 2", idx)
	}
	sz, _ := s2.Size()
	if sz != 3 {
		t.Fatalf("size: got %d want 3", sz)
	}
}

func TestFileStorage_CorruptedLogRejected(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-corrupt-*")
	defer os.RemoveAll(dir)

	s, _ := NewFileStorage(dir)
	s.AppendStatement([]byte(`{"ok":true}`))
	s.Close()

	// 末尾に不完全なフレームを追加 (truncation simulation)
	p := filepath.Join(dir, ledgerFileName)
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	f.Write([]byte{0x00, 0x00, 0x01}) // 3 bytes, incomplete header
	f.Close()

	_, err := NewFileStorage(dir)
	if err == nil {
		t.Fatal("corrupted log should be rejected")
	}
}

func TestFileStorage_AfterCloseErrors(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-closed-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	s.Close()
	if _, err := s.AppendStatement([]byte(`{"x":1}`)); err != ErrAlreadyClosed {
		t.Fatalf("want ErrAlreadyClosed, got %v", err)
	}
}

func bytesEqual(a, b []byte) bool {
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

// ============================================================================
// Additional coverage: keypair, bad blob size, second Close, callback error
// ============================================================================

func TestFileStorage_KeyPairRoundTrip(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-kp-*")
	defer os.RemoveAll(dir)
	s, err := NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Before any key is stored, LoadKeyPair must return ErrNotFound.
	if _, _, err := s.LoadKeyPair(); err != ErrNotFound {
		t.Fatalf("want ErrNotFound before save, got %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.SaveKeyPair(pub, priv); err != nil {
		t.Fatal(err)
	}
	// Reload and verify round-trip.
	gotPub, gotPriv, err := s.LoadKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(pub, gotPub) || !bytesEqual(priv, gotPriv) {
		t.Error("keypair round-trip mismatch")
	}
}

func TestFileStorage_SaveKeyPairWrongSize(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-kpbad-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	defer s.Close()
	if err := s.SaveKeyPair([]byte("short"), []byte("short")); err == nil {
		t.Error("wrong-size keypair should fail")
	}
}

func TestFileStorage_LoadKeyPairBadSize(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-kpbad2-*")
	defer os.RemoveAll(dir)
	// Write a keypair file with wrong length.
	p := filepath.Join(dir, "keypair.bin")
	if err := os.WriteFile(p, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewFileStorage(dir)
	defer s.Close()
	if _, _, err := s.LoadKeyPair(); err == nil {
		t.Error("bad-size keypair file should fail")
	}
}

func TestFileStorage_AppendBadBlobSize(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-badblob-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	defer s.Close()
	// Empty blob → error.
	if _, err := s.AppendStatement([]byte{}); err == nil {
		t.Error("empty blob should fail")
	}
	// Oversized blob > 16 MiB → error.
	big := make([]byte, 16*1024*1024+1)
	if _, err := s.AppendStatement(big); err == nil {
		t.Error("oversized blob should fail")
	}
}

func TestFileStorage_IterateCallbackError(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-iter-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	defer s.Close()
	s.AppendStatement([]byte(`{"a":1}`))
	s.AppendStatement([]byte(`{"b":2}`))
	boom := errors.New("callback boom")
	err := s.IterateStatements(func(idx uint64, _ StatementBlob) error {
		if idx == 0 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want callback error propagated, got %v", err)
	}
}

func TestFileStorage_CloseIdempotent(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-close2-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Second Close must return nil (idempotent).
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ============================================================================
// Coverage uplift: MemoryStorage closed path, iterate callback error,
// syncDir error, FileStorage iterate bad-frame paths
// ============================================================================

func TestMemoryStorage_AfterClose(t *testing.T) {
	s := NewMemoryStorage()
	s.Close()
	if _, err := s.AppendStatement([]byte(`{"x":1}`)); err != ErrAlreadyClosed {
		t.Fatalf("want ErrAlreadyClosed after Close, got %v", err)
	}
}

func TestMemoryStorage_IterateCallbackError(t *testing.T) {
	s := NewMemoryStorage()
	s.AppendStatement([]byte(`{"a":1}`))
	s.AppendStatement([]byte(`{"b":2}`))
	boom := errors.New("boom")
	err := s.IterateStatements(func(_ uint64, _ StatementBlob) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("callback error not propagated, got %v", err)
	}
}

func TestSyncDirNonExistent(t *testing.T) {
	err := syncDir("/nonexistent-dir-blrcs-test-xyzzy")
	if err == nil {
		t.Error("syncDir on non-existent path should fail")
	}
}

func TestFileStorage_IterateBadFrameSize(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-iterfs-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	s.AppendStatement([]byte(`{"ok":true}`))
	// Write a zero-size frame header directly into the open file.
	var badHeader [frameHeaderSize]byte // all zeros = size 0
	if _, err := s.file.Write(badHeader[:]); err != nil {
		t.Fatalf("write bad header: %v", err)
	}
	err := s.IterateStatements(func(_ uint64, _ StatementBlob) error { return nil })
	if err == nil {
		t.Fatal("bad frame size (0) should cause IterateStatements to return error")
	}
}

func TestFileStorage_IterateTruncatedPayload(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-itertrunc-*")
	defer os.RemoveAll(dir)
	s, _ := NewFileStorage(dir)
	s.AppendStatement([]byte(`{"ok":true}`))
	// Write a header claiming 100 bytes but write no payload bytes.
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], 100)
	if _, err := s.file.Write(header[:]); err != nil {
		t.Fatalf("write truncated header: %v", err)
	}
	err := s.IterateStatements(func(_ uint64, _ StatementBlob) error { return nil })
	if err == nil {
		t.Fatal("truncated payload should cause IterateStatements to return error")
	}
}
