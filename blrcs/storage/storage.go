// Package storage — BLRCS SCITT ledger永続化層
//
// 設計契約:
//   - AppendStatement: statement を耐久化 (fsync保証)
//   - IterateStatements: 起動時リプレイ用
//   - LoadKeyPair/SaveKeyPair: TS keypair の永続化
//
// 提供実装:
//   - MemoryStorage: テスト/一時用
//   - FileStorage:   append-log + keypair file (crash-safe, Carmack式直接的)
//
// 将来実装 (契約不変):
//   - SQLiteStorage, CloudflareKV, S3, etc.
package storage

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrNotFound      = errors.New("storage: keypair not found")
	ErrCorrupted     = errors.New("storage: log corrupted")
	ErrAlreadyClosed = errors.New("storage: already closed")
)

// Statement — ledgerに格納する最小形式
// scittパッケージと構造が一致する必要あり。JSON互換性で紐付け。
// 循環import回避のためここでは map[string]any ではなく生JSONを扱う。
type StatementBlob = json.RawMessage

// Storage — ledger永続化契約
type Storage interface {
	// AppendStatement — 耐久化書込。戻り値は付与された leafIndex (0始まり)
	AppendStatement(blob StatementBlob) (uint64, error)

	// IterateStatements — 起動時リプレイ。順序保証必須
	IterateStatements(fn func(idx uint64, blob StatementBlob) error) error

	// Size — 現在のleaf数
	Size() (uint64, error)

	// LoadKeyPair — 以前保存したkeypairを取得
	LoadKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error)

	// SaveKeyPair — TS keypairを耐久化
	SaveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) error

	Close() error
}

// ============================================================================
// MemoryStorage — テスト用
// ============================================================================

type MemoryStorage struct {
	mu     sync.RWMutex
	log    []StatementBlob
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	closed bool
}

func NewMemoryStorage() *MemoryStorage { return &MemoryStorage{} }

func (m *MemoryStorage) AppendStatement(blob StatementBlob) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrAlreadyClosed
	}
	// Copy to protect against mutation
	cp := make(json.RawMessage, len(blob))
	copy(cp, blob)
	idx := uint64(len(m.log))
	m.log = append(m.log, cp)
	return idx, nil
}

func (m *MemoryStorage) IterateStatements(fn func(idx uint64, blob StatementBlob) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i, b := range m.log {
		if err := fn(uint64(i), b); err != nil {
			return err
		}
	}
	return nil
}

func (m *MemoryStorage) Size() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return uint64(len(m.log)), nil
}

func (m *MemoryStorage) LoadKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.priv == nil {
		return nil, nil, ErrNotFound
	}
	return m.pub, m.priv, nil
}

func (m *MemoryStorage) SaveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pub = pub
	m.priv = priv
	return nil
}

func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

// ============================================================================
// FileStorage — append-log + keypair file
//
// ディレクトリ構造:
//   <dir>/ledger.log   — フレーム: [len:uint32 BE][JSON bytes]
//   <dir>/keypair.bin  — [32B pub][64B priv]
//
// 耐久性: 各 AppendStatement で fsync。 partial write 検出あり。
// Truncate/rotate は未対応 (TB超になったら別層で snapshot すればよい)。
// ============================================================================

const (
	keypairFileName = "keypair.bin"
	ledgerFileName  = "ledger.log"
	frameHeaderSize = 4 // uint32 BE length prefix
)

type FileStorage struct {
	mu     sync.Mutex
	dir    string
	file   *os.File
	size   uint64 // 現在のleaf数 (起動時に確定)
	closed bool
}

// NewFileStorage — ディレクトリを開き/作成し、既存ログをリプレイしてsizeを確定
func NewFileStorage(dir string) (*FileStorage, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	p := filepath.Join(dir, ledgerFileName)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ledger: %w", err)
	}
	fs := &FileStorage{dir: dir, file: f}
	// 既存ログをスキャンして size を求める + 破損検出
	if err := fs.rescanSize(); err != nil {
		f.Close()
		return nil, err
	}
	// fsync the directory so the ledger file's directory entry is durable on
	// crash (file.Sync alone flushes file data/inode, not the dir entry).
	if err := syncDir(dir); err != nil {
		f.Close()
		return nil, err
	}
	return fs, nil
}

// syncDir fsyncs a directory so newly created/renamed entries survive a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

func (fs *FileStorage) rescanSize() error {
	// 読込用に別hd
	rp := filepath.Join(fs.dir, ledgerFileName)
	rf, err := os.Open(rp)
	if err != nil {
		return err
	}
	defer rf.Close()
	br := bufio.NewReader(rf)
	var count uint64
	var header [frameHeaderSize]byte
	for {
		_, err := io.ReadFull(br, header[:])
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			return fmt.Errorf("%w: truncated header at frame %d", ErrCorrupted, count)
		}
		if err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 || n > 16*1024*1024 {
			return fmt.Errorf("%w: invalid frame size %d at frame %d", ErrCorrupted, n, count)
		}
		// スキップ
		if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
			return fmt.Errorf("%w: truncated payload at frame %d: %v", ErrCorrupted, count, err)
		}
		count++
	}
	fs.size = count
	return nil
}

func (fs *FileStorage) AppendStatement(blob StatementBlob) (uint64, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.closed {
		return 0, ErrAlreadyClosed
	}
	if len(blob) == 0 || len(blob) > 16*1024*1024 {
		return 0, fmt.Errorf("storage: bad blob size %d", len(blob))
	}
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(blob)))
	buf := make([]byte, 0, frameHeaderSize+len(blob))
	buf = append(buf, header[:]...)
	buf = append(buf, blob...)

	// Record the file offset before the write so we can truncate back on partial
	// failure. With O_APPEND the OS atomically seeks to end-of-file before each
	// write (POSIX), but a short write (e.g. disk full mid-frame) or a write error
	// after partial bytes can leave a torn frame. Truncating to preSize undoes the
	// partial write, keeping the log parseable for future appends and preventing
	// rescanSize from returning ErrCorrupted on the next startup.
	fi, err := fs.file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat before write: %w", err)
	}
	preSize := fi.Size()

	n, err := fs.file.Write(buf)
	if err != nil || n < len(buf) {
		// Best-effort rollback: truncate back to pre-write size to discard any
		// partial frame. Ignore any truncate error (we're already in an error path).
		_ = fs.file.Truncate(preSize)
		if err != nil {
			return 0, fmt.Errorf("write: %w", err)
		}
		return 0, fmt.Errorf("write: short write %d/%d", n, len(buf))
	}
	if err := fs.file.Sync(); err != nil {
		return 0, fmt.Errorf("fsync: %w", err)
	}
	idx := fs.size
	fs.size++
	return idx, nil
}

func (fs *FileStorage) IterateStatements(fn func(idx uint64, blob StatementBlob) error) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rp := filepath.Join(fs.dir, ledgerFileName)
	rf, err := os.Open(rp)
	if err != nil {
		return err
	}
	defer rf.Close()
	br := bufio.NewReader(rf)
	var idx uint64
	var header [frameHeaderSize]byte
	for {
		_, err := io.ReadFull(br, header[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(header[:])
		// Bound the frame size before allocating (matches rescanSize): a
		// corrupted/truncated header can declare up to ~4 GiB, which would
		// otherwise OOM on replay of a damaged log.
		if n == 0 || n > 16*1024*1024 {
			return fmt.Errorf("%w: frame size %d at idx %d", ErrCorrupted, n, idx)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			return fmt.Errorf("read payload at idx %d: %w", idx, err)
		}
		if err := fn(idx, json.RawMessage(payload)); err != nil {
			return err
		}
		idx++
	}
}

func (fs *FileStorage) Size() (uint64, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.size, nil
}

func (fs *FileStorage) LoadKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	p := filepath.Join(fs.dir, keypairFileName)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if len(b) != ed25519.PublicKeySize+ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: keypair file bad size %d", ErrCorrupted, len(b))
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(pub, b[:ed25519.PublicKeySize])
	copy(priv, b[ed25519.PublicKeySize:])
	// Verify the stored public key matches the private key's embedded public key.
	// A mismatch means the file is corrupted or tampered: signing would succeed
	// but receipts carrying the stored pub would fail verification.
	if !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
		return nil, nil, fmt.Errorf("%w: keypair public key does not match private key", ErrCorrupted)
	}
	return pub, priv, nil
}

func (fs *FileStorage) SaveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return errors.New("storage: keypair wrong size")
	}
	// Crash-safe atomic write: (1) write + fsync tmp file, (2) rename, (3) syncDir.
	// os.WriteFile does not fsync file data before close — a crash between WriteFile
	// and Rename can leave the renamed keypair.bin with zero/garbage bytes (page-cache
	// flush not guaranteed), silently destroying the private key.
	// syncDir alone makes the rename durable (directory entry), not the data.
	tmp := filepath.Join(fs.dir, keypairFileName+".tmp")
	final := filepath.Join(fs.dir, keypairFileName)
	buf := make([]byte, 0, ed25519.PublicKeySize+ed25519.PrivateKeySize)
	buf = append(buf, pub...)
	buf = append(buf, priv...)

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	// fsync the directory so the rename (the keypair's directory entry) is
	// durable on crash — otherwise a reported-successful SaveKeyPair can be lost.
	return syncDir(fs.dir)
}

func (fs *FileStorage) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.closed {
		return nil
	}
	fs.closed = true
	return fs.file.Close()
}

// ============================================================================
// EncryptedStorage — envelope-encryption decorator (atrest integration)
// ============================================================================

// BlobCipher is the subset of atrest.Cipher / atrest.Keyring that
// EncryptedStorage needs. Declared here (not by importing blrcs/atrest) so this
// package stays decoupled from the encryption implementation; any type with
// this shape works, including a Keyring for key-rotation support.
type BlobCipher interface {
	Encrypt(payload []byte) ([]byte, error)
	Decrypt(envelope []byte) ([]byte, error)
}

// EncryptedStorage wraps another Storage and transparently encrypts every
// statement blob with the given BlobCipher before delegating to it, and
// decrypts on the way back out. It implements Storage, so it composes with
// FileStorage, MemoryStorage, or any future backend without those backends
// needing to know about encryption.
//
// Scope: only AppendStatement/IterateStatements (the statement log — the DPP/
// Battery-Passport payloads, which may carry PII/confidential supply-chain
// data) are encrypted. LoadKeyPair/SaveKeyPair pass through unchanged: the
// Transparency Service's own Ed25519 signing key is a bootstrapping secret
// (whatever key protects it would itself need protecting), and atrest is
// explicitly designed to take its key from an external KMS/HSM rather than
// hold a root key itself — see atrest's package doc. Signing-key-at-rest
// protection belongs to that external KMS/HSM layer, not here.
type EncryptedStorage struct {
	underlying Storage
	cipher     BlobCipher
}

// NewEncryptedStorage wraps underlying so every AppendStatement/
// IterateStatements blob is encrypted/decrypted with cipher.
func NewEncryptedStorage(underlying Storage, cipher BlobCipher) *EncryptedStorage {
	return &EncryptedStorage{underlying: underlying, cipher: cipher}
}

func (e *EncryptedStorage) AppendStatement(blob StatementBlob) (uint64, error) {
	ct, err := e.cipher.Encrypt(blob)
	if err != nil {
		return 0, fmt.Errorf("storage: encrypt statement: %w", err)
	}
	return e.underlying.AppendStatement(StatementBlob(ct))
}

func (e *EncryptedStorage) IterateStatements(fn func(idx uint64, blob StatementBlob) error) error {
	return e.underlying.IterateStatements(func(idx uint64, ct StatementBlob) error {
		pt, err := e.cipher.Decrypt(ct)
		if err != nil {
			return fmt.Errorf("storage: decrypt statement at leaf %d: %w", idx, err)
		}
		return fn(idx, StatementBlob(pt))
	})
}

func (e *EncryptedStorage) Size() (uint64, error) { return e.underlying.Size() }

func (e *EncryptedStorage) LoadKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return e.underlying.LoadKeyPair()
}

func (e *EncryptedStorage) SaveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	return e.underlying.SaveKeyPair(pub, priv)
}

func (e *EncryptedStorage) Close() error { return e.underlying.Close() }
