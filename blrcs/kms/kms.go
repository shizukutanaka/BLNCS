// Package kms — 鍵管理抽象 (Apple Secure Enclave / TPM 相当)
//
// 設計思想:
//
//	Apple Secure Enclave は「秘密鍵がメモリに出ない」ことを物理保証する。
//	BLRCS ではプロセスメモリ滞留が現状のため、本番では HSM / Cloud KMS が必須。
//
//	この package は鍵操作を Signer interface に抽象化し、本番では実装を差替可能にする:
//	  - MemorySigner    : 開発/テスト (現状の compliance.Issuer 互換)
//	  - FileSigner      : ファイル永続化 + 起動時復元
//	  - 将来: AWSKMSSigner, GCPKMSSigner, PKCS11Signer (HSM), AppleSESigner
//
// 重要 invariant:
//   - PrivateKey() メソッドは MemorySigner 限定 (テスト専用)
//   - 本番 Signer は Sign() だけを公開、鍵が外に出ない
//
// 規制対応:
//   - SOC2 Type II: 鍵管理の証跡
//   - FIPS 140-2: HSM 必須環境
//   - EU eIDAS Qualified: QSCD (Qualified Signature Creation Device)
package kms

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// ============================================================================
// Signer interface — Apple SecKeyCreateSignature 相当
// ============================================================================

// Signer — Ed25519 署名者抽象
//
// 本番実装 (HSM 等) は PrivateKey() を export しない。
// Sign() のみが許可された操作。
type Signer interface {
	// ID — 鍵識別子 (DID, JWK kid, HSM slot 等)
	ID() string

	// PublicKey — 公開鍵取得 (常に許可)
	PublicKey() ed25519.PublicKey

	// Sign — payload を署名、Ed25519 詳細形式
	Sign(payload []byte) ([]byte, error)

	// Close — リソース解放 (HSM セッション切断等)
	Close() error
}

// PrivateKeyExporter — 開発/テスト/migration 用の特殊 interface
//
// 本番 Signer は実装してはならない (HSM はそもそも実装不可能)
type PrivateKeyExporter interface {
	// PrivateKey — Ed25519 秘密鍵を外に出す (BREAKS Secure Enclave invariant)
	PrivateKey() ed25519.PrivateKey
}

// ============================================================================
// MemorySigner — 開発/テスト/MVP用
// ============================================================================

// MemorySigner — メモリ滞留 Ed25519 鍵 (compliance.Issuer 互換)
//
// 用途: 開発、テスト、CI、低リスク本番 (単一サーバ・小規模)
// 警告: マルチサーバ・高リスク環境では FileSigner / 外部 KMS 推奨
type MemorySigner struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewMemorySigner — ランダム鍵生成
func NewMemorySigner(id string) (*MemorySigner, error) {
	if id == "" {
		return nil, errors.New("kms: signer ID required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kms: keygen: %w", err)
	}
	return &MemorySigner{id: id, pub: pub, priv: priv}, nil
}

// ImportMemorySigner — 既存鍵から MemorySigner 構築 (migration 用)
func ImportMemorySigner(id string, priv ed25519.PrivateKey) (*MemorySigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("kms: invalid private key size")
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &MemorySigner{id: id, pub: pub, priv: priv}, nil
}

func (m *MemorySigner) ID() string                   { return m.id }
func (m *MemorySigner) PublicKey() ed25519.PublicKey { return m.pub }

func (m *MemorySigner) Sign(payload []byte) ([]byte, error) {
	if m.priv == nil {
		return nil, errors.New("kms: signer closed")
	}
	return ed25519.Sign(m.priv, payload), nil
}

// PrivateKey — テスト/migration 専用。本番 Signer は実装してはならない。
// PrivateKeyExporter interface に従う。
func (m *MemorySigner) PrivateKey() ed25519.PrivateKey { return m.priv }

func (m *MemorySigner) Close() error {
	// ベストエフォート: メモリゼロクリア (Go GC で完全には保証されない)
	if m.priv != nil {
		for i := range m.priv {
			m.priv[i] = 0
		}
		m.priv = nil
	}
	return nil
}

// ============================================================================
// FileSigner — ファイル永続化、起動時に鍵復元
// ============================================================================

// FileSigner — ファイル保存 Ed25519 鍵
//
// ディスク鍵はファイルパーミッション 0600 のみ。
// 起動時に鍵が無ければ生成、あれば復元。
type FileSigner struct {
	id   string
	path string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	mu   sync.Mutex
}

// NewFileSigner — 鍵を path から読込、無ければ生成
func NewFileSigner(id, path string) (*FileSigner, error) {
	if id == "" {
		return nil, errors.New("kms: signer ID required")
	}
	if path == "" {
		return nil, errors.New("kms: path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("kms: mkdir: %w", err)
	}
	fs := &FileSigner{id: id, path: path}
	// load or generate
	if _, err := os.Stat(path); err == nil {
		if err := fs.load(); err != nil {
			return nil, err
		}
		return fs, nil
	}
	// generate new
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kms: keygen: %w", err)
	}
	fs.pub, fs.priv = pub, priv
	if err := fs.save(); err != nil {
		return nil, err
	}
	return fs, nil
}

func (f *FileSigner) load() error {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("kms: read keyfile: %w", err)
	}
	if len(b) != ed25519.PublicKeySize+ed25519.PrivateKeySize {
		return fmt.Errorf("kms: bad keyfile size %d", len(b))
	}
	f.pub = make(ed25519.PublicKey, ed25519.PublicKeySize)
	f.priv = make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(f.pub, b[:ed25519.PublicKeySize])
	copy(f.priv, b[ed25519.PublicKeySize:])
	return nil
}

func (f *FileSigner) save() error {
	tmp := f.path + ".tmp"
	buf := make([]byte, 0, ed25519.PublicKeySize+ed25519.PrivateKeySize)
	buf = append(buf, f.pub...)
	buf = append(buf, f.priv...)
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("kms: write keyfile: %w", err)
	}
	return os.Rename(tmp, f.path)
}

func (f *FileSigner) ID() string                   { return f.id }
func (f *FileSigner) PublicKey() ed25519.PublicKey { return f.pub }

func (f *FileSigner) Sign(payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.priv == nil {
		return nil, errors.New("kms: signer closed")
	}
	return ed25519.Sign(f.priv, payload), nil
}

func (f *FileSigner) PrivateKey() ed25519.PrivateKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.priv
}

func (f *FileSigner) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.priv != nil {
		for i := range f.priv {
			f.priv[i] = 0
		}
		f.priv = nil
	}
	return nil
}

// ============================================================================
// ExternalSigner — HSM / Cloud KMS への adapter
// ============================================================================

// SignFunc — 外部 KMS からの署名コールバック
type SignFunc func(payload []byte) ([]byte, error)

// ExternalSigner — 任意のリモート署名関数を Signer 化
//
// 用途: AWS KMS, GCP KMS, HashiCorp Vault, PKCS#11 HSM 等
// PrivateKey() は意図的に実装しない (外部に出ない)
type ExternalSigner struct {
	id     string
	pub    ed25519.PublicKey
	signFn SignFunc
	closer io.Closer // optional, for HSM session
}

// NewExternalSigner — 外部署名関数を Signer 化
func NewExternalSigner(id string, pub ed25519.PublicKey, sign SignFunc, closer io.Closer) (*ExternalSigner, error) {
	if id == "" {
		return nil, errors.New("kms: signer ID required")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("kms: invalid public key size")
	}
	if sign == nil {
		return nil, errors.New("kms: sign function required")
	}
	return &ExternalSigner{
		id:     id,
		pub:    pub,
		signFn: sign,
		closer: closer,
	}, nil
}

func (e *ExternalSigner) ID() string                   { return e.id }
func (e *ExternalSigner) PublicKey() ed25519.PublicKey { return e.pub }

func (e *ExternalSigner) Sign(payload []byte) ([]byte, error) {
	if e.signFn == nil {
		return nil, errors.New("kms: external signer closed")
	}
	sig, err := e.signFn(payload)
	if err != nil {
		return nil, fmt.Errorf("kms: external sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("kms: external returned wrong sig size %d", len(sig))
	}
	return sig, nil
}

func (e *ExternalSigner) Close() error {
	e.signFn = nil
	if e.closer != nil {
		return e.closer.Close()
	}
	return nil
}

// ============================================================================
// SignerVerifier — 公開鍵から検証専用 (Signer 反対側)
// ============================================================================

// VerifySignature — 署名検証 (signer-agnostic)
//
// 検証側は signer 種別を気にしない。公開鍵のみ。
func VerifySignature(pub ed25519.PublicKey, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

// ============================================================================
// Compile-time interface assertions
// ============================================================================

var (
	_ Signer             = (*MemorySigner)(nil)
	_ PrivateKeyExporter = (*MemorySigner)(nil)
	_ Signer             = (*FileSigner)(nil)
	_ PrivateKeyExporter = (*FileSigner)(nil)
	_ Signer             = (*ExternalSigner)(nil)
	// ExternalSigner は意図的に PrivateKeyExporter ではない
)
