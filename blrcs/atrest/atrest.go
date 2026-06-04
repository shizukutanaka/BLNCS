// Package atrest — Encryption at rest
//
// 設計: Apple FileVault / iOS Data Protection 思想を application layer に適用。
//   - AES-256-GCM (stdlib のみ) による envelope 暗号化
//   - 鍵は外部から注入 (KMS/HSM 互換、本パッケージは持たない)
//   - 整合性チェック内蔵 (GCM authentication tag)
//   - バージョン付きフォーマット (将来 ChaCha20-Poly1305 等への移行可)
//
// 解決する短所:
//   - "Storage encryption at rest無 — FileStorage は平文 (PII/機密含む可能性)"
//
// Apple原則:
//   - 暗号化失敗時は安全側に倒す (起動拒否、無音壊死禁止)
//   - 鍵ローテーション可能設計 (key id 埋込み)
//   - 開発者エラー削減 (鍵長/IV 検証強制)
package atrest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ============================================================================
// Constants & errors
// ============================================================================

const (
	// EnvelopeVersion — 現行フォーマットバージョン
	EnvelopeVersion uint8 = 1

	// KeySize — AES-256 必須鍵長
	KeySize = 32

	// nonceSize — GCM 標準 nonce 長
	nonceSize = 12

	// keyIDSize — 鍵識別子 (4 bytes、ローテーション対応)
	keyIDSize = 4
)

var (
	ErrInvalidKey         = errors.New("atrest: key must be 32 bytes (AES-256)")
	ErrInvalidEnvelope    = errors.New("atrest: invalid envelope format")
	ErrUnsupportedVersion = errors.New("atrest: unsupported envelope version")
	ErrIntegrityFail      = errors.New("atrest: integrity check failed (tampered data)")
	ErrUnknownKey         = errors.New("atrest: key ID not found in keyring")
)

// ============================================================================
// Envelope format
// ============================================================================

// Envelope binary layout:
//
// [version: 1 byte]
// [keyID:   4 bytes]
// [nonce:   12 bytes]
// [ciphertext + auth tag: variable, GCM]
//
// 合計オーバヘッド = 1 + 4 + 12 + 16 (GCM tag) = 33 bytes
//
// 鍵ローテーション: keyID で keyring から正しい鍵を選ぶ

// ============================================================================
// Cipher — 鍵を保持して暗号化/復号化を提供
// ============================================================================

// Cipher — 単一鍵の暗号化/復号化器
type Cipher struct {
	keyID [keyIDSize]byte
	gcm   cipher.AEAD
}

// NewCipher — 鍵から Cipher 構築
//
// keyID: 4-byte 識別子 (例: time-based 又は version 番号、ローテーション識別用)
// key: AES-256 鍵 (32 bytes)
func NewCipher(keyID [keyIDSize]byte, key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("atrest: aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("atrest: gcm init: %w", err)
	}
	return &Cipher{keyID: keyID, gcm: gcm}, nil
}

// Encrypt — payload を envelope 形式で暗号化
//
// nonce はランダム生成 (caller は同じ payload を複数回呼んでも問題なし)
func (c *Cipher) Encrypt(payload []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("atrest: nonce gen: %w", err)
	}
	ciphertext := c.gcm.Seal(nil, nonce, payload, nil)

	// Build envelope: version || keyID || nonce || ciphertext
	envelope := make([]byte, 0, 1+keyIDSize+nonceSize+len(ciphertext))
	envelope = append(envelope, EnvelopeVersion)
	envelope = append(envelope, c.keyID[:]...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)
	return envelope, nil
}

// Decrypt — envelope を復号化
//
// 整合性チェック失敗 (改ざん検知) → ErrIntegrityFail
func (c *Cipher) Decrypt(envelope []byte) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	// Extract keyID — must match this Cipher
	var envKeyID [keyIDSize]byte
	copy(envKeyID[:], envelope[1:1+keyIDSize])
	if envKeyID != c.keyID {
		return nil, fmt.Errorf("%w: envelope key %x, cipher key %x",
			ErrUnknownKey, envKeyID, c.keyID)
	}
	nonce := envelope[1+keyIDSize : 1+keyIDSize+nonceSize]
	ciphertext := envelope[1+keyIDSize+nonceSize:]

	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntegrityFail, err)
	}
	return plaintext, nil
}

// KeyID — このCipherの鍵識別子
func (c *Cipher) KeyID() [keyIDSize]byte {
	return c.keyID
}

// ============================================================================
// Keyring — 複数鍵の管理 (ローテーション対応)
// ============================================================================

// Keyring — keyID → Cipher のマップ
//
// 用途: 鍵ローテーション後も古い envelope を読める。
// 新規 Encrypt は最新 (Active) 鍵のみ使用。
type Keyring struct {
	ciphers map[[keyIDSize]byte]*Cipher
	active  *Cipher
}

// NewKeyring — 空の keyring
func NewKeyring() *Keyring {
	return &Keyring{ciphers: make(map[[keyIDSize]byte]*Cipher)}
}

// Add — 鍵追加 (最初に追加された鍵が active になる)
func (k *Keyring) Add(c *Cipher) {
	k.ciphers[c.keyID] = c
	if k.active == nil {
		k.active = c
	}
}

// SetActive — Encrypt で使う鍵を選択
func (k *Keyring) SetActive(keyID [keyIDSize]byte) error {
	c, ok := k.ciphers[keyID]
	if !ok {
		return ErrUnknownKey
	}
	k.active = c
	return nil
}

// Encrypt — active 鍵で暗号化
func (k *Keyring) Encrypt(payload []byte) ([]byte, error) {
	if k.active == nil {
		return nil, errors.New("atrest: no active key in keyring")
	}
	return k.active.Encrypt(payload)
}

// Decrypt — envelope の keyID から正しい鍵を選んで復号
//
// 鍵ローテーション後でも古い envelope を読める
func (k *Keyring) Decrypt(envelope []byte) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	var envKeyID [keyIDSize]byte
	copy(envKeyID[:], envelope[1:1+keyIDSize])
	c, ok := k.ciphers[envKeyID]
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrUnknownKey, envKeyID)
	}
	return c.Decrypt(envelope)
}

// HasKey — keyID 登録済みか
func (k *Keyring) HasKey(keyID [keyIDSize]byte) bool {
	_, ok := k.ciphers[keyID]
	return ok
}

// ActiveKeyID — 現在 Encrypt に使われる鍵
func (k *Keyring) ActiveKeyID() [keyIDSize]byte {
	if k.active == nil {
		return [keyIDSize]byte{}
	}
	return k.active.keyID
}

// ============================================================================
// helpers
// ============================================================================

func validateEnvelope(envelope []byte) error {
	minSize := 1 + keyIDSize + nonceSize + 16 // 16 = GCM tag
	if len(envelope) < minSize {
		return ErrInvalidEnvelope
	}
	if envelope[0] != EnvelopeVersion {
		return fmt.Errorf("%w: got version %d", ErrUnsupportedVersion, envelope[0])
	}
	return nil
}

// GenerateKey — 安全な乱数から AES-256 鍵生成
//
// crypto/rand 使用 — テストや初期化で使用
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// KeyIDFromUint32 — uint32 番号から keyID 生成 (ローテーション ID 用)
func KeyIDFromUint32(n uint32) [keyIDSize]byte {
	var id [keyIDSize]byte
	binary.BigEndian.PutUint32(id[:], n)
	return id
}
