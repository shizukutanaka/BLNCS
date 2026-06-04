// Bitstring Status List — W3C Bitstring Status List v1.0 (Recommendation) 実装。
//
// https://www.w3.org/TR/vc-bitstring-status-list/
//
// 旧 StatusList2021 を置換する現行標準。各 credential は 1 bit を占有し、
// status list 全体は GZIP 圧縮 + base64url エンコードで配布される。
//
// 設計上の要点:
//   - bit=1 は statusPurpose に従った状態 (revocation なら「失効」)
//   - 最小サイズ 16KB (131,072 entries) で herd privacy を担保 (§5.3)
//   - GZIP + base64url(no padding) で encodedList を生成 (§3.2)
package revocation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MinBitstringSize — W3C 推奨最小サイズ (§5.3 herd privacy): 16KB(bytes) = 131,072 bits。
const MinBitstringSize = 16 * 1024 * 8

// maxEncodedListBytes / maxDecodedListBytes — decompression-bomb 防御の上限。
// 現実の status list は 16KB〜数百KB (展開後)。攻撃者が供給しうる encodedList に
// 対し、圧縮済み入力長と展開後サイズの双方を制限する。
const (
	maxEncodedListBytes = 8 << 20  // 8 MiB: 圧縮済み入力の上限
	maxDecodedListBytes = 64 << 20 // 64 MiB: 展開後の上限
)

// StatusPurpose — Bitstring Status List のエントリ用途。
type StatusPurpose string

const (
	// PurposeRevocation — 取り消し不能な失効。
	PurposeRevocation StatusPurpose = "revocation"
	// PurposeSuspension — 一時停止 (後で解除可能)。
	PurposeSuspension StatusPurpose = "suspension"
)

// BitstringStatusList — 圧縮可能なビット配列ベースの status list。
//
// スレッドセーフ。SetStatus/GetStatus は index で O(1) アクセス。
type BitstringStatusList struct {
	mu      sync.RWMutex
	bits    []byte
	purpose StatusPurpose
}

// NewBitstringStatusList — 指定 entry 数の status list を構築。
//
// sizeBits は MinBitstringSize 未満なら自動的に切り上げ (herd privacy)。
func NewBitstringStatusList(purpose StatusPurpose, sizeBits int) *BitstringStatusList {
	if sizeBits < MinBitstringSize {
		sizeBits = MinBitstringSize
	}
	return &BitstringStatusList{
		bits:    make([]byte, (sizeBits+7)/8),
		purpose: purpose,
	}
}

// Purpose — この list の statusPurpose。
func (b *BitstringStatusList) Purpose() StatusPurpose {
	return b.purpose
}

// Capacity — 収容可能な entry 数 (bits)。
func (b *BitstringStatusList) Capacity() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.bits) * 8
}

// SetStatus — index のビットを設定 (true=該当状態オン, 例: 失効)。
func (b *BitstringStatusList) SetStatus(index int, on bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if index < 0 || index >= len(b.bits)*8 {
		return fmt.Errorf("revocation: index %d out of range [0,%d)", index, len(b.bits)*8)
	}
	byteIdx := index / 8
	bitIdx := uint(index % 8)
	if on {
		b.bits[byteIdx] |= 1 << bitIdx
	} else {
		b.bits[byteIdx] &^= 1 << bitIdx
	}
	return nil
}

// GetStatus — index のビット状態を取得。
func (b *BitstringStatusList) GetStatus(index int) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if index < 0 || index >= len(b.bits)*8 {
		return false, fmt.Errorf("revocation: index %d out of range [0,%d)", index, len(b.bits)*8)
	}
	byteIdx := index / 8
	bitIdx := uint(index % 8)
	return b.bits[byteIdx]&(1<<bitIdx) != 0, nil
}

// EncodedList — W3C §3.2 準拠の encodedList を生成 (GZIP + base64url, no padding)。
func (b *BitstringStatusList) EncodedList() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(b.bits); err != nil {
		return "", fmt.Errorf("revocation: gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("revocation: gzip close: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeBitstringStatusList — encodedList から status list を復元 (§3.2 逆変換)。
func DecodeBitstringStatusList(purpose StatusPurpose, encoded string) (*BitstringStatusList, error) {
	if encoded == "" {
		return nil, errors.New("revocation: empty encodedList")
	}
	if len(encoded) > maxEncodedListBytes {
		return nil, fmt.Errorf("revocation: encodedList too large (%d > %d bytes)", len(encoded), maxEncodedListBytes)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// padding 付きも許容 (相互運用)
		compressed, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("revocation: base64 decode: %w", err)
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("revocation: gzip reader: %w", err)
	}
	defer gz.Close()
	// decompression-bomb 防御: 上限+1 まで読み、超過なら拒否。
	bits, err := io.ReadAll(io.LimitReader(gz, maxDecodedListBytes+1))
	if err != nil {
		return nil, fmt.Errorf("revocation: gzip read: %w", err)
	}
	if len(bits) > maxDecodedListBytes {
		return nil, fmt.Errorf("revocation: decoded status list exceeds %d bytes (decompression bomb?)", maxDecodedListBytes)
	}
	return &BitstringStatusList{bits: bits, purpose: purpose}, nil
}
