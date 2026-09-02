// Package revocation — Verifiable Credential 失効リスト
//
// 設計: Apple OCSP / W3C VC StatusList 2021 思想:
//   - 発行済 VC を後から無効化 (リコール、誤発行訂正)
//   - 失効リストは Issuer が ed25519 で署名 (改ざん検知)
//   - SCITT 透明性ログに登録可能 (失効履歴の audit trail)
//   - 時限失効サポート (RevokedAt + Reason)
//
// 解決する短所:
//   - "Time-bound revocation list無 — issued credential を後から失効する仕組みなし"
//
// Apple原則:
//   - 失効状態は陽性 list (default = 有効、失効のみ list)
//   - 高速 lookup (sync.Map ベース)
//   - 構造化 reason (リコール / 誤発行 / セキュリティ事案 区別)
package revocation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrAlreadyRevoked = errors.New("revocation: credential already revoked")
	ErrNotRevoked     = errors.New("revocation: credential not in list")
	ErrInvalidSig     = errors.New("revocation: invalid signature")
)

// ============================================================================
// Reason codes (Apple HealthKit / Apple Wallet revocation reason 同水準)
// ============================================================================

// Reason — 失効理由
type Reason string

const (
	ReasonRecall     Reason = "recall"          // 製品リコール
	ReasonError      Reason = "issuance_error"  // 発行ミス
	ReasonExpired    Reason = "expired"         // 期限切れ
	ReasonSuperseded Reason = "superseded"      // 新版発行で旧版無効化
	ReasonSecurity   Reason = "security_breach" // 鍵漏洩等
	ReasonCompliance Reason = "compliance"      // 規制違反検知
	ReasonOther      Reason = "other"
)

// IsValid — 既知の reason コードか
func (r Reason) IsValid() bool {
	switch r {
	case ReasonRecall, ReasonError, ReasonExpired, ReasonSuperseded,
		ReasonSecurity, ReasonCompliance, ReasonOther:
		return true
	}
	return false
}

// ============================================================================
// Entry
// ============================================================================

// Entry — 失効した1件
type Entry struct {
	CredentialID string    `json:"credentialId"` // 例: VC ID, GTIN+serial
	Reason       Reason    `json:"reason"`
	RevokedAt    time.Time `json:"revokedAt"`
	Detail       string    `json:"detail,omitempty"` // 任意 free text
}

// ============================================================================
// SignedList — Issuer 署名済の失効リスト
// ============================================================================

// SignedList — 発行者が署名した失効リスト (JSON 出力可能)
type SignedList struct {
	Issuer    string    `json:"issuer"`
	UpdatedAt time.Time `json:"updatedAt"`
	Entries   []Entry   `json:"entries"`
	Signature string    `json:"signature"` // hex-encoded ed25519
}

// ============================================================================
// List
// ============================================================================

// List — 失効リスト管理器
type List struct {
	issuer string

	mu      sync.RWMutex
	entries map[string]*Entry // credentialID → Entry
}

// New — 空 List (issuer DID を必須)
func New(issuerDID string) *List {
	return &List{
		issuer:  issuerDID,
		entries: make(map[string]*Entry),
	}
}

// Issuer — このリストの発行者 DID
func (l *List) Issuer() string {
	return l.issuer
}

// Revoke — credential を失効リストに追加
//
// 既に失効済 → ErrAlreadyRevoked
func (l *List) Revoke(credentialID string, reason Reason, detail string) (*Entry, error) {
	if !reason.IsValid() {
		return nil, fmt.Errorf("revocation: unknown reason %q", reason)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.entries[credentialID]; exists {
		return nil, ErrAlreadyRevoked
	}
	entry := &Entry{
		CredentialID: credentialID,
		Reason:       reason,
		RevokedAt:    time.Now().UTC(),
		Detail:       detail,
	}
	l.entries[credentialID] = entry
	return entry, nil
}

// IsRevoked — 失効済か
func (l *List) IsRevoked(credentialID string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.entries[credentialID]
	return ok
}

// Lookup — entry 取得 (存在しないなら ErrNotRevoked)
func (l *List) Lookup(credentialID string) (*Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[credentialID]
	if !ok {
		return nil, ErrNotRevoked
	}
	cp := *e
	return &cp, nil
}

// Size — 現在の失効件数
func (l *List) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// Entries — 全 entry の copy
func (l *List) Entries() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, *e)
	}
	// Deterministic order for signing
	sort.Slice(out, func(i, j int) bool {
		return out[i].CredentialID < out[j].CredentialID
	})
	return out
}

// ============================================================================
// Sign / Verify
// ============================================================================

// Sign — 現在の状態を ed25519 で署名し SignedList を返す
//
// 用途: 失効リストを SCITT に登録、外部 verifier に配布
func (l *List) Sign(privKey ed25519.PrivateKey) (*SignedList, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("revocation: invalid private key")
	}
	signed := &SignedList{
		Issuer:    l.issuer,
		UpdatedAt: time.Now().UTC(),
		Entries:   l.Entries(),
	}
	digest, err := computeDigest(signed)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(privKey, digest)
	signed.Signature = hex.EncodeToString(sig)
	return signed, nil
}

// Verify — SignedList の署名を検証
func Verify(signed *SignedList, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("revocation: invalid public key")
	}
	sig, err := hex.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature hex decode: %v", ErrInvalidSig, err)
	}
	digest, err := computeDigest(signed)
	if err != nil {
		// Fail closed: a list whose digest cannot be computed is unverifiable.
		return fmt.Errorf("%w: %v", ErrInvalidSig, err)
	}
	if !ed25519.Verify(pubKey, digest, sig) {
		return ErrInvalidSig
	}
	return nil
}

// ============================================================================
// Load — 署名済リストから List を再構築
// ============================================================================

// Load — SignedList から List を復元 (verify 後に呼ぶこと)
//
// 用途: SCITT から取得した最新 revocation list をローカルに展開
func Load(signed *SignedList) *List {
	l := New(signed.Issuer)
	l.mu.Lock()
	for i := range signed.Entries {
		e := signed.Entries[i]
		l.entries[e.CredentialID] = &e
	}
	l.mu.Unlock()
	return l
}

// ============================================================================
// JSON encode/decode helpers
// ============================================================================

// MarshalJSON — SignedList を JSON 化 (SCITT payload 用)
func (s *SignedList) MarshalToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// UnmarshalSignedList — JSON から復元
func UnmarshalSignedList(data []byte) (*SignedList, error) {
	var s SignedList
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ============================================================================
// helpers
// ============================================================================

// computeDigest — Sign / Verify で使う SHA-256 ダイジェスト
//
// 重要: Signature フィールドを除外して computed (chicken-and-egg 解決)
// entries は ID 順にソート済 (Sign で実施)
// It returns an error rather than discarding one: json.Marshal fails on a
// time.Time whose year falls outside [0,9999], and the discarded form then
// hashed nil — so every list carrying such a timestamp shared one digest,
// leaving issuer and entries unauthenticated.
func computeDigest(s *SignedList) ([]byte, error) {
	// 署名対象を deterministic に直列化
	withoutSig := struct {
		Issuer    string    `json:"issuer"`
		UpdatedAt time.Time `json:"updatedAt"`
		Entries   []Entry   `json:"entries"`
	}{
		Issuer:    s.Issuer,
		UpdatedAt: s.UpdatedAt,
		Entries:   s.Entries,
	}
	body, err := json.Marshal(withoutSig)
	if err != nil {
		return nil, fmt.Errorf("revocation: encode signing payload: %w", err)
	}
	h := sha256.Sum256(body)
	return h[:], nil
}
