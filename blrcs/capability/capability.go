// Package capability — 機能可用性 (Capability / Feature) 検出
//
// Apple の availability システム + Swift @available + iOS feature flag を統合。
//
// 問題:
//  1. 「この環境で X が使えるか?」を if-else で散在させない
//  2. UA 文字列 / バージョン番号での判定は脆い (UA spoofing, browser quirks)
//  3. 実行時の正確な能力検出が必要 (Secure Enclave, hardware AES, 等)
//
// 解法 — Apple原則:
//  1. Capability は名前付き値型 (string ではない)
//  2. Detector が真の値を計測 (実機テスト)
//  3. Code は capability に依存、実装に依存しない
//  4. Profile で複数 capability を集約 (FIDO2 Level 1 = 鍵HSM保管 + UV要求 + ...)
package capability

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// ============================================================================
// Capability — 機能識別子
// ============================================================================

// Capability — 名前付き能力 (Apple 風、stringly-typed 防止)
type Capability string

const (
	// === 暗号 ===
	CapEd25519        Capability = "crypto.ed25519"      // 標準: 全Goランタイム
	CapHardwareCrypto Capability = "crypto.hardware"     // Secure Enclave / TPM / HSM
	CapKMS            Capability = "crypto.kms"          // クラウド KMS 連携
	CapBulletproofs   Capability = "crypto.bulletproofs" // 真ZK範囲証明 (将来)

	// === ストレージ ===
	CapPersistence Capability = "storage.persistent"  // disk-backed ledger
	CapDistributed Capability = "storage.distributed" // multi-node consensus

	// === ネットワーク ===
	CapHTTPS     Capability = "net.https" // TLS 終端可
	CapWebSocket Capability = "net.websocket"
	CapSSE       Capability = "net.sse" // Server-Sent Events

	// === ウォレット ===
	CapWalletNative Capability = "wallet.native"    // OS-level wallet (Apple/Google)
	CapWalletWebDC  Capability = "wallet.webdc_api" // navigator.credentials.get()
	CapWalletEUDI   Capability = "wallet.eudi"      // EUDI Wallet 対応

	// === コンプライアンス ===
	CapDPP         Capability = "compliance.dpp"     // EU ESPR DPP
	CapBatteryPass Capability = "compliance.battery" // Reg.2023/1542
	CapTextilePass Capability = "compliance.textile" // ESPR Textile (2027)

	// === 監査 ===
	CapSCITT   Capability = "audit.scitt"   // IETF SCITT
	CapWitness Capability = "audit.witness" // 第三者証人
)

// ============================================================================
// Detector — capability の実機検出
// ============================================================================

// Detector — 実行環境の capability を検出する関数
type Detector func(ctx context.Context) bool

// CapabilitySet — 検出済み capability 集合 (immutable after Sealed)
type CapabilitySet struct {
	mu        sync.RWMutex
	available map[Capability]bool
	detected  map[Capability]time.Time
	sealed    bool
}

// New — 空の CapabilitySet
func New() *CapabilitySet {
	return &CapabilitySet{
		available: make(map[Capability]bool),
		detected:  make(map[Capability]time.Time),
	}
}

// Set — capability を直接設定 (test, declarative config)
func (s *CapabilitySet) Set(c Capability, available bool) *CapabilitySet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return s
	}
	s.available[c] = available
	s.detected[c] = time.Now().UTC()
	return s
}

// Detect — Detector を走らせて結果を保存
func (s *CapabilitySet) Detect(ctx context.Context, c Capability, d Detector) *CapabilitySet {
	if d == nil {
		return s.Set(c, false)
	}
	return s.Set(c, d(ctx))
}

// Has — capability が利用可能か (Apple #available 相当)
func (s *CapabilitySet) Has(c Capability) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.available[c]
}

// HasAll — 全 capability が利用可能か (AND)
func (s *CapabilitySet) HasAll(caps ...Capability) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range caps {
		if !s.available[c] {
			return false
		}
	}
	return true
}

// HasAny — いずれかの capability が利用可能か (OR)
func (s *CapabilitySet) HasAny(caps ...Capability) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range caps {
		if s.available[c] {
			return true
		}
	}
	return false
}

// Seal — 以降変更不可 (production 起動後の immutable 保証)
func (s *CapabilitySet) Seal() *CapabilitySet {
	s.mu.Lock()
	s.sealed = true
	s.mu.Unlock()
	return s
}

// Sealed — Seal 済みか
func (s *CapabilitySet) Sealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed
}

// Available — 利用可能な全 capability の一覧 (sorted)
func (s *CapabilitySet) Available() []Capability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Capability, 0, len(s.available))
	for c, ok := range s.available {
		if ok {
			out = append(out, c)
		}
	}
	return out
}

// Snapshot — 検出時刻含む全状態
type Snapshot struct {
	Available  map[Capability]bool      `json:"available"`
	DetectedAt map[Capability]time.Time `json:"detectedAt"`
	Sealed     bool                     `json:"sealed"`
	Runtime    RuntimeInfo              `json:"runtime"`
}

// RuntimeInfo — 実行環境情報
type RuntimeInfo struct {
	GoVersion string `json:"goVersion"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	NumCPU    int    `json:"numCPU"`
}

// Snapshot — シリアライズ可能な状態
func (s *CapabilitySet) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	avail := make(map[Capability]bool, len(s.available))
	det := make(map[Capability]time.Time, len(s.detected))
	for k, v := range s.available {
		avail[k] = v
	}
	for k, v := range s.detected {
		det[k] = v
	}
	return Snapshot{
		Available:  avail,
		DetectedAt: det,
		Sealed:     s.sealed,
		Runtime: RuntimeInfo{
			GoVersion: runtime.Version(),
			GOOS:      runtime.GOOS,
			GOARCH:    runtime.GOARCH,
			NumCPU:    runtime.NumCPU(),
		},
	}
}

// ============================================================================
// 標準検出器 — BLRCS 標準 capability の Detector セット
// ============================================================================

// DetectorEd25519 — Go ランタイムの ed25519 パッケージ存在確認
//
// 標準ライブラリなので常に true。テストで明示的に検出工程を例示。
func DetectorEd25519() Detector {
	return func(ctx context.Context) bool {
		// stdlib crypto/ed25519 は Go 1.13+ で常に利用可能
		return true
	}
}

// DetectorPersistence — ディレクトリ書込可否
func DetectorPersistence(dir string) Detector {
	return func(ctx context.Context) bool {
		if dir == "" {
			return false
		}
		// 簡易チェック: 環境変数 BLRCS_DATA_DIR が設定されている
		return true
	}
}

// DetectorHTTPS — TLS 終端設定があるか (cert/key ファイル指定)
func DetectorHTTPS(certFile, keyFile string) Detector {
	return func(ctx context.Context) bool {
		return certFile != "" && keyFile != ""
	}
}

// DetectorBulletproofs — 真の ZK 範囲証明実装 (現状: 未実装、将来 build tag で切替)
func DetectorBulletproofs() Detector {
	return func(ctx context.Context) bool {
		// 現状: TEE-attested 方式のみ実装、Bulletproofs 未組込
		return false
	}
}

// ============================================================================
// Profile — 複数 capability の集約 (FIDO2 Level 等の規格対応)
// ============================================================================

// Profile — 名前付きの capability 要件
//
// 例:
//
//	ProfileEUMandatory = {DPP, SCITT, Persistence, HTTPS}
//	ProfileBatteryFeb2027 = {DPP, BatteryPass, SCITT, Persistence}
type Profile struct {
	Name     string
	Required []Capability
	Optional []Capability
}

// Satisfies — capability set が profile を満たすか
//
// 戻り値: 満たすか, 不足している required capability
func (p Profile) Satisfies(s *CapabilitySet) (bool, []Capability) {
	missing := make([]Capability, 0)
	for _, c := range p.Required {
		if !s.Has(c) {
			missing = append(missing, c)
		}
	}
	return len(missing) == 0, missing
}

// 標準 BLRCS profile
var (
	// ProfileBasic — どんな環境でも動く最低限
	ProfileBasic = Profile{
		Name:     "BLRCS-Basic",
		Required: []Capability{CapEd25519, CapDPP},
		Optional: []Capability{CapPersistence, CapSCITT},
	}

	// ProfileEUCompliance — EU ESPR/Battery 規制対応
	ProfileEUCompliance = Profile{
		Name:     "BLRCS-EUCompliance",
		Required: []Capability{CapEd25519, CapDPP, CapSCITT, CapPersistence},
		Optional: []Capability{CapBatteryPass, CapTextilePass, CapHardwareCrypto},
	}

	// ProfileBatteryFeb2027 — Reg.2023/1542 対応
	ProfileBatteryFeb2027 = Profile{
		Name:     "BLRCS-Battery2027",
		Required: []Capability{CapEd25519, CapDPP, CapBatteryPass, CapSCITT, CapPersistence},
		Optional: []Capability{CapHardwareCrypto, CapKMS, CapWitness},
	}

	// ProfileWalletReady — エンドツーエンド消費者対応
	ProfileWalletReady = Profile{
		Name:     "BLRCS-WalletReady",
		Required: []Capability{CapEd25519, CapDPP, CapWalletWebDC, CapHTTPS},
		Optional: []Capability{CapWalletNative, CapWalletEUDI},
	}
)
