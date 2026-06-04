// Package privacy — BLRCS プライバシーマニフェスト
//
// Apple の PrivacyInfo.xcprivacy (iOS 17 / Xcode 15 要件) を参考に設計。
// 機能:
//  1. PrivacyManifest — アプリが触るデータカテゴリと目的の機械可読宣言
//  2. DataLineage — 操作ごとに「どのデータに触ったか」を追跡 (GDPR Art.30 記録義務)
//  3. MinimizationGuard — 不必要なフィールドへのアクセスをブロック
//
// Apple の PrivacyInfo.xcprivacy の構造を Go 構造体に写像:
//
//	NSPrivacyAccessedAPITypes → AccessedAPIs
//	NSPrivacyCollectedDataTypes → CollectedData
//	NSPrivacyTrackingDomains → TrackingDomains (BLRCS: 送信先ドメイン)
//
// 規制対応:
//   - GDPR Article 30 (処理活動の記録)
//   - EU ESPR Article 9 (DPP プライバシー要件)
//   - CCPA Section 1798.100 (消費者の知る権利)
package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// Data Categories — Apple NSPrivacyCollectedDataTypes 相当
// ============================================================================

// DataCategory — データカテゴリ (Apple の Data type 定義に準拠)
type DataCategory string

const (
	// Product data (DPP core)
	DataCategoryProductID      DataCategory = "product.identifier" // GTIN, EPC
	DataCategoryProductCarbon  DataCategory = "product.carbon"     // 炭素フットプリント
	DataCategoryProductOrigin  DataCategory = "product.origin"     // 原産国
	DataCategoryProductRecycle DataCategory = "product.recyclability"

	// Supplier / supply chain
	DataCategorySupplierName DataCategory = "supplier.name" // 取引先名称
	DataCategorySupplierDID  DataCategory = "supplier.did"  // DID (公開可能)
	DataCategoryBOMDetail    DataCategory = "bom.detail"    // 部品表 (機密)

	// Sensor / IoT
	DataCategorySensorReading DataCategory = "sensor.reading" // 温度/湿度等 (ZK後は非公開)
	DataCategorySensorID      DataCategory = "sensor.id"      // センサ DID

	// User / holder
	DataCategoryHolderDID    DataCategory = "holder.did"
	DataCategoryHolderWallet DataCategory = "holder.wallet" // ウォレット識別子

	// Cryptographic
	DataCategoryPublicKey DataCategory = "crypto.public_key" // 公開鍵 (public)
	DataCategorySignature DataCategory = "crypto.signature"  // 署名バイト (public)
	DataCategoryProof     DataCategory = "crypto.proof"      // ZK証明
)

// CollectionPurpose — 収集目的 (GDPR 6条 法的根拠と対応)
type CollectionPurpose string

const (
	PurposeCompliance  CollectionPurpose = "regulatory_compliance" // ESPR/バッテリー法
	PurposeAudit       CollectionPurpose = "audit_trail"           // 不変監査
	PurposeVerify      CollectionPurpose = "credential_verification"
	PurposeSupplyChain CollectionPurpose = "supply_chain_transparency"
	PurposeSecurity    CollectionPurpose = "security"
)

// DataDeclaration — データカテゴリ × 目的 × プライバシー属性
type DataDeclaration struct {
	Category        DataCategory        `json:"category"`
	Purposes        []CollectionPurpose `json:"purposes"`
	LinkedToUser    bool                `json:"linkedToUser"`    // Apple: Linked to Identity
	UsedForTracking bool                `json:"usedForTracking"` // Apple: Used for Tracking
	Minimized       bool                `json:"minimized"`       // ZK等で最小化済み
	Retention       string              `json:"retention"`       // "session" | "7days" | "permanent"
	LegalBasis      string              `json:"legalBasis"`      // GDPR Art.6 根拠
}

// ============================================================================
// Manifest — 機械可読プライバシー宣言
// ============================================================================

// Manifest — BLRCS プライバシーマニフェスト (Apple PrivacyInfo.xcprivacy 相当)
//
// /.well-known/privacy.json で公開することで:
//   - Apple App Store レビュー相当の自動チェック可能
//   - GDPR Art.30 処理活動記録の機械可読版
//   - EU ESPR デジタル透明性要件への対応
type Manifest struct {
	SpecVersion string    `json:"specVersion"` // "1.0"
	ProductName string    `json:"product"`
	Version     string    `json:"version"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Controller  string    `json:"controller"` // データ管理者 DID
	Processor   string    `json:"processor,omitempty"`

	// 宣言
	CollectedData []DataDeclaration `json:"collectedData"`
	ThirdParties  []ThirdParty      `json:"thirdParties,omitempty"`
	APIAccess     []APIAccess       `json:"apiAccess,omitempty"`

	// ユーザー権利
	SubjectRights SubjectRights `json:"subjectRights"`
}

// ThirdParty — データ送信先 (Apple NSPrivacyTrackingDomains 相当)
type ThirdParty struct {
	Name     string   `json:"name"`
	Domain   string   `json:"domain"`
	Purpose  string   `json:"purpose"`
	DataSent []string `json:"dataSent"`
}

// APIAccess — 使用するシステムAPI (Apple NSPrivacyAccessedAPITypes 相当)
type APIAccess struct {
	API     string   `json:"api"` // "crypto.randomBytes" | "clock.now" 等
	Purpose []string `json:"purpose"`
}

// SubjectRights — GDPR 権利フィールド
type SubjectRights struct {
	ContactEmail string `json:"contactEmail"`
	DPOContact   string `json:"dpoContact,omitempty"`
	RequestURL   string `json:"requestUrl"`
	ResponseDays int    `json:"responseDays"` // GDPR 30日要件
}

// BLRCSDefaultManifest — BLRCS の標準マニフェスト
func BLRCSDefaultManifest(controllerDID, version string) *Manifest {
	return &Manifest{
		SpecVersion: "1.0",
		ProductName: "BLRCS",
		Version:     version,
		UpdatedAt:   time.Now().UTC(),
		Controller:  controllerDID,
		CollectedData: []DataDeclaration{
			{
				Category:        DataCategoryProductID,
				Purposes:        []CollectionPurpose{PurposeCompliance, PurposeAudit},
				LinkedToUser:    false,
				UsedForTracking: false,
				Minimized:       false,
				Retention:       "permanent",
				LegalBasis:      "GDPR Art.6(1)(c) - Legal obligation (ESPR)",
			},
			{
				Category:        DataCategoryProductCarbon,
				Purposes:        []CollectionPurpose{PurposeCompliance, PurposeSupplyChain},
				LinkedToUser:    false,
				UsedForTracking: false,
				Retention:       "permanent",
				LegalBasis:      "GDPR Art.6(1)(c)",
			},
			{
				Category:        DataCategorySupplierName,
				Purposes:        []CollectionPurpose{PurposeCompliance},
				LinkedToUser:    false,
				UsedForTracking: false,
				Minimized:       true, // SD-JWT で選択開示
				Retention:       "permanent",
				LegalBasis:      "GDPR Art.6(1)(c)",
			},
			{
				Category:        DataCategorySensorReading,
				Purposes:        []CollectionPurpose{PurposeAudit, PurposeCompliance},
				LinkedToUser:    false,
				UsedForTracking: false,
				Minimized:       true, // ZK range proof で値非公開
				Retention:       "permanent",
				LegalBasis:      "GDPR Art.6(1)(c)",
			},
			{
				Category:        DataCategoryHolderDID,
				Purposes:        []CollectionPurpose{PurposeVerify},
				LinkedToUser:    true,
				UsedForTracking: false,
				Minimized:       true, // holder binding optional
				Retention:       "session",
				LegalBasis:      "GDPR Art.6(1)(a) - Consent",
			},
			{
				Category:        DataCategoryPublicKey,
				Purposes:        []CollectionPurpose{PurposeSecurity, PurposeVerify},
				LinkedToUser:    false,
				UsedForTracking: false,
				Retention:       "permanent",
				LegalBasis:      "GDPR Art.6(1)(c)",
			},
		},
		APIAccess: []APIAccess{
			{API: "crypto.ed25519", Purpose: []string{"credential signing", "verification"}},
			{API: "crypto.sha256", Purpose: []string{"merkle tree", "commitment"}},
			{API: "clock.now", Purpose: []string{"credential issuance timestamp"}},
			{API: "random.bytes", Purpose: []string{"nonce generation", "salt for SD-JWT"}},
		},
		SubjectRights: SubjectRights{
			RequestURL:   "/.well-known/privacy/requests",
			ResponseDays: 30,
		},
	}
}

// JSON — /.well-known/privacy.json 用の出力
func (m *Manifest) JSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// ============================================================================
// DataLineage — 操作ごとのデータアクセス記録 (GDPR Art.30 自動化)
// ============================================================================

// AccessRecord — 1つのデータアクセス記録
type AccessRecord struct {
	Timestamp  time.Time      `json:"ts"`
	Operation  string         `json:"op"`
	Categories []DataCategory `json:"categories"`
	Principal  string         `json:"principal,omitempty"` // 誰が
	Subject    string         `json:"subject,omitempty"`   // 何について
}

// Tracker — コンテキスト経由で操作に紐付くデータアクセス追跡
type Tracker struct {
	mu      sync.Mutex
	records []AccessRecord
}

type contextKey struct{}

// WithTracker — context に Tracker を attach
func WithTracker(ctx context.Context, t *Tracker) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

// TrackerFromContext — context から Tracker を取り出す (nil safe)
func TrackerFromContext(ctx context.Context) *Tracker {
	t, _ := ctx.Value(contextKey{}).(*Tracker)
	return t
}

// Record — データアクセスを記録
func Record(ctx context.Context, op string, cats ...DataCategory) {
	t := TrackerFromContext(ctx)
	if t == nil {
		return
	}
	t.mu.Lock()
	t.records = append(t.records, AccessRecord{
		Timestamp:  time.Now().UTC(),
		Operation:  op,
		Categories: cats,
	})
	t.mu.Unlock()
}

// Records — 記録されたアクセス一覧 (GDPR Art.30 レポート用)
func (t *Tracker) Records() []AccessRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]AccessRecord, len(t.records))
	copy(cp, t.records)
	return cp
}

// CategoriesAccessed — 操作で触ったカテゴリの一意集合
func (t *Tracker) CategoriesAccessed() []DataCategory {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := make(map[DataCategory]bool)
	for _, r := range t.records {
		for _, c := range r.Categories {
			seen[c] = true
		}
	}
	out := make([]DataCategory, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	return out
}

// ============================================================================
// MinimizationGuard — 必要最小限チェック (Apple Privacy NutritionLabel の実装側)
// ============================================================================

// ErrMinimization — 必要最小限違反
var ErrMinimization = errors.New("privacy: data minimization violation")

// AllowedCategories — 操作名 → 許可データカテゴリ のポリシーマップ
type AllowedCategories map[string][]DataCategory

// Guard — データアクセスが宣言ポリシーの範囲内かをチェック
type Guard struct {
	policy AllowedCategories
}

// NewGuard — ポリシー設定で Guard を構築
func NewGuard(policy AllowedCategories) *Guard {
	return &Guard{policy: policy}
}

// Check — 操作がカテゴリへのアクセスを許可されているか
func (g *Guard) Check(op string, cats ...DataCategory) error {
	allowed, ok := g.policy[op]
	if !ok {
		return fmt.Errorf("%w: operation %q not declared", ErrMinimization, op)
	}
	allowedSet := make(map[DataCategory]bool)
	for _, a := range allowed {
		allowedSet[a] = true
	}
	for _, c := range cats {
		if !allowedSet[c] {
			return fmt.Errorf("%w: op %q accessing undeclared category %q", ErrMinimization, op, c)
		}
	}
	return nil
}

// BLRCSDefaultPolicy — BLRCS 標準ポリシー
var BLRCSDefaultPolicy = AllowedCategories{
	"compliance.IssueDPP": {
		DataCategoryProductID, DataCategoryProductCarbon,
		DataCategoryProductOrigin, DataCategoryProductRecycle,
		DataCategoryPublicKey, DataCategorySignature,
	},
	"compliance.IssueSDJWT": {
		DataCategoryProductID, DataCategoryProductCarbon,
		DataCategorySupplierName, DataCategoryBOMDetail,
		DataCategoryPublicKey, DataCategorySignature,
	},
	"compliance.RangeAttest": {
		DataCategorySensorReading, DataCategorySensorID,
		DataCategoryProof,
	},
	"scitt.Register": {
		DataCategoryProductID, DataCategoryPublicKey,
		DataCategorySignature,
	},
	"openid4vp.Verify": {
		DataCategoryHolderDID, DataCategoryPublicKey,
		DataCategorySignature,
	},
}
