// Package builder — DPP / Battery Passport のフルエント型セーフ構築
//
// Apple 設計思想: URLComponents, URLRequest, NSMutableURLRequest の設計
//   - フルエント API: builder.SetCarbonKgCO2e(...).SetCategory(...).Build()
//   - 中間状態は typed、stringly-typed 禁止
//   - Build() で全バリデーション、パーシャルビルドは不可
//   - デフォルト値は sensible (validFor = 1 year)
//
// 使用例:
//
//	cred, err := builder.NewDPP().
//	    Issuer(issuerDID).
//	    ProductID(gtin).
//	    Category("textile/garment").
//	    OriginCountry(jpCode).
//	    Carbon(carbon).
//	    Recyclability(recycled).
//	    ValidFor(365 * 24 * time.Hour).
//	    Build(issuer)
package builder

import (
	"strconv"
	"time"

	"blrcs/compliance"
	"blrcs/types"
)

// ============================================================================
// DPP Builder — EU ESPR Digital Product Passport
// ============================================================================

// DPPBuilder — EU Digital Product Passport 構築
// Apple URLComponents: 各フィールドを独立メソッドで設定、Build で最終化
type DPPBuilder struct {
	issuerID       types.DID
	productID      types.GTIN
	category       string
	originCountry  types.CountryCode
	carbon         types.CarbonFootprint
	recyclability  types.Percent
	hazardous      []string
	lifecyclePhase string
	validFor       time.Duration
	attrs          map[string]string
	errs           []string // accumulated validation issues
}

// NewDPP — DPP Builder を作成
func NewDPP() *DPPBuilder {
	return &DPPBuilder{
		lifecyclePhase: "manufacture",
		validFor:       365 * 24 * time.Hour, // sensible default: 1 year
		attrs:          make(map[string]string),
	}
}

// Issuer — 発行者 DID を設定
func (b *DPPBuilder) Issuer(did types.DID) *DPPBuilder {
	b.issuerID = did
	return b
}

// ProductID — GTIN-14 (検証済み)
func (b *DPPBuilder) ProductID(g types.GTIN) *DPPBuilder {
	b.productID = g
	return b
}

// Category — EU製品カテゴリコード (例: "textile/garment", "electronics/smartphone")
func (b *DPPBuilder) Category(c string) *DPPBuilder {
	b.category = c
	return b
}

// OriginCountry — ISO 3166-1 alpha-2 (検証済み)
func (b *DPPBuilder) OriginCountry(cc types.CountryCode) *DPPBuilder {
	b.originCountry = cc
	return b
}

// Carbon — 炭素フットプリント (非負保証)
func (b *DPPBuilder) Carbon(c types.CarbonFootprint) *DPPBuilder {
	b.carbon = c
	return b
}

// Recyclability — リサイクル率 0..100% (範囲保証)
func (b *DPPBuilder) Recyclability(p types.Percent) *DPPBuilder {
	b.recyclability = p
	return b
}

// Hazardous — EU REACH 規制有害物質 (RoHS, SVHC等)
func (b *DPPBuilder) Hazardous(substances ...string) *DPPBuilder {
	b.hazardous = append(b.hazardous, substances...)
	return b
}

// LifecyclePhase — "raw" | "manufacture" | "distribution" | "use" | "eol"
func (b *DPPBuilder) LifecyclePhase(phase string) *DPPBuilder {
	valid := map[string]bool{"raw": true, "manufacture": true, "distribution": true, "use": true, "eol": true}
	if !valid[phase] {
		b.errs = append(b.errs, "lifecyclePhase must be one of: raw|manufacture|distribution|use|eol, got: "+phase)
		return b
	}
	b.lifecyclePhase = phase
	return b
}

// ValidFor — 有効期間 (ゼロで無期限)
func (b *DPPBuilder) ValidFor(d time.Duration) *DPPBuilder {
	b.validFor = d
	return b
}

// Attr — 拡張属性 (追加フィールド)
func (b *DPPBuilder) Attr(key, value string) *DPPBuilder {
	b.attrs[key] = value
	return b
}

// Build — 全バリデーション後に W3C VC を発行
// Apple: Build パターンでは成功か完全失敗、半分構築状態は存在しない
func (b *DPPBuilder) Build(issuer *compliance.Issuer) (*compliance.Credential, error) {
	// 積算エラーを最初に確認
	if len(b.errs) > 0 {
		return nil, buildError(b.errs)
	}
	// 必須フィールド検証
	if b.productID.IsZero() {
		return nil, buildError([]string{"ProductID (GTIN) required — use ProductID(gtin)"})
	}
	if b.issuerID.IsZero() {
		return nil, buildError([]string{"Issuer DID required — use Issuer(did)"})
	}
	if b.category == "" {
		return nil, buildError([]string{"Category required — use Category(code)"})
	}

	claim := compliance.PassportClaim{
		ProductID:        b.productID.String(),
		Category:         b.category,
		OriginCountry:    b.originCountry.String(),
		Manufacturer:     b.issuerID.String(),
		CarbonKgCO2e:     b.carbon.KgCO2e(),
		Recyclability:    float32(b.recyclability.Value() / 100),
		HazardousContent: b.hazardous,
		LifecyclePhase:   b.lifecyclePhase,
		Attrs:            b.attrs,
	}
	return issuer.Issue(claim, b.validFor)
}

// ============================================================================
// Battery Builder — EU Battery Regulation 2023/1542
// ============================================================================

// BatteryBuilder — Regulation 2023/1542 電池パスポート構築
type BatteryBuilder struct {
	batteryID       string
	gtin            types.GTIN
	serialNo        string
	category        compliance.BatteryCategory
	chemistry       compliance.BatteryChemistry
	capacity        float32 // kWh
	voltage         float32 // V
	weightKg        float32
	place           string
	modelID         string
	dateOfMfr       time.Time
	carbon          types.CarbonFootprint // per kWh
	cfClass         string
	recycled        compliance.RecycledContent
	hazardous       []string
	soh             float32 // state of health %
	cycleCount      int
	validFor        time.Duration
	dueDiligenceURL string
	euDoCURL        string
	renewablePct    float32
	lifetimeYears   float32
	separateCollect bool
	errs            []string
}

// NewBattery — Battery Passport Builder
func NewBattery() *BatteryBuilder {
	return &BatteryBuilder{validFor: 10 * 365 * 24 * time.Hour} // 10 years default
}

func (b *BatteryBuilder) BatteryID(id string) *BatteryBuilder { b.batteryID = id; return b }
func (b *BatteryBuilder) GTIN(g types.GTIN) *BatteryBuilder   { b.gtin = g; return b }
func (b *BatteryBuilder) Serial(s string) *BatteryBuilder     { b.serialNo = s; return b }
func (b *BatteryBuilder) Category(c compliance.BatteryCategory) *BatteryBuilder {
	b.category = c
	return b
}
func (b *BatteryBuilder) Chemistry(c compliance.BatteryChemistry) *BatteryBuilder {
	b.chemistry = c
	return b
}
func (b *BatteryBuilder) CapacityKWh(v float32) *BatteryBuilder         { b.capacity = v; return b }
func (b *BatteryBuilder) VoltageV(v float32) *BatteryBuilder            { b.voltage = v; return b }
func (b *BatteryBuilder) WeightKg(v float32) *BatteryBuilder            { b.weightKg = v; return b }
func (b *BatteryBuilder) PlaceOfManufacture(p string) *BatteryBuilder   { b.place = p; return b }
func (b *BatteryBuilder) ModelID(m string) *BatteryBuilder              { b.modelID = m; return b }
func (b *BatteryBuilder) DateOfManufacture(d time.Time) *BatteryBuilder { b.dateOfMfr = d; return b }
func (b *BatteryBuilder) ValidFor(d time.Duration) *BatteryBuilder      { b.validFor = d; return b }
func (b *BatteryBuilder) StateOfHealth(pct float32) *BatteryBuilder     { b.soh = pct; return b }
func (b *BatteryBuilder) CycleCount(n int) *BatteryBuilder              { b.cycleCount = n; return b }

// CarbonIntensity — kg CO2e per kWh (cradle-to-gate)
func (b *BatteryBuilder) CarbonIntensity(c types.CarbonFootprint) *BatteryBuilder {
	b.carbon = c
	return b
}

// CarbonClass — EU Label A-G (optional)
func (b *BatteryBuilder) CarbonClass(class string) *BatteryBuilder {
	validClasses := map[string]bool{"A": true, "B": true, "C": true, "D": true, "E": true, "F": true, "G": true}
	if class != "" && !validClasses[class] {
		b.errs = append(b.errs, "CarbonClass must be A-G, got: "+class)
		return b
	}
	b.cfClass = class
	return b
}

// RecycledContent — EU必須開示: 各材料のリサイクル含有率 (0-100%)
func (b *BatteryBuilder) RecycledContent(cobalt, lithium, nickel, lead float32) *BatteryBuilder {
	for _, v := range []float32{cobalt, lithium, nickel, lead} {
		if v < 0 || v > 100 {
			b.errs = append(b.errs, "RecycledContent percentages must be 0-100")
			return b
		}
	}
	b.recycled = compliance.RecycledContent{Cobalt: cobalt, Lithium: lithium, Nickel: nickel, Lead: lead}
	return b
}

// Build — 全バリデーション後に Battery Passport VC を発行
// DueDiligenceReport — Art.52 デューデリジェンス報告 URL (EV/産業用で必須)
func (b *BatteryBuilder) DueDiligenceReport(url string) *BatteryBuilder {
	b.dueDiligenceURL = url
	return b
}

// EUDeclarationOfConformity — Art.6 適合宣言 URL
func (b *BatteryBuilder) EUDeclarationOfConformity(url string) *BatteryBuilder {
	b.euDoCURL = url
	return b
}

// RenewableContent — Art.7 再生可能エネルギー由来割合 (%)
func (b *BatteryBuilder) RenewableContent(pct float32) *BatteryBuilder {
	b.renewablePct = pct
	return b
}

// ExpectedLifetime — Annex XIII §4 期待寿命 (年)
func (b *BatteryBuilder) ExpectedLifetime(years float32) *BatteryBuilder {
	b.lifetimeYears = years
	return b
}

// SeparateCollection — Art.13 分別回収シンボル該当
func (b *BatteryBuilder) SeparateCollection(v bool) *BatteryBuilder {
	b.separateCollect = v
	return b
}

func (b *BatteryBuilder) Build(issuer *compliance.Issuer) (*compliance.Credential, error) {
	if len(b.errs) > 0 {
		return nil, buildError(b.errs)
	}
	if b.batteryID == "" {
		return nil, buildError([]string{"BatteryID required"})
	}
	if b.category == "" {
		return nil, buildError([]string{"Category required (ev/lmt/industrial/sli/portable)"})
	}
	if b.chemistry == "" {
		return nil, buildError([]string{"Chemistry required"})
	}
	if b.capacity <= 0 {
		return nil, buildError([]string{"CapacityKWh must be > 0"})
	}
	claim := compliance.BatteryPassportClaim{
		BatteryID:                    b.batteryID,
		GTIN:                         b.gtin.String(),
		SerialNo:                     b.serialNo,
		Category:                     b.category,
		Chemistry:                    b.chemistry,
		CapacityKWh:                  b.capacity,
		VoltageV:                     b.voltage,
		WeightKg:                     b.weightKg,
		PlaceOfMfr:                   b.place,
		ModelID:                      b.modelID,
		DateOfMfr:                    b.dateOfMfr,
		Manufacturer:                 issuer.ID,
		CarbonFootprintKgCO2ePerKWh:  float32(b.carbon.KgCO2e()),
		CarbonFootprintClass:         b.cfClass,
		RecycledContent:              b.recycled,
		HazardousSubstances:          b.hazardous,
		StateOfHealthPct:             b.soh,
		CycleCount:                   b.cycleCount,
		RenewableContentPct:          b.renewablePct,
		ExpectedLifetimeYears:        b.lifetimeYears,
		EUDeclarationOfConformityURL: b.euDoCURL,
		DueDiligenceReportURL:        b.dueDiligenceURL,
		SeparateCollection:           b.separateCollect,
		Recyclable:                   true,
	}
	return issuer.IssueBatteryPassport(claim, b.validFor)
}

// ============================================================================
// Error accumulation — Apple Error Accumulation Pattern
// ============================================================================

// BuildValidationError — 複数フィールドエラーを1エラーに集約
// Apple: フォームバリデーションでは全エラーを一度に返す (1つ直したら別エラー、は悪いUX)
type BuildValidationError struct {
	Issues []string
}

func (e *BuildValidationError) Error() string {
	if len(e.Issues) == 1 {
		return "builder: " + e.Issues[0]
	}
	out := "builder: " + strconv.Itoa(len(e.Issues)) + " validation errors:\n"
	for _, issue := range e.Issues {
		out += "  • " + issue + "\n"
	}
	return out
}

func buildError(issues []string) *BuildValidationError {
	return &BuildValidationError{Issues: issues}
}
