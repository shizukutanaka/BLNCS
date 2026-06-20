// Package types — BLRCS の強型ドメインプリミティブ
//
// 哲学: "Make invalid states unrepresentable" (Yaron Minsky, Apple Swift teamに引用される)
//
// Apple SDK での例:
//   - URL は string ではない (init?(string:) がfail可能)
//   - Date は double ではない (TimeInterval / Date分離)
//   - Locale は識別子検証付き
//
// 本パッケージはBLRCS全体で使う基本値型を提供。
// すべて生成時に検証、生成成功 = invariant 保証。
package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// DID — Decentralized Identifier
// ============================================================================

// DID — W3C DID Core 1.0 準拠の識別子
//
// 例: did:web:example.com, did:key:z6Mk..., did:jwk:eyJ...
//
// 不正な DID は構築不可: NewDID() が失敗する
type DID struct {
	value string
}

// NewDID — DID 検証付き構築
func NewDID(s string) (DID, error) {
	if s == "" {
		return DID{}, errors.New("did: empty")
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 3 {
		return DID{}, fmt.Errorf("did: must have 3 parts (did:method:id), got %d in %q", len(parts), s)
	}
	if parts[0] != "did" {
		return DID{}, fmt.Errorf("did: must start with 'did:', got %q", parts[0])
	}
	if parts[1] == "" {
		return DID{}, errors.New("did: method missing")
	}
	if parts[2] == "" {
		return DID{}, errors.New("did: identifier missing")
	}
	// Method validation (sample — supported methods registered)
	switch parts[1] {
	case "web", "key", "jwk", "ion", "ebsi", "indy":
		// ok
	default:
		// 未知 method を即時拒否しない (拡張性)、警告レベル相当
	}
	return DID{value: s}, nil
}

// MustDID — テスト/初期化用、失敗時panic
func MustDID(s string) DID {
	d, err := NewDID(s)
	if err != nil {
		panic("MustDID: " + err.Error())
	}
	return d
}

func (d DID) String() string { return d.value }
func (d DID) IsZero() bool   { return d.value == "" }

// Method — DID method (web, key, jwk...)
func (d DID) Method() string {
	parts := strings.SplitN(d.value, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// Identifier — method-specific 識別子部分
func (d DID) Identifier() string {
	parts := strings.SplitN(d.value, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// MarshalJSON / UnmarshalJSON — JSON互換
func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.value)
}

func (d *DID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("did: %w", err)
	}
	got, err := NewDID(s)
	if err != nil {
		return err
	}
	*d = got
	return nil
}

// ============================================================================
// GTIN — Global Trade Item Number (8/12/13/14 normalized to 14)
// ============================================================================

// GTIN — 14桁正規化済み GS1 GTIN、check digit 検証済み
type GTIN struct {
	value string // 14 digits
}

// NewGTIN — 8/12/13/14桁を受け、14桁に正規化、Mod-10検証
func NewGTIN(s string) (GTIN, error) {
	s = strings.TrimSpace(s)
	for _, c := range s {
		if c < '0' || c > '9' {
			return GTIN{}, fmt.Errorf("gtin: non-digit %q", c)
		}
	}
	switch len(s) {
	case 8, 12, 13, 14:
	default:
		return GTIN{}, fmt.Errorf("gtin: length %d (must be 8/12/13/14)", len(s))
	}
	for len(s) < 14 {
		s = "0" + s
	}
	if !verifyMod10(s) {
		return GTIN{}, errors.New("gtin: check digit invalid")
	}
	return GTIN{value: s}, nil
}

// MustGTIN — テスト用
func MustGTIN(s string) GTIN {
	g, err := NewGTIN(s)
	if err != nil {
		panic("MustGTIN: " + err.Error())
	}
	return g
}

func (g GTIN) String() string { return g.value }
func (g GTIN) IsZero() bool   { return g.value == "" }

func (g GTIN) MarshalJSON() ([]byte, error) { return []byte(`"` + g.value + `"`), nil }
func (g *GTIN) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return errors.New("gtin: not a JSON string")
	}
	got, err := NewGTIN(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	*g = got
	return nil
}

func verifyMod10(g14 string) bool {
	if len(g14) != 14 {
		return false
	}
	sum := 0
	for i := 0; i < 13; i++ {
		d := int(g14[i] - '0')
		// rightmost data digit (pos 13) ×3, alternating
		if (13-i)%2 == 1 {
			sum += d * 3
		} else {
			sum += d
		}
	}
	check := (10 - (sum % 10)) % 10
	actual := int(g14[13] - '0')
	return check == actual
}

// ============================================================================
// CountryCode — ISO 3166-1 alpha-2
// ============================================================================

// CountryCode — 2文字の ISO 3166-1 国コード
type CountryCode struct {
	value string // 2-char uppercase
}

// validCountries — 主要なISO 3166-1 alpha-2 (網羅ではなく、無効値の早期検出が目的)
// 完全リストは外部 i18n パッケージで提供推奨
var validCountries = map[string]bool{
	"JP": true, "US": true, "DE": true, "FR": true, "IT": true, "ES": true,
	"NL": true, "BE": true, "GB": true, "IE": true, "CH": true, "AT": true,
	"SE": true, "NO": true, "FI": true, "DK": true, "PL": true, "CZ": true,
	"PT": true, "GR": true, "RO": true, "HU": true, "BG": true, "HR": true,
	"SI": true, "SK": true, "LT": true, "LV": true, "EE": true, "MT": true,
	"CY": true, "LU": true, "IS": true, "LI": true,
	"CN": true, "KR": true, "TW": true, "HK": true, "SG": true, "TH": true,
	"VN": true, "MY": true, "PH": true, "ID": true, "IN": true,
	"CA": true, "MX": true, "BR": true, "AR": true, "CL": true, "CO": true,
	"AU": true, "NZ": true, "ZA": true, "EG": true, "AE": true, "SA": true,
	"IL": true, "TR": true, "RU": true, "UA": true,
}

// NewCountryCode — ISO 3166-1 alpha-2 検証付き
// 大文字小文字を吸収、内部は大文字
func NewCountryCode(s string) (CountryCode, error) {
	if len(s) != 2 {
		return CountryCode{}, fmt.Errorf("country: alpha-2 expected, got %q (length %d)", s, len(s))
	}
	upper := strings.ToUpper(s)
	for _, c := range upper {
		if c < 'A' || c > 'Z' {
			return CountryCode{}, fmt.Errorf("country: non-alpha %q", s)
		}
	}
	if !validCountries[upper] {
		return CountryCode{}, fmt.Errorf("country: unknown ISO code %q (extend validCountries if legitimate)", upper)
	}
	return CountryCode{value: upper}, nil
}

func MustCountryCode(s string) CountryCode {
	c, err := NewCountryCode(s)
	if err != nil {
		panic("MustCountryCode: " + err.Error())
	}
	return c
}

func (c CountryCode) String() string { return c.value }
func (c CountryCode) IsZero() bool   { return c.value == "" }

func (c CountryCode) MarshalJSON() ([]byte, error) { return []byte(`"` + c.value + `"`), nil }
func (c *CountryCode) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return errors.New("country: not a JSON string")
	}
	got, err := NewCountryCode(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	*c = got
	return nil
}

// ============================================================================
// CarbonFootprint — kg CO2-equivalent (non-negative)
// ============================================================================

// CarbonFootprint — 炭素足跡 (kg CO2e), 非負保証
type CarbonFootprint struct {
	kgCO2e float64
}

func NewCarbonFootprint(kg float64) (CarbonFootprint, error) {
	// NaN/Inf slip past < / > comparisons, defeating the non-negativity invariant.
	if math.IsNaN(kg) || math.IsInf(kg, 0) {
		return CarbonFootprint{}, fmt.Errorf("carbon: not a finite number")
	}
	if kg < 0 {
		return CarbonFootprint{}, fmt.Errorf("carbon: negative %f", kg)
	}
	if kg > 1e12 {
		return CarbonFootprint{}, fmt.Errorf("carbon: implausibly large %f", kg)
	}
	return CarbonFootprint{kgCO2e: kg}, nil
}

func MustCarbonFootprint(kg float64) CarbonFootprint {
	c, err := NewCarbonFootprint(kg)
	if err != nil {
		panic("MustCarbonFootprint: " + err.Error())
	}
	return c
}

func (c CarbonFootprint) KgCO2e() float64 { return c.kgCO2e }
func (c CarbonFootprint) IsZero() bool    { return c.kgCO2e == 0 }
func (c CarbonFootprint) String() string {
	return strconv.FormatFloat(c.kgCO2e, 'f', 4, 64) + " kgCO2e"
}

func (c CarbonFootprint) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(c.kgCO2e, 'f', -1, 64)), nil
}

func (c *CarbonFootprint) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("carbon: parse: %w", err)
	}
	got, err := NewCarbonFootprint(v)
	if err != nil {
		return err
	}
	*c = got
	return nil
}

// ============================================================================
// Percent — 0..100 inclusive
// ============================================================================

// Percent — 0..100 範囲の百分率
type Percent struct {
	v float64
}

func NewPercent(v float64) (Percent, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return Percent{}, fmt.Errorf("percent: not a finite number")
	}
	if v < 0 || v > 100 {
		return Percent{}, fmt.Errorf("percent: %f out of [0..100]", v)
	}
	return Percent{v: v}, nil
}

func MustPercent(v float64) Percent {
	p, err := NewPercent(v)
	if err != nil {
		panic("MustPercent: " + err.Error())
	}
	return p
}

func (p Percent) Value() float64 { return p.v }
func (p Percent) IsZero() bool   { return p.v == 0 }
func (p Percent) String() string { return strconv.FormatFloat(p.v, 'f', 2, 64) + "%" }

func (p Percent) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(p.v, 'f', -1, 64)), nil
}

func (p *Percent) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("percent: parse: %w", err)
	}
	got, err := NewPercent(v)
	if err != nil {
		return err
	}
	*p = got
	return nil
}

// ============================================================================
// Duration — 非負時間
// ============================================================================

// Duration — 非負 time.Duration ラッパ
type Duration struct {
	d time.Duration
}

func NewDuration(d time.Duration) (Duration, error) {
	if d < 0 {
		return Duration{}, fmt.Errorf("duration: negative %v", d)
	}
	return Duration{d: d}, nil
}

func (du Duration) Time() time.Duration { return du.d }
func (du Duration) IsZero() bool        { return du.d == 0 }
