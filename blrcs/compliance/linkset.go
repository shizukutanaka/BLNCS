package compliance

import (
	"encoding/json"
	"fmt"
)

// GS1 Digital Link Linkset — 単一の製品識別子 URI から複数の関連リソースへ
// linkType で振り分ける標準機構 (GS1 Digital Link / RFC 9264 Linkset)。
//
// DPP 発見の実標準: QR をスキャン → GTIN URI 解決 → linkset が
// passport / 適合宣言 / due-diligence / 取扱説明書 などへリンクする。
// 各 linkType は IANA / GS1 が定義する関係を表す。

// GS1 標準の linkType 識別子 (https://www.gs1.org/voc/)。
const (
	LinkTypeDPP            = "https://gs1.org/voc/epil" // EPCIS / product info link
	LinkTypeProductInfo    = "https://gs1.org/voc/pip"  // product information page
	LinkTypeSustainability = "https://gs1.org/voc/sustainabilityInfo"
	LinkTypeCertification  = "https://gs1.org/voc/certificationInfo"
	LinkTypeInstructions   = "https://gs1.org/voc/instructions"
	LinkTypeRecall         = "https://gs1.org/voc/recallStatus"
)

// Link — linkset 内の1リンク (RFC 9264)。
type Link struct {
	Href     string `json:"href"`
	Type     string `json:"type,omitempty"` // MIME type, e.g. "application/vc+ld+json"
	Title    string `json:"title,omitempty"`
	HrefLang string `json:"hreflang,omitempty"` // 言語タグ, e.g. "en", "ja"
}

// Linkset — anchor (製品 URI) から linkType 別のリンク集合 (RFC 9264 §4.2.4.2)。
//
// JSON 形 (application/linkset+json):
//
//	{"linkset":[{"anchor":"https://id.example/01/...",
//	             "https://gs1.org/voc/pip":[{"href":"..."}]}]}
type Linkset struct {
	Anchor string
	links  map[string][]Link
}

// NewLinkset — anchor URI から空 linkset を構築。
func NewLinkset(anchor string) *Linkset {
	return &Linkset{Anchor: anchor, links: make(map[string][]Link)}
}

// Add — linkType に Link を追加 (同一 linkType に複数可: 言語別など)。
func (ls *Linkset) Add(linkType string, link Link) *Linkset {
	if ls.links == nil {
		ls.links = make(map[string][]Link)
	}
	ls.links[linkType] = append(ls.links[linkType], link)
	return ls
}

// Get — linkType のリンク群を取得 (無ければ nil)。
func (ls *Linkset) Get(linkType string) []Link {
	return ls.links[linkType]
}

// LinkTypes — 登録済み linkType を列挙。
func (ls *Linkset) LinkTypes() []string {
	out := make([]string, 0, len(ls.links))
	for k := range ls.links {
		out = append(out, k)
	}
	return out
}

// MarshalJSON — RFC 9264 application/linkset+json 形式で出力。
func (ls *Linkset) MarshalJSON() ([]byte, error) {
	if ls.Anchor == "" {
		return nil, fmt.Errorf("compliance: linkset anchor required")
	}
	ctx := map[string]any{"anchor": ls.Anchor}
	for linkType, links := range ls.links {
		arr := make([]map[string]any, 0, len(links))
		for _, l := range links {
			m := map[string]any{"href": l.Href}
			if l.Type != "" {
				m["type"] = l.Type
			}
			if l.Title != "" {
				m["title"] = l.Title
			}
			if l.HrefLang != "" {
				m["hreflang"] = l.HrefLang
			}
			arr = append(arr, m)
		}
		ctx[linkType] = arr
	}
	return json.Marshal(map[string]any{"linkset": []any{ctx}})
}

// ParseLinkset — RFC 9264 application/linkset+json を解析。
func ParseLinkset(data []byte) (*Linkset, error) {
	var doc struct {
		Linkset []map[string]json.RawMessage `json:"linkset"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("compliance: parse linkset: %w", err)
	}
	if len(doc.Linkset) == 0 {
		return nil, fmt.Errorf("compliance: empty linkset")
	}
	entry := doc.Linkset[0]
	ls := &Linkset{links: make(map[string][]Link)}
	for key, raw := range entry {
		if key == "anchor" {
			var anchor string
			if err := json.Unmarshal(raw, &anchor); err == nil {
				ls.Anchor = anchor
			}
			continue
		}
		var links []Link
		if err := json.Unmarshal(raw, &links); err == nil {
			ls.links[key] = links
		}
	}
	if ls.Anchor == "" {
		return nil, fmt.Errorf("compliance: linkset missing anchor")
	}
	return ls, nil
}
