// DCQL — Digital Credentials Query Language (OpenID4VP v1.0 §6)。
//
// OpenID4VP v1.0 で Presentation Exchange は削除され、DCQL が唯一の照会言語と
// なった (Draft 22, 2024-10 追加 → final 前に PE 削除)。DCQL は JSON エンコード
// された format-agnostic な照会言語で、`dc+sd-jwt` を vct_values で要求できる。
//
// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6
package openid4vp

import (
	"encoding/json"
	"errors"
)

// DCQLQuery — dcql_query Authorization Request パラメータ (§6)。
type DCQLQuery struct {
	// Credentials — 要求する credential 群 (§6.1)。非空必須。
	Credentials []CredentialQuery `json:"credentials"`
	// CredentialSets — どの組合せを返すかの追加制約 (§6.2)。任意。
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// CredentialQuery — 個別 credential 要求 (§6.1)。
type CredentialQuery struct {
	// ID — このクエリの一意識別子 (response の matching に使う)。
	ID string `json:"id"`
	// Format — credential フォーマット。"dc+sd-jwt" | "mso_mdoc" など。
	Format string `json:"format"`
	// Meta — フォーマット固有メタ。SD-JWT VC は vct_values を含む。
	Meta *CredentialQueryMeta `json:"meta,omitempty"`
	// Claims — 要求するクレーム群 (§6.3)。空なら全クレーム。
	Claims []ClaimQuery `json:"claims,omitempty"`
}

// CredentialQueryMeta — フォーマット固有メタデータ。
type CredentialQueryMeta struct {
	// VCTValues — SD-JWT VC の許容 vct 一覧 (dc+sd-jwt 用)。
	VCTValues []string `json:"vct_values,omitempty"`
	// DoctypeValue — mso_mdoc の doctype。
	DoctypeValue string `json:"doctype_value,omitempty"`
}

// ClaimQuery — 要求する個別クレーム (§6.3)。
type ClaimQuery struct {
	// Path — クレームへの JSON path (配列要素 = ネストのキー)。
	Path []string `json:"path"`
	// Values — 許容値 (指定時はこの値のみ受理)。
	Values []any `json:"values,omitempty"`
}

// CredentialSetQuery — credential の組合せ制約 (§6.2)。
type CredentialSetQuery struct {
	// Options — 各要素は CredentialQuery.ID の集合。いずれか1つを満たせば良い。
	Options [][]string `json:"options"`
	// Required — false なら任意提示 (デフォルト true)。
	Required bool `json:"required"`
}

// Validate — DCQL クエリの構造的妥当性を検査 (§6)。
func (q *DCQLQuery) Validate() error {
	if len(q.Credentials) == 0 {
		return errors.New("openid4vp: dcql_query.credentials must be non-empty")
	}
	ids := map[string]bool{}
	for _, c := range q.Credentials {
		if c.ID == "" {
			return errors.New("openid4vp: credential query missing id")
		}
		if ids[c.ID] {
			return errors.New("openid4vp: duplicate credential query id: " + c.ID)
		}
		ids[c.ID] = true
		if c.Format == "" {
			return errors.New("openid4vp: credential query missing format")
		}
	}
	// credential_sets の options は既知の id を参照すること
	for _, set := range q.CredentialSets {
		if len(set.Options) == 0 {
			return errors.New("openid4vp: credential_set.options must be non-empty")
		}
		for _, opt := range set.Options {
			for _, id := range opt {
				if !ids[id] {
					return errors.New("openid4vp: credential_set references unknown id: " + id)
				}
			}
		}
	}
	return nil
}

// DCQLFromPresentationDefinition — 既存 PresentationDefinition から DCQL を構築。
//
// 後方互換ブリッジ: 旧 API 利用者が DCQL へ移行する経路。RequiredClaims を
// SD-JWT VC の claims に、AcceptableDIDs は credential_sets では表現しないため
// verifier 側の信頼検証で扱う (DCQL は trusted_authorities 拡張があるが MVP 外)。
func DCQLFromPresentationDefinition(def PresentationDefinition) DCQLQuery {
	format := "dc+sd-jwt"
	if def.Format == "mso-mdoc" {
		format = "mso_mdoc"
	}
	claims := make([]ClaimQuery, 0, len(def.RequiredClaims))
	for _, c := range def.RequiredClaims {
		claims = append(claims, ClaimQuery{Path: []string{c}})
	}
	id := def.ID
	if id == "" {
		id = "dpp_credential"
	}
	cq := CredentialQuery{
		ID:     id,
		Format: format,
		Claims: claims,
	}
	if format == "dc+sd-jwt" {
		cq.Meta = &CredentialQueryMeta{VCTValues: []string{"https://schema.europa.eu/dpp/sd-jwt-vc/v1"}}
	}
	return DCQLQuery{Credentials: []CredentialQuery{cq}}
}

// MatchClaims — credential のクレーム集合が CredentialQuery を満たすか判定。
//
// claim.Path の全セグメントを辿ってネストオブジェクトに対応する (DCQL §6.3)。
// 例: Path=["address","country"] は {"address":{"country":"DE"}} にマッチする。
// Values が指定されている場合は最終値がそのいずれかに一致しなければならない。
func (cq *CredentialQuery) MatchClaims(presented map[string]any) bool {
	for _, claim := range cq.Claims {
		if len(claim.Path) == 0 {
			continue
		}
		val, found := walkPath(presented, claim.Path)
		if !found {
			return false
		}
		if len(claim.Values) > 0 {
			matched := false
			for _, want := range claim.Values {
				if val == want {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

// walkPath navigates a nested map[string]any using the given path segments,
// returning the value at the end of the path and whether it was found.
func walkPath(root map[string]any, path []string) (any, bool) {
	var cur any = root
	for _, seg := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// MarshalDCQL — DCQLQuery を JSON にシリアライズ (Authorization Request 埋込用)。
func MarshalDCQL(q DCQLQuery) ([]byte, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(q)
}

// ParseDCQL — dcql_query JSON を解析・検証。
func ParseDCQL(data []byte) (*DCQLQuery, error) {
	var q DCQLQuery
	if err := json.Unmarshal(data, &q); err != nil {
		return nil, err
	}
	if err := q.Validate(); err != nil {
		return nil, err
	}
	return &q, nil
}
