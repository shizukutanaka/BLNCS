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
	"fmt"
	"reflect"

	"blrcs/compliance"
)

// DCQL complexity bounds — guard against DoS via crafted Authorization Requests.
// Each limit is generous enough for any real credential wallet scenario while
// bounding worst-case O(credentials × claims × depth × values) work in MatchClaims.
const (
	dcqlMaxCredentials    = 32 // max CredentialQuery entries per DCQLQuery
	dcqlMaxClaims         = 64 // max ClaimQuery entries per CredentialQuery
	dcqlMaxPathDepth      = 16 // max path segments in a single ClaimQuery.Path
	dcqlMaxValuesPerClaim = 32 // max allowed Values entries in a single ClaimQuery
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
	// ClaimSets — claims の代替な組合せ制約 (§6.3.1)。任意。指定時は各 ClaimQuery が
	// id を持つ必要があり、ClaimSets の各 option (id の集合) のいずれか1つを全て
	// 満たせば良い (credential_sets の claims 版、個々のクレームを "任意" にする機構
	// ではなく "この組合せか、あの組合せか" を表す — 例: パスポート番号 か
	// 運転免許証番号のどちらかを開示)。
	ClaimSets [][]string `json:"claim_sets,omitempty"`
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
	// ID — このクレーム照会の識別子。ClaimSets から参照するために使う。ClaimSets
	// が指定される CredentialQuery では必須 (§6.3.1)、それ以外では任意。同一
	// CredentialQuery.Claims 内で重複不可。
	ID string `json:"id,omitempty"`
	// Path — クレームへの JSON path (配列要素 = ネストのキー)。
	Path []string `json:"path"`
	// Values — 許容値 (指定時はこの値のみ受理)。
	Values []any `json:"values,omitempty"`
}

// CredentialSetQuery — credential の組合せ制約 (§6.2)。
type CredentialSetQuery struct {
	// Options — 各要素は CredentialQuery.ID の集合。いずれか1つを満たせば良い。
	Options [][]string `json:"options"`
	// Required — false なら任意提示。§6.2 の既定値は true で、JSON に `required` が
	// 無い場合は UnmarshalJSON が true を補う (spec default)。
	Required bool `json:"required"`
}

// UnmarshalJSON applies the OpenID4VP §6.2 default for `required` (true when the
// member is absent). A plain Go bool cannot distinguish "absent" from "false", so
// without this an omitted `required` would wrongly be treated as optional and the
// set would not be enforced.
func (s *CredentialSetQuery) UnmarshalJSON(data []byte) error {
	type alias CredentialSetQuery
	tmp := alias{Required: true} // spec default
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	*s = CredentialSetQuery(tmp)
	return nil
}

// Validate — DCQL クエリの構造的妥当性を検査 (§6)。
func (q *DCQLQuery) Validate() error {
	if len(q.Credentials) == 0 {
		return errors.New("openid4vp: dcql_query.credentials must be non-empty")
	}
	if len(q.Credentials) > dcqlMaxCredentials {
		return fmt.Errorf("%w: %d credentials exceeds limit of %d",
			ErrDCQLQueryTooComplex, len(q.Credentials), dcqlMaxCredentials)
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
		if len(c.Claims) > dcqlMaxClaims {
			return fmt.Errorf("%w: credential %q has %d claims, limit is %d",
				ErrDCQLQueryTooComplex, c.ID, len(c.Claims), dcqlMaxClaims)
		}
		claimIDs := make(map[string]bool, len(c.Claims))
		for j, claim := range c.Claims {
			if len(claim.Path) > dcqlMaxPathDepth {
				return fmt.Errorf("%w: credential %q claim[%d] path depth %d exceeds limit of %d",
					ErrDCQLQueryTooComplex, c.ID, j, len(claim.Path), dcqlMaxPathDepth)
			}
			if len(claim.Values) > dcqlMaxValuesPerClaim {
				return fmt.Errorf("%w: credential %q claim[%d] has %d values, limit is %d",
					ErrDCQLQueryTooComplex, c.ID, j, len(claim.Values), dcqlMaxValuesPerClaim)
			}
			if claim.ID != "" {
				if claimIDs[claim.ID] {
					return fmt.Errorf("openid4vp: credential %q has duplicate claim id: %s", c.ID, claim.ID)
				}
				claimIDs[claim.ID] = true
			}
		}
		// §6.3.1: claim_sets requires every claim in this CredentialQuery to carry
		// an id (otherwise there is nothing for an option to reference), and every
		// id an option references must exist in this same CredentialQuery's claims.
		if len(c.ClaimSets) > 0 {
			if len(claimIDs) != len(c.Claims) {
				return fmt.Errorf("openid4vp: credential %q: claim_sets requires every claim to have an id", c.ID)
			}
			for _, opt := range c.ClaimSets {
				if len(opt) == 0 {
					return fmt.Errorf("openid4vp: credential %q: claim_sets option must be non-empty", c.ID)
				}
				for _, claimID := range opt {
					if !claimIDs[claimID] {
						return fmt.Errorf("openid4vp: credential %q: claim_sets references unknown claim id: %s", c.ID, claimID)
					}
				}
			}
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
//
// ClaimSets が指定されている場合 (§6.3.1) は全 Claims の同時充足を要求する
// 代わりに、いずれか1つの option (claim id の集合) が指すクレーム群を全て
// 満たせば良い — "この組合せか、あの組合せか" という代替表現であり、個々の
// クレームを任意にする機構ではない。
func (cq *CredentialQuery) MatchClaims(presented map[string]any) bool {
	if len(cq.ClaimSets) > 0 {
		byID := make(map[string]*ClaimQuery, len(cq.Claims))
		for i := range cq.Claims {
			if cq.Claims[i].ID != "" {
				byID[cq.Claims[i].ID] = &cq.Claims[i]
			}
		}
		for _, opt := range cq.ClaimSets {
			allMatch := true
			for _, claimID := range opt {
				claim, ok := byID[claimID]
				if !ok || !matchOneClaim(claim, presented) {
					allMatch = false
					break
				}
			}
			if allMatch {
				return true
			}
		}
		return false
	}
	for i := range cq.Claims {
		if !matchOneClaim(&cq.Claims[i], presented) {
			return false
		}
	}
	return true
}

// matchOneClaim reports whether a single ClaimQuery is satisfied by the
// presented claims (path resolution + optional value-set membership).
func matchOneClaim(claim *ClaimQuery, presented map[string]any) bool {
	if len(claim.Path) == 0 {
		return true
	}
	val, found := walkPath(presented, claim.Path)
	if !found {
		return false
	}
	if len(claim.Values) == 0 {
		return true
	}
	for _, want := range claim.Values {
		// reflect.DeepEqual, not ==: a disclosed claim value can be a JSON
		// array/object (map[string]any / []any). The == operator panics when
		// both operands share an uncomparable dynamic type — reachable when a
		// verifier lists a composite value in DCQL `values` and a (possibly
		// malicious) wallet discloses a same-typed composite claim. DeepEqual
		// never panics and also matches composites structurally.
		if reflect.DeepEqual(val, want) {
			return true
		}
	}
	return false
}

// enforceDCQLConstraints checks the single presented credential against a DCQL
// query (OpenID4VP v1.0 §6). Because the BLRCS verifier accepts one vp_token per
// response, a credential "satisfies" a CredentialQuery when its vct is within that
// query's vct_values (dc+sd-jwt) and every requested claim path is disclosed with
// any value constraints met.
//
//   - Without credential_sets (§6.1): the presentation must satisfy at least one
//     credential query.
//   - With credential_sets (§6.2): every *required* set must have at least one
//     option all of whose referenced credential queries are satisfied. Optional
//     sets (required:false) do not gate. The §6.2 default for `required` is true
//     (see CredentialSetQuery.UnmarshalJSON).
//
// Returns ErrDCQLUnsatisfied when the presentation does not meet the query.
func enforceDCQLConstraints(q *DCQLQuery, vc *compliance.VerifiedClaims) error {
	satisfied := make(map[string]bool, len(q.Credentials))
	anySatisfied := false
	for i := range q.Credentials {
		cq := &q.Credentials[i]
		if credentialSatisfiesQuery(cq, vc) {
			satisfied[cq.ID] = true
			anySatisfied = true
		}
	}
	if len(q.CredentialSets) == 0 {
		if !anySatisfied {
			return ErrDCQLUnsatisfied
		}
		return nil
	}
	for i := range q.CredentialSets {
		set := &q.CredentialSets[i]
		if !set.Required {
			continue
		}
		if !optionSatisfied(set.Options, satisfied) {
			return ErrDCQLUnsatisfied
		}
	}
	return nil
}

// credentialSatisfiesQuery reports whether the presented credential meets a single
// CredentialQuery (vct gate + claim/value match).
func credentialSatisfiesQuery(cq *CredentialQuery, vc *compliance.VerifiedClaims) bool {
	if cq.Meta != nil && len(cq.Meta.VCTValues) > 0 {
		if !containsString(cq.Meta.VCTValues, vc.VCT) {
			return false
		}
	}
	return cq.MatchClaims(vc.Claims)
}

// optionSatisfied reports whether any option (a set of credential query IDs) is
// fully covered by the satisfied-query-ID set.
func optionSatisfied(options [][]string, satisfied map[string]bool) bool {
	for _, opt := range options {
		all := true
		for _, id := range opt {
			if !satisfied[id] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
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
