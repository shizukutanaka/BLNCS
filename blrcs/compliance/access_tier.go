package compliance

import "sort"

// ESPR 3-tier access model — Digital Product Passport のアクセス階層。
//
// ESPR (Reg 2024/1781) と EU Battery Reg 2023/1542 は、DPP データを3階層で
// 区分することを要求する:
//   - public:    消費者を含め誰でもアクセス可能 (例: 炭素フットプリント、再生材含有率)
//   - restricted: リサイクラー・修理業者など正当な利益を持つ事業者 (例: 分解手順、材料組成)
//   - authority:  市場監視当局・税関のみ (例: 適合宣言詳細、サプライチェーン機密)
//
// SD-JWT の選択開示と整合する: public 階層は常時開示 (clear claims)、
// restricted/authority は選択開示 (SD claims) として発行される。

// AccessTier — DPP クレームのアクセス階層。
type AccessTier string

const (
	// TierPublic — 誰でもアクセス可能 (常時開示)。
	TierPublic AccessTier = "public"
	// TierRestricted — 正当な利益を持つ事業者 (リサイクラー・修理業者)。
	TierRestricted AccessTier = "restricted"
	// TierAuthority — 市場監視当局・税関のみ。
	TierAuthority AccessTier = "authority"
)

// IsValid — 既知の階層か判定。
func (t AccessTier) IsValid() bool {
	switch t {
	case TierPublic, TierRestricted, TierAuthority:
		return true
	}
	return false
}

// rank — 階層の機密度順位 (public < restricted < authority)。
func (t AccessTier) rank() int {
	switch t {
	case TierPublic:
		return 0
	case TierRestricted:
		return 1
	case TierAuthority:
		return 2
	}
	return -1
}

// TieredClaims — クレームをアクセス階層別に保持する。
//
// 発行者が「どのフィールドがどの階層か」を構造的に宣言するための型。
// SD-JWT 発行時に public=clear、restricted/authority=SD として分割される。
type TieredClaims struct {
	tiers map[string]AccessTier // claim key -> tier
	vals  map[string]any        // claim key -> value
}

// NewTieredClaims — 空の階層付きクレーム集合を構築。
func NewTieredClaims() *TieredClaims {
	return &TieredClaims{
		tiers: make(map[string]AccessTier),
		vals:  make(map[string]any),
	}
}

// Set — claim を階層付きで登録する。
// tier が不明な場合は最も厳格な TierAuthority に倒す (安全側への失敗):
// 誤った tier 指定による情報流出は、過剰保護より遥かに危険なため。
func (tc *TieredClaims) Set(key string, value any, tier AccessTier) *TieredClaims {
	if !tier.IsValid() {
		tier = TierAuthority // fail secure: unknown tier → maximally restricted
	}
	tc.tiers[key] = tier
	tc.vals[key] = value
	return tc
}

// Tier — claim の階層を取得 (未登録は false)。
func (tc *TieredClaims) Tier(key string) (AccessTier, bool) {
	t, ok := tc.tiers[key]
	return t, ok
}

// Keys — 登録済 claim キーをソート済で返す (決定的)。
func (tc *TieredClaims) Keys() []string {
	out := make([]string, 0, len(tc.vals))
	for k := range tc.vals {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ClaimsAtOrBelow — 指定階層以下 (機密度) の claim を返す。
//
// 例: ClaimsAtOrBelow(TierRestricted) は public + restricted を返し、
// authority は含めない。verifier の権限に応じた開示判断に使う。
func (tc *TieredClaims) ClaimsAtOrBelow(tier AccessTier) map[string]any {
	limit := tier.rank()
	out := make(map[string]any)
	for k, v := range tc.vals {
		if tc.tiers[k].rank() <= limit {
			out[k] = v
		}
	}
	return out
}

// SplitForSDJWT — SD-JWT 発行用に (clearClaims, sdClaims) に分割。
//
// public 階層は clear (常時開示)、restricted/authority は SD (選択開示)。
// これにより誰でも public データを読め、上位階層は holder の同意と
// verifier の権限の下でのみ開示される。
func (tc *TieredClaims) SplitForSDJWT() (clearClaims, sdClaims map[string]any) {
	clearClaims = make(map[string]any)
	sdClaims = make(map[string]any)
	for k, v := range tc.vals {
		if tc.tiers[k] == TierPublic {
			clearClaims[k] = v
		} else {
			sdClaims[k] = v
		}
	}
	return clearClaims, sdClaims
}
