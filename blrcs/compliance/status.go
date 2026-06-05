package compliance

import "blrcs/revocation"

// ============================================================================
// Credential status (revocation) — draft-ietf-oauth-status-list の `status` claim
//
// 発行された SD-JWT VC に失効参照 (status list の URI + bit index) を埋め込み、
// verifier が失効確認できるようにする。実際の bit 配列は revocation パッケージ
// (W3C Bitstring Status List) を再利用する。
// ============================================================================

// StatusRef — credential の失効参照 (status_list claim)。
//
// IETF Token Status List 形式: {"status":{"status_list":{"idx":N,"uri":"…"}}}。
type StatusRef struct {
	URI   string `json:"uri"` // status list token の取得先 URL
	Index int    `json:"idx"` // この credential が占有する bit index
}

// statusClaim — payload["status"] に埋め込む JSON 構造を生成。
func (s *StatusRef) statusClaim() map[string]any {
	return map[string]any{
		"status_list": map[string]any{
			"idx": s.Index,
			"uri": s.URI,
		},
	}
}

// extractStatus — payload["status"].status_list から StatusRef を復元 (無ければ nil)。
func extractStatus(payload map[string]any) *StatusRef {
	status, ok := payload["status"].(map[string]any)
	if !ok {
		return nil
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		return nil
	}
	uri, _ := sl["uri"].(string)
	idxF, ok := sl["idx"].(float64) // JSON 数値は float64
	if uri == "" || !ok {
		return nil
	}
	return &StatusRef{URI: uri, Index: int(idxF)}
}

// CheckRevoked — credential の status bit が、取得済みの status list 内で
// 立っているか (= 失効) を返す。
//
// status list の URI からの取得は呼び出し側の責務 (このレイヤを network-free に
// 保つ)。典型フロー:
//
//	vc, _ := VerifySDJWT(token, issuerPub)
//	enc := httpGet(vc.Status.URI)                       // 呼び出し側
//	list, _ := revocation.DecodeBitstringStatusList(revocation.PurposeRevocation, enc)
//	revoked, _ := CheckRevoked(vc, list)
//
// status claim を持たない credential は (false, nil) を返す。
func CheckRevoked(vc *VerifiedClaims, list *revocation.BitstringStatusList) (bool, error) {
	if vc == nil || vc.Status == nil {
		return false, nil
	}
	if list == nil {
		return false, ErrStatusListRequired
	}
	return list.GetStatus(vc.Status.Index)
}
