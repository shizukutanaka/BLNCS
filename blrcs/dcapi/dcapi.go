// Package dcapi — W3C Digital Credentials API adapter
//
// 目的: BLRCS verifier を Safari 26 / Chrome 141 / Firefox 149 全対応にする
//
// 背景:
//
//	2025/11 W3C FedID WG TPAC決定でプロトコル登録簡易化。
//	ハードコード5種類:
//	  openid4vp-v1-unsigned, openid4vp-v1-signed, openid4vp-v1-multisigned
//	  org-iso-mdoc (Safari 26独占対応)
//	  openid4vci-v1
//
// 実装方針: 同じBLRCS verifier を複数プロトコル文字列に対して露出
//   - BuildChromeRequest()  — Chrome/Firefox 向け openid4vp-v1-unsigned
//   - BuildSafariRequest()  — Safari向け org-iso-mdoc エンベロープ (MVPはfallback)
//   - ParseDCAPIResponse()  — vp_token抽出 (3種のレスポンス形式統一)
//
// Apple式設計:
//   - 呼出側コードは1行: req := dcapi.NewRequest(def); js := req.ToJavaScript()
//   - browser差異は内部で吸収
//   - 将来プロトコル追加時も契約不変
package dcapi

import (
	"encoding/json"
	"errors"
	"fmt"

	"blrcs/openid4vp"
)

// Protocol — W3C FedID protocol identifier
type Protocol string

const (
	// ProtocolOpenID4VPUnsigned — 基本的な VP (Chrome 141, Firefox 149)
	ProtocolOpenID4VPUnsigned Protocol = "openid4vp-v1-unsigned"
	// ProtocolOpenID4VPSigned — JWS署名済 request (相手確認が必要なフロー)
	ProtocolOpenID4VPSigned Protocol = "openid4vp-v1-signed"
	// ProtocolISOmDoc — Safari 26独占、ISO 18013-5/7 mobile document
	ProtocolISOmDoc Protocol = "org-iso-mdoc"
	// ProtocolOpenID4VCI — Credential issuance (Chrome 143+)
	ProtocolOpenID4VCI Protocol = "openid4vci-v1"
)

// IsSupported — W3C FedID WG 2025/11 ハードコード5種のいずれか
func IsSupported(p Protocol) bool {
	switch p {
	case ProtocolOpenID4VPUnsigned, ProtocolOpenID4VPSigned,
		"openid4vp-v1-multisigned", ProtocolISOmDoc, ProtocolOpenID4VCI:
		return true
	}
	return false
}

// ============================================================================
// Request envelope — DC-API が navigator.credentials.get() に渡す構造
// ============================================================================

// Request — DC-API の requests[] 1要素
type Request struct {
	Protocol Protocol        `json:"protocol"`
	Data     json.RawMessage `json:"data"`
}

// GetCall — navigator.credentials.get() 全体パラメータ
type GetCall struct {
	Digital struct {
		Requests []Request `json:"requests"`
	} `json:"digital"`
}

// ============================================================================
// Builder API
// ============================================================================

// BuildForVerifier — BLRCS openid4vp.Verifier から DC-API 呼出用データを作成
//
// 戻り値: navigator.credentials.get() に渡す JavaScript互換 JSON 構造体
// ブラウザは protocol=openid4vp-v1-unsigned 側を優先、
// 対応していない (Safari) は org-iso-mdoc 側で試行する。
//
// 典型的なブラウザ側コード:
//
//	const raw = await fetch('/openid4vp/authorize', {method:'POST', body: JSON.stringify(def)})
//	const {requestURL, state, dcapi} = await raw.json();
//	const cred = await navigator.credentials.get(dcapi);
//	fetch('/openid4vp/callback', {method:'POST', body: new URLSearchParams({vp_token: cred.data, state})});
func BuildForVerifier(def openid4vp.PresentationDefinition, nonce, clientID, responseURI string) (*GetCall, error) {
	if len(def.RequiredClaims) == 0 {
		return nil, openid4vp.ErrDefinitionEmpty
	}
	chromeData, err := buildOpenID4VPData(def, nonce, clientID, responseURI, false)
	if err != nil {
		return nil, err
	}
	// Safari向け org-iso-mdoc はMVPではstub (同じPDを含めるが本来はdoctype+nameSpace形式)
	safariData, err := buildMdocData(def, nonce, clientID, responseURI)
	if err != nil {
		return nil, err
	}
	call := &GetCall{}
	call.Digital.Requests = []Request{
		{Protocol: ProtocolOpenID4VPUnsigned, Data: chromeData},
		{Protocol: ProtocolISOmDoc, Data: safariData},
	}
	return call, nil
}

// BuildForVerifierDCQL — OpenID4VP v1.0 の dcql_query を用いた DC-API リクエスト。
//
// Presentation Exchange は v1.0 で削除されたため、v1.0 準拠ブラウザ/ウォレットには
// こちらを使う。query は §6 に従い検証される。
func BuildForVerifierDCQL(query openid4vp.DCQLQuery, nonce, clientID, responseURI string) (*GetCall, error) {
	if err := query.Validate(); err != nil {
		return nil, err
	}
	data := map[string]any{
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"client_id":     clientID,
		"nonce":         nonce,
		"dcql_query":    query,
	}
	if responseURI != "" {
		data["response_uri"] = responseURI
	}
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	call := &GetCall{}
	call.Digital.Requests = []Request{
		{Protocol: ProtocolOpenID4VPUnsigned, Data: body},
	}
	return call, nil
}

// buildOpenID4VPData — Chrome/Firefox 向け unsigned request body
// OpenID4VP §5.4 + DC-API profile
func buildOpenID4VPData(def openid4vp.PresentationDefinition, nonce, clientID, responseURI string, signed bool) (json.RawMessage, error) {
	pdCopy := def
	pdCopy.AcceptableIssuers = nil // wire送信禁止
	data := map[string]any{
		"response_type":           "vp_token",
		"response_mode":           "dc_api", // DC-API 特有 — redirect_uri 不要
		"client_id":               clientID,
		"nonce":                   nonce,
		"presentation_definition": pdCopy,
	}
	if responseURI != "" {
		data["response_uri"] = responseURI
	}
	return json.Marshal(data)
}

// buildMdocData — Safari向け org-iso-mdoc request body
// ISO 18013-7 Annex C (W3C DCAPI profile) 形式
// MVP: minimal envelope, full mdoc negotiator は専用パッケージが必要
func buildMdocData(def openid4vp.PresentationDefinition, nonce, clientID, responseURI string) (json.RawMessage, error) {
	// 最小 deviceRequest: org.iso.18013.5.1.mDL namespace の item request
	// 実運用では mdoc responder層と統合
	mdocReq := map[string]any{
		"client_id":                      clientID,
		"nonce":                          nonce,
		"response_mode":                  "dc_api",
		"presentation_definition_compat": def,
	}
	if responseURI != "" {
		mdocReq["response_uri"] = responseURI
	}
	return json.Marshal(mdocReq)
}

// ============================================================================
// Response parsing — ブラウザからの credential を抽出
// ============================================================================

// DCAPIResponse — credential.data に入ってくる JSON
// ブラウザ毎に shape が異なるので union 的に parse
type DCAPIResponse struct {
	Protocol Protocol        `json:"protocol"`
	Data     json.RawMessage `json:"data"`
}

// ExtractVPToken — 各プロトコルレスポンスから vp_token を取り出し
//
// DC-API 応答は少なくとも3形式:
//  1. Chrome openid4vp-v1-unsigned: {"data": {"vp_token": "..."}}
//  2. Safari org-iso-mdoc: {"data": base64(COSE_Sign1)} — mdoc独自
//  3. 暗号化応答 (Chrome JWE): {"data": "<jwe>"}
//
// MVP: 1) と 2) の生文字列化のみサポート。JWE 復号は別パッケージ。
func (r *DCAPIResponse) ExtractVPToken() (vpToken string, state string, err error) {
	switch r.Protocol {
	case ProtocolOpenID4VPUnsigned, ProtocolOpenID4VPSigned, "openid4vp-v1-multisigned":
		var payload struct {
			VPToken string `json:"vp_token"`
			State   string `json:"state"`
		}
		if err := json.Unmarshal(r.Data, &payload); err != nil {
			return "", "", fmt.Errorf("dcapi: parse vp response: %w", err)
		}
		if payload.VPToken == "" {
			return "", "", errors.New("dcapi: vp_token missing")
		}
		return payload.VPToken, payload.State, nil
	case ProtocolISOmDoc:
		// Safari mdoc は base64 CBOR 文字列のみ。mdoc パッケージが解読する。
		// MVP: 生データをそのまま返す (caller 側で mdoc parse)
		var raw string
		if err := json.Unmarshal(r.Data, &raw); err != nil {
			return "", "", fmt.Errorf("dcapi: parse mdoc response: %w", err)
		}
		return raw, "", nil
	default:
		return "", "", fmt.Errorf("dcapi: unsupported protocol: %s", r.Protocol)
	}
}

// ============================================================================
// JavaScript 出力ヘルパ — ブラウザに埋込めるコピペ可能なスニペット
// ============================================================================

// ToJavaScript — ブラウザ <script> にそのまま貼れる呼出コード生成
//
// 使い方:
//
//	html := fmt.Sprintf("<script>%s</script>", call.ToJavaScript())
//
// ブラウザ側では data 変数に await navigator.credentials.get() の結果が入る
func (c *GetCall) ToJavaScript() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return `(async () => {
  const request = ` + string(b) + `;
  if (!('credentials' in navigator) || !navigator.credentials.get) {
    throw new Error('Digital Credentials API not supported');
  }
  const cred = await navigator.credentials.get(request);
  return cred.data;
})()`
}

// ============================================================================
// Capability detection helper
// ============================================================================

// DetectUserAgent — User-Agent heuristic で適切な protocol を返す
// 本来は navigator.credentials.userAgentAllowsProtocol() を browser側で使うべき
// サーバ側での hint として利用 (完全に信頼しない)
func DetectUserAgent(userAgent string) Protocol {
	switch {
	// Chrome/Edg must come first — their UA string contains "Safari/" for legacy compat
	case containsAny(userAgent, "Chrome/", "Edg/"):
		return ProtocolOpenID4VPUnsigned
	case containsAny(userAgent, "Firefox/"):
		return ProtocolOpenID4VPUnsigned
	// Real Safari UA contains "Version/" + "Safari/" but no "Chrome/"
	case containsAny(userAgent, "Version/26") || containsAny(userAgent, "Version/27"):
		return ProtocolISOmDoc
	default:
		return ProtocolOpenID4VPUnsigned
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
