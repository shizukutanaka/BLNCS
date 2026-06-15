// OpenID4VP HTTP 統合 — Apple/Google Wallet 直接接続エンドポイント
//
// 2エンドポイント (Apple式シンプル):
//
//	GET  /openid4vp/authorize  — verifier app がリクエストを作り、walletに渡すURL返却
//	POST /openid4vp/callback   — Apple Wallet / Google Wallet が vp_token を POST
//
// ブラウザ統合 (W3C Digital Credentials API):
//
//	const cred = await navigator.credentials.get({
//	  digital: { providers: [{ protocol: 'openid4vp', request: <URL>.search }] }
//	})
//
// (iOS 26 Safari 26 / Chrome 143+)
package openid4vp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// AuthorizeHandler — verifier app が利用する request 生成エンドポイント
//
// ライブラリ利用側 (BLRCS deploy) が呼ぶ:
//
//	http.Handle("/openid4vp/authorize", verifier.AuthorizeHandler())
//
// 期待 request body (JSON): PresentationDefinition
// 応答: {"requestURL": "openid4vp://...", "state": "..."}
//
// 本番構成: authz 層 (API key / OAuth) をこのHandlerの前に挟む
func (v *Verifier) AuthorizeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "body read: "+err.Error(), http.StatusBadRequest)
			return
		}
		var def PresentationDefinition
		if err := json.Unmarshal(body, &def); err != nil {
			http.Error(w, "json parse: "+err.Error(), http.StatusBadRequest)
			return
		}
		reqURL, state, err := v.CreateRequest(def)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"requestURL": reqURL,
			"state":      state,
		})
	})
}

// CallbackHandler — Wallet direct_post モードの受付
//
// OpenID4VP 仕様: Wallet は POST application/x-www-form-urlencoded で
//
//	vp_token, state, presentation_submission を送信
//
// 検証成功時: 200 + {"status":"success", "claims":{...}}
// 検証失敗時: 400 + {"status":"failure", "error":"..."}
//
// OnSuccess callback で、検証完了後のビジネスロジックをフック可能:
//
//	"compliance DB に記録", "WebSocket経由でフロントに即時通知", 等
func (v *Verifier) CallbackHandler(onSuccess func(*VerifiedPresentation)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ct := r.Header.Get("Content-Type")
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		if err != nil {
			writeCallbackError(w, "body read: "+err.Error())
			return
		}
		var resp *AuthorizationResponse
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			resp, err = ParseResponseForm(string(bodyBytes))
		} else {
			// JSON fallback — 一部 wallet 実装に対応
			resp = &AuthorizationResponse{}
			err = json.Unmarshal(bodyBytes, resp)
		}
		if err != nil {
			writeCallbackError(w, "parse: "+err.Error())
			return
		}
		vp, err := v.ProcessResponse(resp)
		if err != nil {
			// Do not leak which verification step failed (issuer unknown / signature
			// mismatch / revoked / claim missing) — that is an oracle for an attacker
			// probing the endpoint (CWE-209). Surface the detail server-side only.
			if v.OnVerifyError != nil {
				v.OnVerifyError(err)
			}
			writeCallbackError(w, "presentation verification failed")
			return
		}
		if onSuccess != nil {
			onSuccess(vp)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "success",
			"subject": vp.Subject,
			"issuer":  vp.Issuer,
			"claims":  vp.Claims,
		})
	})
}

func writeCallbackError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "failure",
		"error":  msg,
	})
}
