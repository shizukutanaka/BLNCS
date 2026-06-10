// Package openid4vp — request_uri mode (JAR / request by reference)
//
// OpenID4VP v1.0 §5.8: request_uri を使うことで、Authorization Request の全パラメータを
// URL に直接埋め込まず、wallet がサーバから取得する形式にできる。
//
// メリット:
//   - QR コード / Deep Link の URL 長制限を回避 (presentation_definition は数百バイト)
//   - 要求内容のログ残留リスク低減
//   - 要求を後から無効化可能 (Consume でサーバ側の一時ストアを削除)
//
// 使い方:
//
//	reqURL, state, _ := verifier.CreateRequestByRef(def, "https://verify.example/vp/request")
//	// → "openid4vp://authorize?client_id=...&request_uri=https://verify.example/vp/request/STATE"
//
//	// HTTP サーバに RequestHandler を登録:
//	mux.Handle("/vp/request/", verifier.RequestHandler())
//
//	// Wallet が request_uri を fetch すると Authorization Request JSON が返る
package openid4vp

import (
	"encoding/json"
	"net/http"
	"strings"
)

// CreateRequestByRef — request_uri モードで Authorization Request を発行。
//
// requestBaseURI はウォレットが request object を取得する URL のベースパス
// (例: "https://verify.example/vp/request")。
// 戻り値 requestURL は "openid4vp://authorize?client_id=...&request_uri=..." 形式。
// ウォレットは request_uri を HTTP GET し、JSON でリクエストパラメータを取得する。
func (v *Verifier) CreateRequestByRef(def PresentationDefinition, requestBaseURI string) (requestURL string, state string, err error) {
	_, state, err = v.CreateRequest(def)
	if err != nil {
		return "", "", err
	}
	reqURI := strings.TrimRight(requestBaseURI, "/") + "/" + state
	return buildRequestByRefURL(v.ClientID, reqURI), state, nil
}

// CreateRequestDCQLByRef — DCQL クエリで request_uri モードの Authorization Request を発行。
func (v *Verifier) CreateRequestDCQLByRef(query DCQLQuery, requestBaseURI string) (requestURL string, state string, err error) {
	_, state, err = v.CreateRequestDCQL(query)
	if err != nil {
		return "", "", err
	}
	reqURI := strings.TrimRight(requestBaseURI, "/") + "/" + state
	return buildRequestByRefURL(v.ClientID, reqURI), state, nil
}

// buildRequestByRefURL — RFC 9101 §4 / OpenID4VP §5.8 形式の URL を構築。
// inline パラメータは client_id + request_uri のみ (最小限)。
func buildRequestByRefURL(clientID, requestURI string) string {
	// net/url.Values でエンコードすると順序が不定になりテスト困難なため手動構築
	return "openid4vp://authorize?client_id=" + clientID + "&request_uri=" + requestURI
}

// RequestHandler — ウォレット/ブラウザが request_uri を取得するための HTTP ハンドラ。
//
// パス末尾の state トークンを読み、対応する AuthorizationRequest を JSON で返す。
// Content-Type は "application/oauth-authz-req+jwt" (OpenID4VP §5.8)。
//
// マウント例:
//
//	mux.Handle("/vp/request/", verifier.RequestHandler())
//
// ウォレットが "/vp/request/{state}" へ GET すると Authorization Request が返る。
// request object は一度取得した後も state 消費まで再取得可能 (nonce リプレイはProcessResponseで防ぐ)。
func (v *Verifier) RequestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// state はパスの末尾セグメント
		state := extractLastPathSegment(r.URL.Path)
		if state == "" {
			http.Error(w, "missing state", http.StatusBadRequest)
			return
		}
		req, err := v.store.Load(state)
		if err != nil {
			http.Error(w, "request not found or expired", http.StatusNotFound)
			return
		}
		// AcceptableIssuers は内部マップのため wire に出さない
		// PresentationDefinition の AcceptableDIDs は含める (wallet が発行者マッチに使う)
		b, err := json.Marshal(req)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})
}

// extractLastPathSegment — "/a/b/c" → "c"
func extractLastPathSegment(path string) string {
	path = strings.TrimRight(path, "/")
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return path
	}
	return path[i+1:]
}
