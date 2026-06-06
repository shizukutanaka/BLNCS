// Client Identifier Prefix の検証 — OpenID4VP v1.0 §5.10。
//
// verifier の client_id は `<prefix>:<value>` 形式 (prefix 無しは pre-registered)。
// 形式不正な verifier 識別子で Authorization Request を発行しないよう CreateRequest
// 時に検証する。これは wallet 側が verifier を認証する前提を守るための入口検証で、
// クロスデバイス・フィッシングの緩和に資する (Stuttgart 形式分析)。
package openid4vp

import (
	"net/url"
	"strings"
)

// knownClientIDPrefixes — OpenID4VP v1.0 が定義する Client Identifier Prefix。
// これらの prefix が付く場合のみ scheme 検証を行う。未知の prefix を含む値
// (例: "https://verifier.example") は pre-registered な bare 識別子として扱う。
var knownClientIDPrefixes = map[string]bool{
	"redirect_uri":             true,
	"openid_federation":        true,
	"decentralized_identifier": true,
	"verifier_attestation":     true,
	"x509_san_dns":             true,
	"x509_hash":                true,
	"web-origin":               true,
}

// ValidateClientID — client_id の形式を検証する。
//
// 空・空白混入・制御文字は不正。既知 prefix が付く場合は scheme ごとに値の形式を
// 検証する。prefix 無し / 未知 prefix は非空であれば pre-registered として許容
// (URL を直接 client_id にする一般的な運用を壊さない)。
func ValidateClientID(clientID string) error {
	if clientID == "" || strings.TrimSpace(clientID) != clientID {
		return ErrClientIDInvalid
	}
	if strings.ContainsAny(clientID, " \t\r\n") {
		return ErrClientIDInvalid
	}
	prefix, value, found := strings.Cut(clientID, ":")
	if !found || !knownClientIDPrefixes[prefix] {
		return nil // bare / pre-registered identifier (incl. plain https URL)
	}
	switch prefix {
	case "redirect_uri", "web-origin", "openid_federation":
		return validateAbsHTTPSURL(value)
	case "decentralized_identifier":
		// value は DID 全体 (例 "did:web:verifier.example")。
		if !strings.HasPrefix(value, "did:") || len(value) <= len("did:") {
			return ErrClientIDInvalid
		}
		return nil
	case "x509_san_dns":
		// DNS 名: 非空・パスや scheme 区切りを含まない。
		if value == "" || strings.ContainsAny(value, "/:") {
			return ErrClientIDInvalid
		}
		return nil
	case "x509_hash", "verifier_attestation":
		if value == "" {
			return ErrClientIDInvalid
		}
		return nil
	}
	return nil
}

// validateAbsHTTPSURL — 絶対 https URL (host 有り) であることを確認。
func validateAbsHTTPSURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ErrClientIDInvalid
	}
	return nil
}
