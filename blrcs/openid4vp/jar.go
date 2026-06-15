// OpenID4VP JAR — JWT-secured Authorization Request (RFC 9101), by value.
//
// 問題 (authentication scope): 既定の Authorization Request は署名のない query
// parameters で送られる。ウォレットは KB-JWT の aud を request 内の client_id に
// バインドするが、その client_id 自体が認証されていない。攻撃者は本物の verifier の
// request を中継しつつ client_id はそのままに response_uri だけ自分のものへ差し替え
// られる (OpenID4VP cross-device / relay 脅威)。
//
// 対策: verifier が秘密鍵を持つ場合、request 全体を Ed25519 で署名した JWT
// (RFC 9101 §5.1 "by value") を `request` パラメータに同梱する。ウォレットは
// VerifyRequestObject で署名・有効期限・client_id 一致を検証し、認証済みの
// response_uri / nonce / client_id のみを信頼できる。
//
// ゼロ依存制約: SD-JWT issuer と同じ Ed25519 + JSON + base64url のみを使用。
package openid4vp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// JAR request object の JWT typ (RFC 9101 §10.8 で登録された値)。
const requestObjectTyp = "oauth-authz-req+jwt"

var (
	// ErrRequestObjectMissing — URL に署名付き `request` パラメータが無い。
	ErrRequestObjectMissing = errors.New("openid4vp: signed request object missing")
	// ErrRequestObjectInvalid — 署名/構造/有効期限/バインドの検証に失敗。
	ErrRequestObjectInvalid = errors.New("openid4vp: request object invalid")
)

// signRequestObject — AuthorizationRequest を RFC 9101 の署名付き JWT にする。
//
// header: {"alg":"EdDSA","typ":"oauth-authz-req+jwt"}
// payload: request の各フィールド + iss(=client_id) + iat + exp。
// response_uri / nonce / state / dcql_query|presentation_definition を署名範囲に
// 含めることで、ウォレットは response_uri が client_id 保持者に由来すると確認できる。
func signRequestObject(req *AuthorizationRequest, key ed25519.PrivateKey, ttl time.Duration) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: bad signing key", ErrRequestObjectInvalid)
	}
	now := time.Now().UTC()
	payload := map[string]any{
		// RFC 9101 §5.1: request object の iss は client_id。
		"iss":           req.ClientID,
		"client_id":     req.ClientID,
		"response_type": req.ResponseType,
		"response_mode": req.ResponseMode,
		"response_uri":  req.ResponseURI,
		"nonce":         req.Nonce,
		"state":         req.State,
		"iat":           now.Unix(),
		"exp":           now.Add(ttl).Unix(),
	}
	if req.DCQLQuery != nil {
		payload["dcql_query"] = req.DCQLQuery
	} else {
		payload["presentation_definition"] = req.PresentationDefinition
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"EdDSA","typ":"` + requestObjectTyp + `"}`))
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("openid4vp: marshal request object: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyRequestObject — ウォレット側。requestURL の署名付き `request` JWT を
// verifierPub で検証し、認証済みの AuthorizationRequest を返す。
//
// 検証内容:
//   - JWT 構造 + header の alg=EdDSA / typ=oauth-authz-req+jwt 固定 (alg-confusion 防止)
//   - Ed25519 署名 (verifierPub)
//   - exp による有効期限 (60s leeway)
//   - 署名内 client_id が URL 先頭の client_id query と一致 (dispatcher↔署名内容のバインド)
//
// これにより、ウォレットは response_uri / nonce が本物の client_id に由来すると
// 確認でき、relay 攻撃で response_uri を差し替えても検知できる。
func VerifyRequestObject(requestURL string, verifierPub ed25519.PublicKey) (*AuthorizationRequest, error) {
	if len(verifierPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad verifier key", ErrRequestObjectInvalid)
	}
	u, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestObjectInvalid, err)
	}
	q := u.Query()
	jwt := q.Get("request")
	if jwt == "" {
		return nil, ErrRequestObjectMissing
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWS", ErrRequestObjectInvalid)
	}
	// Header: alg/typ を固定値に pin (header-dispatched verifier を作らない)。
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header b64", ErrRequestObjectInvalid)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrRequestObjectInvalid)
	}
	if hdr.Alg != "EdDSA" || hdr.Typ != requestObjectTyp {
		return nil, fmt.Errorf("%w: unexpected alg/typ", ErrRequestObjectInvalid)
	}
	// 署名検証 (header.payload に対して)。
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: sig b64", ErrRequestObjectInvalid)
	}
	if !ed25519.Verify(verifierPub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("%w: signature", ErrRequestObjectInvalid)
	}
	plRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload b64", ErrRequestObjectInvalid)
	}
	var pl struct {
		ClientID               string           `json:"client_id"`
		ResponseType           string           `json:"response_type"`
		ResponseMode           string           `json:"response_mode"`
		ResponseURI            string           `json:"response_uri"`
		Nonce                  string           `json:"nonce"`
		State                  string           `json:"state"`
		Exp                    int64            `json:"exp"`
		DCQLQuery              *DCQLQuery       `json:"dcql_query,omitempty"`
		PresentationDefinition *json.RawMessage `json:"presentation_definition,omitempty"`
	}
	if err := json.Unmarshal(plRaw, &pl); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrRequestObjectInvalid)
	}
	// 有効期限 (60s leeway)。
	if pl.Exp != 0 && time.Now().After(time.Unix(pl.Exp, 0).Add(60*time.Second)) {
		return nil, fmt.Errorf("%w: expired", ErrRequestObjectInvalid)
	}
	// dispatcher↔署名内容バインド: URL 先頭の client_id と署名内の client_id が一致必須。
	// (一致しなければ、攻撃者が本物の署名済 request を別の client_id 文脈で再利用しようと
	//  している。署名は本物でも、それを提示する文脈が偽。)
	if topCID := q.Get("client_id"); topCID != "" && topCID != pl.ClientID {
		return nil, fmt.Errorf("%w: client_id mismatch", ErrRequestObjectInvalid)
	}
	req := &AuthorizationRequest{
		ClientID:     pl.ClientID,
		ResponseType: pl.ResponseType,
		ResponseMode: pl.ResponseMode,
		ResponseURI:  pl.ResponseURI,
		Nonce:        pl.Nonce,
		State:        pl.State,
		DCQLQuery:    pl.DCQLQuery,
	}
	if pl.PresentationDefinition != nil {
		if err := json.Unmarshal(*pl.PresentationDefinition, &req.PresentationDefinition); err != nil {
			return nil, fmt.Errorf("%w: presentation_definition json", ErrRequestObjectInvalid)
		}
	}
	return req, nil
}
