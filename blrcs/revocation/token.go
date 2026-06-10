// Status List Token — draft-ietf-oauth-status-list の signed JWT 形式
// (media type application/statuslist+jwt) 実装。
//
// status list そのものを Issuer 署名付きトークンとして配布することで、verifier が
// vc.Status.URI から取得したリストの真正性・鮮度 (exp/ttl) を検証できる。
// 中身の bit 配列は BitstringStatusList (W3C Bitstring) を再利用する。
package revocation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrTokenMalformed — Status List Token の構造不正。
	ErrTokenMalformed = errors.New("revocation: status list token malformed")
	// ErrTokenSigFailed — Status List Token の署名検証失敗。
	ErrTokenSigFailed = errors.New("revocation: status list token signature failed")
	// ErrTokenExpired — Status List Token が exp を超過。
	ErrTokenExpired = errors.New("revocation: status list token expired")
)

// statusListClaims — Status List Token の JWT payload (draft-ietf-oauth-status-list §5)。
type statusListClaims struct {
	Sub        string `json:"sub"`           // status list URI (credential の status.uri と一致)
	Iss        string `json:"iss,omitempty"` // 発行者識別子
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp,omitempty"`
	TTL        int64  `json:"ttl,omitempty"` // キャッシュ可能秒数
	StatusList struct {
		Bits int    `json:"bits"` // entry あたり bit 数 (BLRCS は 1)
		Lst  string `json:"lst"`  // gzip + base64url の bit 配列
	} `json:"status_list"`
}

// TokenMeta — 検証済み Status List Token のメタデータ。
type TokenMeta struct {
	Subject  string
	Issuer   string
	IssuedAt int64
	Expires  int64
	TTL      int64
}

// IsStale reports whether a verifier holding a cached copy of this token should
// refresh it, per draft-ietf-oauth-status-list: the `ttl` claim is the maximum
// number of seconds the status list may be cached after issuance. Returns false
// when no TTL was advertised (caller falls back to `exp` / its own policy).
func (m *TokenMeta) IsStale() bool {
	return m.IsStaleAt(time.Now())
}

// IsStaleAt is IsStale with an injectable clock (deterministic tests).
func (m *TokenMeta) IsStaleAt(now time.Time) bool {
	if m.TTL <= 0 {
		return false
	}
	freshUntil := time.Unix(m.IssuedAt, 0).Add(time.Duration(m.TTL) * time.Second)
	return now.After(freshUntil)
}

// IssueToken — この status list を署名付き Status List Token として発行。
//
// sub は配布 URI (credential の status.uri と一致させる)。ttl>0 で exp を付与。
func (b *BitstringStatusList) IssueToken(issuer, sub string, priv ed25519.PrivateKey, ttl time.Duration) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("revocation: invalid private key")
	}
	enc, err := b.EncodedList()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	var claims statusListClaims
	claims.Sub = sub
	claims.Iss = issuer
	claims.Iat = now.Unix()
	if ttl > 0 {
		claims.TTL = int64(ttl.Seconds())
		claims.Exp = now.Add(ttl).Unix()
	}
	claims.StatusList.Bits = 1
	claims.StatusList.Lst = enc

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"statuslist+jwt"}`))
	plBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(plBytes)
	sig := ed25519.Sign(priv, []byte(header+"."+payload))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyStatusListToken — Status List Token を検証し、bit 配列とメタデータを返す。
//
// 署名・exp (leeway 込み) を検証し、lst を復元する。purpose は呼び出し側が期待する用途。
func VerifyStatusListToken(token string, pub ed25519.PublicKey, purpose StatusPurpose) (*BitstringStatusList, *TokenMeta, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, nil, ErrTokenSigFailed
	}
	segs := strings.SplitN(token, ".", 3)
	if len(segs) != 3 {
		return nil, nil, ErrTokenMalformed
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return nil, nil, ErrTokenMalformed
	}
	var hdr struct{ Alg, Typ string }
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "EdDSA" || hdr.Typ != "statuslist+jwt" {
		return nil, nil, ErrTokenMalformed
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil {
		return nil, nil, ErrTokenMalformed
	}
	if !ed25519.Verify(pub, []byte(segs[0]+"."+segs[1]), sigBytes) {
		return nil, nil, ErrTokenSigFailed
	}
	plBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil, nil, ErrTokenMalformed
	}
	var claims statusListClaims
	if err := json.Unmarshal(plBytes, &claims); err != nil {
		return nil, nil, ErrTokenMalformed
	}
	// BLRCS reads the list as 1 bit per entry. A token declaring a different
	// bit width would be misread (every index after the first maps to the wrong
	// entry), so reject anything other than the implicit/explicit 1-bit form.
	if claims.StatusList.Bits != 0 && claims.StatusList.Bits != 1 {
		return nil, nil, ErrTokenMalformed
	}
	if claims.Exp != 0 && time.Now().After(time.Unix(claims.Exp, 0).Add(60*time.Second)) {
		return nil, nil, ErrTokenExpired
	}
	list, err := DecodeBitstringStatusList(purpose, claims.StatusList.Lst)
	if err != nil {
		return nil, nil, err
	}
	meta := &TokenMeta{
		Subject:  claims.Sub,
		Issuer:   claims.Iss,
		IssuedAt: claims.Iat,
		Expires:  claims.Exp,
		TTL:      claims.TTL,
	}
	return list, meta, nil
}

// TokenHandler — 事前発行した Status List Token を application/statuslist+jwt として
// 配信する HTTP ハンドラ。maxAge>0 で Cache-Control を付与する。
func TokenHandler(token string, maxAge time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		if maxAge > 0 {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
		}
		_, _ = w.Write([]byte(token))
	}
}
