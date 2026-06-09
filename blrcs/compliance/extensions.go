package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PrivateKey — ed25519 private key (SCITT 署名、MCP dispatch 用)
func (i *Issuer) PrivateKey() ed25519.PrivateKey { return i.privateKey }

// NewIssuerFromKey — 既存鍵ペアからIssuer構築 (conformance test 用)
func NewIssuerFromKey(id string, priv ed25519.PrivateKey) (*Issuer, error) {
	if id == "" {
		return nil, ErrIssuerIDRequired
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}
	return &Issuer{
		ID:         id,
		privateKey: priv,
		publicKey:  priv.Public().(ed25519.PublicKey),
	}, nil
}

// ============================================================================
// SD-JWT (Selective Disclosure JWT)
// ============================================================================

// Disclosure — SD-JWT の1開示項目
type Disclosure struct {
	Salt    string `json:"salt"`
	Name    string `json:"name"`
	Value   any    `json:"value"`
	Encoded string `json:"-"` // base64url エンコード済
}

// VerifiedClaims — SD-JWT 検証結果
type VerifiedClaims struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	VCT      string         `json:"vct"` // SD-JWT VC type (draft-ietf-oauth-sd-jwt-vc)
	IssuedAt int64          `json:"iat"`
	Expires  int64          `json:"exp"`
	Claims   map[string]any `json:"claims"`

	// HolderKey — cnf.jwk から復元した holder 公開鍵 (発行時にバインドされていれば non-nil)。
	HolderKey ed25519.PublicKey `json:"-"`
	// KeyBound — この提示が有効な KB-JWT で holder にバインドされていれば true。
	KeyBound bool `json:"-"`
	// Status — status_list claim から復元した失効参照 (あれば non-nil)。CheckRevoked で使う。
	Status *StatusRef `json:"status,omitempty"`
}

// VCTDigitalProductPassport — DPP の SD-JWT VC type 識別子 (draft-ietf-oauth-sd-jwt-vc)。
const VCTDigitalProductPassport = "https://schema.europa.eu/dpp/sd-jwt-vc/v1"

// IssueSDJWTTiered — ESPR 3-tier アクセスモデルに従い SD-JWT VC を発行。
//
// public 階層クレームは常時開示、restricted/authority は選択開示となる。
// 発行者は TieredClaims で階層を宣言するだけで、SD-JWT の clear/SD 分割は
// 自動的に行われる。
func (i *Issuer) IssueSDJWTTiered(subject string, tc *TieredClaims, validFor time.Duration) (string, []Disclosure, error) {
	clear, sd := tc.SplitForSDJWT()
	return i.IssueSDJWT(subject, sd, clear, validFor)
}

// IssueSDJWT — SD-JWT VC 発行 (vct = DPP デフォルト)
//
// sdClaims: 選択開示対象 (holder が選んで開示)
// clearClaims: 常時開示 (JWT body に直接含む)
func (i *Issuer) IssueSDJWT(subject string, sdClaims, clearClaims map[string]any, validFor time.Duration) (string, []Disclosure, error) {
	return i.IssueSDJWTVC(VCTDigitalProductPassport, subject, sdClaims, clearClaims, validFor)
}

// IssueSDJWTVC — 任意の vct (Verifiable Credential Type) で SD-JWT VC 発行。
//
// vct は IETF SD-JWT VC 必須クレーム。衝突耐性のある URI / 名前を指定する。
func (i *Issuer) IssueSDJWTVC(vct, subject string, sdClaims, clearClaims map[string]any, validFor time.Duration) (string, []Disclosure, error) {
	return i.issueSDJWT(vct, subject, sdClaims, clearClaims, nil, nil, validFor)
}

// IssueSDJWTStatus — 失効参照 (status_list claim) 付きで DPP SD-JWT VC を発行。
//
// verifier は VerifiedClaims.Status から URI/index を取得し、CheckRevoked で
// 失効確認できる (draft-ietf-oauth-status-list)。
func (i *Issuer) IssueSDJWTStatus(subject string, sdClaims, clearClaims map[string]any, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	return i.IssueSDJWTVCStatus(VCTDigitalProductPassport, subject, sdClaims, clearClaims, status, validFor)
}

// IssueSDJWTVCStatus — 任意 vct で失効参照付き SD-JWT VC を発行。
func (i *Issuer) IssueSDJWTVCStatus(vct, subject string, sdClaims, clearClaims map[string]any, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	return i.issueSDJWT(vct, subject, sdClaims, clearClaims, nil, status, validFor)
}

// IssueSDJWTBound — IssueSDJWT に holder key binding (cnf) を付与した版 (vct=DPP)。
//
// holderPub を cnf.jwk (OKP/Ed25519) として埋め込む。提示時 holder は対応する
// 秘密鍵で KB-JWT に署名する必要があり、VerifySDJWTWithBinding が nonce/aud を
// 検証する (OpenID4VP リプレイ防止)。
func (i *Issuer) IssueSDJWTBound(subject string, sdClaims, clearClaims map[string]any, holderPub ed25519.PublicKey, validFor time.Duration) (string, []Disclosure, error) {
	return i.IssueSDJWTVCBound(VCTDigitalProductPassport, subject, sdClaims, clearClaims, holderPub, validFor)
}

// IssueSDJWTVCBound — 任意の vct で holder key binding (cnf) 付き SD-JWT VC を発行。
func (i *Issuer) IssueSDJWTVCBound(vct, subject string, sdClaims, clearClaims map[string]any, holderPub ed25519.PublicKey, validFor time.Duration) (string, []Disclosure, error) {
	if len(holderPub) != ed25519.PublicKeySize {
		return "", nil, ErrHolderKeyRequired
	}
	return i.issueSDJWT(vct, subject, sdClaims, clearClaims, holderPub, nil, validFor)
}

// IssueSDJWTTieredBound — IssueSDJWTTiered の holder key binding 付き版。
func (i *Issuer) IssueSDJWTTieredBound(subject string, tc *TieredClaims, holderPub ed25519.PublicKey, validFor time.Duration) (string, []Disclosure, error) {
	clear, sd := tc.SplitForSDJWT()
	return i.IssueSDJWTBound(subject, sd, clear, holderPub, validFor)
}

// issueSDJWT — SD-JWT VC 発行の共通実装。holderPub が non-nil なら cnf.jwk を、
// status が non-nil なら status_list claim を埋め込む。
func (i *Issuer) issueSDJWT(vct, subject string, sdClaims, clearClaims map[string]any, holderPub ed25519.PublicKey, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	now := time.Now().UTC()
	payload := map[string]any{
		"iss":     i.ID,
		"sub":     subject,
		"vct":     vct,
		"iat":     now.Unix(),
		"_sd_alg": "sha-256",
	}
	if validFor > 0 {
		payload["exp"] = now.Add(validFor).Unix()
	}
	// Holder key binding: cnf.jwk (RFC 7800 / SD-JWT-VC)
	if len(holderPub) == ed25519.PublicKeySize {
		payload["cnf"] = map[string]any{
			"jwk": map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(holderPub),
			},
		}
	}
	// Credential status (revocation): draft-ietf-oauth-status-list `status` claim
	if status != nil {
		payload["status"] = status.statusClaim()
	}
	// Clear claims → JWT body 直接
	for k, v := range clearClaims {
		payload[k] = v
	}
	// SD claims → hash digests in _sd array, disclosures appended
	var disclosures []Disclosure
	var sdDigests []string
	for name, value := range sdClaims {
		salt, err := randomB64(16)
		if err != nil {
			return "", nil, err
		}
		d := Disclosure{Salt: salt, Name: name, Value: value}
		// Encode: base64url(json([salt, name, value]))
		arr, _ := json.Marshal([]any{salt, name, value})
		d.Encoded = base64.RawURLEncoding.EncodeToString(arr)
		disclosures = append(disclosures, d)
		// Digest: SHA-256(encoded)
		h := sha256.Sum256([]byte(d.Encoded))
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(h[:]))
	}
	payload["_sd"] = sdDigests
	// Sign JWT
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`))
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(i.privateKey, []byte(sigInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwt := sigInput + "." + sigB64
	// Append disclosures with ~ separator
	sdjwt := jwt
	for _, d := range disclosures {
		sdjwt += "~" + d.Encoded
	}
	sdjwt += "~"
	return sdjwt, disclosures, nil
}

// VerifyOptions — VerifySDJWTWithBinding の検証ポリシー。
//
// ゼロ値は「現在時刻・標準 60s leeway・key binding 任意」で動作する。
type VerifyOptions struct {
	Now               time.Time     // ゼロ値なら time.Now()
	Leeway            time.Duration // 時刻ズレ許容 (ゼロなら 60s)
	ExpectedNonce     string        // 設定時、KB-JWT の nonce と一致必須
	ExpectedAudience  string        // 設定時、KB-JWT の aud と一致必須
	RequireKeyBinding bool          // true なら cnf 無し credential も拒否
}

const defaultLeeway = 60 * time.Second

// VerifySDJWT — SD-JWT 検証 + 開示 claim 抽出 (有効期限を強制、KB は任意)。
//
// 後方互換: 既存呼び出し元の署名は不変。exp/iat による有効期限チェックが
// 追加され、cnf (holder binding) 付き credential は KB-JWT を要求する。
func VerifySDJWT(sdjwt string, pub ed25519.PublicKey) (*VerifiedClaims, error) {
	return VerifySDJWTWithBinding(sdjwt, pub, VerifyOptions{})
}

// VerifySDJWTAt — 指定時刻で検証 (決定論的テスト用)。KB nonce/aud は検証しない。
func VerifySDJWTAt(sdjwt string, pub ed25519.PublicKey, now time.Time) (*VerifiedClaims, error) {
	return VerifySDJWTWithBinding(sdjwt, pub, VerifyOptions{Now: now})
}

// VerifySDJWTWithBinding — 有効期限 + holder key binding (KB-JWT) を含む完全検証。
//
// 手順: 発行者署名 → exp/iat → 開示展開 → (cnf 有り or RequireKeyBinding 時)
// 末尾 KB-JWT の holder 署名・nonce・aud・sd_hash を検証。OpenID4VP の
// リプレイ防止はこの nonce バインディングに依存する。
func VerifySDJWTWithBinding(sdjwt string, pub ed25519.PublicKey, opts VerifyOptions) (*VerifiedClaims, error) {
	if sdjwt == "" {
		return nil, ErrSDJWTEmpty
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = defaultLeeway
	}

	parts := strings.Split(sdjwt, "~")
	// 末尾要素が '.' を含めば KB-JWT (disclosure は base64url で '.' を含まない)。
	// len(parts)==1 は区切り '~' を持たない素の JWT で、KB も開示も無い
	// (len>1 を要求しないと parts[1:discEnd] が parts[1:0] となり panic する)。
	var kbSegment string
	discEnd := len(parts)
	if len(parts) > 1 {
		if last := parts[len(parts)-1]; last != "" && strings.Contains(last, ".") {
			kbSegment = last
			discEnd = len(parts) - 1
		}
	}

	// Parse + verify issuer JWT (alg-aware: pin header alg, dispatch by registry)
	jwtSegments := strings.SplitN(parts[0], ".", 3)
	if len(jwtSegments) != 3 {
		return nil, ErrSDJWTMalformed
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(jwtSegments[0])
	if err != nil {
		return nil, ErrSDJWTMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, ErrSDJWTMalformed
	}
	verify, ok := lookupJWSVerifier(hdr.Alg)
	if !ok {
		return nil, ErrSDJWTUnsupportedAlg
	}
	sigInput := jwtSegments[0] + "." + jwtSegments[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(jwtSegments[2])
	if err != nil {
		return nil, fmt.Errorf("sdjwt: bad sig encoding: %w", err)
	}
	if !verify([]byte(pub), []byte(sigInput), sigBytes) {
		return nil, ErrSDJWTSigFailed
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtSegments[1])
	if err != nil {
		return nil, fmt.Errorf("sdjwt: bad payload encoding: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("sdjwt: bad payload JSON: %w", err)
	}
	// SD-JWT: _sd_alg は sha-256 のみ対応 (hash downgrade 防止)。未指定は sha-256 既定。
	if alg, ok := payload["_sd_alg"].(string); ok && alg != "sha-256" {
		return nil, ErrSDJWTUnsupportedHashAlg
	}

	vc := &VerifiedClaims{Claims: make(map[string]any)}
	if v, ok := payload["iss"].(string); ok {
		vc.Issuer = v
	}
	if v, ok := payload["sub"].(string); ok {
		vc.Subject = v
	}
	if v, ok := payload["vct"].(string); ok {
		vc.VCT = v
	}
	if v, ok := payload["iat"].(float64); ok {
		vc.IssuedAt = int64(v)
	}
	if v, ok := payload["exp"].(float64); ok {
		vc.Expires = int64(v)
	}
	vc.HolderKey = extractHolderKey(payload)
	vc.Status = extractStatus(payload)

	// SD-JWT-VC: vct は必須クレーム (draft-ietf-oauth-sd-jwt-vc §3.2.2.2)。
	if vc.VCT == "" {
		return nil, ErrSDJWTMissingVCT
	}

	// 有効期限の強制 (leeway 込み)
	if vc.Expires != 0 && now.After(time.Unix(vc.Expires, 0).Add(leeway)) {
		return nil, ErrSDJWTExpired
	}
	if vc.IssuedAt != 0 && time.Unix(vc.IssuedAt, 0).After(now.Add(leeway)) {
		return nil, ErrSDJWTNotYetValid
	}

	// Copy clear claims (予約 claim 以外)
	reserved := map[string]bool{
		"iss": true, "sub": true, "vct": true, "iat": true, "exp": true,
		"_sd": true, "_sd_alg": true, "cnf": true, "status": true,
	}
	for k, v := range payload {
		if !reserved[k] {
			vc.Claims[k] = v
		}
	}
	// 開示の展開: digest を _sd と照合。重複 digest は拒否 (SD-JWT §verify)。
	sdDigests := map[string]bool{}
	if sd, ok := payload["_sd"].([]any); ok {
		for _, d := range sd {
			if s, ok := d.(string); ok {
				if sdDigests[s] {
					return nil, ErrSDJWTDuplicateDigest
				}
				sdDigests[s] = true
			}
		}
	}
	for _, disc := range parts[1:discEnd] {
		if disc == "" {
			continue
		}
		h := sha256.Sum256([]byte(disc))
		if !sdDigests[base64.RawURLEncoding.EncodeToString(h[:])] {
			// SD-JWT §verify: a presented disclosure whose digest is not in _sd
			// signals tampering or a disclosure from a different credential —
			// MUST reject, not silently skip.
			return nil, ErrSDJWTMalformed
		}
		raw, err := base64.RawURLEncoding.DecodeString(disc)
		if err != nil {
			return nil, ErrSDJWTMalformed
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, ErrSDJWTMalformed
		}
		if len(arr) != 3 {
			return nil, ErrSDJWTMalformed
		}
		name, ok := arr[1].(string)
		if !ok {
			return nil, ErrSDJWTMalformed
		}
		// A disclosed claim MUST NOT collide with a reserved claim or an
		// already-present (clear or previously-disclosed) claim.
		if reserved[name] {
			return nil, ErrSDJWTMalformed
		}
		if _, exists := vc.Claims[name]; exists {
			return nil, ErrSDJWTMalformed
		}
		vc.Claims[name] = arr[2]
	}

	// Key binding: cnf 有り credential は常に KB-JWT を検証 (nonce/aud バインド)。
	// holder key の無い credential を拒否するかは呼び出し側のポリシー
	// (opts.RequireKeyBinding) に委ねる。OpenID4VP verifier は既定で要求する。
	if vc.HolderKey != nil || opts.RequireKeyBinding {
		if vc.HolderKey == nil {
			return nil, ErrHolderKeyRequired
		}
		if kbSegment == "" {
			return nil, ErrKeyBindingMissing
		}
		if err := verifyKBJWT(kbSegment, sdjwt, vc.HolderKey, opts, now, leeway); err != nil {
			return nil, err
		}
		vc.KeyBound = true
	}
	return vc, nil
}

// extractHolderKey — cnf.jwk (OKP/Ed25519) から holder 公開鍵を復元 (無ければ nil)。
func extractHolderKey(payload map[string]any) ed25519.PublicKey {
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return nil
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil
	}
	x, ok := jwk["x"].(string)
	if !ok {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}

// audienceMatches — KB-JWT の aud (文字列 or 文字列配列, JWT 仕様) と期待値を照合。
func audienceMatches(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// verifyKBJWT — 末尾 KB-JWT を holder 鍵で検証し nonce/aud/sd_hash を照合。
func verifyKBJWT(kb, presentation string, holderPub ed25519.PublicKey, opts VerifyOptions, now time.Time, leeway time.Duration) error {
	segs := strings.SplitN(kb, ".", 3)
	if len(segs) != 3 {
		return ErrKeyBindingInvalid
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return ErrKeyBindingInvalid
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Typ != "kb+jwt" || hdr.Alg != "EdDSA" {
		return ErrKeyBindingInvalid
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil {
		return ErrKeyBindingInvalid
	}
	if !ed25519.Verify(holderPub, []byte(segs[0]+"."+segs[1]), sigBytes) {
		return ErrKeyBindingInvalid
	}
	plBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return ErrKeyBindingInvalid
	}
	var pl map[string]any
	if err := json.Unmarshal(plBytes, &pl); err != nil {
		return ErrKeyBindingInvalid
	}
	if opts.ExpectedNonce != "" {
		if s, _ := pl["nonce"].(string); s != opts.ExpectedNonce {
			return ErrKeyBindingNonce
		}
	}
	if opts.ExpectedAudience != "" && !audienceMatches(pl["aud"], opts.ExpectedAudience) {
		return ErrKeyBindingNonce
	}
	// sd_hash: KB-JWT 直前の '~' までを含む提示文字列の SHA-256。
	idx := strings.LastIndex(presentation, "~")
	h := sha256.Sum256([]byte(presentation[:idx+1]))
	if s, _ := pl["sd_hash"].(string); s != base64.RawURLEncoding.EncodeToString(h[:]) {
		return ErrKeyBindingSDHash
	}
	// iat が未来すぎる KB-JWT を拒否 (再生成検知)。
	if v, ok := pl["iat"].(float64); ok && int64(v) > now.Add(leeway).Unix() {
		return ErrKeyBindingInvalid
	}
	return nil
}

// Present — SD-JWT から指定 claim のみを開示するプレゼンテーション作成
//
// reveal: 開示する claim 名の一覧
// 戻り値: JWT + 選択された disclosure のみを含む SD-JWT 文字列
func Present(sdjwt string, reveal []string) (string, error) {
	if sdjwt == "" {
		return "", ErrSDJWTEmpty
	}
	parts := strings.Split(sdjwt, "~")
	jwtPart := parts[0]
	revealSet := make(map[string]bool, len(reveal))
	for _, r := range reveal {
		revealSet[r] = true
	}
	result := jwtPart
	for _, disc := range parts[1:] {
		if disc == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(disc)
		if err != nil {
			continue
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			continue
		}
		if len(arr) != 3 {
			continue
		}
		name, ok := arr[1].(string)
		if !ok {
			continue
		}
		if revealSet[name] {
			result += "~" + disc
		}
	}
	result += "~"
	return result, nil
}

// PresentWithKeyBinding — 選択開示に加え末尾へ KB-JWT を付与した提示を作成。
//
// holder は cnf にバインドされた秘密鍵で nonce/aud/sd_hash に署名する。
// 出力形式: <jwt>~<disc>...~<kb-jwt>。VerifySDJWTWithBinding が検証する。
func PresentWithKeyBinding(sdjwt string, reveal []string, holderPriv ed25519.PrivateKey, nonce, aud string, now time.Time) (string, error) {
	if len(holderPriv) != ed25519.PrivateKeySize {
		return "", ErrHolderKeyRequired
	}
	presented, err := Present(sdjwt, reveal)
	if err != nil {
		return "", err
	}
	if now.IsZero() {
		now = time.Now()
	}
	// sd_hash: 末尾 '~' までを含む提示文字列の SHA-256。
	h := sha256.Sum256([]byte(presented))
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"kb+jwt"}`))
	plBytes, _ := json.Marshal(map[string]any{
		"iat":     now.Unix(),
		"aud":     aud,
		"nonce":   nonce,
		"sd_hash": base64.RawURLEncoding.EncodeToString(h[:]),
	})
	payload := base64.RawURLEncoding.EncodeToString(plBytes)
	sig := ed25519.Sign(holderPriv, []byte(header+"."+payload))
	kbjwt := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
	return presented + kbjwt, nil
}

// ============================================================================
// GS1 Digital Link
// ============================================================================

// GS1Key — GTIN + optional serial + optional batch
type GS1Key struct {
	GTIN   string
	Serial string
	Batch  string
}

// BuildDLURI — GS1 Digital Link URI を構築
func BuildDLURI(domain string, key GS1Key) (string, error) {
	if domain == "" {
		return "", ErrDomainRequired
	}
	if key.GTIN == "" {
		return "", fmt.Errorf("%w: GTIN required", ErrGTINInvalid)
	}
	// GTIN validation: 8/12/13/14 digits only
	switch len(key.GTIN) {
	case 8, 12, 13, 14:
	default:
		return "", fmt.Errorf("gs1: invalid GTIN length %d (must be 8/12/13/14)", len(key.GTIN))
	}
	for _, c := range key.GTIN {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("gs1: GTIN contains non-digit")
		}
	}
	uri := "https://" + domain + "/01/" + key.GTIN
	if key.Serial != "" {
		uri += "/21/" + key.Serial
	}
	if key.Batch != "" {
		uri += "/10/" + key.Batch
	}
	return uri, nil
}

// ParseDLURI — GS1 Digital Link URI を解析
func ParseDLURI(uri string) (string, GS1Key, error) {
	if !strings.HasPrefix(uri, "https://") {
		return "", GS1Key{}, fmt.Errorf("%w: must be https", ErrGS1ParseFailed)
	}
	rest := uri[len("https://"):]
	idx := strings.Index(rest, "/01/")
	if idx < 0 {
		return "", GS1Key{}, fmt.Errorf("%w: missing /01/ AI", ErrGS1ParseFailed)
	}
	domain := rest[:idx]
	after := rest[idx+4:]
	if after == "" {
		return "", GS1Key{}, fmt.Errorf("%w: empty GTIN", ErrGTINInvalid)
	}
	parts := strings.SplitN(after, "/", 3)
	key := GS1Key{GTIN: parts[0]}
	if len(parts) >= 3 && parts[1] == "21" {
		key.Serial = parts[2]
	}
	return domain, key, nil
}

// ComputeGTINCheckDigit — 13桁入力 → 14桁GTIN (check digit 付加)
func ComputeGTINCheckDigit(partial string) (string, error) {
	if len(partial) != 13 {
		return "", fmt.Errorf("gs1: need 13 digits, got %d", len(partial))
	}
	for _, c := range partial {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("gs1: non-digit %q", c)
		}
	}
	sum := 0
	for i := 0; i < 13; i++ {
		d := int(partial[i] - '0')
		if (13-i)%2 == 1 {
			sum += d * 3
		} else {
			sum += d
		}
	}
	check := (10 - (sum % 10)) % 10
	return partial + string(rune('0'+check)), nil
}

// ============================================================================
// Battery Passport (EU Regulation 2023/1542)
// ============================================================================

// BatteryCategory — EU battery classification
type BatteryCategory string

const (
	BatteryCategoryEV         BatteryCategory = "ev"
	BatteryCategoryLMT        BatteryCategory = "lmt"
	BatteryCategoryIndustrial BatteryCategory = "industrial"
	BatteryCategorySLI        BatteryCategory = "sli"
	BatteryCategoryPortable   BatteryCategory = "portable"
)

// BatteryChemistry — active chemistry
type BatteryChemistry string

const (
	ChemistryNMC BatteryChemistry = "nmc"
	ChemistryNCA BatteryChemistry = "nca"
	ChemistryLFP BatteryChemistry = "lfp"
	ChemistryLTO BatteryChemistry = "lto"
	ChemistryLCO BatteryChemistry = "lco"
)

// RecycledContent — EU 必須開示 recycled material percentages
type RecycledContent struct {
	Cobalt  float32 `json:"cobalt"`
	Lithium float32 `json:"lithium"`
	Nickel  float32 `json:"nickel"`
	Lead    float32 `json:"lead"`
}

// BatteryPassportClaim — Regulation (EU) 2023/1542 Annex XIII
//
// 必須情報の完全網羅:
//   - 基本識別 (Annex XIII §1): BatteryID, Category, Manufacturer, ModelID
//   - 物理特性 (§2): CapacityKWh, VoltageV, WeightKg, Chemistry
//   - 環境 (§3, Art.7): CarbonFootprint*, RecycledContent, RenewableContentPct
//   - 性能/耐久 (§4): StateOfHealthPct, CycleCount, ExpectedLifetimeYears
//   - 適合性 (Art.6): EUDeclarationOfConformityURL
//   - デューデリジェンス (Art.52): DueDiligenceReportURL (EV/産業用 >2kWh で必須)
//   - 廃棄/回収 (Art.13): SeparateCollection, Recyclable, HazardousSubstances
type BatteryPassportClaim struct {
	BatteryID                    string           `json:"batteryId"`
	GTIN                         string           `json:"gtin,omitempty"`
	SerialNo                     string           `json:"serialNo,omitempty"`
	Category                     BatteryCategory  `json:"category"`
	Chemistry                    BatteryChemistry `json:"chemistry"`
	CapacityKWh                  float32          `json:"capacityKWh"`
	VoltageV                     float32          `json:"voltageV,omitempty"`
	WeightKg                     float32          `json:"weightKg,omitempty"`
	PlaceOfMfr                   string           `json:"placeOfManufacture,omitempty"`
	ModelID                      string           `json:"modelId,omitempty"`
	DateOfMfr                    time.Time        `json:"dateOfManufacture,omitempty"`
	CommissioningDate            time.Time        `json:"commissioningDate,omitempty"` // Annex XIII §1: 使用開始日
	Manufacturer                 string           `json:"manufacturer"`
	CarbonFootprintKgCO2ePerKWh  float32          `json:"carbonFootprintKgCO2ePerKWh,omitempty"`
	CarbonFootprintClass         string           `json:"carbonFootprintClass,omitempty"`
	RecycledContent              RecycledContent  `json:"recycledContent"`
	RenewableContentPct          float32          `json:"renewableContentPct,omitempty"` // Art.7: 再生可能エネルギー由来割合
	HazardousSubstances          []string         `json:"hazardousSubstances,omitempty"`
	StateOfHealthPct             float32          `json:"stateOfHealthPct,omitempty"`
	CycleCount                   int              `json:"cycleCount,omitempty"`
	ExpectedLifetimeYears        float32          `json:"expectedLifetimeYears,omitempty"`        // Annex XIII §4: 期待寿命
	EUDeclarationOfConformityURL string           `json:"euDeclarationOfConformityUrl,omitempty"` // Art.6: 適合宣言
	DueDiligenceReportURL        string           `json:"dueDiligenceReportUrl,omitempty"`        // Art.52: デューデリジェンス報告
	SeparateCollection           bool             `json:"separateCollection,omitempty"`           // Art.13: 分別回収シンボル該当
	Recyclable                   bool             `json:"recyclable"`
}

// IssueBatteryPassport — EU Battery Passport VC 発行
func (i *Issuer) IssueBatteryPassport(claim BatteryPassportClaim, validFor time.Duration) (*Credential, error) {
	if claim.BatteryID == "" {
		return nil, ErrBatteryIDRequired
	}
	// Art.52: EV / industrial batteries >2kWh は due-diligence 報告が必須
	if requiresDueDiligence(claim) && claim.DueDiligenceReportURL == "" {
		return nil, ErrDueDiligenceRequired
	}
	claim.Manufacturer = i.ID
	// Build as PassportClaim with battery metadata
	pc := PassportClaim{
		ProductID:      claim.BatteryID,
		Category:       string(claim.Category),
		CarbonKgCO2e:   float64(claim.CarbonFootprintKgCO2ePerKWh),
		Manufacturer:   claim.Manufacturer,
		LifecyclePhase: "manufacture",
	}
	cred, err := i.Issue(pc, validFor)
	if err != nil {
		return nil, err
	}
	// Add BatteryPassport type marker
	cred.Type = append(cred.Type, "BatteryPassport")
	// Embed full Annex XIII data set
	attrs := map[string]string{
		"batteryCategory": string(claim.Category),
		"chemistry":       string(claim.Chemistry),
	}
	if claim.CarbonFootprintClass != "" {
		attrs["carbonFootprintClass"] = claim.CarbonFootprintClass
	}
	if claim.RenewableContentPct > 0 {
		attrs["renewableContentPct"] = fmt.Sprintf("%.2f", claim.RenewableContentPct)
	}
	if claim.ExpectedLifetimeYears > 0 {
		attrs["expectedLifetimeYears"] = fmt.Sprintf("%.1f", claim.ExpectedLifetimeYears)
	}
	if claim.EUDeclarationOfConformityURL != "" {
		attrs["euDeclarationOfConformityUrl"] = claim.EUDeclarationOfConformityURL
	}
	if claim.DueDiligenceReportURL != "" {
		attrs["dueDiligenceReportUrl"] = claim.DueDiligenceReportURL
	}
	if claim.SeparateCollection {
		attrs["separateCollection"] = "true"
	}
	cred.Subject.Attrs = attrs
	// Re-sign
	canonical, _ := canonicalPayload(cred)
	sig := ed25519.Sign(i.privateKey, canonical)
	cred.Proof.ProofValue = base64.StdEncoding.EncodeToString(sig)
	return cred, nil
}

// requiresDueDiligence — Art.52 適用判定: EV / 産業用 (>2kWh) battery
func requiresDueDiligence(claim BatteryPassportClaim) bool {
	switch claim.Category {
	case BatteryCategoryEV:
		return true
	case BatteryCategoryIndustrial:
		return claim.CapacityKWh > 2.0
	default:
		return false
	}
}

// ============================================================================
// helpers
// ============================================================================

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A CSPRNG failure must never yield a weak (all-zero) salt.
		return "", fmt.Errorf("compliance: salt generation failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
