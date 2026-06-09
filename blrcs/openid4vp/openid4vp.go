// Package openid4vp — OpenID for Verifiable Presentations verifier
//
// 標準: OpenID4VP Draft 24 (2025), DIF Presentation Exchange 2.0
// Appleの動向: iOS 26 Safari 26 で W3C Digital Credentials API 経由
//
//	org-iso-mdoc + openid4vp-v1-unsigned/signed プロトコルに対応。
//	EUDI Wallet 規制 (eIDAS 2.0) 準拠。
//
// 役割:
//   - Verifier (BLRCS): ブランド/消費者サイト側で DPP を要求
//   - Wallet (ユーザ側): Apple Wallet / Google Wallet / EUDI Wallet
//
// 提示フロー:
//  1. Verifier creates Authorization Request (presentation_definition 含む)
//  2. Wallet redirects user, prompts disclosure consent
//  3. Wallet POSTs vp_token (SD-JWT-VC) + presentation_submission to redirect_uri
//  4. Verifier: signature verify + disclosure check + nonce anti-replay
//
// Apple式設計: シンプル公開API、内部複雑さ隠蔽、デフォルト安全
//   - NewVerifier → CreateRequest → ProcessResponse の3ステップ
//   - nonce生成・検証は内部、使う側が意識しない
//   - セッション状態は差替可能 (memory / KV / Redis)
package openid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"blrcs/compliance"
)

var (
	ErrNonceMismatch       = errors.New("openid4vp: nonce mismatch")
	ErrStateNotFound       = errors.New("openid4vp: unknown state / session expired")
	ErrPresentationMissing = errors.New("openid4vp: vp_token missing")
	ErrClaimMissing        = errors.New("openid4vp: required claim not disclosed")
	ErrDefinitionEmpty     = errors.New("openid4vp: presentation_definition requires >=1 input descriptor")
	ErrClientIDInvalid     = errors.New("openid4vp: invalid client_id (scheme/format)")
)

// ============================================================================
// Presentation Definition (DIF PE 2.0 簡易実装)
// ============================================================================

// PresentationDefinition — 何を要求するかの宣言
//
// Apple式の最小抽象:
//   - RequiredClaims: 絶対必要 (SD disclosureで必ず開示)
//   - AcceptableDIDs: 信頼する発行者DID一覧 (wire送信、walletが match に使う)
//   - AcceptableIssuers: verifier内部のDID→公開鍵マップ (JSON非送信、検証時のみ使う)
//   - Format: "sd-jwt" (MVP)、将来 "mso-mdoc" 追加可能
type PresentationDefinition struct {
	ID             string   `json:"id"`             // 一意識別子
	Purpose        string   `json:"purpose"`        // 人間可読 "Verify EU battery compliance"
	Format         string   `json:"format"`         // "sd-jwt" | "mso-mdoc"
	RequiredClaims []string `json:"requiredClaims"` // e.g. ["carbonKgCO2ePerKWh","batteryCategory"]
	AcceptableDIDs []string `json:"acceptableDIDs"` // wallet公開対象

	// AcceptableIssuers — verifier内部の公開鍵マップ (JSON シリアライズ対象外)
	// CreateRequest 前に AcceptableDIDs と整合させること
	AcceptableIssuers map[string][]byte `json:"-"`
}

// AuthorizationRequest — Wallet/ブラウザへ渡すリクエスト
//
// OpenID4VP 仕様フィールド + Appleが使う形式:
type AuthorizationRequest struct {
	ClientID               string                 `json:"client_id"`
	ResponseType           string                 `json:"response_type"` // "vp_token"
	ResponseMode           string                 `json:"response_mode"` // "direct_post"
	RedirectURI            string                 `json:"redirect_uri,omitempty"`
	ResponseURI            string                 `json:"response_uri,omitempty"` // direct_postモード
	Nonce                  string                 `json:"nonce"`
	State                  string                 `json:"state"`
	PresentationDefinition PresentationDefinition `json:"presentation_definition,omitempty"`
	DCQLQuery              *DCQLQuery             `json:"dcql_query,omitempty"` // OpenID4VP v1.0 §5 (PE 後継)
	CreatedAt              time.Time              `json:"-"`                    // サーバ内部
}

// AuthorizationResponse — Walletから受け取るレスポンス
type AuthorizationResponse struct {
	VPToken                string          `json:"vp_token"` // SD-JWT 文字列
	PresentationSubmission json.RawMessage `json:"presentation_submission,omitempty"`
	State                  string          `json:"state"`
}

// ============================================================================
// SessionStore — 差替可能、Apple式の拡張性保証
// ============================================================================

// SessionStore — nonce/state → Authorization Request の対応を管理
// 実装: MemoryStore (MVP) / Redis / Cloudflare KV (本番)
type SessionStore interface {
	Save(state string, req *AuthorizationRequest, ttl time.Duration) error
	Load(state string) (*AuthorizationRequest, error)
	Consume(state string) error // ワンタイム: 使用後無効化 (リプレイ防止)
}

type memoryStore struct {
	mu   sync.Mutex
	data map[string]*memEntry
}

type memEntry struct {
	req     *AuthorizationRequest
	expires time.Time
}

// NewMemoryStore — インメモリ SessionStore 構築 (TTL 付き GC 内蔵)。
func NewMemoryStore() SessionStore {
	s := &memoryStore{data: make(map[string]*memEntry)}
	go s.gcLoop()
	return s
}

func (m *memoryStore) Save(state string, req *AuthorizationRequest, ttl time.Duration) error {
	m.mu.Lock()
	m.data[state] = &memEntry{req: req, expires: time.Now().Add(ttl)}
	m.mu.Unlock()
	return nil
}

func (m *memoryStore) Load(state string) (*AuthorizationRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[state]
	if !ok {
		return nil, ErrStateNotFound
	}
	if time.Now().After(e.expires) {
		delete(m.data, state)
		return nil, ErrStateNotFound
	}
	return e.req, nil
}

func (m *memoryStore) Consume(state string) error {
	m.mu.Lock()
	delete(m.data, state)
	m.mu.Unlock()
	return nil
}

func (m *memoryStore) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		m.mu.Lock()
		now := time.Now()
		for k, e := range m.data {
			if now.After(e.expires) {
				delete(m.data, k)
			}
		}
		m.mu.Unlock()
	}
}

// ============================================================================
// Verifier — Apple式シンプル公開API
// ============================================================================

// Verifier — BLRCS side OpenID4VP verifier
//
// ClientID: verifier Origin (例 "https://verify.blrcs.example")
// ResponseURI: Walletが POST で回答する endpoint
// DefaultTTL: Authorization Request の有効時間
type Verifier struct {
	ClientID    string
	ResponseURI string
	store       SessionStore
	DefaultTTL  time.Duration

	// RequireKeyBinding — true なら holder binding (cnf + KB-JWT) 無しの提示を拒否。
	// NewVerifier は既定で true (secure-by-default): holder key の無い credential は
	// 暗号的に nonce へバインドできず、捕捉した vp_token がリプレイ可能なため。
	// bearer credential を許容する場合のみ明示的に false を設定する
	// (anti-replay はワンタイム state 消費のみに依存することになる)。
	RequireKeyBinding bool
}

// NewVerifier — Apple式の1行構築。secure-by-default で RequireKeyBinding=true。
func NewVerifier(clientID, responseURI string, store SessionStore) *Verifier {
	if store == nil {
		store = NewMemoryStore()
	}
	return &Verifier{
		ClientID:          clientID,
		ResponseURI:       responseURI,
		store:             store,
		DefaultTTL:        10 * time.Minute,
		RequireKeyBinding: true,
	}
}

// CreateRequest — 新 Authorization Request を発行
//
// 戻り値: QRやディープリンクに埋込む URL (openid4vp://...) と state
// Walletはこの URL を解釈し、ユーザに同意を求めた後、vp_token を ResponseURI に POST する
func (v *Verifier) CreateRequest(def PresentationDefinition) (requestURL string, state string, err error) {
	if err := ValidateClientID(v.ClientID); err != nil {
		return "", "", err
	}
	if len(def.RequiredClaims) == 0 {
		return "", "", ErrDefinitionEmpty
	}
	if def.Format == "" {
		def.Format = "sd-jwt"
	}
	// AcceptableIssuers map から AcceptableDIDs を自動生成 (wire送信用)
	if len(def.AcceptableDIDs) == 0 && len(def.AcceptableIssuers) > 0 {
		def.AcceptableDIDs = make([]string, 0, len(def.AcceptableIssuers))
		for did := range def.AcceptableIssuers {
			def.AcceptableDIDs = append(def.AcceptableDIDs, did)
		}
	}
	nonce := randomB64(32)
	state = randomB64(16)
	req := &AuthorizationRequest{
		ClientID:               v.ClientID,
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post",
		ResponseURI:            v.ResponseURI,
		Nonce:                  nonce,
		State:                  state,
		PresentationDefinition: def,
		CreatedAt:              time.Now().UTC(),
	}
	if err := v.store.Save(state, req, v.DefaultTTL); err != nil {
		return "", "", err
	}
	return buildRequestURL(req), state, nil
}

// CreateRequestDCQL — OpenID4VP v1.0 §5 の dcql_query で Authorization Request を作成。
//
// Presentation Exchange は v1.0 で削除されたため、v1.0 準拠ウォレットには
// こちらを使う。query は §6 に従い検証される。
func (v *Verifier) CreateRequestDCQL(query DCQLQuery) (requestURL string, state string, err error) {
	if err := ValidateClientID(v.ClientID); err != nil {
		return "", "", err
	}
	if err := query.Validate(); err != nil {
		return "", "", err
	}
	nonce := randomB64(32)
	state = randomB64(16)
	req := &AuthorizationRequest{
		ClientID:     v.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  v.ResponseURI,
		Nonce:        nonce,
		State:        state,
		DCQLQuery:    &query,
		CreatedAt:    time.Now().UTC(),
	}
	if err := v.store.Save(state, req, v.DefaultTTL); err != nil {
		return "", "", err
	}
	return buildRequestURL(req), state, nil
}

// 本番は request_uri モード推奨 (URLが長大化しないよう)、MVP は inline query parameters
func buildRequestURL(req *AuthorizationRequest) string {
	q := url.Values{}
	q.Set("client_id", req.ClientID)
	q.Set("response_type", req.ResponseType)
	q.Set("response_mode", req.ResponseMode)
	q.Set("response_uri", req.ResponseURI)
	q.Set("nonce", req.Nonce)
	q.Set("state", req.State)
	// presentation_definition は JSON 文字列として渡す (OpenID4VP §5.4)
	pdBytes, _ := json.Marshal(req.PresentationDefinition)
	q.Set("presentation_definition", string(pdBytes))
	return "openid4vp://authorize?" + q.Encode()
}

// ============================================================================
// ProcessResponse — Wallet からの vp_token を受付・検証
// ============================================================================

// VerifiedPresentation — 検証後の結果 (Apple式のシンプルな戻り値)
type VerifiedPresentation struct {
	State     string
	Issuer    string
	Subject   string
	Claims    map[string]any // 開示されたクレーム (SD-JWT)
	IssuedAt  int64
	ExpiresAt int64
}

// ProcessResponse — Wallet Authorization Response を検証
//
// 手順:
//  1. state を store から Load — 存在・非期限切れを確認
//  2. vp_token (SD-JWT) の署名検証
//  3. PresentationDefinition.RequiredClaims がすべて disclosed であることを確認
//  4. cnf 付き credential は KB-JWT の holder 署名 + nonce + aud を検証 (リプレイ防止)
//  5. state を Consume (使い捨て、リプレイ防止)
func (v *Verifier) ProcessResponse(resp *AuthorizationResponse) (*VerifiedPresentation, error) {
	if resp.VPToken == "" {
		return nil, ErrPresentationMissing
	}
	req, err := v.store.Load(resp.State)
	if err != nil {
		return nil, err
	}
	// Issuer Public Key 決定
	// PresentationDefinition.AcceptableIssuers に登録された発行者のいずれかで検証できれば OK
	if len(req.PresentationDefinition.AcceptableIssuers) == 0 {
		return nil, errors.New("openid4vp: no acceptable issuers configured")
	}
	// この Authorization Request の nonce / client_id に提示を暗号的にバインド。
	opts := compliance.VerifyOptions{
		ExpectedNonce:     req.Nonce,
		ExpectedAudience:  v.ClientID,
		RequireKeyBinding: v.RequireKeyBinding,
	}
	var verified *compliance.VerifiedClaims
	var usedIssuer string
	// Read the (unverified) iss claim once and verify against exactly that
	// issuer's key, instead of trial-verifying against every acceptable issuer
	// (O(issuers) Ed25519 verifies per token). The cryptographic check below is
	// what establishes trust; iss is only used to select the key.
	if claimedIss, ok := peekIssuer(resp.VPToken); ok {
		if pubKey, known := req.PresentationDefinition.AcceptableIssuers[claimedIss]; known {
			if vc, verr := compliance.VerifySDJWTWithBinding(resp.VPToken, ed25519.PublicKey(pubKey), opts); verr == nil && vc.Issuer == claimedIss {
				verified = vc
				usedIssuer = claimedIss
			}
		}
	}
	if verified == nil {
		return nil, errors.New("openid4vp: vp_token signature/issuer mismatch")
	}
	// 必須 claim 開示チェック
	for _, req := range req.PresentationDefinition.RequiredClaims {
		if _, ok := verified.Claims[req]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrClaimMissing, req)
		}
	}
	// ワンタイム消費 (リプレイ防止)
	_ = v.store.Consume(resp.State)

	return &VerifiedPresentation{
		State:     resp.State,
		Issuer:    usedIssuer,
		Subject:   verified.Subject,
		Claims:    verified.Claims,
		IssuedAt:  verified.IssuedAt,
		ExpiresAt: verified.Expires,
	}, nil
}

// ============================================================================
// Helpers
// ============================================================================

// peekIssuer extracts the UNVERIFIED `iss` claim from an SD-JWT vp_token so the
// verifier can select the matching issuer key. The signature is verified
// separately; this only chooses which key to verify against.
func peekIssuer(vpToken string) (string, bool) {
	jwt := vpToken
	if i := strings.IndexByte(jwt, '~'); i >= 0 {
		jwt = jwt[:i]
	}
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss == "" {
		return "", false
	}
	return claims.Iss, true
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ParseResponseForm — HTTP POST form body (application/x-www-form-urlencoded) を parse
// Walletの direct_post 実装対応のため
func ParseResponseForm(body string) (*AuthorizationResponse, error) {
	vals, err := url.ParseQuery(body)
	if err != nil {
		return nil, fmt.Errorf("openid4vp: parse form: %w", err)
	}
	vp := vals.Get("vp_token")
	state := vals.Get("state")
	if vp == "" || state == "" {
		return nil, errors.New("openid4vp: missing vp_token or state")
	}
	resp := &AuthorizationResponse{VPToken: vp, State: state}
	if ps := vals.Get("presentation_submission"); ps != "" {
		resp.PresentationSubmission = json.RawMessage(ps)
	}
	return resp, nil
}

// BuildResponseForm — Wallet side: レスポンスを form エンコード (テスト支援)
func BuildResponseForm(resp *AuthorizationResponse) string {
	v := url.Values{}
	v.Set("vp_token", resp.VPToken)
	v.Set("state", resp.State)
	if len(resp.PresentationSubmission) > 0 {
		v.Set("presentation_submission", string(resp.PresentationSubmission))
	}
	return v.Encode()
}

// StripTrailingTilde — SD-JWT 末尾~を削除 (OpenID4VP vp_token 伝送用)
// 本MVPでは標準SD-JWTをそのまま使うので明示的なstrip不要
func StripTrailingTilde(s string) string {
	return strings.TrimSuffix(s, "~")
}
