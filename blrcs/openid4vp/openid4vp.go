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
	ErrDCQLUnsatisfied     = errors.New("openid4vp: presented credential satisfies no dcql_query credential")
	ErrCredentialRevoked   = errors.New("openid4vp: presented credential is revoked")
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
	// Consume — ワンタイム: 使用後無効化 (リプレイ防止)。atomic な
	// check-and-delete であること: 既に消費済み (または不在/期限切れ) なら
	// ErrStateNotFound を返さねばならない。並行リプレイ検出のため、戻り値で
	// 「自分が消費に成功した唯一の呼び出しか」を判別できる必要がある。
	Consume(state string) error
}

// defaultMemStoreMax caps pending authorization sessions to prevent unbounded
// memory growth from unauthenticated CreateRequest floods. Each entry is small
// (~200B) so 50 000 entries ≈ 10 MB, a negligible fraction of typical heap.
// The GC loop clears expired entries every 5 minutes; this cap is the safety
// net for the attack window between GC ticks.
const defaultMemStoreMax = 50_000

// MemoryStore is an in-process SessionStore with a TTL-based GC ticker.
// It implements both SessionStore and io.Closer; callers must call Close when
// done to stop the background GC goroutine and prevent leaks.
type MemoryStore struct {
	mu      sync.Mutex
	once    sync.Once
	stop    chan struct{}
	data    map[string]*memEntry
	maxSize int
}

type memEntry struct {
	req     *AuthorizationRequest
	expires time.Time
}

// NewMemoryStore — インメモリ SessionStore 構築 (TTL 付き GC 内蔵)。
// The returned *MemoryStore implements io.Closer; call Close to stop the GC goroutine.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithCap(defaultMemStoreMax)
}

// NewMemoryStoreWithCap constructs a MemoryStore with a custom session cap.
// cap ≤ 0 is replaced by defaultMemStoreMax.
func NewMemoryStoreWithCap(cap int) *MemoryStore {
	if cap <= 0 {
		cap = defaultMemStoreMax
	}
	s := &MemoryStore{data: make(map[string]*memEntry), maxSize: cap, stop: make(chan struct{})}
	go s.gcLoop()
	return s
}

// Close stops the background GC goroutine. It is safe to call multiple times.
func (m *MemoryStore) Close() error {
	m.once.Do(func() { close(m.stop) })
	return nil
}

func (m *MemoryStore) Save(state string, req *AuthorizationRequest, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.data) >= m.maxSize {
		// Sweep one expired entry to make room before failing.
		now := time.Now()
		for k, e := range m.data {
			if now.After(e.expires) {
				delete(m.data, k)
				break
			}
		}
		if len(m.data) >= m.maxSize {
			return errors.New("openid4vp: session store full")
		}
	}
	m.data[state] = &memEntry{req: req, expires: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryStore) Load(state string) (*AuthorizationRequest, error) {
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

// Consume atomically invalidates a one-time state, returning ErrStateNotFound if
// the state was already consumed (or never existed / has expired). This lets
// ProcessResponse detect a concurrent replay: Load does not delete, so two
// simultaneous submissions of the same valid vp_token+state can both pass Load
// and both verify, but only the first Consume wins — the loser is rejected.
func (m *MemoryStore) Consume(state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[state]; !ok {
		return ErrStateNotFound
	}
	delete(m.data, state)
	return nil
}

func (m *MemoryStore) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.mu.Lock()
			now := time.Now()
			for k, e := range m.data {
				if now.After(e.expires) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		case <-m.stop:
			return
		}
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

	// TrustedIssuers — DCQL フロー用の DID→公開鍵マップ (JSON 非送信)。
	// dcql_query は PresentationDefinition.AcceptableIssuers を持たないため、
	// CreateRequestDCQL で発行した request の応答検証はこの集合を信頼アンカーとして
	// 使う。PresentationDefinition フローには影響しない (そちらは request 同梱の
	// AcceptableIssuers を使う)。空のままだと DCQL 応答は検証できない。
	TrustedIssuers map[string][]byte

	// RevocationChecker — 任意。設定すると、status_list 参照を持つ credential の提示時に
	// ProcessResponse がフロー内で失効確認する (fail-closed: revoked なら ErrCredentialRevoked)。
	// status list token の取得 (HTTP GET) は呼び出し側の責務 — このコールバック内で行う
	// ことで openid4vp の検証コアを network-free に保つ。典型実装は
	// compliance.CheckRevokedToken を status issuer 鍵付きで包む。nil の場合は確認せず、
	// VerifiedPresentation.Status を介して relying party が自分で確認できる。
	RevocationChecker func(status *compliance.StatusRef) (revoked bool, err error)

	// OnVerifyError — 任意。設定すると CallbackHandler は ProcessResponse の詳細エラーを
	// これに渡す (サーバ側ログ/監査用)。クライアントには常に一般化したメッセージのみ返す:
	// どの検証段階で失敗したか (issuer 不明 / 署名不一致 / 失効 / claim 欠落 等) を
	// 攻撃者に対する oracle として漏らさないため (CWE-209)。
	OnVerifyError func(error)

	// RequestSigningKey — 任意 (RFC 9101 JAR)。設定すると CreateRequest /
	// CreateRequestDCQL が署名なし query に加えて、request 全体を Ed25519 で署名した
	// JWT を `request` パラメータに同梱する。ウォレットは VerifyRequestObject で
	// response_uri / nonce / client_id の真正性を確認でき、本物の client_id を保ったまま
	// response_uri を差し替える relay 攻撃を検知できる。鍵が無い場合は従来どおり
	// 署名なし request のみ (back-compat)。署名検証鍵は ed25519.PrivateKey.Public()。
	RequestSigningKey ed25519.PrivateKey
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

// Close releases resources held by the Verifier. If the underlying SessionStore
// implements io.Closer (e.g. *MemoryStore), its GC goroutine is stopped.
// Calling Close multiple times is safe.
func (v *Verifier) Close() error {
	type closer interface{ Close() error }
	if c, ok := v.store.(closer); ok {
		return c.Close()
	}
	return nil
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
	nonce, err := randomB64(32)
	if err != nil {
		return "", "", err
	}
	state, err = randomB64(16)
	if err != nil {
		return "", "", err
	}
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
	reqURL, err := buildRequestURL(req, v.RequestSigningKey, v.DefaultTTL)
	if err != nil {
		return "", "", err
	}
	return reqURL, state, nil
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
	nonce, err := randomB64(32)
	if err != nil {
		return "", "", err
	}
	state, err = randomB64(16)
	if err != nil {
		return "", "", err
	}
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
	reqURL, err := buildRequestURL(req, v.RequestSigningKey, v.DefaultTTL)
	if err != nil {
		return "", "", err
	}
	return reqURL, state, nil
}

// buildRequestURL — request を query parameters へ。signKey が non-nil なら
// RFC 9101 の署名付き request object を `request` パラメータに追加で同梱する
// (署名なしパラメータは非 JAR ウォレット向けに残す)。
func buildRequestURL(req *AuthorizationRequest, signKey ed25519.PrivateKey, ttl time.Duration) (string, error) {
	q := url.Values{}
	q.Set("client_id", req.ClientID)
	q.Set("response_type", req.ResponseType)
	q.Set("response_mode", req.ResponseMode)
	q.Set("response_uri", req.ResponseURI)
	q.Set("nonce", req.Nonce)
	q.Set("state", req.State)
	if req.DCQLQuery != nil {
		// OpenID4VP v1.0 §5: dcql_query supersedes presentation_definition
		b, err := json.Marshal(req.DCQLQuery)
		if err != nil {
			return "", fmt.Errorf("openid4vp: marshal dcql_query: %w", err)
		}
		q.Set("dcql_query", string(b))
	} else {
		// OpenID4VP §5.4: presentation_definition (JSON string)
		b, err := json.Marshal(req.PresentationDefinition)
		if err != nil {
			return "", fmt.Errorf("openid4vp: marshal presentation_definition: %w", err)
		}
		q.Set("presentation_definition", string(b))
	}
	// RFC 9101 JAR (by value): 署名鍵があれば request 全体の署名付き JWT を同梱。
	if len(signKey) == ed25519.PrivateKeySize {
		jwt, err := signRequestObject(req, signKey, ttl)
		if err != nil {
			return "", err
		}
		q.Set("request", jwt)
	}
	return "openid4vp://authorize?" + q.Encode(), nil
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
	// Status — credential が status_list 失効参照を持つ場合に non-nil。relying party
	// はこれを使って revocation を確認できる (compliance.CheckRevokedToken)。verifier に
	// RevocationChecker を設定すれば ProcessResponse がフロー内で確認する。
	Status *compliance.StatusRef
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
	// Issuer Public Key 決定。
	// PresentationDefinition フローは request 同梱の AcceptableIssuers を信頼アンカーに
	// 使う。DCQL フロー (dcql_query は鍵を運ばない) は verifier-level の TrustedIssuers に
	// フォールバックする。
	acceptable := req.PresentationDefinition.AcceptableIssuers
	if len(acceptable) == 0 && req.DCQLQuery != nil {
		acceptable = v.TrustedIssuers
	}
	if len(acceptable) == 0 {
		return nil, errors.New("openid4vp: no acceptable issuers configured")
	}
	// この Authorization Request の nonce / client_id に提示を暗号的にバインド。
	// MaxKBAge を DefaultTTL に設定することで KB-JWT のフレッシュネスも保証する:
	// ウォレットが事前に KB-JWT を生成してキャッシュすることを防ぐ。
	// (nonce バインドが replay を防ぐが、iat フレッシュネスがセッション TTL を超えた
	//  古い提示を追加で防ぐ — SD-JWT draft §KB-JWT freshness requirement)
	opts := compliance.VerifyOptions{
		ExpectedNonce:     req.Nonce,
		ExpectedAudience:  v.ClientID,
		RequireKeyBinding: v.RequireKeyBinding,
		MaxKBAge:          v.DefaultTTL,
	}
	var verified *compliance.VerifiedClaims
	var usedIssuer string
	// Read the (unverified) iss claim once and verify against exactly that
	// issuer's key, instead of trial-verifying against every acceptable issuer
	// (O(issuers) Ed25519 verifies per token). The cryptographic check below is
	// what establishes trust; iss is only used to select the key.
	if claimedIss, ok := peekIssuer(resp.VPToken); ok {
		if pubKey, known := acceptable[claimedIss]; known {
			if vc, verr := compliance.VerifySDJWTWithBinding(resp.VPToken, ed25519.PublicKey(pubKey), opts); verr == nil && vc.Issuer == claimedIss {
				verified = vc
				usedIssuer = claimedIss
			}
		}
	}
	if verified == nil {
		return nil, errors.New("openid4vp: vp_token signature/issuer mismatch")
	}
	// クレーム制約の充足チェック。dcql_query (v1.0) があればそちらを優先し、
	// なければ従来の PresentationDefinition.RequiredClaims を使う。
	if req.DCQLQuery != nil {
		if err := enforceDCQLConstraints(req.DCQLQuery, verified); err != nil {
			return nil, err
		}
	} else {
		for _, rc := range req.PresentationDefinition.RequiredClaims {
			if _, ok := verified.Claims[rc]; !ok {
				return nil, fmt.Errorf("%w: %s", ErrClaimMissing, rc)
			}
		}
	}
	// 失効確認 (fail-closed)。RevocationChecker が設定されており credential が status
	// 参照を持つ場合のみ実行する。state 消費前に確認し、revoked なら state を温存して
	// 監査・再試行を可能にする。
	if v.RevocationChecker != nil && verified.Status != nil {
		revoked, rerr := v.RevocationChecker(verified.Status)
		if rerr != nil {
			return nil, fmt.Errorf("openid4vp: revocation check: %w", rerr)
		}
		if revoked {
			return nil, ErrCredentialRevoked
		}
	}

	// ワンタイム消費 (リプレイ防止)。Consume は atomic check-and-delete なので、
	// 同一 vp_token+state を並行送信した TOCTOU リプレイでは、Load・検証を両方が
	// 通過しても Consume に勝てるのは一方のみ。敗者は ErrStateNotFound で拒否し、
	// 一度きりの提示が二重に受理されるのを防ぐ。
	if err := v.store.Consume(resp.State); err != nil {
		return nil, err
	}

	return &VerifiedPresentation{
		State:     resp.State,
		Issuer:    usedIssuer,
		Subject:   verified.Subject,
		Claims:    verified.Claims,
		IssuedAt:  verified.IssuedAt,
		ExpiresAt: verified.Expires,
		Status:    verified.Status,
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

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("openid4vp: CSPRNG failure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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
