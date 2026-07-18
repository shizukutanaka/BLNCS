// Package openid4vci — Verifiable Credential Issuance
//
// OpenID4VCI 1.0 Final 準拠。Apple/Google/EUDI wallet 互換。
// Pre-Authorized Code Flow (consumer側操作最小、Apple推奨)。
//
// 対称設計 — verifier (openid4vp) の反対側:
//
//	issuer → credential_offer URL → wallet
//	  → wallet fetches issuer metadata
//	  → wallet exchanges pre-auth code for access token
//	  → wallet requests credential with proof-of-possession
//	  → issuer returns signed SD-JWT
//
// Apple原則:
//   - 5エンドポイント全て明示的な動詞 (offer, token, credential, meta, jwks)
//   - メタデータ自動公開 (/.well-known/openid-credential-issuer)
//   - 公開鍵JWKSを自動公開 (/.well-known/jwks.json)
//   - claim → credential configuration 宣言的マッピング
package openid4vci

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"blrcs/compliance"
)

var (
	ErrUnknownConfig      = errors.New("vci: unknown credential_configuration_id")
	ErrBadPreAuthCode     = errors.New("vci: pre-authorized_code invalid or consumed")
	ErrBadAccessToken     = errors.New("vci: access_token invalid or expired")
	ErrMissingClaims      = errors.New("vci: required claims missing from offer")
	ErrInvalidProof       = errors.New("vci: proof invalid")
	ErrProofNonceMismatch = errors.New("vci: proof nonce mismatch")
	ErrBadTxCode          = errors.New("vci: transaction code (tx_code) missing or incorrect")
	// ErrFormatMismatch is returned when the wallet's credential_configuration_id or
	// format field does not match the configuration bound to the pre-authorized offer.
	// Accepting a mismatched format would allow credential-format-confusion attacks
	// (a wallet requests a weaker/different format than the issuer configured, and
	// the issuer silently issues its own format anyway — confusing both parties about
	// what was actually bound).
	ErrFormatMismatch = errors.New("vci: credential format or configuration_id mismatch")
	// ErrUnknownNotification is returned by HandleNotification when the
	// notification_id is unknown, expired, already consumed, or was not issued to
	// the presented access_token. Deliberately collapses all four cases into one
	// error (mirrors the pre-authorized_code/tx_code oracle defense elsewhere in
	// this file): distinguishing "wrong token" from "unknown id" would let a
	// caller probe for valid notification_ids issued to other wallets.
	ErrUnknownNotification = errors.New("vci: unknown, expired, or already-consumed notification_id")
	// ErrInvalidNotificationEvent is returned when the event field is not one of
	// the three values OpenID4VCI 1.0 §10.1 defines.
	ErrInvalidNotificationEvent = errors.New("vci: notification event must be credential_accepted, credential_failure, or credential_deleted")
)

// Notification event values (OpenID4VCI 1.0 §10.1).
const (
	NotificationEventAccepted = "credential_accepted"
	NotificationEventFailure  = "credential_failure"
	NotificationEventDeleted  = "credential_deleted"
)

// ============================================================================
// Types
// ============================================================================

// CredentialConfiguration — 発行可能なクレデンシャル種別
//
// Apple式宣言的スキーマ: どんなクレームを発行するかの契約
type CredentialConfiguration struct {
	ID                string   // 例: "eu-battery-passport-v1"
	Format            string   // "dc+sd-jwt" (current) / "vc+sd-jwt" (legacy, still verifier-accepted)
	CredentialType    string   // "BatteryPassport" / "DigitalProductPassport"
	Scope             string   // OAuth2 scope
	DisclosableClaims []string // SD開示可 (プライバシーガード対象)
	ClearClaims       []string // 常時開示
	ValidForDays      int
}

// preAuthEntry — 発行キュー内部エントリ
type preAuthEntry struct {
	code           string
	configID       string
	subject        string
	sdClaims       map[string]any
	clearClaims    map[string]any
	expiresAt      time.Time
	accessToken    string // 一度交換されると埋まる
	tokenExpiresAt time.Time
	consumed       bool                  // credentialエンドポイント使用済み
	cNonce         string                // Proof-of-Possession nonce (token交換時に発行)
	txCode         string                // 取引コード (PIN)。空なら不要。設定時は ExchangeCode で必須照合。
	txCodeFails    int                   // tx_code 失敗回数 (ブルートフォース防御)
	status         *compliance.StatusRef // 失効参照 (任意)。設定時は発行クレデンシャルに埋込。
}

// ============================================================================
// Issuer
// ============================================================================

// Issuer — OpenID4VCI credential issuer
//
// URL例:
//
//	IssuerURL = "https://issue.blrcs.example"
//	Metadata:    GET {IssuerURL}/.well-known/openid-credential-issuer
//	JWKS:        GET {IssuerURL}/.well-known/jwks.json
//	Offer (QR):  openid-credential-offer://...
//	Token:       POST {IssuerURL}/token
//	Credential:  POST {IssuerURL}/credential
type Issuer struct {
	URL          string
	RequireProof bool               // OpenID4VCI 1.0 Final §8.2.1.1: Proof-of-Possession を必須化
	signer       *compliance.Issuer // 既存の compliance.Issuer を再利用 (DRY)
	configs      map[string]CredentialConfiguration
	preAuthTTL   time.Duration
	tokenTTL     time.Duration
	// MaxTxCodeAttempts — tx_code の許容失敗回数。超過で pre-authorized code を無効化し
	// 短い PIN へのブルートフォースを防ぐ (1.0 Final §6.1 推奨)。0 は既定 (5) を使う。
	MaxTxCodeAttempts int

	// OnTxCodeLockout — 任意。tx_code (PIN) の失敗が上限に達し pre-authorized code を
	// 無効化した (burn した) ときに呼ばれる、ブルートフォース検知用の監査フック。
	// 引数は攻撃対象の offer を識別する subject / configID のみで、秘密 (code・PIN・
	// tx_code) は決して渡さない。eIDAS/DPP の監査証跡要件向け。ロック解放後に呼ばれる
	// ため、フック内から Issuer を再呼び出ししても安全。nil なら何もしない (既定)。
	OnTxCodeLockout func(subject, configID string)

	// OnNotification — 任意。wallet が Notification Endpoint (OpenID4VCI 1.0 §10) 経由で
	// 発行済みクレデンシャルの受理/失敗/削除を通知してきたときに呼ばれる監査フック。
	// eIDAS/DPP の「発行したクレデンシャルを wallet が実際に受理したか」の監査証跡要件
	// 向け。引数は subject/configID/event/eventDescription のみで、notification_id や
	// access_token などの秘密は渡さない。nil なら何もしない (既定)。
	OnNotification func(subject, configID, event, eventDescription string)

	// NotificationTTL — notification_id の有効期限。0 は既定 (24h) を使う。issuance と
	// 実際の wallet 側受理確認の間には (offer/token の TTL よりずっと長い) 現実的な遅延が
	// あり得るため、pre-auth/token より長い既定値にしている。
	NotificationTTL time.Duration

	mu            sync.Mutex
	preAuths      map[string]*preAuthEntry      // code → entry
	tokens        map[string]*preAuthEntry      // access_token → same entry
	nonces        map[string]time.Time          // Nonce Endpoint c_nonce → expiry (single-use)
	notifications map[string]*notificationEntry // notification_id → entry (single-use)
	lastGC        time.Time                     // 最後に期限切れ掃除を実行した時刻
}

// notificationEntry — Notification Endpoint 用の内部エントリ。issuance 成功時に
// 発行され、wallet が対応する access_token 付きで notification_id を提示したときのみ
// 消費される (単一使用)。
type notificationEntry struct {
	accessToken string // 発行時に使われた access_token — 同じトークンの提示を要求 (spec)
	subject     string
	configID    string
	expiresAt   time.Time
	consumed    bool
}

// defaultNotificationTTL — notification_id の既定有効期限。
const defaultNotificationTTL = 24 * time.Hour

// gcInterval — 期限切れエントリ掃除の最小間隔。CreateOffer ごとに O(n) 走査すると
// コストが嵩むため、掃除はこの間隔に1回までに制限する (償却 O(1))。
const gcInterval = 1 * time.Minute

// gcExpiredLocked — 期限切れの pre-authorized code / access token を退避する。
// 呼び出し側は iss.mu を保持していること。
//
// preAuths / tokens は成功・burn 経路でしか縮まないため、発行されたが一度も
// 引き換えられなかった offer / token (放置フロー) がマップに永久に残り、無制限の
// メモリ増加 (DoS 面) になっていた。新規エントリが増える唯一の経路である
// CreateOffer から時間ゲート付きで本掃除を呼び、両マップのサイズを
// 「未期限切れエントリ + 直近バースト分」に拘束する。
func (iss *Issuer) gcExpiredLocked(now time.Time) {
	if now.Sub(iss.lastGC) < gcInterval {
		return
	}
	iss.lastGC = now
	for code, e := range iss.preAuths {
		if now.After(e.expiresAt) {
			delete(iss.preAuths, code)
		}
	}
	for tok, e := range iss.tokens {
		if !e.tokenExpiresAt.IsZero() && now.After(e.tokenExpiresAt) {
			delete(iss.tokens, tok)
		}
	}
	for id, e := range iss.notifications {
		if now.After(e.expiresAt) {
			delete(iss.notifications, id)
		}
	}
}

// defaultMaxTxCodeAttempts — tx_code 失敗の既定上限。
const defaultMaxTxCodeAttempts = 5

// notificationTTL returns iss.NotificationTTL, falling back to the default
// when unset.
func (iss *Issuer) notificationTTL() time.Duration {
	if iss.NotificationTTL > 0 {
		return iss.NotificationTTL
	}
	return defaultNotificationTTL
}

// NewIssuer — Apple式の1行構築
//
// signerDID は compliance.Issuer 経由で ed25519 鍵を生成/保持する既存の仕組み
// 同一鍵で DPP credential も SD-JWT も署名可能 (DRY)
func NewIssuer(url string, signer *compliance.Issuer) *Issuer {
	return &Issuer{
		URL:           strings.TrimRight(url, "/"),
		signer:        signer,
		configs:       make(map[string]CredentialConfiguration),
		preAuths:      make(map[string]*preAuthEntry),
		tokens:        make(map[string]*preAuthEntry),
		nonces:        make(map[string]time.Time),
		notifications: make(map[string]*notificationEntry),
		preAuthTTL:    10 * time.Minute,
		tokenTTL:      5 * time.Minute,
	}
}

// RegisterConfiguration — 発行可能な credential config を登録
func (iss *Issuer) RegisterConfiguration(c CredentialConfiguration) {
	if c.Format == "" {
		// dc+sd-jwt is the current SD-JWT-VC typ (renamed from vc+sd-jwt, Nov 2024
		// draft; compliance.Issuer has issued dc+sd-jwt by default since Axis 113).
		// Defaulting here to the retired string would advertise a format id that no
		// longer matches what IssueCredentialWithProof actually signs.
		c.Format = "dc+sd-jwt"
	}
	if c.ValidForDays == 0 {
		c.ValidForDays = 365
	}
	iss.mu.Lock()
	iss.configs[c.ID] = c
	iss.mu.Unlock()
}

// isSDJWTVCFormat reports whether a credential_configuration Format string names
// the SD-JWT-VC profile — the current "dc+sd-jwt" or the retired-but-still-
// verifier-accepted "vc+sd-jwt". These use a top-level `vct` in issuer metadata
// rather than the W3C-VC-style credential_definition.type.
func isSDJWTVCFormat(format string) bool {
	return format == "dc+sd-jwt" || format == "vc+sd-jwt"
}

// Signer — 内部コンポーネント統合用 (MCP層から鍵にアクセスするため)
func (iss *Issuer) Signer() *compliance.Issuer { return iss.signer }

// ============================================================================
// Phase 1 — Offer creation (issuer → holder の第一歩)
// ============================================================================

// CreateOffer — 消費者に「このクレデンシャルを保存する？」を促すオファー
//
// 戻り値: credential_offer URL (QR/ディープリンク化してユーザに提示)
//
// 内部で pre-authorized code を発行し、TTL付きで保管。
// Wallet がこのコードを使って /token エンドポイントで access_token を取得する。
// TxCodeSpec describes the transaction code (PIN) the wallet must collect from the
// user before redeeming a pre-authorized code (OpenID4VCI 1.0 Final §6.1). The
// metadata is advertised in the offer; the code *value* is communicated to the user
// out-of-band (never in the offer). All fields are optional.
type TxCodeSpec struct {
	InputMode   string // "numeric" (default) | "text"
	Length      int    // expected length (0 = unspecified)
	Description string // human-readable hint shown by the wallet
}

// OfferOptions carries the optional knobs for a credential offer. The zero value
// reproduces CreateOffer (no transaction code, no revocation status).
type OfferOptions struct {
	// TxCode — transaction code (PIN) value; empty disables tx_code binding.
	TxCode string
	// TxCodeSpec — optional tx_code metadata advertised to the wallet.
	TxCodeSpec *TxCodeSpec
	// Status — optional revocation reference embedded in the issued credential so the
	// verifier can later check status (draft-ietf-oauth-status-list). The issuer owns
	// status-index allocation; this records which (URI, index) the credential occupies.
	Status *compliance.StatusRef
}

// CreateOffer creates a pre-authorized credential offer with no transaction code.
func (iss *Issuer) CreateOffer(configID, subject string, sdClaims, clearClaims map[string]any) (string, string, error) {
	return iss.CreateOfferWithOptions(configID, subject, sdClaims, clearClaims, OfferOptions{})
}

// CreateOfferWithTxCode creates a pre-authorized offer bound to a transaction code
// (PIN). The returned offer advertises that a tx_code is required (per spec metadata
// only, never the value); ExchangeCode then requires the matching code, defeating
// interception of the pre-authorized code alone (e.g. a photographed QR offer).
//
// txCode is the secret value to communicate to the user out-of-band; spec is optional
// metadata describing how the wallet should collect it. An empty txCode behaves like
// CreateOffer (no tx_code).
func (iss *Issuer) CreateOfferWithTxCode(configID, subject string, sdClaims, clearClaims map[string]any, txCode string, spec *TxCodeSpec) (string, string, error) {
	return iss.CreateOfferWithOptions(configID, subject, sdClaims, clearClaims, OfferOptions{TxCode: txCode, TxCodeSpec: spec})
}

// CreateOfferWithOptions creates a pre-authorized offer with full control over the
// transaction code and revocation status. When opts.Status is set, the credential
// issued for this offer carries the status_list reference, so a VCI-issued credential
// can be revoked (and, with proof-of-possession, be holder-bound and revocable at once).
func (iss *Issuer) CreateOfferWithOptions(configID, subject string, sdClaims, clearClaims map[string]any, opts OfferOptions) (string, string, error) {
	iss.mu.Lock()
	cfg, ok := iss.configs[configID]
	iss.mu.Unlock()
	if !ok {
		return "", "", ErrUnknownConfig
	}
	// 必須 claim 存在チェック (Apple式 early-fail)
	for _, c := range cfg.DisclosableClaims {
		if _, has := sdClaims[c]; !has {
			// 宣言されたSDクレームが offer に無い → warning レベルだが、今は strict
			return "", "", fmt.Errorf("%w: %s", ErrMissingClaims, c)
		}
	}
	code, err := randomB64(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	iss.mu.Lock()
	iss.gcExpiredLocked(now) // 放置された期限切れ offer/token を退避 (無制限増加防止)
	iss.preAuths[code] = &preAuthEntry{
		code:        code,
		configID:    configID,
		subject:     subject,
		sdClaims:    sdClaims,
		clearClaims: clearClaims,
		expiresAt:   now.Add(iss.preAuthTTL),
		txCode:      opts.TxCode,
		status:      opts.Status,
	}
	iss.mu.Unlock()
	preAuthGrant := map[string]any{
		"pre-authorized_code": code,
	}
	if opts.TxCode != "" {
		// Advertise that a tx_code is required (metadata only — never the value).
		tc := map[string]any{}
		if opts.TxCodeSpec != nil {
			if opts.TxCodeSpec.InputMode != "" {
				tc["input_mode"] = opts.TxCodeSpec.InputMode
			}
			if opts.TxCodeSpec.Length > 0 {
				tc["length"] = opts.TxCodeSpec.Length
			}
			if opts.TxCodeSpec.Description != "" {
				tc["description"] = opts.TxCodeSpec.Description
			}
		}
		preAuthGrant["tx_code"] = tc
	}
	offer := map[string]any{
		"credential_issuer":            iss.URL,
		"credential_configuration_ids": []string{configID},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": preAuthGrant,
		},
	}
	b, _ := json.Marshal(offer)
	offerURL := "openid-credential-offer://?credential_offer=" + urlEscape(string(b))
	return offerURL, code, nil
}

// ============================================================================
// Phase 2 — Token exchange (wallet ← pre-auth code)
// ============================================================================

// TokenResponse — OAuth2 Token Endpoint 応答
type TokenResponse struct {
	AccessToken          string          `json:"access_token"`
	TokenType            string          `json:"token_type"` // "Bearer"
	ExpiresIn            int             `json:"expires_in"`
	CNonce               string          `json:"c_nonce"` // Proof-of-Possession nonce
	CNonceExpiresIn      int             `json:"c_nonce_expires_in"`
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// ExchangeCode — pre-auth code → access_token
//
// RFC 6749 §4.4 準拠、Pre-Authorized Code Flow。
// ワンタイム: code は消費後無効化。
// ExchangeCode redeems a pre-authorized code with no transaction code. If the offer
// set a tx_code, this fails with ErrBadTxCode — use ExchangeCodeWithTxCode.
func (iss *Issuer) ExchangeCode(code string) (*TokenResponse, error) {
	return iss.ExchangeCodeWithTxCode(code, "")
}

// ExchangeCodeWithTxCode redeems a pre-authorized code, enforcing the transaction
// code (PIN) when the offer was created with one. The comparison is constant-time.
func (iss *Issuer) ExchangeCodeWithTxCode(code, txCode string) (*TokenResponse, error) {
	// Audit hook for brute-force lockout. Captured under the lock, fired after it
	// is released (LIFO defers: unlock runs before this), so the callback can
	// safely re-enter the Issuer and never holds iss.mu.
	var lockedOut bool
	var loSubject, loConfig string
	defer func() {
		if lockedOut && iss.OnTxCodeLockout != nil {
			iss.OnTxCodeLockout(loSubject, loConfig)
		}
	}()
	iss.mu.Lock()
	defer iss.mu.Unlock()
	entry, ok := iss.preAuths[code]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, ErrBadPreAuthCode
	}
	if entry.accessToken != "" {
		// 既に交換済み
		return nil, ErrBadPreAuthCode
	}
	// tx_code (PIN) binding: when the offer set one, redemption must present the exact
	// value. Constant-time compare avoids leaking the code via response timing. Failed
	// attempts are counted; once the limit is exceeded the code is invalidated so a
	// short PIN cannot be brute-forced (1.0 Final §6.1).
	if entry.txCode != "" {
		if subtle.ConstantTimeCompare([]byte(entry.txCode), []byte(txCode)) != 1 {
			entry.txCodeFails++
			limit := iss.MaxTxCodeAttempts
			if limit <= 0 {
				limit = defaultMaxTxCodeAttempts
			}
			if entry.txCodeFails >= limit {
				delete(iss.preAuths, code) // burn the code; further attempts → ErrBadPreAuthCode
				lockedOut = true           // signal the audit hook (fired after unlock)
				loSubject, loConfig = entry.subject, entry.configID
			}
			return nil, ErrBadTxCode
		}
	}
	accessToken, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	cNonce, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	entry.accessToken = accessToken
	entry.tokenExpiresAt = time.Now().Add(iss.tokenTTL)
	entry.cNonce = cNonce // Proof-of-Possession 用 nonce を保持
	iss.tokens[accessToken] = entry
	// code は消費済みにする
	delete(iss.preAuths, code)
	return &TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(iss.tokenTTL.Seconds()),
		CNonce:          cNonce,
		CNonceExpiresIn: int(iss.tokenTTL.Seconds()), // must not exceed access token lifetime
	}, nil
}

// ============================================================================
// Phase 3 — Credential issuance (wallet ← access_token)
// ============================================================================

// CredentialRequest — Wallet からのリクエスト
type CredentialRequest struct {
	Format                    string          `json:"format"`
	CredentialConfigurationID string          `json:"credential_configuration_id,omitempty"`
	Proof                     json.RawMessage `json:"proof,omitempty"` // 単一鍵保有証明 (MVP では未必須)
	// Proofs — batch issuance 用の複数鍵保有証明 (OpenID4VCI 1.0 §8.2)。proof と
	// 相互排他。設定時は proofs.jwt の各鍵ごとに1クレデンシャルを発行し、
	// BatchCredentialResponse (credentials 配列) を返す。1回の往復で複数の単一使用
	// unlinkable コピーを得るための、提示リンク可能性緩和の標準機構。
	Proofs *ProofsObject `json:"proofs,omitempty"`
}

// ProofsObject — batch 鍵保有証明群 (OpenID4VCI 1.0 §8.2)。jwt proof type の場合、
// jwt は各鍵の proof JWT 配列 (それぞれ §8.2.1.1 の形式)。
type ProofsObject struct {
	JWT []string `json:"jwt,omitempty"`
}

// maxBatchProofs — batch 発行の proof 上限。無制限だと単一トークンで大量の署名を
// 誘発する DoS 面になるため上限を設ける。実運用の unlinkable コピー数として十分。
const maxBatchProofs = 32

// CredentialResponse — SD-JWT credential 応答 (単一)
type CredentialResponse struct {
	Credential      string `json:"credential"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
	// NotificationID — Notification Endpoint (OpenID4VCI 1.0 §10) 経由で、この
	// クレデンシャルの受理/失敗/削除を issuer に通知する際に提示する識別子。
	NotificationID string `json:"notification_id,omitempty"`
}

// CredentialObject — batch 応答の credentials 配列要素 (OpenID4VCI 1.0)。
type CredentialObject struct {
	Credential string `json:"credential"`
}

// BatchCredentialResponse — batch 発行応答 (credentials 配列, OpenID4VCI 1.0 §8.3)。
// notification_id は「1応答で発行された1つ以上のクレデンシャル」を識別するため、
// batch 全体で1つ (spec)。
type BatchCredentialResponse struct {
	Credentials     []CredentialObject `json:"credentials"`
	CNonce          string             `json:"c_nonce,omitempty"`
	CNonceExpiresIn int                `json:"c_nonce_expires_in,omitempty"`
	NotificationID  string             `json:"notification_id,omitempty"`
}

// IssueCredential — access_token を検証し SD-JWT を生成 (proof なし / 後方互換)
func (iss *Issuer) IssueCredential(accessToken string) (*CredentialResponse, error) {
	return iss.IssueCredentialWithProof(accessToken, CredentialRequest{})
}

// IssueCredentialWithProof — access_token + Proof-of-Possession を検証し SD-JWT を生成。
//
// OpenID4VCI 1.0 Final §8.2.1.1:
//   - req.Proof が存在する場合は proof JWT を検証 (typ, alg, nonce, aud, iat, 署名)
//   - iss.RequireProof=true かつ proof 欠如 → ErrInvalidProof
//   - proof なし かつ iss.RequireProof=false → 従来動作 (後方互換)
func (iss *Issuer) IssueCredentialWithProof(accessToken string, req CredentialRequest) (*CredentialResponse, error) {
	iss.mu.Lock()
	entry, ok := iss.tokens[accessToken]
	if !ok || time.Now().After(entry.tokenExpiresAt) || entry.consumed {
		iss.mu.Unlock()
		return nil, ErrBadAccessToken
	}
	cfg, cfgOk := iss.configs[entry.configID]
	if !cfgOk {
		iss.mu.Unlock()
		return nil, ErrUnknownConfig
	}
	// Validate the wallet's format / configuration_id against the offer's binding.
	// Must happen under the lock but before consumed=true so no rollback is needed.
	// Accepting a mismatched value would allow credential-format-confusion: the wallet
	// could request a different configuration or weaker format than the issuer set up,
	// and the issuer would silently issue its own format — confusing both parties and
	// undermining the pre-auth code binding that ties a specific credential type to
	// each offer.
	if req.CredentialConfigurationID != "" && req.CredentialConfigurationID != entry.configID {
		iss.mu.Unlock()
		return nil, ErrFormatMismatch
	}
	if req.Format != "" && req.Format != cfg.Format {
		iss.mu.Unlock()
		return nil, ErrFormatMismatch
	}
	// Optimistically consume under lock; restore on error below.
	entry.consumed = true
	cNonce := entry.cNonce
	subject, sdClaims, clearClaims := entry.subject, entry.sdClaims, entry.clearClaims
	status := entry.status
	validForDays := cfg.ValidForDays
	iss.mu.Unlock()

	restore := func() { iss.mu.Lock(); entry.consumed = false; iss.mu.Unlock() }

	// Proof-of-Possession validation (OpenID4VCI 1.0 Final §8.2.1.1)
	var holderKey ed25519.PublicKey
	if len(req.Proof) > 0 {
		var proofEnv struct {
			ProofType string `json:"proof_type"`
			JWT       string `json:"jwt"`
		}
		if err := json.Unmarshal(req.Proof, &proofEnv); err != nil || proofEnv.ProofType != "jwt" || proofEnv.JWT == "" {
			restore()
			return nil, ErrInvalidProof
		}
		// The wallet proved possession of this key; bind the credential to it so
		// the holder can later produce a KB-JWT (cnf) in OpenID4VP. Discarding the
		// key would yield a bearer credential that the secure-by-default VP verifier
		// (RequireKeyBinding=true) rejects — defeating the proof-of-possession step.
		pub, err := iss.verifyProofOfPossession(proofEnv.JWT, cNonce)
		if err != nil {
			restore()
			return nil, err
		}
		holderKey = pub
	} else if iss.RequireProof {
		restore()
		return nil, ErrInvalidProof
	}

	validFor := time.Duration(validForDays) * 24 * time.Hour
	vct := issuanceVCT(cfg)
	sdjwt, err := iss.signBoundCredential(vct, subject, sdClaims, clearClaims, holderKey, status, validFor)
	if err != nil {
		restore()
		return nil, err
	}
	// Rotate c_nonce per OpenID4VCI spec: the rotated nonce is stored under the
	// token entry so that proof-of-possession for a subsequent credential request
	// (multi-use token or deferred issuance) is bound to the new challenge.
	// Without this write-back, newCNonce is dead code: the entry retains the old
	// nonce indefinitely, making every retry use the same stale nonce.
	newCNonce, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	// notification_id (OpenID4VCI 1.0 §10): lets the wallet later tell this issuer
	// whether it actually accepted/stored the credential, failed to, or deleted it —
	// an audit signal issuance alone cannot provide. Bound to the access_token used
	// for this issuance (spec requires the same token to submit the notification)
	// so a caller cannot notify about a credential it never received.
	notificationID, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	iss.mu.Lock()
	entry.cNonce = newCNonce
	iss.gcExpiredLocked(time.Now())
	iss.notifications[notificationID] = &notificationEntry{
		accessToken: accessToken,
		subject:     subject,
		configID:    entry.configID,
		expiresAt:   time.Now().Add(iss.notificationTTL()),
	}
	iss.mu.Unlock()
	return &CredentialResponse{
		Credential:      sdjwt,
		CNonce:          newCNonce,
		CNonceExpiresIn: int(iss.tokenTTL.Seconds()), // must not exceed access token lifetime
		NotificationID:  notificationID,
	}, nil
}

// verifyProofOfPossession parses and validates a single key-proof JWT and returns
// the holder public key it proves possession of. The proof's nonce must be either
// the token-bound c_nonce or a fresh, single-use Nonce Endpoint nonce (consumed
// here so it cannot be replayed). Checking the token-bound value first avoids
// consuming a Nonce Endpoint nonce when the wallet used the legacy flow. Shared by
// the single- and batch-issuance paths so the replay defense lives in one place.
func (iss *Issuer) verifyProofOfPossession(proofJWT, cNonce string) (ed25519.PublicKey, error) {
	pub, proofNonce, err := parseProofJWT(proofJWT, iss.URL)
	if err != nil {
		return nil, err
	}
	if proofNonce != cNonce && !iss.consumeNonce(proofNonce) {
		return nil, ErrProofNonceMismatch
	}
	return pub, nil
}

// issuanceVCT returns the vct to stamp on issued credentials for a configuration,
// falling back to the DPP default when the config declares none (preserving
// behavior for configs that never set CredentialType) — a non-empty value MUST be
// honored so differently-configured credential_configurations don't collapse to
// the same vct despite advertising distinct types in issuer metadata.
func issuanceVCT(cfg CredentialConfiguration) string {
	if cfg.CredentialType != "" {
		return cfg.CredentialType
	}
	return compliance.VCTDigitalProductPassport
}

// signBoundCredential issues one SD-JWT VC with whichever combination the offer +
// proof selected: holder-bound (cnf) when proof-of-possession was provided, and/or
// revocable (status_list) when the offer set a status reference. Shared by the
// single- and batch-issuance paths.
func (iss *Issuer) signBoundCredential(vct, subject string, sdClaims, clearClaims map[string]any, holderKey ed25519.PublicKey, status *compliance.StatusRef, validFor time.Duration) (string, error) {
	var sdjwt string
	var err error
	switch {
	case holderKey != nil && status != nil:
		sdjwt, _, err = iss.signer.IssueSDJWTVCBoundStatus(vct, subject, sdClaims, clearClaims, holderKey, status, validFor)
	case holderKey != nil:
		sdjwt, _, err = iss.signer.IssueSDJWTVCBound(vct, subject, sdClaims, clearClaims, holderKey, validFor)
	case status != nil:
		sdjwt, _, err = iss.signer.IssueSDJWTVCStatus(vct, subject, sdClaims, clearClaims, status, validFor)
	default:
		sdjwt, _, err = iss.signer.IssueSDJWTVC(vct, subject, sdClaims, clearClaims, validFor)
	}
	if err != nil {
		return "", fmt.Errorf("vci: sdjwt sign: %w", err)
	}
	return sdjwt, nil
}

// IssueBatchWithProofs issues one credential per key proof in req.Proofs, binding
// each to the corresponding holder key (OpenID4VCI 1.0 batch issuance, §8.2/§8.3).
// This is the standard mechanism for a wallet to obtain multiple single-use,
// unlinkable credential copies in one round trip — the EUDI-approved-crypto
// mitigation for presentation linkability.
//
// All proofs are validated up-front before any credential is signed (all-or-
// nothing): a batch where any single proof fails yields no credentials and does
// not consume the access token, so a wallet can safely retry. One notification_id
// covers the whole response (spec: a notification_id "identifies one or more
// Credentials issued in one Credential Response").
func (iss *Issuer) IssueBatchWithProofs(accessToken string, req CredentialRequest) (*BatchCredentialResponse, error) {
	if req.Proofs == nil || len(req.Proofs.JWT) == 0 {
		return nil, ErrInvalidProof
	}
	// proof and proofs are mutually exclusive (§8.2): accepting both would leave
	// it ambiguous which key(s) the issued credential(s) are bound to.
	if len(req.Proof) > 0 {
		return nil, ErrInvalidProof
	}
	if len(req.Proofs.JWT) > maxBatchProofs {
		return nil, fmt.Errorf("vci: batch of %d proofs exceeds limit of %d", len(req.Proofs.JWT), maxBatchProofs)
	}

	iss.mu.Lock()
	entry, ok := iss.tokens[accessToken]
	if !ok || time.Now().After(entry.tokenExpiresAt) || entry.consumed {
		iss.mu.Unlock()
		return nil, ErrBadAccessToken
	}
	cfg, cfgOk := iss.configs[entry.configID]
	if !cfgOk {
		iss.mu.Unlock()
		return nil, ErrUnknownConfig
	}
	if req.CredentialConfigurationID != "" && req.CredentialConfigurationID != entry.configID {
		iss.mu.Unlock()
		return nil, ErrFormatMismatch
	}
	if req.Format != "" && req.Format != cfg.Format {
		iss.mu.Unlock()
		return nil, ErrFormatMismatch
	}
	entry.consumed = true
	cNonce := entry.cNonce
	subject, sdClaims, clearClaims := entry.subject, entry.sdClaims, entry.clearClaims
	status := entry.status
	validForDays := cfg.ValidForDays
	iss.mu.Unlock()

	restore := func() { iss.mu.Lock(); entry.consumed = false; iss.mu.Unlock() }

	// Validate every proof first (all-or-nothing) so a partial batch is never
	// issued and a wallet whose Nth proof was malformed can retry cleanly.
	holderKeys := make([]ed25519.PublicKey, 0, len(req.Proofs.JWT))
	for _, jwt := range req.Proofs.JWT {
		if jwt == "" {
			restore()
			return nil, ErrInvalidProof
		}
		pub, err := iss.verifyProofOfPossession(jwt, cNonce)
		if err != nil {
			restore()
			return nil, err
		}
		holderKeys = append(holderKeys, pub)
	}

	validFor := time.Duration(validForDays) * 24 * time.Hour
	vct := issuanceVCT(cfg)
	creds := make([]CredentialObject, 0, len(holderKeys))
	for _, hk := range holderKeys {
		sdjwt, err := iss.signBoundCredential(vct, subject, sdClaims, clearClaims, hk, status, validFor)
		if err != nil {
			restore()
			return nil, err
		}
		creds = append(creds, CredentialObject{Credential: sdjwt})
	}

	newCNonce, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	notificationID, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	iss.mu.Lock()
	entry.cNonce = newCNonce
	iss.gcExpiredLocked(time.Now())
	iss.notifications[notificationID] = &notificationEntry{
		accessToken: accessToken,
		subject:     subject,
		configID:    entry.configID,
		expiresAt:   time.Now().Add(iss.notificationTTL()),
	}
	iss.mu.Unlock()
	return &BatchCredentialResponse{
		Credentials:     creds,
		CNonce:          newCNonce,
		CNonceExpiresIn: int(iss.tokenTTL.Seconds()),
		NotificationID:  notificationID,
	}, nil
}

// ============================================================================
// Phase 3b — Notification Endpoint (OpenID4VCI 1.0 §10)
// ============================================================================

// NotificationRequest is the wallet's request body to the Notification
// Endpoint (OpenID4VCI 1.0 §10).
type NotificationRequest struct {
	NotificationID   string `json:"notification_id"`
	Event            string `json:"event"`
	EventDescription string `json:"event_description,omitempty"`
}

// HandleNotification processes a wallet's notification about the outcome of
// issuing a specific credential (OpenID4VCI 1.0 Notification Endpoint,
// §10). accessToken must be the SAME token used for the credential request
// that returned this notification_id (spec requirement) — this is what lets
// an issuer trust that the notifier actually received that credential rather
// than guessing another wallet's notification_id.
//
// notification_id is single-use: a second submission (retry, replay) returns
// ErrUnknownNotification rather than silently re-invoking OnNotification,
// matching the burn-after-use pattern already used for pre-authorized codes
// and Nonce Endpoint nonces elsewhere in this file.
func (iss *Issuer) HandleNotification(accessToken string, req NotificationRequest) error {
	switch req.Event {
	case NotificationEventAccepted, NotificationEventFailure, NotificationEventDeleted:
	default:
		return ErrInvalidNotificationEvent
	}
	iss.mu.Lock()
	entry, ok := iss.notifications[req.NotificationID]
	if !ok || entry.consumed || time.Now().After(entry.expiresAt) ||
		subtle.ConstantTimeCompare([]byte(entry.accessToken), []byte(accessToken)) != 1 {
		iss.mu.Unlock()
		return ErrUnknownNotification
	}
	entry.consumed = true
	subject, configID := entry.subject, entry.configID
	hook := iss.OnNotification
	iss.mu.Unlock()

	if hook != nil {
		hook(subject, configID, req.Event, req.EventDescription)
	}
	return nil
}

// verifyProofJWT — OpenID4VCI 1.0 Final §8.2.1.1 の proof JWT を検証する。
//
// 対応アルゴリズム: EdDSA (Ed25519) のみ (ゼロ依存制約)。
// header に jwk (OKP/Ed25519) が必須。expectedNonce に proof の nonce を束縛する
// (token-endpoint 由来の c_nonce 用)。Nonce Endpoint 由来の nonce を許容するには
// parseProofJWT を直接呼び、nonce を呼び出し側で検証すること。
func verifyProofJWT(proofJWT, expectedNonce, issuerURL string) (ed25519.PublicKey, error) {
	pub, nonce, err := parseProofJWT(proofJWT, issuerURL)
	if err != nil {
		return nil, err
	}
	if nonce != expectedNonce {
		return nil, ErrProofNonceMismatch
	}
	return pub, nil
}

// parseProofJWT verifies a proof JWT's structure, algorithm (EdDSA), embedded JWK
// (OKP/Ed25519), signature, audience (== issuerURL), and iat freshness, returning
// the holder public key and the proof's embedded nonce. It deliberately does NOT
// validate the nonce value: the caller decides which nonces are acceptable — the
// token-bound c_nonce, or a single-use Nonce Endpoint nonce — so the same parser
// serves both the legacy token-endpoint flow and the dedicated Nonce Endpoint
// (the OpenID4VCI mitigation for proof replay).
func parseProofJWT(proofJWT, issuerURL string) (ed25519.PublicKey, string, error) {
	parts := strings.SplitN(proofJWT, ".", 3)
	if len(parts) != 3 {
		return nil, "", ErrInvalidProof
	}
	// header
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", ErrInvalidProof
	}
	var hdr struct {
		Alg string          `json:"alg"`
		Typ string          `json:"typ"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "EdDSA" || hdr.Typ != "openid4vci-proof+jwt" || len(hdr.JWK) == 0 {
		return nil, "", ErrInvalidProof
	}
	// JWK (OKP Ed25519)
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(hdr.JWK, &jwk); err != nil || jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, "", ErrInvalidProof
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, "", ErrInvalidProof
	}
	pub := ed25519.PublicKey(keyBytes)
	// signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, "", ErrInvalidProof
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sigBytes) {
		return nil, "", ErrInvalidProof
	}
	// payload
	plBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", ErrInvalidProof
	}
	var pl struct {
		Nonce string `json:"nonce"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
	}
	if err := json.Unmarshal(plBytes, &pl); err != nil {
		return nil, "", ErrInvalidProof
	}
	if pl.Aud != issuerURL {
		return nil, "", ErrInvalidProof
	}
	// iat freshness: ±5 分
	iat := time.Unix(pl.Iat, 0)
	now := time.Now()
	if iat.After(now.Add(30*time.Second)) || iat.Before(now.Add(-5*time.Minute)) {
		return nil, "", ErrInvalidProof
	}
	return pub, pl.Nonce, nil
}

// ============================================================================
// Nonce Endpoint (OpenID4VCI §7) — proof-replay mitigation
// ============================================================================

// maxNonces bounds the Nonce Endpoint store so an attacker hammering /nonce
// cannot exhaust memory. Expired entries are swept on each issuance; if the live
// set still exceeds this cap, IssueNonce fails closed (ErrNonceStoreFull) rather
// than growing without bound.
const maxNonces = 50_000

// ErrNonceStoreFull is returned by IssueNonce when the live nonce set is at the
// cap (after sweeping expired entries) — backpressure against /nonce flooding.
var ErrNonceStoreFull = errors.New("vci: nonce store full")

// IssueNonce mints a fresh, single-use c_nonce for the Nonce Endpoint
// (OpenID4VCI §7). The wallet places it in a proof JWT's `nonce` claim; the
// credential endpoint accepts it exactly once (see consumeNonce). Decoupling
// nonce issuance from the token response is the spec's mitigation for proof
// replay: every credential request can be bound to an unpredictable, server-
// issued, single-use challenge. The nonce expires after tokenTTL.
func (iss *Issuer) IssueNonce() (cNonce string, expiresIn int, err error) {
	n, err := randomB64(16)
	if err != nil {
		return "", 0, err
	}
	iss.mu.Lock()
	defer iss.mu.Unlock()
	now := time.Now()
	// Opportunistic sweep of expired nonces (also bounds memory).
	for k, exp := range iss.nonces {
		if now.After(exp) {
			delete(iss.nonces, k)
		}
	}
	if len(iss.nonces) >= maxNonces {
		return "", 0, ErrNonceStoreFull
	}
	iss.nonces[n] = now.Add(iss.tokenTTL)
	return n, int(iss.tokenTTL.Seconds()), nil
}

// consumeNonce reports whether n is a currently-valid Nonce Endpoint nonce,
// removing it so it can never be replayed (single-use). An unknown or expired
// nonce returns false. The delete-before-expiry-check makes even an expired-but-
// present nonce one-shot.
func (iss *Issuer) consumeNonce(n string) bool {
	if n == "" {
		return false
	}
	iss.mu.Lock()
	defer iss.mu.Unlock()
	exp, ok := iss.nonces[n]
	if !ok {
		return false
	}
	delete(iss.nonces, n)
	return time.Now().Before(exp)
}

// handleNonce serves POST {issuer}/nonce, returning a fresh single-use c_nonce
// (OpenID4VCI §7). Per spec the response is non-cacheable.
func (iss *Issuer) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n, expiresIn, err := iss.IssueNonce()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"c_nonce":            n,
		"c_nonce_expires_in": expiresIn,
	})
}

// ============================================================================
// Phase 4 — Metadata + JWKS public discovery
// ============================================================================

// Metadata — /.well-known/openid-credential-issuer 応答
func (iss *Issuer) Metadata() map[string]any {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	configs := make(map[string]any, len(iss.configs))
	for id, cfg := range iss.configs {
		entry := map[string]any{
			"format": cfg.Format,
			"scope":  cfg.Scope,
			"cryptographic_binding_methods_supported": []string{"did:web"},
			"credential_signing_alg_values_supported": []string{"EdDSA"},
			// proof_types_supported (OpenID4VCI 1.0 §11.2.3): the wallet must know
			// which proof types/algorithms the issuer accepts before attempting
			// issuance. This mirrors exactly what parseProofJWT enforces — a
			// jwt-typed proof (typ=openid4vci-proof+jwt) signed with EdDSA.
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{"EdDSA"},
				},
			},
		}
		// The SD-JWT-VC format profile (dc+sd-jwt / legacy vc+sd-jwt) identifies
		// the credential type with a top-level `vct`, NOT the jwt_vc_json-style
		// `credential_definition.type` (which belongs to the W3C VC formats). A
		// wallet reading credential_configurations_supported for an SD-JWT-VC
		// config expects `vct`; the old shape broke display-metadata-driven
		// wallets. Non-SD-JWT formats keep the credential_definition.type shape.
		if isSDJWTVCFormat(cfg.Format) {
			entry["vct"] = cfg.CredentialType
		} else {
			entry["credential_definition"] = map[string]any{"type": []string{"VerifiableCredential", cfg.CredentialType}}
		}
		configs[id] = entry
	}
	return map[string]any{
		"credential_issuer":                   iss.URL,
		"credential_endpoint":                 iss.URL + "/credential",
		"token_endpoint":                      iss.URL + "/token",
		"nonce_endpoint":                      iss.URL + "/nonce",
		"notification_endpoint":               iss.URL + "/notification",
		"credential_configurations_supported": configs,
		"grant_types_supported":               []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"response_types_supported":            []string{"vp_token"},
		"jwks_uri":                            iss.URL + "/.well-known/jwks.json",
	}
}

// JWKS — 公開鍵 (Ed25519, OKP curve Ed25519)
func (iss *Issuer) JWKS() map[string]any {
	pub := iss.signer.PublicKey()
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"use": "sig",
				"alg": "EdDSA",
				"kid": iss.signer.ID + "#key-1",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	}
}

// ============================================================================
// HTTP handler — Apple式 1-liner wiring
//
//   mux.Handle(issuer.URL + "/", issuer.Handler())
// ============================================================================

// Handler — 全 VCI エンドポイント mux 済みの http.Handler
func (iss *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-credential-issuer", iss.handleMetadata)
	mux.HandleFunc("/.well-known/jwks.json", iss.handleJWKS)
	mux.HandleFunc("/token", iss.handleToken)
	mux.HandleFunc("/nonce", iss.handleNonce)
	mux.HandleFunc("/credential", iss.handleCredential)
	mux.HandleFunc("/notification", iss.handleNotification)
	return mux
}

func (iss *Issuer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(iss.Metadata())
}

func (iss *Issuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_ = json.NewEncoder(w).Encode(iss.JWKS())
}

func (iss *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536) // 64 KiB: ample for any token request
	if err := r.ParseForm(); err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		writeVCIError(w, http.StatusBadRequest, "unsupported_grant_type", "only pre-auth supported")
		return
	}
	code := r.Form.Get("pre-authorized_code")
	if code == "" {
		writeVCIError(w, http.StatusBadRequest, "invalid_grant", "pre-authorized_code required")
		return
	}
	tr, err := iss.ExchangeCodeWithTxCode(code, r.Form.Get("tx_code"))
	if err != nil {
		// Do not reveal whether the code or the tx_code (PIN) was wrong, or whether the
		// code was already consumed: distinguishing these is an oracle that helps an
		// attacker brute-force the PIN or confirm a stolen code (CWE-209).
		writeVCIError(w, http.StatusBadRequest, "invalid_grant", "pre-authorized_code or tx_code invalid")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(tr)
}

func (iss *Issuer) handleCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeVCIError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
		return
	}
	accessToken := strings.TrimPrefix(authz, "Bearer ")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "request body too large or unreadable")
		return
	}
	var req CredentialRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeVCIError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
			return
		}
	}
	// Batch issuance (OpenID4VCI §8.2): a `proofs` object yields a `credentials`
	// array; the legacy singular `proof` yields a single `credential`.
	var resp any
	if req.Proofs != nil && len(req.Proofs.JWT) > 0 {
		resp, err = iss.IssueBatchWithProofs(accessToken, req)
	} else {
		resp, err = iss.IssueCredentialWithProof(accessToken, req)
	}
	if err != nil {
		writeCredentialError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// writeCredentialError maps an issuance error to an opaque client-safe response
// (CWE-209): internal details (signer state, key IDs, nonce oracle) must not
// leak. Shared by the single- and batch-issuance HTTP paths.
func writeCredentialError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBadAccessToken):
		writeVCIError(w, http.StatusUnauthorized, "invalid_token", "access token invalid or expired")
	case errors.Is(err, ErrProofNonceMismatch), errors.Is(err, ErrInvalidProof):
		writeVCIError(w, http.StatusBadRequest, "invalid_proof", "proof validation failed")
	case errors.Is(err, ErrUnknownConfig):
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "unknown credential configuration")
	case errors.Is(err, ErrFormatMismatch):
		writeVCIError(w, http.StatusBadRequest, "invalid_request", "credential format or configuration_id mismatch")
	default:
		writeVCIError(w, http.StatusInternalServerError, "server_error", "credential issuance failed")
	}
}

// handleNotification serves POST {issuer}/notification (OpenID4VCI 1.0 §10):
// the wallet reports whether it accepted, failed to store, or deleted a
// previously-issued credential, identified by the notification_id returned
// in that credential's CredentialResponse. Requires the same Bearer token
// used for the original credential request.
func (iss *Issuer) handleNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeVCIError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
		return
	}
	accessToken := strings.TrimPrefix(authz, "Bearer ")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096)) // 4 KiB: ample for notification_id/event/event_description
	if err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_notification_request", "request body too large or unreadable")
		return
	}
	var req NotificationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_notification_request", "malformed request body")
		return
	}
	if err := iss.HandleNotification(accessToken, req); err != nil {
		if errors.Is(err, ErrInvalidNotificationEvent) {
			writeVCIError(w, http.StatusBadRequest, "invalid_notification_request", err.Error())
		} else {
			writeVCIError(w, http.StatusBadRequest, "invalid_notification_id", "unknown, expired, or already-consumed notification_id")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeVCIError(w http.ResponseWriter, code int, errName, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errName,
		"error_description": desc,
	})
}

// ============================================================================
// Helpers
// ============================================================================

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("vci: CSPRNG failure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func urlEscape(s string) string {
	// 単純 URL-encode (標準 url.QueryEscape で十分だが明示的な wrapping で置換可能)
	// Avoid importing net/url just for this — use inline replacement for known unsafe chars
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-' || c == '_' || c == '.' || c == '~':
			out = append(out, c)
		default:
			out = append(out, '%')
			const hex = "0123456789ABCDEF"
			out = append(out, hex[c>>4], hex[c&0x0F])
		}
	}
	return string(out)
}

// ============================================================================
// Wallet side helpers (for MockWallet / client SDK)
//
// WalletClient simulates the wallet pulling the credential.
// ============================================================================

// walletMaxResponseBytes caps HTTP response body reads to guard against
// a malicious or misconfigured issuer sending unbounded data.
const walletMaxResponseBytes = 4 << 20 // 4 MiB

// WalletClient — wallet 実装向けの薄いクライアント
type WalletClient struct {
	HTTP    *http.Client
	BaseURL string
}

// NewWalletClient — テスト/SDK用
func NewWalletClient(baseURL string) *WalletClient {
	return &WalletClient{
		HTTP:    &http.Client{Timeout: 10 * time.Second},
		BaseURL: strings.TrimRight(baseURL, "/"),
	}
}

// FetchCredential — 1コールで pre-auth code → token → credential の3ステップ完了
//
// Apple式: 複雑なOAuth/OIDCフローを1メソッドで隠蔽
func (c *WalletClient) FetchCredential(preAuthCode string) (string, error) {
	return c.FetchCredentialCtx(context.Background(), preAuthCode)
}

// FetchCredentialCtx is FetchCredential with caller-supplied context for timeout/cancellation.
func (c *WalletClient) FetchCredentialCtx(ctx context.Context, preAuthCode string) (string, error) {
	// token endpoint
	form := strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=" + preAuthCode)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/token", form)
	if err != nil {
		return "", fmt.Errorf("wallet: token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("wallet: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, walletMaxResponseBytes))
		return "", fmt.Errorf("wallet: token %d: %s", resp.StatusCode, b)
	}
	var tr TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, walletMaxResponseBytes)).Decode(&tr); err != nil {
		return "", fmt.Errorf("wallet: token decode: %w", err)
	}
	// credential endpoint. Format is intentionally omitted: this generic wallet
	// client has no way to know which format string a given issuer configuration
	// advertises (dc+sd-jwt today, previously vc+sd-jwt, potentially mso_mdoc for a
	// future config) — IssueCredentialWithProof only enforces a format match when
	// the wallet supplies one, so omitting it lets the issuer's own registered
	// config decide, matching how a real wallet would read credential_configuration_id
	// from the offer rather than guessing a format string.
	body, _ := json.Marshal(CredentialRequest{})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/credential", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("wallet: credential request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp2, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("wallet: credential request: %w", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp2.Body, walletMaxResponseBytes))
		return "", fmt.Errorf("wallet: credential %d: %s", resp2.StatusCode, b)
	}
	var cr CredentialResponse
	if err := json.NewDecoder(io.LimitReader(resp2.Body, walletMaxResponseBytes)).Decode(&cr); err != nil {
		return "", fmt.Errorf("wallet: credential decode: %w", err)
	}
	return cr.Credential, nil
}

// FetchMetadata — discovery endpoint helper
func (c *WalletClient) FetchMetadata() (map[string]any, error) {
	return c.FetchMetadataCtx(context.Background())
}

// FetchMetadataCtx is FetchMetadata with caller-supplied context.
func (c *WalletClient) FetchMetadataCtx(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/.well-known/openid-credential-issuer", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, walletMaxResponseBytes)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// FetchJWKS — public key fetch for verifier
func (c *WalletClient) FetchJWKS() (ed25519.PublicKey, error) {
	return c.FetchJWKSCtx(context.Background())
}

// FetchJWKSCtx is FetchJWKS with caller-supplied context.
func (c *WalletClient) FetchJWKSCtx(ctx context.Context) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, walletMaxResponseBytes)).Decode(&jwks); err != nil {
		return nil, err
	}
	for _, k := range jwks.Keys {
		if k.Kty == "OKP" && k.Crv == "Ed25519" {
			return base64.RawURLEncoding.DecodeString(k.X)
		}
	}
	return nil, errors.New("wallet: no Ed25519 key in JWKS")
}
