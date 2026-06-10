// Package openid4vci — Verifiable Credential Issuance
//
// OpenID4VCI Draft 15 準拠。Apple/Google/EUDI wallet 互換。
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
)

// ============================================================================
// Types
// ============================================================================

// CredentialConfiguration — 発行可能なクレデンシャル種別
//
// Apple式宣言的スキーマ: どんなクレームを発行するかの契約
type CredentialConfiguration struct {
	ID                string   // 例: "eu-battery-passport-v1"
	Format            string   // "sd-jwt" / "vc+sd-jwt"
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
	consumed       bool   // credentialエンドポイント使用済み
	cNonce         string // Proof-of-Possession nonce (token交換時に発行)
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
	RequireProof bool               // OpenID4VCI Draft 15 §5.1.2: Proof-of-Possession を必須化
	signer       *compliance.Issuer // 既存の compliance.Issuer を再利用 (DRY)
	configs      map[string]CredentialConfiguration
	preAuthTTL   time.Duration
	tokenTTL     time.Duration

	mu       sync.Mutex
	preAuths map[string]*preAuthEntry // code → entry
	tokens   map[string]*preAuthEntry // access_token → same entry
}

// NewIssuer — Apple式の1行構築
//
// signerDID は compliance.Issuer 経由で ed25519 鍵を生成/保持する既存の仕組み
// 同一鍵で DPP credential も SD-JWT も署名可能 (DRY)
func NewIssuer(url string, signer *compliance.Issuer) *Issuer {
	return &Issuer{
		URL:        strings.TrimRight(url, "/"),
		signer:     signer,
		configs:    make(map[string]CredentialConfiguration),
		preAuths:   make(map[string]*preAuthEntry),
		tokens:     make(map[string]*preAuthEntry),
		preAuthTTL: 10 * time.Minute,
		tokenTTL:   5 * time.Minute,
	}
}

// RegisterConfiguration — 発行可能な credential config を登録
func (iss *Issuer) RegisterConfiguration(c CredentialConfiguration) {
	if c.Format == "" {
		c.Format = "vc+sd-jwt"
	}
	if c.ValidForDays == 0 {
		c.ValidForDays = 365
	}
	iss.mu.Lock()
	iss.configs[c.ID] = c
	iss.mu.Unlock()
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
func (iss *Issuer) CreateOffer(configID, subject string, sdClaims, clearClaims map[string]any) (string, string, error) {
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
	code := randomB64(32)
	iss.mu.Lock()
	iss.preAuths[code] = &preAuthEntry{
		code:        code,
		configID:    configID,
		subject:     subject,
		sdClaims:    sdClaims,
		clearClaims: clearClaims,
		expiresAt:   time.Now().Add(iss.preAuthTTL),
	}
	iss.mu.Unlock()
	offer := map[string]any{
		"credential_issuer":            iss.URL,
		"credential_configuration_ids": []string{configID},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": code,
			},
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
func (iss *Issuer) ExchangeCode(code string) (*TokenResponse, error) {
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
	accessToken := randomB64(32)
	cNonce := randomB64(16)
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
		CNonceExpiresIn: 600,
	}, nil
}

// ============================================================================
// Phase 3 — Credential issuance (wallet ← access_token)
// ============================================================================

// CredentialRequest — Wallet からのリクエスト
type CredentialRequest struct {
	Format                    string          `json:"format"`
	CredentialConfigurationID string          `json:"credential_configuration_id,omitempty"`
	Proof                     json.RawMessage `json:"proof,omitempty"` // 鍵保有証明 (MVP では未必須)
}

// CredentialResponse — SD-JWT credential 応答
type CredentialResponse struct {
	Credential      string `json:"credential"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
}

// IssueCredential — access_token を検証し SD-JWT を生成 (proof なし / 後方互換)
func (iss *Issuer) IssueCredential(accessToken string) (*CredentialResponse, error) {
	return iss.IssueCredentialWithProof(accessToken, CredentialRequest{})
}

// IssueCredentialWithProof — access_token + Proof-of-Possession を検証し SD-JWT を生成。
//
// OpenID4VCI Draft 15 §5.1.2:
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
	// Optimistically consume under lock; restore on error below.
	entry.consumed = true
	cNonce := entry.cNonce
	subject, sdClaims, clearClaims := entry.subject, entry.sdClaims, entry.clearClaims
	validForDays := cfg.ValidForDays
	iss.mu.Unlock()

	// Proof-of-Possession validation (OpenID4VCI Draft 15 §5.1.2)
	if len(req.Proof) > 0 {
		var proofEnv struct {
			ProofType string `json:"proof_type"`
			JWT       string `json:"jwt"`
		}
		if err := json.Unmarshal(req.Proof, &proofEnv); err != nil || proofEnv.ProofType != "jwt" || proofEnv.JWT == "" {
			iss.mu.Lock()
			entry.consumed = false
			iss.mu.Unlock()
			return nil, ErrInvalidProof
		}
		if _, err := verifyProofJWT(proofEnv.JWT, cNonce, iss.URL); err != nil {
			iss.mu.Lock()
			entry.consumed = false
			iss.mu.Unlock()
			return nil, err
		}
	} else if iss.RequireProof {
		iss.mu.Lock()
		entry.consumed = false
		iss.mu.Unlock()
		return nil, ErrInvalidProof
	}

	validFor := time.Duration(validForDays) * 24 * time.Hour
	sdjwt, _, err := iss.signer.IssueSDJWT(subject, sdClaims, clearClaims, validFor)
	if err != nil {
		iss.mu.Lock()
		entry.consumed = false
		iss.mu.Unlock()
		return nil, fmt.Errorf("vci: sdjwt sign: %w", err)
	}
	newCNonce := randomB64(16)
	return &CredentialResponse{
		Credential:      sdjwt,
		CNonce:          newCNonce,
		CNonceExpiresIn: 600,
	}, nil
}

// verifyProofJWT — OpenID4VCI Draft 15 §5.1.2 の proof JWT を検証する。
//
// 対応アルゴリズム: EdDSA (Ed25519) のみ (ゼロ依存制約)。
// header に jwk (OKP/Ed25519) が必須。
func verifyProofJWT(proofJWT, expectedNonce, issuerURL string) (ed25519.PublicKey, error) {
	parts := strings.SplitN(proofJWT, ".", 3)
	if len(parts) != 3 {
		return nil, ErrInvalidProof
	}
	// header
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidProof
	}
	var hdr struct {
		Alg string          `json:"alg"`
		Typ string          `json:"typ"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "EdDSA" || hdr.Typ != "openid4vci-proof+jwt" || len(hdr.JWK) == 0 {
		return nil, ErrInvalidProof
	}
	// JWK (OKP Ed25519)
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(hdr.JWK, &jwk); err != nil || jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, ErrInvalidProof
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidProof
	}
	pub := ed25519.PublicKey(keyBytes)
	// signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, ErrInvalidProof
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sigBytes) {
		return nil, ErrInvalidProof
	}
	// payload
	plBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidProof
	}
	var pl struct {
		Nonce string `json:"nonce"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
	}
	if err := json.Unmarshal(plBytes, &pl); err != nil {
		return nil, ErrInvalidProof
	}
	if pl.Nonce != expectedNonce {
		return nil, ErrProofNonceMismatch
	}
	if pl.Aud != issuerURL {
		return nil, ErrInvalidProof
	}
	// iat freshness: ±5 分
	iat := time.Unix(pl.Iat, 0)
	now := time.Now()
	if iat.After(now.Add(30*time.Second)) || iat.Before(now.Add(-5*time.Minute)) {
		return nil, ErrInvalidProof
	}
	return pub, nil
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
		configs[id] = map[string]any{
			"format":                cfg.Format,
			"credential_definition": map[string]any{"type": []string{"VerifiableCredential", cfg.CredentialType}},
			"scope":                 cfg.Scope,
			"cryptographic_binding_methods_supported": []string{"did:web"},
			"credential_signing_alg_values_supported": []string{"EdDSA"},
		}
	}
	return map[string]any{
		"credential_issuer":                   iss.URL,
		"credential_endpoint":                 iss.URL + "/credential",
		"token_endpoint":                      iss.URL + "/token",
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
	mux.HandleFunc("/credential", iss.handleCredential)
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
	if err := r.ParseForm(); err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
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
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_grant", err.Error())
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
		writeVCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	var req CredentialRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeVCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	resp, err := iss.IssueCredentialWithProof(accessToken, req)
	if err != nil {
		writeVCIError(w, http.StatusBadRequest, "invalid_token", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
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

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
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
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("wallet: token %d: %s", resp.StatusCode, b)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("wallet: token decode: %w", err)
	}
	// credential endpoint
	body, _ := json.Marshal(CredentialRequest{Format: "vc+sd-jwt"})
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
		b, _ := io.ReadAll(resp2.Body)
		return "", fmt.Errorf("wallet: credential %d: %s", resp2.StatusCode, b)
	}
	var cr CredentialResponse
	if err := json.NewDecoder(resp2.Body).Decode(&cr); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	for _, k := range jwks.Keys {
		if k.Kty == "OKP" && k.Crv == "Ed25519" {
			return base64.RawURLEncoding.DecodeString(k.X)
		}
	}
	return nil, errors.New("wallet: no Ed25519 key in JWKS")
}
