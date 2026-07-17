// Wallet export — BLRCS 発行側から Wallet 取り込みまでの橋渡し層
//
// Apple方針: 消費者は「Add to Wallet」を押すだけ。裏の complexity はユーザが見えない。
// そのレベルのAPI を verifier/issuer 利用コードに提供する。
//
// 本ファイルの役割:
//  1. SD-JWT credential から wallet offer URL 生成 (OpenID4VCI Pre-Authorized flow 互換)
//  2. モック wallet — ローカル E2E テスト / CI 用 (Apple Wallet 無しで検証可能)
//
// 将来拡張 (契約不変):
//   - Apple Wallet .pkpass 生成 (実機展開)
//   - Google Wallet pass JWT
//   - EUDI Wallet native export
package openid4vp

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"blrcs/compliance"
)

// CredentialOffer — Wallet に「この DPP を保存する？」と聞くオファー
//
// OpenID4VCI (Verifiable Credential Issuance) の Pre-Authorized Code Flow に準拠。
// iOS 26 Safari / Apple Wallet 互換ドラフト仕様。
type CredentialOffer struct {
	CredentialIssuer    string                `json:"credential_issuer"` // DID/URL
	CredentialConfigIDs []string              `json:"credential_configuration_ids"`
	Grants              map[string]OfferGrant `json:"grants"`
}

// OfferGrant — 取得方法のhint (pre-auth のみMVP対応)
type OfferGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code,omitempty"`
	UserPinRequired   bool   `json:"user_pin_required,omitempty"`
}

// BuildCredentialOfferURL — Wallet インストール促すリンク生成
//
// 返却URL例:
//
//	openid-credential-offer://?credential_offer=<URL-encoded-JSON>
//
// QRコード/ディープリンクに埋込む。Apple Wallet / Google Wallet / EUDI Wallet
// いずれもこの形式を受付可能 (OpenID4VCI Draft 14 準拠)。
func BuildCredentialOfferURL(offer CredentialOffer) (string, error) {
	if offer.CredentialIssuer == "" {
		return "", errors.New("wallet: CredentialIssuer required")
	}
	if len(offer.CredentialConfigIDs) == 0 {
		return "", errors.New("wallet: at least one credential_configuration_id required")
	}
	b, err := json.Marshal(offer)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("credential_offer", string(b))
	return "openid-credential-offer://?" + q.Encode(), nil
}

// ============================================================================
// MockWallet — ローカル E2E テスト用
//
// Apple/Google Wallet の挙動を simulate。
// CI でフロー全体 (verifier → wallet → verifier) を走らせるため。
// ============================================================================

// MockWallet — テスト用 wallet 実装
// 保持する credential に SD-JWT を格納、要求時に開示フィールドを自動選択
type MockWallet struct {
	HolderDID   string
	Credentials map[string]StoredCredential // id → stored

	// HolderKey — 設定時、Present は cnf にバインドされた秘密鍵で KB-JWT を生成し
	// リクエストの nonce / client_id に提示をバインドする (anti-replay)。
	// nil の場合は従来どおり KB 無しの提示 (cnf 無し credential 用)。
	HolderKey ed25519.PrivateKey

	// VerifierKey — 設定時、Present は RFC 9101 JAR の署名付き request object を
	// 必須とし、VerifyRequestObject で検証したうえで nonce / client_id /
	// presentation_definition を「署名済みの値のみ」から取る。これにより、
	// 署名なし query を改竄した relay (response_uri 差し替え等) を検知・無効化する。
	// nil の場合は従来どおり署名なし query を信頼する (back-compat)。
	VerifierKey ed25519.PublicKey
}

// StoredCredential — wallet 内保管形式
type StoredCredential struct {
	ID         string
	IssuerDID  string
	IssuerPub  ed25519.PublicKey
	SDJWT      string
	ClaimNames []string // 全開示可能 claim 名 (UI で選択肢として表示)
}

// NewMockWallet — テスト用
func NewMockWallet(holder string) *MockWallet {
	return &MockWallet{
		HolderDID:   holder,
		Credentials: make(map[string]StoredCredential),
	}
}

// Store — wallet に credential を保管 (Add to Wallet 相当)
func (w *MockWallet) Store(c StoredCredential) {
	w.Credentials[c.ID] = c
}

// Present — Authorization Request を解釈し、自動応答を生成
//
// 自動ロジック (Apple式の smart default):
//  1. PresentationDefinition.AcceptableIssuers の中で一致する credential を検索
//  2. RequiredClaims を自動開示、それ以外は秘匿
//  3. SD-JWT Present() で選択開示結果を作成
//  4. AuthorizationResponse を返す
//
// 実wallet UIではユーザが確認ステップを挟むが、テストでは自動化
func (w *MockWallet) Present(reqURL string) (*AuthorizationResponse, error) {
	var (
		state, nonce, clientID string
		def                    PresentationDefinition
		transactionData        []string
	)
	if w.VerifierKey != nil {
		// Secure path (RFC 9101 JAR): trust ONLY the signed request object.
		// Tampered unsigned query params (e.g. a relayed response_uri) are ignored
		// because every value the wallet acts on comes from the verified JWT.
		authReq, err := VerifyRequestObject(reqURL, w.VerifierKey)
		if err != nil {
			return nil, fmt.Errorf("wallet: request object: %w", err)
		}
		state, nonce, clientID = authReq.State, authReq.Nonce, authReq.ClientID
		def = authReq.PresentationDefinition
		transactionData = authReq.TransactionData
		if state == "" {
			return nil, errors.New("wallet: state missing in signed request")
		}
		if len(def.RequiredClaims) == 0 {
			return nil, errors.New("wallet: signed request has no presentation_definition")
		}
	} else {
		// Legacy unsigned path — trusts query parameters as-is (back-compat).
		u, err := url.Parse(reqURL)
		if err != nil {
			return nil, fmt.Errorf("wallet: parse request URL: %w", err)
		}
		q := u.Query()
		state = q.Get("state")
		if state == "" {
			return nil, errors.New("wallet: state missing in request")
		}
		nonce = q.Get("nonce")
		clientID = q.Get("client_id")
		pdRaw := q.Get("presentation_definition")
		if pdRaw == "" {
			return nil, errors.New("wallet: presentation_definition missing")
		}
		if err := json.Unmarshal([]byte(pdRaw), &def); err != nil {
			return nil, fmt.Errorf("wallet: pd parse: %w", err)
		}
		if tdRaw := q.Get("transaction_data"); tdRaw != "" {
			if err := json.Unmarshal([]byte(tdRaw), &transactionData); err != nil {
				return nil, fmt.Errorf("wallet: transaction_data parse: %w", err)
			}
		}
	}
	// 適合 credential 検索 — AcceptableDIDs (wire) を使う
	acceptSet := make(map[string]bool, len(def.AcceptableDIDs))
	for _, did := range def.AcceptableDIDs {
		acceptSet[did] = true
	}
	var matched *StoredCredential
	for _, cred := range w.Credentials {
		if acceptSet[cred.IssuerDID] {
			matched = &cred
			break
		}
	}
	if matched == nil {
		return nil, errors.New("wallet: no credential matches request")
	}
	// 選択開示 — holder key があれば KB-JWT で nonce/aud にバインド。
	var presented string
	var err error
	if w.HolderKey != nil {
		presented, err = compliance.PresentWithKeyBindingTx(
			matched.SDJWT, def.RequiredClaims, w.HolderKey,
			nonce, clientID, transactionData, time.Time{})
	} else {
		presented, err = compliance.Present(matched.SDJWT, def.RequiredClaims)
	}
	if err != nil {
		return nil, fmt.Errorf("wallet: present: %w", err)
	}
	return &AuthorizationResponse{
		VPToken: presented,
		State:   state,
	}, nil
}
