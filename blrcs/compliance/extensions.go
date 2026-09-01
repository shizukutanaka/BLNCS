package compliance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"blrcs/ecdsakey"
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
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	VCT       string         `json:"vct"` // SD-JWT VC type (draft-ietf-oauth-sd-jwt-vc)
	IssuedAt  int64          `json:"iat"`
	Expires   int64          `json:"exp"`
	NotBefore int64          `json:"nbf,omitempty"` // RFC 9901: not-before (optional)
	Claims    map[string]any `json:"claims"`

	// HolderKey — cnf.jwk から復元した Ed25519 holder 公開鍵 (発行時にバインドされていれば non-nil)。
	HolderKey ed25519.PublicKey `json:"-"`
	// HolderKeyES256 — cnf.jwk が P-256 (EC) の場合の holder 公開鍵。SEC1 uncompressed
	// point (0x04||X||Y)。HolderKey / HolderKeyES256 は高々一方が non-nil。EUDI
	// wallet の device key は P-256 なので、その KB-JWT (ES256) を検証するために必要。
	HolderKeyES256 []byte `json:"-"`
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

// IssueSDJWTBoundStatus — holder key binding (cnf) と失効参照 (status_list) を併せ持つ
// DPP SD-JWT VC を発行 (vct=DPP)。規制 DPP は通常その両方を要する: 提示はホルダに
// 暗号的に束縛され (リプレイ防止)、かつ issuer が後から失効できる。
func (i *Issuer) IssueSDJWTBoundStatus(subject string, sdClaims, clearClaims map[string]any, holderPub ed25519.PublicKey, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	return i.IssueSDJWTVCBoundStatus(VCTDigitalProductPassport, subject, sdClaims, clearClaims, holderPub, status, validFor)
}

// IssueSDJWTVCBoundStatus — 任意の vct で holder key binding + 失効参照付き SD-JWT VC を発行。
func (i *Issuer) IssueSDJWTVCBoundStatus(vct, subject string, sdClaims, clearClaims map[string]any, holderPub ed25519.PublicKey, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	if len(holderPub) != ed25519.PublicKeySize {
		return "", nil, ErrHolderKeyRequired
	}
	return i.issueSDJWT(vct, subject, sdClaims, clearClaims, holderPub, status, validFor)
}

// issueSDJWT — SD-JWT VC 発行の共通実装。holderPub が non-nil なら cnf.jwk を、
// status が non-nil なら status_list claim を埋め込む。
func (i *Issuer) issueSDJWT(vct, subject string, sdClaims, clearClaims map[string]any, holderPub ed25519.PublicKey, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	return buildSDJWT(i, i.ID, vct, subject, sdClaims, clearClaims, holderPub, status, validFor)
}

// buildSDJWT is the single SD-JWT VC construction shared by every issuer
// algorithm. Everything algorithm-specific is reached through the jwsSigner
// seam (alg header, typ, decoy count, signature), so adding an algorithm can
// never fork the disclosure/decoy/shuffle logic that the privacy properties
// depend on.
func buildSDJWT(signer jwsSigner, issuerID, vct, subject string, sdClaims, clearClaims map[string]any, holderPub []byte, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	if subject == "" {
		return "", nil, ErrSubjectRequired
	}
	if vct == "" {
		return "", nil, ErrSDJWTMissingVCT
	}
	now := time.Now().UTC()
	payload := map[string]any{
		"iss":     issuerID,
		"sub":     subject,
		"vct":     vct,
		"iat":     now.Unix(),
		"_sd_alg": "sha-256",
	}
	if validFor > 0 {
		payload["exp"] = now.Add(validFor).Unix()
	}
	// Holder key binding: cnf.jwk (RFC 7800 / SD-JWT-VC). Accepts an Ed25519 key
	// (32 bytes → OKP) or a P-256 key as an uncompressed SEC1 point
	// (65 bytes → EC), so an issuer can bind to whichever curve the holder's
	// device uses. EUDI wallets use P-256.
	switch len(holderPub) {
	case ed25519.PublicKeySize:
		payload["cnf"] = map[string]any{
			"jwk": map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(holderPub),
			},
		}
	case ecdsakey.P256UncompressedSize:
		if _, err := ecdsakey.ParseP256PublicKey(holderPub); err == nil {
			payload["cnf"] = map[string]any{
				"jwk": map[string]any{
					"kty": "EC",
					"crv": "P-256",
					"x":   base64.RawURLEncoding.EncodeToString(holderPub[1 : 1+ecdsakey.P256CoordSize]),
					"y":   base64.RawURLEncoding.EncodeToString(holderPub[1+ecdsakey.P256CoordSize:]),
				},
			}
		}
	}
	// Credential status (revocation): draft-ietf-oauth-status-list `status` claim
	if status != nil {
		payload["status"] = status.statusClaim()
	}
	// Guard against callers accidentally (or adversarially) injecting reserved
	// JWT/SD-JWT claims via clearClaims or sdClaims — those have security-critical
	// semantics that must only be set by the issuer (existing clear guard extended
	// to sd, plus cross-map overlap guard).
	//
	// Without these checks the issuer signs and returns a credential that ALWAYS
	// fails verification (ErrSDJWTMalformed), giving the credential subject no
	// indication the credential was already broken at issuance time.
	for k := range clearClaims {
		if reservedSDJWTClaim(k) {
			return "", nil, fmt.Errorf("compliance: clearClaims: %q collides with reserved claim", k)
		}
	}
	for k := range sdClaims {
		if reservedSDJWTClaim(k) {
			return "", nil, fmt.Errorf("compliance: sdClaims: %q collides with reserved claim", k)
		}
		if _, dup := clearClaims[k]; dup {
			return "", nil, fmt.Errorf("compliance: claim %q appears in both sdClaims and clearClaims", k)
		}
	}
	var disclosures []Disclosure
	decoys := signer.decoyCount()

	// Clear claims → JWT body 直接。値の内部に SD() マーカーがあれば、その位置で
	// nested / array-element disclosure に変換される (Axis 145)。マーカーが無ければ
	// 値はそのまま — 既存呼び出し側の出力は不変。
	for k, v := range clearClaims {
		redacted, err := redactTree(v, decoys, 1, &disclosures)
		if err != nil {
			return "", nil, fmt.Errorf("compliance: clearClaims[%q]: %w", k, err)
		}
		payload[k] = redacted
	}
	// SD claims → hash digests in _sd array, disclosures appended
	var sdDigests []string
	for name, value := range sdClaims {
		// 値を先に redact する (bottom-up)。こうすると開示された値の中に `_sd` /
		// `...` が残るため、RFC 9901 の recursive disclosure になる。
		redacted, err := redactTree(value, decoys, 1, &disclosures)
		if err != nil {
			return "", nil, fmt.Errorf("compliance: sdClaims[%q]: %w", name, err)
		}
		d, err := newObjectDisclosure(name, redacted)
		if err != nil {
			return "", nil, fmt.Errorf("compliance: sdClaims[%q]: %w", name, err)
		}
		disclosures = append(disclosures, d)
		sdDigests = append(sdDigests, digestOf(d.Encoded))
	}
	// Decoy digests (draft-ietf-oauth-sd-jwt §5.6): hashes of fresh random salts
	// with no corresponding disclosure. They are indistinguishable from real
	// digests (same SHA-256 length) and obscure the true number of selectively-
	// disclosable claims, improving holder unlinkability.
	for n := 0; n < decoys; n++ {
		salt, err := randomB64(32)
		if err != nil {
			return "", nil, err
		}
		h := sha256.Sum256([]byte(salt))
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(h[:]))
	}
	// Shuffle so real and decoy digests are not positionally distinguishable
	// (decoys appended last would otherwise reveal which entries are real).
	if err := shuffleDigests(sdDigests); err != nil {
		return "", nil, err
	}
	// Only emit `_sd` when there is something in it. Serialising an empty list
	// produced `"_sd": null`, which is not a valid digest array — a strict
	// verifier is entitled to reject it.
	if len(sdDigests) > 0 {
		payload[sdKey] = sdDigests
	}
	// Sign JWT. typ defaults to the current draft-ietf-oauth-sd-jwt-vc value
	// `dc+sd-jwt` (renamed from `vc+sd-jwt` in Nov 2024 to avoid colliding with
	// the W3C VC media type); overridable via Issuer.SDJWTVCType for legacy
	// verifiers that only accept the old value.
	header := `{"alg":"` + signer.jwsAlg() + `","typ":"` + signer.sdjwtTyp() + `"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	// Surface the Marshal error rather than discarding it: a clearClaims value
	// that cannot be JSON-encoded (channel, func, cyclic reference, non-finite
	// float) makes Marshal fail, and signing the resulting nil payload would
	// return a well-formed-looking credential that can never verify.
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("%w: payload: %v", ErrDisclosableValue, err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := headerB64 + "." + payloadB64
	sig, err := signer.signJWS([]byte(sigInput))
	if err != nil {
		return "", nil, err
	}
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
	Now              time.Time     // ゼロ値なら time.Now()
	Leeway           time.Duration // 時刻ズレ許容 (ゼロなら 60s)
	ExpectedNonce    string        // 設定時、KB-JWT の nonce と一致必須
	ExpectedAudience string        // 設定時、KB-JWT の aud と一致必須
	// ExpectedTransactionData — 設定時 (OpenID4VP 1.0 §Transaction Data)、KB-JWT
	// の transaction_data_hashes が、ここに渡された各 transaction_data エントリ
	// (base64url エンコード済み JSON 文字列) の sha-256 ハッシュを全て含むこと必須。
	// verifier が Authorization Request に transaction_data を載せた場合、提示を
	// その取引 (決済/同意) に暗号的に束縛し、holder が「その取引を見て承認した」
	// ことを保証する。一致しなければ ErrKeyBindingTransactionData。
	ExpectedTransactionData []string
	// ExpectedIssuer — 設定時、JWT の iss クレームと一致必須 (key-confusion 防止)。
	// 検証者は公開鍵をそのまま受け入れず、鍵がどの発行者を表すかも確認すべき。
	ExpectedIssuer    string
	RequireKeyBinding bool          // true なら cnf 無し credential も拒否
	MaxKBAge          time.Duration // >0 なら KB-JWT iat の最大許容経過時間 (freshness)
	// AllowedAlgs — 非空なら、発行者 JWS の `alg` がこのリストに含まれること必須。
	// 空 (ゼロ値) なら登録済みの任意 alg を受理 (後方互換)。
	//
	// crypto-agility のダウングレード対策: RegisterJWSVerifier で 2 つ目の alg
	// (例: ML-DSA) を登録した瞬間、検証はグローバルに「EdDSA も ML-DSA も可」に
	// なる。ポスト量子デプロイが「ML-DSA のみ」を、レガシ検証者が「EdDSA のみ」を
	// 呼び出しごとに固定できるようにする。ErrSDJWTUnsupportedAlg (未登録) とは別の
	// ErrSDJWTAlgNotAllowed を返す。
	AllowedAlgs []string
}

const defaultLeeway = 60 * time.Second

// maxSDJWTSegments caps the number of "~"-delimited segments in an SD-JWT
// before strings.Split is called. A real EU DPP / Battery Passport credential
// has at most a few dozen selective-disclosure claims; 256 is a generous bound
// that prevents a DoS where an attacker appends millions of "~" characters to
// any SD-JWT (the issuer signature covers only the first segment, so the rest
// is attacker-editable) forcing a multi-megabyte slice allocation before the
// signature check runs.
const maxSDJWTSegments = 256

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

	// Cap the number of ~-delimited segments before splitting. An attacker can
	// append thousands of "~" characters to a syntactically valid SD-JWT
	// without invalidating the issuer signature (which covers only parts[0]).
	// strings.Split on a 4 MiB string of "~" would allocate ~4 M string
	// headers (~64 MB) before the sig check runs. The check is O(n) but uses
	// O(1) memory, so it bounds the slice allocation to O(maxSDJWTSegments).
	if strings.Count(sdjwt, "~") > maxSDJWTSegments {
		return nil, ErrSDJWTTooManyDisclosures
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
		Alg  string   `json:"alg"`
		Typ  string   `json:"typ"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, ErrSDJWTMalformed
	}
	// RFC 7515 §4.1.11: a `crit` header lists extension parameters the verifier
	// MUST understand; if any is unsupported the JWS is invalid. BLRCS implements
	// no JWS extensions, so a present `crit` (which by spec lists only extensions)
	// means an unsupported critical parameter — reject rather than silently ignore
	// the issuer's safety signal.
	if len(hdr.Crit) > 0 {
		return nil, ErrSDJWTCritUnsupported
	}
	// SD-JWT-VC media type (draft-ietf-oauth-sd-jwt-vc §3.2.1): when the issuer
	// JWS sets `typ`, it must be an SD-JWT-VC type (`vc+sd-jwt` or the newer
	// `dc+sd-jwt`). Enforcing this prevents cross-JWT-type confusion — replaying a
	// differently-typed JWS (e.g. statuslist+jwt, openid4vci-proof+jwt) signed by
	// the same key as a credential. A missing typ is tolerated for interop (the
	// required vct claim + _sd structure still gate it).
	if hdr.Typ != "" && !isSDJWTVCType(hdr.Typ) {
		return nil, ErrSDJWTUnsupportedType
	}
	// Per-verification algorithm allowlist (crypto-agility downgrade defense).
	// When the caller pins AllowedAlgs, the issuer alg must be a member — checked
	// BEFORE the global registry lookup so an excluded-but-registered alg is
	// rejected as policy (ErrSDJWTAlgNotAllowed), not capability. Empty = any
	// registered alg (backward-compatible).
	if len(opts.AllowedAlgs) > 0 && !containsString(opts.AllowedAlgs, hdr.Alg) {
		return nil, ErrSDJWTAlgNotAllowed
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
	// RFC 7519 NumericDate claims (iat/exp/nbf). A claim that is PRESENT but not a
	// JSON number must be a hard error, not a silent skip: a credential carrying
	// e.g. "exp":"1700000000" (a string — emitted by some non-conformant issuer
	// libraries) would otherwise have its expiry check disabled below
	// (`vc.Expires == 0` ⇒ "no expiry"), a fail-open that lets an expired
	// credential verify. Absent is fine (returns ok=false, no error).
	if iat, ok, err := numericDateClaim(payload, "iat"); err != nil {
		return nil, err
	} else if ok {
		vc.IssuedAt = iat
	}
	if exp, ok, err := numericDateClaim(payload, "exp"); err != nil {
		return nil, err
	} else if ok {
		vc.Expires = exp
	}
	if nbf, ok, err := numericDateClaim(payload, "nbf"); err != nil {
		return nil, err
	} else if ok {
		vc.NotBefore = nbf
	}
	vc.HolderKey, vc.HolderKeyES256 = extractHolderKey(payload)
	vc.Status = extractStatus(payload)

	// SD-JWT-VC: vct は必須クレーム (draft-ietf-oauth-sd-jwt-vc §3.2.2.2)。
	if vc.VCT == "" {
		return nil, ErrSDJWTMissingVCT
	}
	// 発行者バインディング: key-confusion 防止。
	// 検証者が ExpectedIssuer を設定した場合、JWT の iss クレームと一致必須。
	// 設定しない場合は従来動作 (後方互換)。
	if opts.ExpectedIssuer != "" && vc.Issuer != opts.ExpectedIssuer {
		return nil, ErrSDJWTIssuerMismatch
	}

	// 有効期限の強制 (leeway 込み)
	if vc.Expires != 0 && now.After(time.Unix(vc.Expires, 0).Add(leeway)) {
		return nil, ErrSDJWTExpired
	}
	// iat: future-dated issuance rejected.
	if vc.IssuedAt != 0 && time.Unix(vc.IssuedAt, 0).After(now.Add(leeway)) {
		return nil, ErrSDJWTNotYetValid
	}
	// nbf: RFC 9901 §4.2.1 — credential not yet valid before this time.
	if vc.NotBefore != 0 && time.Unix(vc.NotBefore, 0).After(now.Add(leeway)) {
		return nil, ErrSDJWTNotYetValid
	}

	// Copy clear claims (予約 claim 以外)
	reserved := map[string]bool{
		"iss": true, "sub": true, "vct": true, "iat": true, "exp": true,
		"nbf": true, "_sd": true, "_sd_alg": true, "cnf": true, "status": true,
	}
	for k, v := range payload {
		if !reserved[k] {
			vc.Claims[k] = v
		}
	}
	// Disclosure resolution (RFC 9901). Delegated to resolveDisclosures so that
	// object properties, array elements and RECURSIVELY nested disclosures are
	// all handled by one walk — see disclosure.go. The previous inline loop
	// only understood flat, top-level object properties whose digest appeared in
	// the top-level `_sd`, and rejected everything else as malformed.
	resolved, err := resolveDisclosures(payload, parts[1:discEnd], reserved)
	if err != nil {
		return nil, err
	}
	for k, v := range resolved {
		if !reserved[k] {
			vc.Claims[k] = v
		}
	}

	// Key binding: cnf 有り credential は常に KB-JWT を検証 (nonce/aud バインド)。
	// holder key の無い credential を拒否するかは呼び出し側のポリシー
	// (opts.RequireKeyBinding) に委ねる。OpenID4VP verifier は既定で要求する。
	if vc.HolderKey != nil || vc.HolderKeyES256 != nil || opts.RequireKeyBinding {
		if vc.HolderKey == nil && vc.HolderKeyES256 == nil {
			return nil, ErrHolderKeyRequired
		}
		if kbSegment == "" {
			return nil, ErrKeyBindingMissing
		}
		if err := verifyKBJWT(kbSegment, sdjwt, vc.HolderKey, vc.HolderKeyES256, opts, now, leeway); err != nil {
			return nil, err
		}
		vc.KeyBound = true
	}
	return vc, nil
}

// isSDJWTVCType reports whether typ is an accepted SD-JWT-VC media type. Per RFC
// 7515 §4.1.9 the "application/" prefix may be omitted, so it is stripped before
// comparison. Both the original (`vc+sd-jwt`) and current (`dc+sd-jwt`) draft
// values are accepted for cross-draft interop.
func isSDJWTVCType(typ string) bool {
	typ = strings.TrimPrefix(typ, "application/")
	return typ == "vc+sd-jwt" || typ == "dc+sd-jwt"
}

// containsString reports whether s is in list. Used for the per-verification
// algorithm allowlist (VerifyOptions.AllowedAlgs); allowlists are tiny, so a
// linear scan is appropriate.
func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// numericDateClaim extracts an RFC 7519 NumericDate claim (iat/exp/nbf) from a
// decoded JWT payload. It returns:
//   - (0, false, nil)               when the claim is absent — caller skips it,
//   - (int64(v), true, nil)         when present as a JSON number,
//   - (0, false, ErrSDJWTMalformed) when present but the wrong JSON type.
//
// The last case MUST be an error: silently ignoring a present-but-malformed
// time claim is a fail-open (e.g. a string "exp" would disable expiry
// enforcement). json.Unmarshal always decodes a conformant NumericDate as
// float64, so a non-float64 value is genuinely non-conformant.
func numericDateClaim(payload map[string]any, key string) (int64, bool, error) {
	raw, present := payload[key]
	if !present {
		return 0, false, nil
	}
	f, ok := raw.(float64)
	if !ok {
		return 0, false, ErrSDJWTMalformed
	}
	return int64(f), true, nil
}

// extractHolderKey — cnf.jwk (OKP/Ed25519) から holder 公開鍵を復元 (無ければ nil)。
func extractHolderKey(payload map[string]any) (ed25519.PublicKey, []byte) {
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return nil, nil
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, nil
	}
	// RFC 7800 cnf.jwk MUST be a well-formed JWK. Pin the key type so `x` is not
	// silently reinterpreted across algorithms: an OKP/Ed25519 JWK yields the
	// Ed25519 holder key, an EC/P-256 JWK the P-256 one. Any other kty/crv (or a
	// missing one) yields no holder key rather than a coerced one.
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	switch {
	case kty == "OKP" && crv == "Ed25519":
		x, ok := jwk["x"].(string)
		if !ok {
			return nil, nil
		}
		raw, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, nil
		}
		return ed25519.PublicKey(raw), nil

	case kty == "EC" && crv == "P-256":
		xs, _ := jwk["x"].(string)
		ys, _ := jwk["y"].(string)
		if xs == "" || ys == "" {
			return nil, nil
		}
		x, err := base64.RawURLEncoding.DecodeString(xs)
		if err != nil || len(x) != ecdsakey.P256CoordSize {
			return nil, nil
		}
		y, err := base64.RawURLEncoding.DecodeString(ys)
		if err != nil || len(y) != ecdsakey.P256CoordSize {
			return nil, nil
		}
		sec1 := make([]byte, 0, ecdsakey.P256UncompressedSize)
		sec1 = append(sec1, 0x04)
		sec1 = append(sec1, x...)
		sec1 = append(sec1, y...)
		// Reject a point that is not on the curve before it becomes a holder key
		// (invalid-curve defence at the parse boundary).
		if _, err := ecdsakey.ParseP256PublicKey(sec1); err != nil {
			return nil, nil
		}
		return nil, sec1
	}
	return nil, nil
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
func verifyKBJWT(kb, presentation string, holderPub ed25519.PublicKey, holderP256 []byte, opts VerifyOptions, now time.Time, leeway time.Duration) error {
	segs := strings.SplitN(kb, ".", 3)
	if len(segs) != 3 {
		return ErrKeyBindingInvalid
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return ErrKeyBindingInvalid
	}
	var hdr struct {
		Alg  string   `json:"alg"`
		Typ  string   `json:"typ"`
		Crit []string `json:"crit"`
	}
	// Reject unknown critical params (RFC 7515 §4.1.11) and pin typ — BLRCS
	// implements no KB-JWT header extensions.
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Typ != "kb+jwt" || len(hdr.Crit) > 0 {
		return ErrKeyBindingInvalid
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil {
		return ErrKeyBindingInvalid
	}
	// The KB-JWT alg MUST match the algorithm of the key the issuer bound in
	// cnf. Dispatching on the presented alg alone would let a holder bound to an
	// Ed25519 key sign the KB-JWT with a P-256 key it also controls (or vice
	// versa) — the binding must be to THE key in cnf, so the alg is required to
	// name that key's algorithm.
	signingInput := []byte(segs[0] + "." + segs[1])
	switch hdr.Alg {
	case "EdDSA":
		if len(holderPub) != ed25519.PublicKeySize {
			return ErrKeyBindingInvalid
		}
		if !ed25519.Verify(holderPub, signingInput, sigBytes) {
			return ErrKeyBindingInvalid
		}
	case "ES256":
		if len(holderP256) != ecdsakey.P256UncompressedSize {
			return ErrKeyBindingInvalid
		}
		if !ecdsakey.VerifyES256(holderP256, signingInput, sigBytes) {
			return ErrKeyBindingInvalid
		}
	default:
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
	// transaction_data binding (OpenID4VP 1.0 §Transaction Data): when the
	// verifier bound the request to specific transaction_data, require the
	// KB-JWT's transaction_data_hashes to cover the sha-256 of every entry.
	// This is what proves the holder saw and approved this exact transaction.
	if len(opts.ExpectedTransactionData) > 0 {
		if err := verifyTransactionDataHashes(pl, opts.ExpectedTransactionData); err != nil {
			return err
		}
	}
	// sd_hash: KB-JWT 直前の '~' までを含む提示文字列の SHA-256。
	idx := strings.LastIndex(presentation, "~")
	h := sha256.Sum256([]byte(presentation[:idx+1]))
	if s, _ := pl["sd_hash"].(string); s != base64.RawURLEncoding.EncodeToString(h[:]) {
		return ErrKeyBindingSDHash
	}
	// KB-JWT は iat 必須 (draft-ietf-oauth-sd-jwt §KB-JWT)。未来すぎる iat は
	// 拒否し (再生成検知)、MaxKBAge>0 なら古すぎる iat も拒否する (freshness)。
	iatRaw, ok := pl["iat"].(float64)
	if !ok {
		return ErrKeyBindingInvalid
	}
	iat := int64(iatRaw)
	if iat > now.Add(leeway).Unix() {
		return ErrKeyBindingInvalid
	}
	if opts.MaxKBAge > 0 && iat < now.Add(-opts.MaxKBAge).Add(-leeway).Unix() {
		return ErrKeyBindingInvalid
	}
	return nil
}

// transactionDataHash returns the OpenID4VP 1.0 transaction_data hash of one
// entry: base64url(sha-256(entry)), where entry is the base64url-encoded JSON
// string exactly as it appears in the request's transaction_data array (the
// hash is over the encoded string, not the decoded JSON — §Transaction Data).
func transactionDataHash(entry string) string {
	h := sha256.Sum256([]byte(entry))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// verifyTransactionDataHashes checks that the KB-JWT's transaction_data_hashes
// claim covers every expected transaction_data entry. Per OpenID4VP 1.0, the
// only hash algorithm a Wallet may use when the Verifier does not specify one
// is sha-256; if transaction_data_hashes_alg is present it must be sha-256
// (the sole registered value), else the binding is unverifiable here.
func verifyTransactionDataHashes(pl map[string]any, expected []string) error {
	if alg, ok := pl["transaction_data_hashes_alg"].(string); ok && alg != "" && alg != "sha-256" {
		return ErrKeyBindingTransactionData
	}
	rawHashes, ok := pl["transaction_data_hashes"].([]any)
	if !ok {
		return ErrKeyBindingTransactionData
	}
	present := make(map[string]bool, len(rawHashes))
	for _, h := range rawHashes {
		if s, ok := h.(string); ok {
			present[s] = true
		}
	}
	for _, entry := range expected {
		if !present[transactionDataHash(entry)] {
			return ErrKeyBindingTransactionData
		}
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
	if strings.Count(sdjwt, "~") > maxSDJWTSegments {
		return "", ErrSDJWTTooManyDisclosures
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
	return PresentWithKeyBindingTx(sdjwt, reveal, holderPriv, nonce, aud, nil, now)
}

// PresentWithKeyBindingTx is PresentWithKeyBinding with OpenID4VP 1.0
// transaction_data support: when transactionData is non-empty, the holder
// binds the presentation to those exact entries by adding
// transaction_data_hashes (sha-256 of each base64url entry) and
// transaction_data_hashes_alg to the KB-JWT. A verifier with
// VerifyOptions.ExpectedTransactionData set then requires this binding.
func PresentWithKeyBindingTx(sdjwt string, reveal []string, holderPriv ed25519.PrivateKey, nonce, aud string, transactionData []string, now time.Time) (string, error) {
	if len(holderPriv) != ed25519.PrivateKeySize {
		return "", ErrHolderKeyRequired
	}
	presented, err := Present(sdjwt, reveal)
	if err != nil {
		return "", err
	}
	return presentWithKB(presented, nonce, aud, transactionData, now, ed25519KBSigner(holderPriv))
}

// PresentWithKeyBindingES256 is PresentWithKeyBindingTx for a P-256 holder key,
// producing an ES256-signed KB-JWT — what an EUDI wallet emits, since its device
// key is P-256.
func PresentWithKeyBindingES256(sdjwt string, reveal []string, holderPriv *ecdsa.PrivateKey, nonce, aud string, transactionData []string, now time.Time) (string, error) {
	if holderPriv == nil || holderPriv.Curve != elliptic.P256() {
		return "", ErrHolderKeyRequired
	}
	presented, err := Present(sdjwt, reveal)
	if err != nil {
		return "", err
	}
	return presentWithKB(presented, nonce, aud, transactionData, now, es256KBSigner(holderPriv))
}

// PresentPathsWithKeyBinding is PresentPaths plus an EdDSA KB-JWT. Nested and
// array-element disclosures (Axis 145) are only addressable by path, so this is
// the entry point a holder needs to use them in an OpenID4VP flow, where key
// binding is required.
func PresentPathsWithKeyBinding(sdjwt string, paths [][]any, holderPriv ed25519.PrivateKey, nonce, aud string, transactionData []string, now time.Time) (string, error) {
	if len(holderPriv) != ed25519.PrivateKeySize {
		return "", ErrHolderKeyRequired
	}
	presented, err := PresentPaths(sdjwt, paths)
	if err != nil {
		return "", err
	}
	return presentWithKB(presented, nonce, aud, transactionData, now, ed25519KBSigner(holderPriv))
}

// PresentPathsWithKeyBindingES256 is PresentPathsWithKeyBinding for a P-256
// holder key — the combination an EUDI wallet presenting a nested credential
// actually needs.
func PresentPathsWithKeyBindingES256(sdjwt string, paths [][]any, holderPriv *ecdsa.PrivateKey, nonce, aud string, transactionData []string, now time.Time) (string, error) {
	if holderPriv == nil || holderPriv.Curve != elliptic.P256() {
		return "", ErrHolderKeyRequired
	}
	presented, err := PresentPaths(sdjwt, paths)
	if err != nil {
		return "", err
	}
	return presentWithKB(presented, nonce, aud, transactionData, now, es256KBSigner(holderPriv))
}

// kbSigner pairs a KB-JWT signing function with the JOSE algorithm it actually
// produces. Passing the algorithm and the signer as two independent arguments
// let a caller write a header naming one algorithm over a signature made by
// another — the same defect the COSE path closed by making Sign1/Sign1ES256
// reject a mismatched header. Binding them in one value makes that
// unrepresentable rather than merely unlikely.
type kbSigner struct {
	alg  string
	sign func([]byte) []byte
}

// ed25519KBSigner returns the KB-JWT signer for an Ed25519 holder key.
func ed25519KBSigner(priv ed25519.PrivateKey) kbSigner {
	return kbSigner{
		alg:  "EdDSA",
		sign: func(signingInput []byte) []byte { return ed25519.Sign(priv, signingInput) },
	}
}

// es256KBSigner returns the KB-JWT signer for a P-256 holder key.
// ES256 signatures are raw fixed-width R‖S (RFC 7518 §3.4), not ASN.1 DER.
func es256KBSigner(priv *ecdsa.PrivateKey) kbSigner {
	return kbSigner{alg: "ES256", sign: func(signingInput []byte) []byte {
		d := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, d[:])
		if err != nil {
			return nil
		}
		out := make([]byte, ecdsakey.ES256SignatureSize)
		r.FillBytes(out[:ecdsakey.P256CoordSize])
		s.FillBytes(out[ecdsakey.P256CoordSize:])
		return out
	}}
}

// presentWithKB builds a selective-disclosure presentation and appends a KB-JWT
// signed by the caller-supplied signer. The sd_hash / transaction_data logic is
// identical across algorithms, so only the alg header and the signature differ.
// presented is an already-built selective-disclosure presentation (from Present
// or PresentPaths); this function only appends the KB-JWT, so the two selection
// styles share one binding implementation.
func presentWithKB(presented string, nonce, aud string, transactionData []string, now time.Time, signer kbSigner) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	// sd_hash: 末尾 '~' までを含む提示文字列の SHA-256。
	h := sha256.Sum256([]byte(presented))
	hdrBytes, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: signer.alg, Typ: "kb+jwt"})
	if err != nil {
		return "", fmt.Errorf("compliance: encode KB-JWT header: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(hdrBytes)
	payloadClaims := map[string]any{
		"iat":     now.Unix(),
		"aud":     aud,
		"nonce":   nonce,
		"sd_hash": base64.RawURLEncoding.EncodeToString(h[:]),
	}
	if len(transactionData) > 0 {
		hashes := make([]string, len(transactionData))
		for i, entry := range transactionData {
			hashes[i] = transactionDataHash(entry)
		}
		payloadClaims["transaction_data_hashes"] = hashes
		payloadClaims["transaction_data_hashes_alg"] = "sha-256"
	}
	plBytes, _ := json.Marshal(payloadClaims)
	payload := base64.RawURLEncoding.EncodeToString(plBytes)
	sig := signer.sign([]byte(header + "." + payload))
	if sig == nil {
		return "", fmt.Errorf("compliance: KB-JWT signing failed")
	}
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
	return i.issueBatteryPassport(claim, validFor, "", 0, "")
}

// IssueBatteryPassportWithStatus is IssueBatteryPassport with an embedded
// credentialStatus (see IssueWithStatus for the field semantics), so the
// resulting Battery Passport is revocable.
func (i *Issuer) IssueBatteryPassportWithStatus(claim BatteryPassportClaim, validFor time.Duration, statusListURL string, index int, purpose string) (*Credential, error) {
	if statusListURL == "" {
		return nil, fmt.Errorf("compliance: statusListCredential URL required")
	}
	return i.issueBatteryPassport(claim, validFor, statusListURL, index, purpose)
}

// issueBatteryPassport is the shared implementation. statusListURL == "" means
// "no status" (IssueBatteryPassport's contract); non-empty routes through
// IssueWithStatus instead of Issue for the initial credential.
func (i *Issuer) issueBatteryPassport(claim BatteryPassportClaim, validFor time.Duration, statusListURL string, index int, purpose string) (*Credential, error) {
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
	var cred *Credential
	var err error
	if statusListURL != "" {
		cred, err = i.IssueWithStatus(pc, validFor, statusListURL, index, purpose)
	} else {
		cred, err = i.Issue(pc, validFor)
	}
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
	// Re-sign through attachProof so the signature matches the issuer's chosen
	// SUITE. This previously hand-rolled ed25519 over canonicalPayload, which is
	// the legacy Ed25519Signature2020 construction: an issuer using
	// eddsa-jcs-2022 therefore produced a DataIntegrityProof-typed credential
	// carrying a legacy base64 proofValue — signed, returned, and permanently
	// unverifiable, with no signal to the caller. (Same class as the mdoc COSE
	// alg-header mismatch of Axis 141.) The Created timestamp is preserved so
	// re-signing does not move the proof's clock.
	if err := i.attachProof(cred, cred.Proof.Created); err != nil {
		return nil, fmt.Errorf("compliance: re-sign battery passport: %w", err)
	}
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

// shuffleDigests performs an in-place Fisher-Yates shuffle using crypto/rand so
// the order of real vs decoy `_sd` digests carries no information. A CSPRNG
// failure is surfaced rather than silently falling back to a weak source.
func shuffleDigests(d []string) error {
	for i := len(d) - 1; i > 0; i-- {
		j, err := cryptoIntn(i + 1)
		if err != nil {
			return err
		}
		d[i], d[j] = d[j], d[i]
	}
	return nil
}

// cryptoIntn returns a uniformly random int in [0, n) using crypto/rand,
// rejecting values in the biased tail (rejection sampling).
func cryptoIntn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("compliance: cryptoIntn non-positive bound %d", n)
	}
	// 8 random bytes → uint64; reject the non-uniform remainder.
	max := ^uint64(0)
	limit := max - (max % uint64(n))
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("compliance: shuffle rng failed: %w", err)
		}
		v := binary.BigEndian.Uint64(b[:])
		if v < limit {
			return int(v % uint64(n)), nil
		}
	}
}

// reservedSDJWTClaim reports whether k is a JWT/SD-JWT reserved claim name
// that must not appear in caller-supplied clearClaims or sdClaims.
func reservedSDJWTClaim(k string) bool {
	switch k {
	case "iss", "sub", "vct", "iat", "exp", "nbf",
		"_sd", "_sd_alg", "cnf", "status":
		return true
	}
	return false
}
