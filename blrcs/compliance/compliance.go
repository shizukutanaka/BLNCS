// Package compliance — BLRCS EU DPP準拠層 + ZK範囲証明
//
// 設計: Carmack (直接的・高速), Martin (単一責任), Pike (明確なインタフェース)
//
// 目的:
//  1. EU ESPR規則 (2027年適用予定) 準拠の Digital Product Passport 発行/検証
//  2. センサ値 (温度/湿度/照度) の範囲準拠 ZK証明 — 原データ非開示
//  3. 将来 Bulletproofs 差替可能なインタフェース (今日動く、明日強くなる)
//
// 依存: stdlib のみ (crypto/ed25519, crypto/sha256, encoding/json)
// ビルド: go build ./...
// テスト: go test -v ./...
package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ============================================================================
// Errors — 型付きエラー、呼出側が分岐可能
// ============================================================================

var (
	ErrNoProof        = errors.New("compliance: proof missing")
	ErrInvalidSig     = errors.New("compliance: signature invalid")
	ErrOutOfRange     = errors.New("compliance: value out of declared range")
	ErrEmptyProductID = errors.New("compliance: productID required")
	ErrExpired        = errors.New("compliance: credential expired")
	ErrNotYetValid    = errors.New("compliance: credential not yet valid (validFrom in the future)")
)

// ============================================================================
// W3C Verifiable Credential — EU DPP最小実装
// ESPR Art.9 / W3C VC Data Model 1.1 / JSON-LD 準拠
// ============================================================================

// PassportClaim — EU DPP主張スキーマ (ESPR必須項目)
//
// 拡張フィールドは Attrs に格納。コアフィールドは規則変更に強い固定セット。
type PassportClaim struct {
	ProductID        string            `json:"productId"`     // GTIN-14 / EPC
	Category         string            `json:"category"`      // EU product category code
	OriginCountry    string            `json:"originCountry"` // ISO 3166-1 alpha-2
	Manufacturer     string            `json:"manufacturer"`  // Issuer DID or LEI
	CarbonKgCO2e     float64           `json:"carbonKgCO2e"`  // Cradle-to-gate
	Recyclability    float32           `json:"recyclability"` // 0.0 – 1.0
	HazardousContent []string          `json:"hazardous,omitempty"`
	LifecyclePhase   string            `json:"phase"` // raw|manufacture|distribution|use|eol
	Attrs            map[string]string `json:"attrs,omitempty"`
}

// Credential — W3C Verifiable Credential 1.1
type Credential struct {
	Context    []string          `json:"@context"`
	Type       []string          `json:"type"`
	Issuer     string            `json:"issuer"`
	ValidFrom  time.Time         `json:"validFrom"`            // VC 2.0 (replaces issuanceDate)
	ValidUntil *time.Time        `json:"validUntil,omitempty"` // VC 2.0 (replaces expirationDate)
	Subject    PassportClaim     `json:"credentialSubject"`
	Status     *CredentialStatus `json:"credentialStatus,omitempty"` // W3C Bitstring Status List
	Proof      *Proof            `json:"proof,omitempty"`
}

// CredentialStatus — W3C Bitstring Status List v1.0 entry.
//
// 旧 StatusList2021Entry を置換。statusPurpose は "revocation" | "suspension"。
type CredentialStatus struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`                 // "BitstringStatusListEntry"
	StatusPurpose        string `json:"statusPurpose"`        // "revocation" | "suspension"
	StatusListIndex      string `json:"statusListIndex"`      // 文字列化した整数 (VC 2.0 仕様)
	StatusListCredential string `json:"statusListCredential"` // status list VC の URL
}

// Proof — a Verifiable Credential proof. Two suites are supported:
//   - Ed25519Signature2020 (default): Type="Ed25519Signature2020", ProofValue
//     is base64-std over the fixed-field canonicalPayload. Cryptosuite empty.
//   - eddsa-jcs-2022 (opt-in via Issuer.DataIntegrity): Type="DataIntegrityProof",
//     Cryptosuite="eddsa-jcs-2022", ProofValue is multibase-base58btc over the
//     JCS hashData construction (see dataintegrity.go).
type Proof struct {
	Type               string    `json:"type"`
	Cryptosuite        string    `json:"cryptosuite,omitempty"` // "eddsa-jcs-2022" for DataIntegrityProof
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofValue         string    `json:"proofValue"` // base64-std (Ed25519Signature2020) or multibase (DataIntegrity)
}

// ============================================================================
// Issuer — 発行者 (製造者/倉庫/運送業者)
// ============================================================================

// Issuer issues Digital Product Passport credentials signed with Ed25519:
// W3C Verifiable Credentials (compliance.Credential) carrying an
// eddsa-jcs-2022 DataIntegrityProof, and SD-JWT / SD-JWT VC presentations with
// selective disclosure.
//
// It is the Ed25519 counterpart to ES256Issuer. Use this one for the
// Ed25519-only subsystems (SCITT, did:webvh, status lists); use ES256Issuer
// when the credential must be verifiable by a P-256-only EUDI wallet.
//
// The zero value is not usable — construct with NewIssuer (fresh key) or
// NewIssuerFromKey (caller-supplied key). The exported fields below are
// optional settings whose zero values are the recommended behaviour.
type Issuer struct {
	ID         string // DID 例: did:web:factory.example/passport
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	// DecoyDigests — 任意。>0 のとき、発行する SD-JWT の `_sd` 配列にこの数だけ
	// ダミー digest を追加する (draft-ietf-oauth-sd-jwt §5.6 "Decoy Digests")。
	// `_sd` の要素数は「選択的開示可能な claim 数」を——未開示のものまで含めて——
	// 漏らすため、提示間の相関や credential 種別のフィンガープリントに使える。
	// decoy を混ぜると真の claim 数が隠れ、unlinkability/プライバシが向上する。
	// 既定 0 (後方互換: 挙動変化なし)。プライバシ重視の発行者は数個設定する。
	DecoyDigests int

	// LegacyProofSuite — true なら W3C VC (compliance.Credential) の発行時に、
	// 現行 REC の eddsa-jcs-2022 ではなく旧 Ed25519Signature2020 で署名する。
	//
	// 既定 (false) は eddsa-jcs-2022 = W3C Data Integrity 1.0 + EdDSA Cryptosuites
	// v1.0。Ed25519Signature2020 は Data Integrity 以前のスイートで、W3C の
	// standards track から外れている。DPP のような *適合性* を主張するプロダクトが
	// 非推奨スイートを既定で発行するのは、それ自体が適合性の欠陥になる。
	//
	// Verify は proof の type/cryptosuite を見て両方式を自動判別するため、既存
	// クレデンシャルの検証は影響を受けない。旧スイートしか受理しないレガシー
	// verifier 相手に発行する必要がある運用者のみ true を設定する。
	//
	// (Axis 149 以前は DataIntegrity bool として既定が逆だった。フィールドを反転
	//  したのは、Go のゼロ値が「現行標準」を指すようにするため — 既定値は何も
	//  書かなかった人が得るものであり、それは非推奨スイートであってはならない。)
	LegacyProofSuite bool

	// SDJWTVCType — 発行する SD-JWT-VC の JWS `typ` ヘッダ値。空なら現行の
	// draft-ietf-oauth-sd-jwt-vc 推奨値 `dc+sd-jwt` を使う。
	//
	// この typ は 2024年11月 (draft-14 前後) に、W3C VC Data Model が登録した
	// `vc` メディアタイプとの衝突回避のため `vc+sd-jwt` → `dc+sd-jwt` へ変更された。
	// 検証側は移行期間中は両方受理すべきとされており (本実装の isSDJWTVCType も
	// 両方受理する)、既定を現行値 `dc+sd-jwt` にしても現行の verifier とは相互運用
	// できる。旧 `vc+sd-jwt` しか受け付けないレガシー verifier 相手に発行する必要が
	// ある運用者のみ、明示的に "vc+sd-jwt" を設定する。
	SDJWTVCType string
}

// sdjwtVCType — 発行時に使う SD-JWT-VC の typ ヘッダ値を返す。未設定なら
// 現行 draft 推奨値 `dc+sd-jwt`。
func (i *Issuer) sdjwtVCType() string {
	if i.SDJWTVCType != "" {
		return i.SDJWTVCType
	}
	return "dc+sd-jwt"
}

// NewIssuer — ed25519 鍵ペアを生成し Issuer を構築。id は DID 形式。
func NewIssuer(id string) (*Issuer, error) {
	if id == "" {
		return nil, errors.New("issuer ID required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	return &Issuer{ID: id, privateKey: priv, publicKey: pub}, nil
}

// PublicKey — 検証者に配布するキー
func (i *Issuer) PublicKey() ed25519.PublicKey { return i.publicKey }

// canonicalPayload — 決定的バイト列を生成 (署名対象)
// 注意: JSON-LD正規化 (URDNA2015) は重いので、最小フィールドのみ確定順で配列化
// VC 2.0: validFrom/validUntil + credentialStatus を署名対象に含める
//
// Ed25519Signature2020 (W3C LD-Proofs): proofPurpose と verificationMethod も
// 署名対象に含めることで、転送中の改ざん (purpose confusion / key redirection)
// を防ぐ。proofValue は含めない (署名自体は自己参照できない)。
func canonicalPayload(c *Credential) ([]byte, error) {
	var proofPurpose, verificationMethod string
	if c.Proof != nil {
		proofPurpose = c.Proof.ProofPurpose
		verificationMethod = c.Proof.VerificationMethod
	}
	return json.Marshal(struct {
		Context            []string          `json:"@context"`
		Type               []string          `json:"type"`
		Issuer             string            `json:"issuer"`
		VF                 time.Time         `json:"validFrom"`
		VU                 *time.Time        `json:"validUntil,omitempty"`
		Subject            PassportClaim     `json:"credentialSubject"`
		Status             *CredentialStatus `json:"credentialStatus,omitempty"`
		ProofPurpose       string            `json:"proofPurpose"`
		VerificationMethod string            `json:"verificationMethod"`
	}{c.Context, c.Type, c.Issuer, c.ValidFrom, c.ValidUntil, c.Subject, c.Status,
		proofPurpose, verificationMethod})
}

// newPassportCredential builds the unsigned DPP credential shared by every
// issuer and every proof suite. Extracted so the Ed25519 and ES256 issuers
// cannot drift on @context, type, validity or the credentialStatus shape —
// duplicating this is how two issuers end up emitting subtly different
// credentials for the same product.
//
// status may be nil (no credentialStatus member). Returns the credential and
// the `now` used, so the caller stamps the proof with the same instant.
func newPassportCredential(issuerID string, claim PassportClaim, validFor time.Duration, status *CredentialStatus) (*Credential, time.Time, error) {
	if claim.ProductID == "" {
		return nil, time.Time{}, ErrEmptyProductID
	}
	now := time.Now().UTC()
	cred := &Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://schema.europa.eu/dpp/v1",
		},
		Type:      []string{"VerifiableCredential", "DigitalProductPassport"},
		Issuer:    issuerID,
		ValidFrom: now,
		Subject:   claim,
		Status:    status,
	}
	if validFor > 0 {
		exp := now.Add(validFor)
		cred.ValidUntil = &exp
	}
	return cred, now, nil
}

// newStatusEntry builds the W3C Bitstring Status List entry, validating the
// caller-supplied list URL and index.
func newStatusEntry(statusListURL string, index int, purpose string) (*CredentialStatus, error) {
	if statusListURL == "" {
		return nil, errors.New("compliance: statusListCredential URL required")
	}
	if index < 0 {
		return nil, errors.New("compliance: statusListIndex must be non-negative")
	}
	return &CredentialStatus{
		ID:                   fmt.Sprintf("%s#%d", statusListURL, index),
		Type:                 "BitstringStatusListEntry",
		StatusPurpose:        purpose,
		StatusListIndex:      fmt.Sprintf("%d", index),
		StatusListCredential: statusListURL,
	}, nil
}

// Issue — DPP発行
func (i *Issuer) Issue(claim PassportClaim, validFor time.Duration) (*Credential, error) {
	cred, now, err := newPassportCredential(i.ID, claim, validFor, nil)
	if err != nil {
		return nil, err
	}
	if err := i.attachProof(cred, now); err != nil {
		return nil, err
	}
	return cred, nil
}

// attachProof sets cred.Proof (metadata + ProofValue) using the issuer's
// selected cryptosuite. Default is Ed25519Signature2020 (fixed-field
// canonicalPayload, base64-std proofValue); i.LegacyProofSuite switches back to the
// current-REC eddsa-jcs-2022 Data Integrity suite (JCS hashData, multibase
// proofValue — see dataintegrity.go). The proof metadata is set BEFORE the
// signature so both suites bind proofPurpose/verificationMethod (the
// Ed25519Signature2020 path binds them via canonicalPayload; the DI path binds
// them via the hashed proof config), preventing post-issuance tampering.
func (i *Issuer) attachProof(cred *Credential, now time.Time) error {
	if i.LegacyProofSuite {
		cred.Proof = &Proof{
			Type:               "Ed25519Signature2020",
			Created:            now,
			VerificationMethod: i.ID + "#key-1",
			ProofPurpose:       "assertionMethod",
		}
		payload, err := canonicalPayload(cred)
		if err != nil {
			return fmt.Errorf("canonicalize: %w", err)
		}
		cred.Proof.ProofValue = base64.StdEncoding.EncodeToString(ed25519.Sign(i.privateKey, payload))
		return nil
	}
	cred.Proof = &Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        CryptosuiteEdDSAJCS2022,
		Created:            now,
		VerificationMethod: i.ID + "#key-1",
		ProofPurpose:       "assertionMethod",
	}
	return signDataIntegrity(cred, i.privateKey)
}

// IssueWithStatus — W3C Bitstring Status List entry を付与して DPP 発行。
//
// statusListURL は BitstringStatusListCredential の URL、index はその list 内の
// bit 位置。purpose は "revocation" | "suspension"。
// credentialStatus は署名対象に含まれるため、改ざんは検証で検知される。
func (i *Issuer) IssueWithStatus(claim PassportClaim, validFor time.Duration, statusListURL string, index int, purpose string) (*Credential, error) {
	status, err := newStatusEntry(statusListURL, index, purpose)
	if err != nil {
		return nil, err
	}
	cred, now, err := newPassportCredential(i.ID, claim, validFor, status)
	if err != nil {
		return nil, err
	}
	if err := i.attachProof(cred, now); err != nil {
		return nil, err
	}
	return cred, nil
}

// Verify — 発行者公開鍵で検証 (期限切れもチェック)
func Verify(cred *Credential, pub ed25519.PublicKey) error {
	return VerifyAt(cred, pub, time.Now().UTC())
}

// VerifyAt verifies the credential's proof and temporal validity at time `now`
// (deterministic variant of Verify). It rejects expired credentials (validUntil
// passed) and not-yet-valid credentials (validFrom more than a small leeway in the
// future), mirroring the SD-JWT verification path so both credential formats treat
// temporal bounds consistently.
func VerifyAt(cred *Credential, pub ed25519.PublicKey, now time.Time) error {
	if cred.Proof == nil {
		return ErrNoProof
	}
	if cred.ValidUntil != nil && now.After(*cred.ValidUntil) {
		return ErrExpired
	}
	if !cred.ValidFrom.IsZero() && cred.ValidFrom.After(now.Add(defaultLeeway)) {
		return ErrNotYetValid
	}
	if cred.Proof.ProofPurpose != "assertionMethod" {
		return ErrInvalidSig
	}
	// Dispatch on the proof suite. Verification must match what issuance
	// produced: the suites differ in canonicalization, signature algorithm and
	// proofValue encoding.
	//
	// An unknown cryptosuite is REJECTED rather than falling through to the
	// legacy Ed25519Signature2020 branch. Falling through would mean a
	// credential claiming a suite we do not implement gets verified under
	// different rules than it claims — the verifier would be honouring a
	// construction nobody asked for.
	if cred.Proof.Type == "DataIntegrityProof" {
		switch cred.Proof.Cryptosuite {
		case CryptosuiteEdDSAJCS2022:
			return verifyDataIntegrity(cred, pub)
		case CryptosuiteECDSAJCS2019:
			// pub carries an uncompressed SEC1 P-256 point here. ed25519.PublicKey
			// is a named []byte, so the existing signature accommodates it without
			// an API break — the same approach VerifySDJWTWithBinding uses for
			// ES256 SD-JWTs.
			return verifyDataIntegrityES256(cred, pub)
		default:
			return fmt.Errorf("%w: unsupported cryptosuite %q", ErrInvalidSig, cred.Proof.Cryptosuite)
		}
	}
	// Legacy Ed25519Signature2020. Guard the key length: ed25519.Verify panics
	// on a wrong-length key and ed25519.PublicKey is a named []byte, so nothing
	// at compile time stops one reaching here.
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("compliance: Ed25519Signature2020 verification key: %w: want %d bytes, got %d",
			ErrInvalidSig, ed25519.PublicKeySize, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(cred.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("sig decode: %w", err)
	}
	payload, err := canonicalPayload(cred)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrInvalidSig
	}
	return nil
}

// ============================================================================
// ZK Range Proof — センサ値範囲準拠証明 (原データ秘匿)
//
// 現状実装: コミットメント + TEE/センサ署名 による attested-range 方式
// 将来差替: Bulletproofs (range proof 言語サイズ ~700B for 64bit)
//
// インタフェースを分離することで、暗号プリミティブを後から差替可能。
// Apple式 "今日動く、明日強くなる" — ユーザ見える契約は不変。
// ============================================================================

// RangeStatement — 公開された準拠範囲 (例: コールドチェーン 2.0–8.0℃)
type RangeStatement struct {
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Unit string  `json:"unit"` // celsius|percent|lux|g
	Name string  `json:"name"` // 人間可読: "cold_chain_2_to_8C"
}

// Commitment — 値に対する不可逆コミット (hash(value||salt||ts))
type Commitment struct {
	Digest    string         `json:"digest"` // hex sha256
	Statement RangeStatement `json:"statement"`
	TimeNs    int64          `json:"tsNs"`
}

// RangeProof — コミット時点で値が範囲内であった監査可能な証拠
type RangeProof struct {
	Commitment Commitment `json:"commit"`
	InRange    bool       `json:"inRange"`
	AttesterID string     `json:"attester"` // センサ/TEEのDID
	Signature  string     `json:"sig"`      // base64 — attester署名
}

// SensorAttester — TEE/認証済センサハードウェア
// 実運用: Apple SEP, Google Titan, TPM 2.0, Nordic nRF DK, 等
type SensorAttester struct {
	ID         string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewSensorAttester — ZK 範囲証明用センサ構築。
func NewSensorAttester(id string) (*SensorAttester, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SensorAttester{ID: id, privateKey: priv, publicKey: pub}, nil
}

func (s *SensorAttester) PublicKey() ed25519.PublicKey { return s.publicKey }

// Commit — 生値+saltでコミット。saltは呼出側管理 (ハード乱数源)
func Commit(value float64, salt []byte, stmt RangeStatement) Commitment {
	h := sha256.New()
	fmt.Fprintf(h, "%.9f|", value)
	h.Write(salt)
	ts := time.Now().UnixNano()
	fmt.Fprintf(h, "|%d", ts)
	return Commitment{
		Digest:    fmt.Sprintf("%x", h.Sum(nil)),
		Statement: stmt,
		TimeNs:    ts,
	}
}

// Attest — TEE/センサが生値を見て範囲判定し署名
// 生値は外部に出ない。出るのは in-range bool のみ。
func (s *SensorAttester) Attest(commit Commitment, actualValue float64) (*RangeProof, error) {
	inRange := actualValue >= commit.Statement.Min && actualValue <= commit.Statement.Max
	payload, err := json.Marshal(struct {
		C  Commitment `json:"c"`
		IR bool       `json:"ir"`
		A  string     `json:"a"`
	}{commit, inRange, s.ID})
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(s.privateKey, payload)
	return &RangeProof{
		Commitment: commit,
		InRange:    inRange,
		AttesterID: s.ID,
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyRange — 認証済センサ公開鍵で範囲証明を検証
func VerifyRange(pr *RangeProof, attesterPub ed25519.PublicKey) error {
	// ed25519.Verify panics on a wrong-length key; fail closed instead.
	if len(attesterPub) != ed25519.PublicKeySize {
		return ErrInvalidSig
	}
	sig, err := base64.StdEncoding.DecodeString(pr.Signature)
	if err != nil {
		return fmt.Errorf("sig decode: %w", err)
	}
	payload, err := json.Marshal(struct {
		C  Commitment `json:"c"`
		IR bool       `json:"ir"`
		A  string     `json:"a"`
	}{pr.Commitment, pr.InRange, pr.AttesterID})
	if err != nil {
		return err
	}
	if !ed25519.Verify(attesterPub, payload, sig) {
		return ErrInvalidSig
	}
	if !pr.InRange {
		return ErrOutOfRange
	}
	return nil
}

// ============================================================================
// 統合: Passport に RangeProof を埋込 (コールドチェーン実需)
// ============================================================================

// AttachRangeProof — DPPの Attrs に証明を埋込 (base64 JSON)
// 発行後・検証前に使う。Passport署名を破壊しないよう署名は再生成。
func (i *Issuer) ReissueWithProofs(claim PassportClaim, proofs []RangeProof, validFor time.Duration) (*Credential, error) {
	if claim.Attrs == nil {
		claim.Attrs = make(map[string]string, len(proofs))
	}
	for idx, pr := range proofs {
		b, err := json.Marshal(pr)
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("rangeProof.%s.%d", pr.Commitment.Statement.Name, idx)
		claim.Attrs[key] = base64.StdEncoding.EncodeToString(b)
	}
	return i.Issue(claim, validFor)
}
