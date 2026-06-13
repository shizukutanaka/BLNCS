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

// Proof — Ed25519Signature2020 (軽量, 32B鍵, 64B署名)
type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofValue         string    `json:"proofValue"` // base64-std
}

// ============================================================================
// Issuer — 発行者 (製造者/倉庫/運送業者)
// ============================================================================

type Issuer struct {
	ID         string // DID 例: did:web:factory.example/passport
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
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
func canonicalPayload(c *Credential) ([]byte, error) {
	return json.Marshal(struct {
		Context []string          `json:"@context"`
		Type    []string          `json:"type"`
		Issuer  string            `json:"issuer"`
		VF      time.Time         `json:"validFrom"`
		VU      *time.Time        `json:"validUntil,omitempty"`
		Subject PassportClaim     `json:"credentialSubject"`
		Status  *CredentialStatus `json:"credentialStatus,omitempty"`
	}{c.Context, c.Type, c.Issuer, c.ValidFrom, c.ValidUntil, c.Subject, c.Status})
}

// Issue — DPP発行
func (i *Issuer) Issue(claim PassportClaim, validFor time.Duration) (*Credential, error) {
	if claim.ProductID == "" {
		return nil, ErrEmptyProductID
	}
	now := time.Now().UTC()
	cred := &Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://schema.europa.eu/dpp/v1",
		},
		Type:      []string{"VerifiableCredential", "DigitalProductPassport"},
		Issuer:    i.ID,
		ValidFrom: now,
		Subject:   claim,
	}
	if validFor > 0 {
		exp := now.Add(validFor)
		cred.ValidUntil = &exp
	}
	payload, err := canonicalPayload(cred)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	sig := ed25519.Sign(i.privateKey, payload)
	cred.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now,
		VerificationMethod: i.ID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.StdEncoding.EncodeToString(sig),
	}
	return cred, nil
}

// IssueWithStatus — W3C Bitstring Status List entry を付与して DPP 発行。
//
// statusListURL は BitstringStatusListCredential の URL、index はその list 内の
// bit 位置。purpose は "revocation" | "suspension"。
// credentialStatus は署名対象に含まれるため、改ざんは検証で検知される。
func (i *Issuer) IssueWithStatus(claim PassportClaim, validFor time.Duration, statusListURL string, index int, purpose string) (*Credential, error) {
	if claim.ProductID == "" {
		return nil, ErrEmptyProductID
	}
	if statusListURL == "" {
		return nil, errors.New("compliance: statusListCredential URL required")
	}
	if index < 0 {
		return nil, errors.New("compliance: statusListIndex must be non-negative")
	}
	now := time.Now().UTC()
	cred := &Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://schema.europa.eu/dpp/v1",
		},
		Type:      []string{"VerifiableCredential", "DigitalProductPassport"},
		Issuer:    i.ID,
		ValidFrom: now,
		Subject:   claim,
		Status: &CredentialStatus{
			ID:                   fmt.Sprintf("%s#%d", statusListURL, index),
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        purpose,
			StatusListIndex:      fmt.Sprintf("%d", index),
			StatusListCredential: statusListURL,
		},
	}
	if validFor > 0 {
		exp := now.Add(validFor)
		cred.ValidUntil = &exp
	}
	payload, err := canonicalPayload(cred)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	sig := ed25519.Sign(i.privateKey, payload)
	cred.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now,
		VerificationMethod: i.ID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.StdEncoding.EncodeToString(sig),
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
