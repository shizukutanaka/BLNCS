// Package conformance — BLRCS 公開コンフォーマンステストスイート
//
// 目的: 第三者が BLRCS 互換実装を検証可能にする (Web Platform Tests / WebKit conformance パターン)。
//
// テストベクトル (JSON 形式) + Go ランナー の2層構成:
//   - test_vectors.json — 言語非依存の入力/期待値
//   - runner.go         — Go 実装ランナー (他言語は移植容易)
//
// カテゴリ:
//   - GTIN-14 check digit
//   - DID parse / method extraction
//   - SD-JWT issue / verify (Ed25519固定鍵で決定的)
//   - Merkle inclusion proof (RFC 6962)
//   - GS1 Digital Link build / parse
//
// 利用例 (third-party Rust 実装の場合):
//  1. test_vectors.json をダウンロード
//  2. 各 test case の input を実装に与える
//  3. expected_output と比較
//  4. PASS/FAIL を集計
//
// このパッケージ自体 BLRCS のリファレンス実装が全 vector に PASS することを保証する。
package conformance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"blrcs/compliance"
	"blrcs/openid4vp"
	"blrcs/scitt"
	"blrcs/types"
)

// ============================================================================
// Vector schema
// ============================================================================

// TestVector — 1つのコンフォーマンステストケース
type TestVector struct {
	ID       string          `json:"id"`       // unique識別子
	Category string          `json:"category"` // gtin|did|sdjwt|merkle|gs1|vc|dcql|tier|p256
	Desc     string          `json:"desc"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
	// 説明用ラベル
	Tags []string `json:"tags,omitempty"`
}

// VectorSuite — vector のコレクション
type VectorSuite struct {
	Version string       `json:"version"`
	Vectors []TestVector `json:"vectors"`
}

// Result — 1ベクター実行結果
type Result struct {
	VectorID string
	Passed   bool
	Reason   string
}

// RunSummary — 全実行結果サマリ
type RunSummary struct {
	Total   int
	Passed  int
	Failed  int
	Results []Result
}

// String — 人間可読レポート
func (r RunSummary) String() string {
	out := fmt.Sprintf("Conformance: %d/%d passed\n", r.Passed, r.Total)
	for _, res := range r.Results {
		mark := "✓"
		if !res.Passed {
			mark = "✗"
		}
		out += fmt.Sprintf("  %s %-40s %s\n", mark, res.VectorID, res.Reason)
	}
	return out
}

// ============================================================================
// Runner — Go 実装ランナー
// ============================================================================

// RunSuite — vector suite 全実行
func RunSuite(suite *VectorSuite) RunSummary {
	summary := RunSummary{Total: len(suite.Vectors)}
	for _, v := range suite.Vectors {
		r := runVector(v)
		summary.Results = append(summary.Results, r)
		if r.Passed {
			summary.Passed++
		} else {
			summary.Failed++
		}
	}
	return summary
}

func runVector(v TestVector) Result {
	r := Result{VectorID: v.ID}
	defer func() {
		if rec := recover(); rec != nil {
			r.Passed = false
			r.Reason = fmt.Sprintf("panic: %v", rec)
		}
	}()
	switch v.Category {
	case "gtin":
		return runGTIN(v)
	case "did":
		return runDID(v)
	case "sdjwt":
		return runSDJWT(v)
	case "merkle":
		return runMerkle(v)
	case "gs1":
		return runGS1(v)
	case "vc":
		return runVC(v)
	case "dcql":
		return runDCQL(v)
	case "tier":
		return runTier(v)
	case "p256":
		return runP256(v)
	}
	r.Reason = "unknown category: " + v.Category
	return r
}

// ----- GTIN -----

type gtinIn struct {
	GTIN string `json:"gtin"`
}
type gtinOut struct {
	Valid      bool   `json:"valid"`
	Normalized string `json:"normalized,omitempty"`
}

func runGTIN(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in gtinIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = "input unmarshal: " + err.Error()
		return r
	}
	var want gtinOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "expected unmarshal: " + err.Error()
		return r
	}
	g, err := types.NewGTIN(in.GTIN)
	gotValid := err == nil
	if gotValid != want.Valid {
		r.Reason = fmt.Sprintf("valid: got=%v want=%v (err=%v)", gotValid, want.Valid, err)
		return r
	}
	if gotValid && g.String() != want.Normalized {
		r.Reason = fmt.Sprintf("normalized: got=%q want=%q", g.String(), want.Normalized)
		return r
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ----- DID -----

type didIn struct {
	DID string `json:"did"`
}
type didOut struct {
	Valid      bool   `json:"valid"`
	Method     string `json:"method,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

func runDID(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in didIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want didOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}
	d, err := types.NewDID(in.DID)
	gotValid := err == nil
	if gotValid != want.Valid {
		r.Reason = fmt.Sprintf("valid: got=%v want=%v", gotValid, want.Valid)
		return r
	}
	if gotValid {
		if d.Method() != want.Method {
			r.Reason = fmt.Sprintf("method: got=%q want=%q", d.Method(), want.Method)
			return r
		}
		if d.Identifier() != want.Identifier {
			r.Reason = fmt.Sprintf("identifier: got=%q want=%q", d.Identifier(), want.Identifier)
			return r
		}
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ----- SD-JWT (deterministic with fixed seed) -----

type sdjwtIn struct {
	IssuerSeedHex string         `json:"issuerSeedHex"` // 32 byte seed
	IssuerDID     string         `json:"issuerDID"`
	Subject       string         `json:"subject"`
	SDClaims      map[string]any `json:"sdClaims"`
	ClearClaims   map[string]any `json:"clearClaims"`
	// WrongKeyHex, if non-empty, is the seed (hex) of a DIFFERENT Ed25519 key
	// to use as the verification key. This exercises the "wrong issuer key"
	// rejection path: a valid SD-JWT verified against a different public key
	// must fail. Third-party implementations must enforce this.
	WrongKeyHex string `json:"wrongKeyHex,omitempty"`
	// RawToken, if non-empty, bypasses issuance and is used as the SD-JWT
	// token to verify (against the key derived from IssuerSeedHex). This
	// exercises rejection of malformed or tampered tokens.
	RawToken string `json:"rawToken,omitempty"`
}
type sdjwtOut struct {
	// 検証可能であればOK (タイムスタンプ非決定的なので exact match 不可)
	VerifyOK    bool   `json:"verifyOK"`
	IssuerInVC  string `json:"issuerInVC,omitempty"`
	SubjectInVC string `json:"subjectInVC,omitempty"`
	VCT         string `json:"vct,omitempty"` // SD-JWT VC type (draft-ietf-oauth-sd-jwt-vc)
}

// ----- VC 2.0 (W3C Verifiable Credentials Data Model 2.0) -----

type vcIn struct {
	IssuerSeedHex string `json:"issuerSeedHex"`
	IssuerDID     string `json:"issuerDID"`
	ProductID     string `json:"productID"`
}
type vcOut struct {
	HasV2Context bool `json:"hasV2Context"` // @context contains credentials/v2
	HasValidFrom bool `json:"hasValidFrom"` // validFrom set (VC 2.0)
	VerifyOK     bool `json:"verifyOK"`
}

// runVC — W3C VC Data Model 2.0 適合性ベクタ。
func runVC(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in vcIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want vcOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}

	seed, err := hex.DecodeString(in.IssuerSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		r.Reason = "bad seed"
		return r
	}
	iss, issErr := compliance.NewIssuerFromKey(in.IssuerDID, ed25519.NewKeyFromSeed(seed))
	if issErr != nil {
		r.Reason = "issuer: " + issErr.Error()
		return r
	}
	cred, err := iss.Issue(compliance.PassportClaim{ProductID: in.ProductID}, 0)
	if err != nil {
		r.Reason = "issue: " + err.Error()
		return r
	}
	hasV2 := false
	for _, ctx := range cred.Context {
		if ctx == "https://www.w3.org/ns/credentials/v2" {
			hasV2 = true
		}
	}
	if want.HasV2Context && !hasV2 {
		r.Reason = "VC 2.0 context missing"
		return r
	}
	if want.HasValidFrom && cred.ValidFrom.IsZero() {
		r.Reason = "validFrom not set"
		return r
	}
	verifyOK := compliance.Verify(cred, iss.PublicKey()) == nil
	if want.VerifyOK != verifyOK {
		r.Reason = fmt.Sprintf("verifyOK: got=%v want=%v", verifyOK, want.VerifyOK)
		return r
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ----- DCQL (OpenID4VP v1.0 §6 query language) -----

type dcqlIn struct {
	Query  json.RawMessage `json:"query"`  // raw dcql_query JSON
	Claims map[string]any  `json:"claims"` // presented claims to match (optional)
}
type dcqlOut struct {
	ValidQuery bool `json:"validQuery"` // query passes §6 structural validation
	Matches    bool `json:"matches"`    // presented claims satisfy first credential query
}

// runDCQL — OpenID4VP v1.0 DCQL 適合性ベクタ。
func runDCQL(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in dcqlIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want dcqlOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}

	q, parseErr := openid4vp.ParseDCQL(in.Query)
	validQuery := parseErr == nil
	if validQuery != want.ValidQuery {
		r.Reason = fmt.Sprintf("validQuery: got=%v want=%v (%v)", validQuery, want.ValidQuery, parseErr)
		return r
	}
	if validQuery && in.Claims != nil {
		matches := q.Credentials[0].MatchClaims(in.Claims)
		if matches != want.Matches {
			r.Reason = fmt.Sprintf("matches: got=%v want=%v", matches, want.Matches)
			return r
		}
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ----- ESPR three-tier access model -----

type tierIn struct {
	// Claims: key -> {value, tier} の宣言
	Claims map[string]struct {
		Value any    `json:"value"`
		Tier  string `json:"tier"`
	} `json:"claims"`
	// ViewerTier: この権限で ClaimsAtOrBelow した結果を検証
	ViewerTier string `json:"viewerTier"`
}
type tierOut struct {
	VisibleCount int `json:"visibleCount"` // viewer が見られる claim 数
	ClearCount   int `json:"clearCount"`   // SD-JWT clear (public) に入る数
	SDCount      int `json:"sdCount"`      // SD-JWT selectively-disclosed の数
}

// runTier — ESPR 3-tier アクセスモデルの適合性ベクタ。
//
// 重要な安全不変条件を検証する: public は clear、それ以外は SD に分割され、
// authority データが clear に漏れない。
func runTier(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in tierIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want tierOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}

	tc := compliance.NewTieredClaims()
	for k, c := range in.Claims {
		tc.Set(k, c.Value, compliance.AccessTier(c.Tier))
	}

	visible := tc.ClaimsAtOrBelow(compliance.AccessTier(in.ViewerTier))
	if len(visible) != want.VisibleCount {
		r.Reason = fmt.Sprintf("visibleCount: got=%d want=%d", len(visible), want.VisibleCount)
		return r
	}

	clear, sd := tc.SplitForSDJWT()
	if len(clear) != want.ClearCount {
		r.Reason = fmt.Sprintf("clearCount: got=%d want=%d", len(clear), want.ClearCount)
		return r
	}
	if len(sd) != want.SDCount {
		r.Reason = fmt.Sprintf("sdCount: got=%d want=%d", len(sd), want.SDCount)
		return r
	}

	// 安全不変条件: clear に public 以外が含まれてはならない
	for k := range clear {
		tier, _ := tc.Tier(k)
		if tier != compliance.TierPublic {
			r.Reason = "SECURITY: non-public claim leaked into clear set: " + k
			return r
		}
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

func runSDJWT(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in sdjwtIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want sdjwtOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}

	seed, err := hex.DecodeString(in.IssuerSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		r.Reason = "bad seed"
		return r
	}
	priv := ed25519.NewKeyFromSeed(seed)
	// We need an Issuer with this exact key. compliance.NewIssuer generates random.
	// Therefore: we sign + verify directly via SD-JWT implementation through a fake issuer.
	iss, issErr := compliance.NewIssuerFromKey(in.IssuerDID, priv)
	if issErr != nil {
		r.Reason = "issuer: " + issErr.Error()
		return r
	}

	// Determine which token to verify: either a pre-crafted raw token (for
	// negative testing of malformed/tampered inputs) or a freshly issued one.
	token := in.RawToken
	if token == "" {
		var issErr error
		token, _, issErr = iss.IssueSDJWT(in.Subject, in.SDClaims, in.ClearClaims, 0)
		if issErr != nil {
			r.Reason = "issue: " + issErr.Error()
			return r
		}
	}

	// Determine which public key to verify against: either the issuer's own
	// key (normal path) or a deliberately wrong key (negative test vector for
	// "wrong issuer key must be rejected").
	verifyKey := iss.PublicKey()
	if in.WrongKeyHex != "" {
		wrongSeed, hexErr := hex.DecodeString(in.WrongKeyHex)
		if hexErr != nil || len(wrongSeed) != ed25519.SeedSize {
			r.Reason = "bad wrongKeyHex"
			return r
		}
		verifyKey = ed25519.NewKeyFromSeed(wrongSeed).Public().(ed25519.PublicKey)
	}

	vc, err := compliance.VerifySDJWT(token, verifyKey)
	if err != nil {
		if want.VerifyOK {
			r.Reason = "verify: " + err.Error()
			return r
		}
		// Expected failure
		r.Passed = true
		r.Reason = "ok (expected fail)"
		return r
	}
	if !want.VerifyOK {
		r.Reason = "verify unexpectedly succeeded"
		return r
	}
	if want.IssuerInVC != "" && vc.Issuer != want.IssuerInVC {
		r.Reason = fmt.Sprintf("issuer: got=%q want=%q", vc.Issuer, want.IssuerInVC)
		return r
	}
	if want.SubjectInVC != "" && vc.Subject != want.SubjectInVC {
		r.Reason = fmt.Sprintf("subject: got=%q want=%q", vc.Subject, want.SubjectInVC)
		return r
	}
	if want.VCT != "" && vc.VCT != want.VCT {
		r.Reason = fmt.Sprintf("vct: got=%q want=%q", vc.VCT, want.VCT)
		return r
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ----- Merkle -----

type merkleIn struct {
	Leaves []string `json:"leaves"` // hex
}
type merkleOut struct {
	Root string `json:"root"` // hex
}

func runMerkle(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in merkleIn
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want merkleOut
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}
	leaves := make([][]byte, len(in.Leaves))
	for i, h := range in.Leaves {
		b, err := hex.DecodeString(h)
		if err != nil {
			r.Reason = "leaf decode: " + err.Error()
			return r
		}
		leaves[i] = scitt.HashLeaf(b)
	}
	root := scitt.MerkleRootForTest(leaves)
	gotHex := hex.EncodeToString(root)
	if gotHex != want.Root {
		r.Reason = fmt.Sprintf("root: got=%s want=%s", gotHex, want.Root)
		return r
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ----- GS1 Digital Link -----

type gs1In struct {
	Domain string `json:"domain"`
	GTIN   string `json:"gtin"`
	Serial string `json:"serial,omitempty"`
	Batch  string `json:"batch,omitempty"`
}
type gs1Out struct {
	Valid    bool   `json:"valid"`
	BuildURL string `json:"buildURL,omitempty"`
}

func runGS1(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in gs1In
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = err.Error()
		return r
	}
	var want gs1Out
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected vector: " + err.Error()
		return r
	}
	url, err := compliance.BuildDLURI(in.Domain, compliance.GS1Key{
		GTIN:   in.GTIN,
		Serial: in.Serial,
		Batch:  in.Batch,
	})
	gotValid := err == nil
	if gotValid != want.Valid {
		r.Reason = fmt.Sprintf("valid: got=%v want=%v (err=%v)", gotValid, want.Valid, err)
		return r
	}
	if gotValid && url != want.BuildURL {
		r.Reason = fmt.Sprintf("URL: got=%q want=%q", url, want.BuildURL)
		return r
	}
	r.Passed = true
	r.Reason = "ok"
	return r
}

// ============================================================================
// Reference suite — BLRCS が必ず通るベクトル
// ============================================================================

// ReferenceSuite — BLRCS reference test vectors
//
// 第三者実装はこれを fetch して全 PASS することで「BLRCS互換」を主張可能。
func ReferenceSuite() *VectorSuite {
	return &VectorSuite{
		Version: "1.0",
		Vectors: []TestVector{
			// ---- P-256 / EUDI (Axes 135-148) ----
			// RFC 7636 Appendix B: the specification's own published pair, so
			// passing proves agreement with the RFC and not merely with BLRCS.
			{
				ID: "p256/pkce-rfc7636-appendix-b", Category: "p256",
				Desc: "PKCE S256 code_challenge derivation (RFC 7636 Appendix B)",
				Input: raw(map[string]any{
					"op":       "pkce_s256",
					"verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				}),
				Expected: raw(map[string]any{"challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}),
			},
			// ES256 signatures are raw fixed-width R||S (RFC 7518 §3.4), NOT
			// ASN.1 DER. An implementation that emits DER fails this vector,
			// which is the single most common ES256 interop mistake.
			{
				ID: "p256/es256-verify-valid", Category: "p256",
				Desc: "ES256 verification over raw R||S (RFC 7518 §3.4)",
				Input: raw(map[string]any{
					"op":   "es256_verify",
					"sec1": "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
					"msg":  "424c52435320636f6e666f726d616e636520455332353620766563746f72207631",
					"sig":  "942428c565ea1ca9410b971a4a8ad67318f67e7a1de0d0be92416978db149a2539385d5a33db7d1d517527fc4c69c7d6860d47cd1092d10e8ab742eefb4f52d9",
				}),
				Expected: raw(map[string]any{"valid": true}),
			},
			{
				ID: "p256/es256-verify-tampered", Category: "p256",
				Desc: "ES256 verification rejects a flipped signature bit",
				Input: raw(map[string]any{
					"op":   "es256_verify",
					"sec1": "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
					"msg":  "424c52435320636f6e666f726d616e636520455332353620766563746f72207631",
					"sig":  "942428c565ea1ca9410b971a4a8ad67318f67e7a1de0d0be92416978db149a2539385d5a33db7d1d517527fc4c69c7d6860d47cd1092d10e8ab742eefb4f52d8",
				}),
				Expected: raw(map[string]any{"valid": false}),
			},
			// End-to-end ECDH-ES + Concat KDF + A128GCM. The KDF's OtherInfo
			// construction (RFC 7518 §4.6.2) is the part most often got wrong;
			// a wrong one decrypts to nothing, so this vector catches it.
			// The private key is published deliberately — conformance vectors
			// are public and this key exists only to make the vector checkable.
			{
				ID: "p256/jwe-decrypt-ecdh-es-a128gcm", Category: "p256",
				Desc: "JWE ECDH-ES + A128GCM decryption (RFC 7516 / RFC 7518 §4.6, §5.3)",
				Input: raw(map[string]any{
					"op":      "jwe_decrypt",
					"privD":   "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
					"compact": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlA4YzVxdVpoaUl3NWhHZWpsQzdQT2p5RGpLVDlyeTJ3Mk9LVGhCLUVHMjgiLCJ5IjoieDRGRGxzd2FRaUdsWHhGUTE3YW9veV9odUFRRHFDdUplNC0yMC1Uc0lXbyJ9LCJhcHUiOiJZbXh5WTNNIn0..AOfPw_7RnH1O7yen.o0WMrQ9Om6EA6yfDtTb8xQdSIzakiyYzYRZCvhRDg1nPl5DwWMfV.krXhBtCcB5-lBxboj357Vw",
				}),
				Expected: raw(map[string]any{"valid": true, "plaintext": "{\"vp_token\":\"conformance\",\"state\":\"v1\"}"}),
			},
			// RFC 7518 §6.2.1.2: JWK coordinates are FIXED-WIDTH — padded to the
			// full field length, not a minimal big-endian integer.
			{
				ID: "p256/point-to-jwk-coords", Category: "p256",
				Desc: "SEC1 uncompressed point to fixed-width JWK coordinates (RFC 7518 §6.2.1.2)",
				Input: raw(map[string]any{
					"op":    "p256_point",
					"point": "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
				}),
				Expected: raw(map[string]any{
					"valid": true,
					"x":     "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y",
					"y":     "eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk",
				}),
			},
			// An off-curve point must be REJECTED, not coerced. Accepting one is
			// the invalid-curve attack.
			{
				ID: "p256/point-off-curve-rejected", Category: "p256",
				Desc: "Off-curve point rejected (invalid-curve defence)",
				Input: raw(map[string]any{
					"op":    "p256_point",
					"point": "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462298",
				}),
				Expected: raw(map[string]any{"valid": false}),
			},

			// GTIN
			{
				ID: "gtin/valid-14digit", Category: "gtin",
				Desc:     "Valid GTIN-14",
				Input:    raw(map[string]any{"gtin": "04012345678901"}),
				Expected: raw(map[string]any{"valid": true, "normalized": "04012345678901"}),
			},
			{
				ID: "gtin/invalid-checkdigit", Category: "gtin",
				Desc:     "Invalid check digit",
				Input:    raw(map[string]any{"gtin": "04012345678902"}),
				Expected: raw(map[string]any{"valid": false}),
			},
			{
				ID: "gtin/empty", Category: "gtin",
				Desc:     "Empty input rejected",
				Input:    raw(map[string]any{"gtin": ""}),
				Expected: raw(map[string]any{"valid": false}),
			},
			{
				ID: "gtin/non-digit", Category: "gtin",
				Input:    raw(map[string]any{"gtin": "0401234567890A"}),
				Expected: raw(map[string]any{"valid": false}),
			},
			// DID
			{
				ID: "did/web", Category: "did",
				Desc:     "Standard did:web",
				Input:    raw(map[string]any{"did": "did:web:example.com"}),
				Expected: raw(map[string]any{"valid": true, "method": "web", "identifier": "example.com"}),
			},
			{
				ID: "did/key", Category: "did",
				Input:    raw(map[string]any{"did": "did:key:z6Mk1234"}),
				Expected: raw(map[string]any{"valid": true, "method": "key", "identifier": "z6Mk1234"}),
			},
			{
				ID: "did/empty-method", Category: "did",
				Input:    raw(map[string]any{"did": "did::id"}),
				Expected: raw(map[string]any{"valid": false}),
			},
			{
				ID: "did/no-prefix", Category: "did",
				Input:    raw(map[string]any{"did": "web:example.com"}),
				Expected: raw(map[string]any{"valid": false}),
			},
			// SD-JWT (using fixed Ed25519 seed for reproducibility)
			{
				ID: "sdjwt/basic-issue-verify", Category: "sdjwt",
				Desc: "Issue with fixed seed and verify",
				Input: raw(map[string]any{
					"issuerSeedHex": "0001020304050607080910111213141516171819202122232425262728293031",
					"issuerDID":     "did:web:test.example",
					"subject":       "subject-1",
					"sdClaims":      map[string]any{"carbonKgCO2e": 2.5},
					"clearClaims":   map[string]any{"productId": "P1"},
				}),
				Expected: raw(map[string]any{
					"verifyOK":    true,
					"issuerInVC":  "did:web:test.example",
					"subjectInVC": "subject-1",
					"vct":         compliance.VCTDigitalProductPassport,
				}),
			},
			// SD-JWT negative vectors — Axis 81
			// These exercise the rejection paths that third-party implementations
			// must also enforce. A verifier that accepts any of these must be
			// considered non-conformant.
			{
				ID:       "sdjwt/wrong-issuer-key-rejected",
				Category: "sdjwt",
				Desc:     "SD-JWT verified with the wrong issuer public key must be rejected",
				Tags:     []string{"negative", "security"},
				Input: raw(map[string]any{
					"issuerSeedHex": "0001020304050607080910111213141516171819202122232425262728293031",
					"issuerDID":     "did:web:test.example",
					"subject":       "subject-neg-1",
					"sdClaims":      map[string]any{"carbonKgCO2e": 1.0},
					"clearClaims":   map[string]any{"productId": "P-neg-1"},
					// wrongKeyHex: a different Ed25519 seed → wrong public key for verification
					"wrongKeyHex": "3132333435363738393031323334353637383930313233343536373839303132",
				}),
				Expected: raw(map[string]any{"verifyOK": false}),
			},
			{
				ID:       "sdjwt/malformed-token-rejected",
				Category: "sdjwt",
				Desc:     "A malformed SD-JWT (not base64url-encoded JWS) must be rejected",
				Tags:     []string{"negative", "security"},
				Input: raw(map[string]any{
					"issuerSeedHex": "0001020304050607080910111213141516171819202122232425262728293031",
					"issuerDID":     "did:web:test.example",
					// rawToken bypasses issuance; this token has invalid structure
					"rawToken": "not.a.valid.sdjwt~",
				}),
				Expected: raw(map[string]any{"verifyOK": false}),
			},
			{
				ID:       "sdjwt/truncated-signature-rejected",
				Category: "sdjwt",
				Desc:     "SD-JWT with a truncated (corrupt) signature must be rejected",
				Tags:     []string{"negative", "security"},
				Input: raw(map[string]any{
					"issuerSeedHex": "0001020304050607080910111213141516171819202122232425262728293031",
					"issuerDID":     "did:web:test.example",
					// A syntactically valid 3-part structure but with a truncated sig
					"rawToken": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.dHJ1bmNhdGVk~",
				}),
				Expected: raw(map[string]any{"verifyOK": false}),
			},
			// VC 2.0 (W3C Verifiable Credentials Data Model 2.0)
			{
				ID: "vc/v2-context", Category: "vc",
				Desc: "Issued credential uses VC 2.0 context and validFrom",
				Input: raw(map[string]any{
					"issuerSeedHex": "0001020304050607080910111213141516171819202122232425262728293031",
					"issuerDID":     "did:web:test.example",
					"productID":     "04012345678901",
				}),
				Expected: raw(map[string]any{
					"hasV2Context": true,
					"hasValidFrom": true,
					"verifyOK":     true,
				}),
			},
			// DCQL (OpenID4VP v1.0 §6 — the only query language post-v1.0)
			{
				ID: "dcql/valid-sdjwt-query", Category: "dcql",
				Desc: "Well-formed DCQL query for an SD-JWT VC passes validation",
				Input: raw(map[string]any{
					"query": map[string]any{
						"credentials": []any{map[string]any{
							"id":     "dpp",
							"format": "dc+sd-jwt",
							"meta":   map[string]any{"vct_values": []string{"https://schema.europa.eu/dpp/sd-jwt-vc/v1"}},
							"claims": []any{map[string]any{"path": []string{"carbonKgCO2ePerKWh"}}},
						}},
					},
					"claims": map[string]any{"carbonKgCO2ePerKWh": 12.5},
				}),
				Expected: raw(map[string]any{"validQuery": true, "matches": true}),
			},
			{
				ID: "dcql/empty-credentials-invalid", Category: "dcql",
				Desc: "DCQL query with no credentials fails §6 validation",
				Input: raw(map[string]any{
					"query": map[string]any{"credentials": []any{}},
				}),
				Expected: raw(map[string]any{"validQuery": false}),
			},
			{
				ID: "dcql/claim-mismatch", Category: "dcql",
				Desc: "Presented claims missing a required claim do not match",
				Input: raw(map[string]any{
					"query": map[string]any{
						"credentials": []any{map[string]any{
							"id":     "dpp",
							"format": "dc+sd-jwt",
							"claims": []any{map[string]any{"path": []string{"batteryCategory"}}},
						}},
					},
					"claims": map[string]any{"somethingElse": "x"},
				}),
				Expected: raw(map[string]any{"validQuery": true, "matches": false}),
			},
			// ESPR three-tier access model
			{
				ID: "tier/authority-sees-all", Category: "tier",
				Desc: "Authority viewer sees all tiers; clear set holds only public",
				Input: raw(map[string]any{
					"claims": map[string]any{
						"carbon":   map[string]any{"value": 12.5, "tier": "public"},
						"material": map[string]any{"value": "NMC", "tier": "restricted"},
						"contract": map[string]any{"value": "x", "tier": "authority"},
					},
					"viewerTier": "authority",
				}),
				Expected: raw(map[string]any{"visibleCount": 3, "clearCount": 1, "sdCount": 2}),
			},
			{
				ID: "tier/consumer-public-only", Category: "tier",
				Desc: "Consumer (public viewer) sees only public-tier claims",
				Input: raw(map[string]any{
					"claims": map[string]any{
						"carbon":   map[string]any{"value": 12.5, "tier": "public"},
						"material": map[string]any{"value": "NMC", "tier": "restricted"},
					},
					"viewerTier": "public",
				}),
				Expected: raw(map[string]any{"visibleCount": 1, "clearCount": 1, "sdCount": 1}),
			},
			{
				ID: "tier/restricted-excludes-authority", Category: "tier",
				Desc: "Restricted viewer sees public+restricted but not authority",
				Input: raw(map[string]any{
					"claims": map[string]any{
						"a": map[string]any{"value": 1, "tier": "public"},
						"b": map[string]any{"value": 2, "tier": "restricted"},
						"c": map[string]any{"value": 3, "tier": "authority"},
					},
					"viewerTier": "restricted",
				}),
				Expected: raw(map[string]any{"visibleCount": 2, "clearCount": 1, "sdCount": 2}),
			},
			// Merkle (RFC 6962 hashing — leaf prefix 0x00, node prefix 0x01)
			{
				ID: "merkle/single-leaf", Category: "merkle",
				Desc:  "Single leaf root = hashLeaf(value)",
				Input: raw(map[string]any{"leaves": []string{"61"}}), // "a"
				Expected: raw(map[string]any{
					"root": expectedSingleLeafRoot("a"),
				}),
			},
			{
				ID: "merkle/two-leaves", Category: "merkle",
				Desc:  "Two-leaf tree",
				Input: raw(map[string]any{"leaves": []string{"61", "62"}}), // "a", "b"
				Expected: raw(map[string]any{
					"root": expectedTwoLeafRoot("a", "b"),
				}),
			},
			// GS1 Digital Link
			{
				ID: "gs1/basic-build", Category: "gs1",
				Input: raw(map[string]any{
					"domain": "dpp.example.com",
					"gtin":   "04012345678901",
					"serial": "ABC",
				}),
				Expected: raw(map[string]any{
					"valid":    true,
					"buildURL": "https://dpp.example.com/01/04012345678901/21/ABC",
				}),
			},
			{
				ID: "gs1/invalid-gtin", Category: "gs1",
				Input: raw(map[string]any{
					"domain": "x.example",
					"gtin":   "999",
				}),
				Expected: raw(map[string]any{"valid": false}),
			},
		},
	}
}

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// expectedSingleLeafRoot — RFC 6962: root for [v] = hashLeaf(v) only
func expectedSingleLeafRoot(s string) string {
	leaf := scitt.HashLeaf([]byte(s))
	return hex.EncodeToString(leaf)
}

// expectedTwoLeafRoot — RFC 6962: root = hashNode(hashLeaf(a), hashLeaf(b))
func expectedTwoLeafRoot(a, b string) string {
	la := scitt.HashLeaf([]byte(a))
	lb := scitt.HashLeaf([]byte(b))
	root := scitt.HashNode(la, lb)
	return hex.EncodeToString(root)
}

// ============================================================================
// Export — 第三者ダウンロード用 JSON 化
// ============================================================================

// ExportJSON — vector suite を JSON 形式でエクスポート
//
// 公開用: /.well-known/conformance.json で配信、第三者実装が fetch して使う
func ExportJSON(suite *VectorSuite) ([]byte, error) {
	if suite == nil {
		return nil, errors.New("conformance: nil suite")
	}
	// stable hash 用の内容ハッシュも添付
	body, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(body)
	withMeta := struct {
		*VectorSuite
		ContentHashHex string `json:"contentHashHex"`
	}{
		VectorSuite:    suite,
		ContentHashHex: hex.EncodeToString(h[:]),
	}
	return json.MarshalIndent(withMeta, "", "  ")
}
