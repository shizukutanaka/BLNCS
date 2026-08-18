// プロパティベーステスト — 生成的な不変条件検証
//
// Apple Swift Testing の #require / #expect(throws:) + QuickCheck 思想。
// 「任意の有効な入力に対して、この性質は常に成立する」を機械的に検証。
//
// テスト対象の不変条件 (Invariants):
//  1. Round-trip: parse(serialize(x)) == x
//  2. Monotonic: append-only は逆転しない
//  3. Composition: VC 検証は発行者が変わると必ず失敗
//  4. Privacy: SD-JWT 選択開示は決して「見せてはいけない」ものを開示しない
//  5. Merkle: leaf 数増加でも旧 leaf の包含証明は常に検証可能
package property

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	"blrcs/cas"
	"blrcs/compliance"
	"blrcs/errkit"
	"blrcs/scitt"
	"blrcs/types"
)

// ============================================================================
// Generator helpers — Apple 式の "test oracle" 生成
// ============================================================================

// randString — n バイトのランダム ASCII 文字列
func randString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[idx.Int64()]
	}
	return string(b)
}

// randFloat — [min, max] のランダム float64
func randFloat(min, max float64) float64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return min + float64(n.Int64())/float64(1<<32)*(max-min)
}

// randClaim — ランダムな PassportClaim (Product ID は常に有効値)
func randClaim() compliance.PassportClaim {
	return compliance.PassportClaim{
		ProductID:     "P" + randString(6),
		CarbonKgCO2e:  randFloat(0, 1000),
		Recyclability: float32(randFloat(0, 1)),
	}
}

// ============================================================================
// 1. Round-trip 不変条件
// ============================================================================

// TestDIDRoundTrip — 有効な DID は serialize → parse で同値
func TestDIDRoundTrip(t *testing.T) {
	methods := []string{"web", "key", "jwk", "ion", "ebsi"}
	for _, method := range methods {
		for i := 0; i < 20; i++ {
			did := "did:" + method + ":" + randString(8) + ".example"
			d, err := types.NewDID(did)
			if err != nil {
				continue // この入力は無効なので skip
			}
			// serialize → parse 同値
			d2, err := types.NewDID(d.String())
			if err != nil {
				t.Errorf("round-trip parse failed for %q: %v", d.String(), err)
				continue
			}
			if d.String() != d2.String() {
				t.Errorf("round-trip mismatch: %q -> %q", d.String(), d2.String())
			}
		}
	}
}

// TestCarbonFootprintMonotonic — CarbonFootprint の加算は単調増加
func TestCarbonFootprintMonotonic(t *testing.T) {
	for i := 0; i < 50; i++ {
		a := randFloat(0, 500)
		b := randFloat(0, 500)
		ca, _ := types.NewCarbonFootprint(a)
		cb, _ := types.NewCarbonFootprint(b)
		// Property: a + b >= a かつ a + b >= b
		sum := ca.KgCO2e() + cb.KgCO2e()
		if sum < ca.KgCO2e() || sum < cb.KgCO2e() {
			t.Errorf("monotonic violated: %.4f + %.4f = %.4f", a, b, sum)
		}
	}
}

// TestPercentBoundary — Percent は境界値 0, 100 を含む、範囲外は拒否
func TestPercentBoundary(t *testing.T) {
	// 0 と 100 は valid
	for _, v := range []float64{0, 0.001, 50, 99.999, 100} {
		if _, err := types.NewPercent(v); err != nil {
			t.Errorf("%.4f should be valid: %v", v, err)
		}
	}
	// 0 未満と 100 超は invalid
	for _, v := range []float64{-0.001, -1, 100.001, 200} {
		if _, err := types.NewPercent(v); err == nil {
			t.Errorf("%.4f should be invalid", v)
		}
	}
}

// ============================================================================
// 2. VC 署名の構成的性質 (Composition laws)
// ============================================================================

// TestVCSignatureComposition — 発行者が変わると必ず検証失敗
func TestVCSignatureComposition(t *testing.T) {
	for i := 0; i < 10; i++ {
		iss1, _ := compliance.NewIssuer("did:web:issuer1.test")
		iss2, _ := compliance.NewIssuer("did:web:issuer2.test")

		claim := randClaim()
		cred, err := iss1.Issue(claim, 0)
		if err != nil {
			t.Fatal(err)
		}
		// iss1 の鍵で検証 → OK
		if err := compliance.Verify(cred, iss1.PublicKey()); err != nil {
			t.Errorf("valid issuer should verify: %v", err)
		}
		// iss2 の鍵で検証 → MUST FAIL
		if err := compliance.Verify(cred, iss2.PublicKey()); err == nil {
			t.Error("CRITICAL: wrong issuer key must not verify")
		}
	}
}

// TestVCTamperAlwaysFails — どのフィールドを改ざんしても署名検証は失敗
func TestVCTamperAlwaysFails(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:iss.test")
	claim := randClaim()
	cred, _ := iss.Issue(claim, time.Hour)
	original := cred.Subject.CarbonKgCO2e

	// 任意の delta で改ざんしても失敗
	deltas := []float64{0.001, 1.0, -1.0, 1000.0}
	for _, delta := range deltas {
		modified := *cred
		modified.Subject.CarbonKgCO2e = original + delta
		if err := compliance.Verify(&modified, iss.PublicKey()); err == nil {
			t.Errorf("tamper (delta=%.3f) should fail", delta)
		}
	}
}

// ============================================================================
// 3. SD-JWT プライバシー不変条件
// ============================================================================

// TestSDJWTPrivacyInvariant — 選択開示で公開しないフィールドは絶対に漏れない
func TestSDJWTPrivacyInvariant(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:sdj.test")

	// 秘匿すべきフィールドのセット
	secretClaims := map[string]any{
		"supplierName":      "SuperSecret Co.",
		"internalPrice":     9999.99,
		"costBreakdown":     "labor:30%,material:70%",
		"manufacturingLine": "Line-B-7",
	}
	publicClaims := map[string]any{
		"productId": "EV-BATTERY-001",
		"category":  "battery",
	}

	sdjwt, _, err := iss.IssueSDJWT("product-1", secretClaims, publicClaims, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 「何も選択しない」プレゼンテーション
	presented, err := compliance.Present(sdjwt, []string{})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := compliance.VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Property: 秘匿フィールドは claims に存在しない
	for secret := range secretClaims {
		if _, leaked := vc.Claims[secret]; leaked {
			t.Errorf("PRIVACY VIOLATION: %q leaked with no disclosure", secret)
		}
	}
	// Property: 公開フィールドは常に見える
	for pub := range publicClaims {
		if _, ok := vc.Claims[pub]; !ok {
			t.Errorf("clear claim %q should always be visible", pub)
		}
	}
}

// TestSDJWTSelectiveDisclosureMonotonic — 開示フィールド増加 → 可視クレーム増加 (単調)
func TestSDJWTSelectiveDisclosureMonotonic(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:sdj.mono.test")
	keys := []string{"a", "b", "c", "d", "e"}
	sdClaims := make(map[string]any, len(keys))
	for _, k := range keys {
		sdClaims[k] = randString(4)
	}
	sdjwt, _, _ := iss.IssueSDJWT("s", sdClaims, nil, time.Hour)

	var prev int
	for i := range keys {
		reveal := keys[:i+1]
		pres, _ := compliance.Present(sdjwt, reveal)
		vc, err := compliance.VerifySDJWT(pres, iss.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		visible := 0
		for _, k := range keys {
			if _, ok := vc.Claims[k]; ok {
				visible++
			}
		}
		// 単調増加: 前回以上の可視クレーム
		if visible < prev {
			t.Errorf("monotonic violated at i=%d: visible %d < prev %d", i, visible, prev)
		}
		prev = visible
	}
}

// ============================================================================
// 4. Merkle 包含証明の成長不変条件
// ============================================================================

// TestMerkleInclusionAfterGrowth — 旧 leaf の包含証明は tree 成長後も検証可能
func TestMerkleInclusionAfterGrowth(t *testing.T) {
	// N 個登録後に任意の leaf の包含証明を検証
	const N = 50
	ledger, _ := scitt.NewLedger("did:web:prop.ts")
	priv, pub, _ := generateEd25519()
	_ = pub

	// Iss helper
	issuer, _ := compliance.NewIssuer("did:web:prop.iss")
	type saved struct {
		stmt    scitt.Statement
		receipt *scitt.Receipt
	}
	var items []saved

	for i := 0; i < N; i++ {
		stmt, _ := scitt.SignStatement(
			issuer.PrivateKey(), issuer.ID,
			fmt.Sprintf("subject-%d", i), "text/plain",
			[]byte(fmt.Sprintf("payload-%d-%s", i, randString(8))),
		)
		receipt, err := ledger.Register(stmt)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, saved{stmt, receipt})
		_ = priv
	}

	// Property: 全ての登録済み leaf は現在の tree で検証可能
	for _, item := range items {
		// Get fresh receipt from grown tree
		idx := item.receipt.LeafIndex
		gotStmt, freshReceipt, err := ledger.Get(idx)
		if err != nil {
			t.Fatalf("Get(%d): %v", idx, err)
		}
		if err := scitt.VerifyReceipt(freshReceipt, gotStmt, ledger.PublicKey()); err != nil {
			t.Errorf("leaf %d inclusion proof failed after growth to %d: %v",
				idx, ledger.Size(), err)
		}
	}
}

// TestMerkleTreeSizeMonotonic — ledger.Size() は append-only で単調増加
func TestMerkleTreeSizeMonotonic(t *testing.T) {
	ledger, _ := scitt.NewLedger("did:web:mono.ts")
	iss, _ := compliance.NewIssuer("did:web:mono.iss")
	prev := ledger.Size()
	for i := 0; i < 30; i++ {
		stmt, _ := scitt.SignStatement(iss.PrivateKey(), iss.ID, fmt.Sprintf("s%d", i), "c", []byte("p"))
		ledger.Register(stmt)
		cur := ledger.Size()
		if cur <= prev {
			t.Errorf("size not strictly increasing: prev=%d cur=%d", prev, cur)
		}
		prev = cur
	}
}

// ============================================================================
// helpers
// ============================================================================

func generateEd25519() ([]byte, []byte, error) {
	priv := make([]byte, 64)
	rand.Read(priv)
	return priv, priv[32:], nil
}

// ============================================================================
// New property tests
// ============================================================================

// TestCASHashDeterminism — ComputeHash(p) == ComputeHash(p) always
func TestCASHashDeterminism(t *testing.T) {
	for i := 0; i < 100; i++ {
		payload := []byte(randString(mrand.Intn(200) + 1))
		h1 := cas.ComputeHash(payload)
		h2 := cas.ComputeHash(payload)
		if h1 != h2 {
			t.Errorf("non-deterministic hash for %q", payload)
		}
	}
}

// TestCASVerifyInvariant — Verify(Get(Put(p)), Hash(p)) == true always
func TestCASVerifyInvariant(t *testing.T) {
	store := cas.NewMemoryStore()
	for i := 0; i < 50; i++ {
		payload := []byte(randString(mrand.Intn(100) + 1))
		h, _ := store.Put(payload)
		got, _ := store.Get(h)
		if !cas.Verify(got, h) {
			t.Errorf("Verify failed after Put/Get for %q", payload)
		}
	}
}

// TestCASDeduplication — Put(p) N times → Size == 1
func TestCASDeduplication(t *testing.T) {
	store := cas.NewMemoryStore()
	payload := []byte("fixed-dedup-payload")
	for i := 0; i < 50; i++ {
		store.Put(payload)
	}
	if store.Size() != 1 {
		t.Errorf("dedup violated: size=%d", store.Size())
	}
}

// TestGS1URIRoundTrip — BuildDLURI ∘ ParseDLURI == identity
func TestGS1URIRoundTrip(t *testing.T) {
	domains := []string{"dpp.example.com", "gs1.test.org", "scan.factory.jp"}
	gtins := []string{"04012345678901", "07891234567890", "12345678"}
	for _, domain := range domains {
		for _, gtin := range gtins {
			key := compliance.GS1Key{GTIN: gtin}
			uri, err := compliance.BuildDLURI(domain, key)
			if err != nil {
				continue // skip invalid GTINs
			}
			gotDomain, gotKey, err := compliance.ParseDLURI(uri)
			if err != nil {
				t.Errorf("ParseDLURI(%s): %v", uri, err)
				continue
			}
			if gotDomain != domain {
				t.Errorf("domain: %s != %s", gotDomain, domain)
			}
			if gotKey.GTIN != gtin {
				t.Errorf("GTIN: %s != %s", gotKey.GTIN, gtin)
			}
		}
	}
}

// TestErrKitHTTPStatusMapping — known codes always map to expected HTTP status
func TestErrKitHTTPStatusMapping(t *testing.T) {
	cases := []struct {
		code errkit.Code
		want int
	}{
		{errkit.CodeNotFound, 404},
		{errkit.CodeUnauthorized, 401},
		{errkit.CodeForbidden, 403},
		{errkit.CodeInvalidInput, 400},
		{errkit.CodeConflict, 409},
		{errkit.CodeRateLimited, 429},
		{errkit.CodeInternal, 500},
	}
	for _, c := range cases {
		e := errkit.E("test-op", c.code, "msg", nil)
		var ek *errkit.Error
		if !errors.As(e, &ek) {
			t.Fatalf("not errkit.Error: %T", e)
		}
		got := ek.HTTPStatus()
		if got != c.want {
			t.Errorf("Code %v: HTTPStatus()=%d want %d", c.code, got, c.want)
		}
	}
}
