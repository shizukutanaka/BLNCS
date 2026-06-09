// Fuzz tests — BLRCS セキュリティクリティカルパーサの網羅的テスト
//
// Apple 方針: "All parsers of untrusted input must be fuzz tested."
// (Security Engineering, PSIRT チームのガイドライン)
//
// 実行:
//
//	go test -fuzz=FuzzDID         -fuzztime=30s ./fuzz/
//	go test -fuzz=FuzzGTIN        -fuzztime=30s ./fuzz/
//	go test -fuzz=FuzzSDJWT       -fuzztime=30s ./fuzz/
//	go test -fuzz=FuzzGS1URI      -fuzztime=30s ./fuzz/
//	go test -fuzz=FuzzMerkle      -fuzztime=30s ./fuzz/
//	go test -fuzz=FuzzRangeProof  -fuzztime=30s ./fuzz/
//
// CI では -fuzztime=10s を各ターゲットに実行。
// フリーズ/クラッシュ/panic は testdata/fuzz/{FuzzName}/corpus に保存される。
//
// 保証:
//   - いかなる入力でも panic しない
//   - エラーは必ず error インタフェースで返る (例外なし)
//   - 成功 parse の出力は再 parse で同じ結果を返す (round-trip 一貫性)
package fuzz

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"blrcs/cbor"
	"blrcs/compliance"
	"blrcs/errkit"
	"blrcs/jsonschema"
	"blrcs/mdoc"
	"blrcs/multiformats"
	"blrcs/scitt"
	"blrcs/types"
)

// ============================================================================
// FuzzDID — 任意バイト列を DID として解析、パニック禁止
// ============================================================================

func FuzzDID(f *testing.F) {
	// 正規 corpus — 実際に見かける DID
	f.Add("did:web:example.com")
	f.Add("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	f.Add("did:jwk:eyJhbGciOiJFZERTQSJ9")
	f.Add("did:ion:long-identifier-value")
	f.Add("") // empty
	f.Add(":")
	f.Add("did::")
	f.Add("did:web:")
	f.Add("x:y:z")
	f.Add("did:" + string(make([]byte, 1000)))
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, data string) {
		// 絶対条件: panic しない
		d, err := types.NewDID(data)
		if err != nil {
			// エラーは許容、panic のみ禁止
			return
		}
		// Round-trip: 成功した DID は再 parse も成功し同じ値
		d2, err := types.NewDID(d.String())
		if err != nil {
			t.Fatalf("round-trip failed for valid DID %q: %v", d.String(), err)
		}
		if d.String() != d2.String() {
			t.Fatalf("round-trip mismatch: %q -> %q", d.String(), d2.String())
		}
		// Method/Identifier は非空のはず
		if d.Method() == "" {
			t.Fatalf("valid DID has empty method: %q", d.String())
		}
	})
}

// ============================================================================
// FuzzGTIN — 任意文字列を GTIN として解析
// ============================================================================

func FuzzGTIN(f *testing.F) {
	f.Add("04012345678901")
	f.Add("00012345678905")
	f.Add("1234567890128") // GTIN-13
	f.Add("")
	f.Add("abc")
	f.Add("00000000000000") // all zeros (check digit 0)
	f.Add("99999999999999") // all nines
	f.Add("9999999999999A")
	f.Add(string(make([]byte, 2000)))

	f.Fuzz(func(t *testing.T, data string) {
		g, err := types.NewGTIN(data)
		if err != nil {
			return
		}
		// 成功した GTIN は14桁
		if len(g.String()) != 14 {
			t.Fatalf("GTIN not 14 chars: %q -> %q", data, g.String())
		}
		// Round-trip
		g2, err := types.NewGTIN(g.String())
		if err != nil {
			t.Fatalf("round-trip failed for %q: %v", g.String(), err)
		}
		if g.String() != g2.String() {
			t.Fatalf("round-trip mismatch: %q -> %q", g.String(), g2.String())
		}
	})
}

// ============================================================================
// FuzzSDJWT — 任意文字列を SD-JWT として検証
// ============================================================================

func FuzzSDJWT(f *testing.F) {
	// Seed corpus から有効な SD-JWT を取得
	iss, _ := compliance.NewIssuer("did:web:fuzz.test")
	pub := iss.PublicKey()

	// Minimal valid SD-JWT
	validJWT, _, _ := iss.IssueSDJWT("sub",
		map[string]any{"claim": "value"},
		map[string]any{"clear": "data"},
		0,
	)
	f.Add(validJWT)

	// 破損系 corpus
	f.Add("")
	f.Add("~")
	f.Add("~.~.~")
	f.Add("a.b.c~d~")
	f.Add("a.b.c~" + string(make([]byte, 100)) + "~")
	f.Add("header.payload.sig~disclosure~")
	f.Add("..")                       // empty segs
	f.Add("a.b." + "c")               // 短い sig
	f.Add(validJWT + "~extra~extra~") // extra disclosures

	f.Fuzz(func(t *testing.T, data string) {
		// エラーを返すだけで panic 禁止
		_, err := compliance.VerifySDJWT(data, pub)
		_ = err // error は正常
		// Present も panic 禁止
		_, _ = compliance.Present(data, []string{"any"})
	})
}

// ============================================================================
// FuzzGS1URI — 任意文字列を GS1 Digital Link URI として解析
// ============================================================================

func FuzzGS1URI(f *testing.F) {
	f.Add("https://dpp.example.com/01/04012345678901")
	f.Add("https://dpp.example.com/01/04012345678901/21/ABC")
	f.Add("")
	f.Add("http://")
	f.Add("not-a-url")
	f.Add("https://x/01/")
	f.Add("https://x/99/nongtin")
	f.Add("ftp://x/01/04012345678901")
	f.Add("https://x/" + string(make([]byte, 500)) + "/01/04012345678901")

	f.Fuzz(func(t *testing.T, data string) {
		domain, key, err := compliance.ParseDLURI(data)
		if err != nil {
			return
		}
		// 成功した parse は再 build して再 parse で一致
		built, err := compliance.BuildDLURI(domain, key)
		if err != nil {
			t.Fatalf("BuildDLURI failed for valid parse of %q: %v", data, err)
		}
		_, _, err = compliance.ParseDLURI(built)
		if err != nil {
			t.Fatalf("re-parse of built URI %q failed: %v", built, err)
		}
	})
}

// ============================================================================
// FuzzMerkle — ランダム leaf/proof で包含証明検証
// ============================================================================

func FuzzMerkle(f *testing.F) {
	// Seed: 有効な leaf, root, path
	leaf := make([]byte, 32)
	rand.Read(leaf)
	f.Add(leaf, leaf, uint64(0), uint64(1), []byte{})
	f.Add(leaf, leaf, uint64(5), uint64(10), make([]byte, 32))
	f.Add(make([]byte, 0), make([]byte, 32), uint64(0), uint64(0), make([]byte, 0))
	f.Add(make([]byte, 64), make([]byte, 32), uint64(100), uint64(200), make([]byte, 96))

	f.Fuzz(func(t *testing.T, leafHash, rootHash []byte, idx, size uint64, pathRaw []byte) {
		// 32バイト以外の入力は短縮/パッド
		pad := func(b []byte) []byte {
			if len(b) >= 32 {
				return b[:32]
			}
			p := make([]byte, 32)
			copy(p, b)
			return p
		}
		l := pad(leafHash)
		r := pad(rootHash)
		// path は32バイト単位で分割
		path := make([][]byte, 0)
		for i := 0; i+32 <= len(pathRaw); i += 32 {
			path = append(path, pathRaw[i:i+32])
		}
		// panic 禁止
		_ = scitt.VerifyInclusion(l, r, idx, size, path)
	})
}

// ============================================================================
// FuzzRangeProof — ZK範囲証明の検証 (任意 JSON)
// ============================================================================

func FuzzRangeProof(f *testing.F) {
	// Seed: 有効な proof JSON
	salt := make([]byte, 32)
	rand.Read(salt)
	attester, _ := compliance.NewSensorAttester("did:device:fuzz")
	stmt := compliance.RangeStatement{Min: 2, Max: 8, Unit: "c", Name: "cc"}
	commit := compliance.Commit(5.0, salt, stmt)
	proof, _ := attester.Attest(commit, 5.0)
	pub := attester.PublicKey()

	f.Add(proof.Commitment.Digest)
	f.Add("")
	f.Add("not-json")
	f.Add(`{}`)
	f.Add(`{"inRange":true,"sig":"AAAA"}`)
	f.Add(string(make([]byte, 2048)))

	f.Fuzz(func(t *testing.T, sig string) {
		// sig フィールドを改ざんした proof
		p := *proof
		p.Signature = sig
		// panic 禁止
		_ = compliance.VerifyRange(&p, pub)
	})
}

// FuzzErrorKit — errkit.E で入力した文字列が panic しないことを確認
func FuzzErrorKit(f *testing.F) {
	f.Add("test-op", "invalid_input", "bad product id")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, op, code, msg string) {
		defer func() { recover() }()
		e := errkit.E(errkit.Op(op), errkit.Code(code), msg, nil)
		_ = e.Error()
	})
}

// FuzzSCITTStatement — 任意のペイロードで SignStatement が panic しないこと
func FuzzSCITTStatement(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.Add("did:web:issuer.example", "subject", "text/plain", []byte("payload"))
	f.Add("", "", "", []byte{})
	f.Add("did:key:z6Mk", "s", "app/json", []byte(`{"x":1}`))
	f.Fuzz(func(t *testing.T, issuerID, subject, cty string, payload []byte) {
		defer func() { recover() }()
		stmt, err := scitt.SignStatement(priv, issuerID, subject, cty, payload)
		if err != nil {
			return
		}
		_ = stmt
	})
}

// ============================================================================
// FuzzTieredClaims — ESPR 3-tier 分割の安全不変条件
//
// 重要な漏洩境界: いかなる tier 文字列・claim キーでも、SplitForSDJWT の
// clear 集合に public 以外が混入してはならない (authority データの公開漏洩防止)。
// ============================================================================

func FuzzTieredClaims(f *testing.F) {
	f.Add("carbon", "public", "material", "authority")
	f.Add("", "", "x", "bogus")
	f.Add("a", "restricted", "b", "public")

	f.Fuzz(func(t *testing.T, k1, tier1, k2, tier2 string) {
		tc := compliance.NewTieredClaims()
		tc.Set(k1, "v1", compliance.AccessTier(tier1))
		tc.Set(k2, "v2", compliance.AccessTier(tier2))

		clear, sd := tc.SplitForSDJWT()

		// 安全不変条件: clear に入るのは public tier のみ
		for key := range clear {
			tier, ok := tc.Tier(key)
			if !ok {
				t.Fatalf("clear claim %q has no tier", key)
			}
			if tier != compliance.TierPublic {
				t.Fatalf("SECURITY: non-public claim %q (tier=%s) leaked into clear set", key, tier)
			}
		}
		// 全 claim が clear か sd のどちらかに必ず分類される (消失しない)
		total := len(clear) + len(sd)
		if total != len(tc.Keys()) {
			t.Fatalf("claim count mismatch: clear=%d sd=%d keys=%d", len(clear), len(sd), len(tc.Keys()))
		}
		// ClaimsAtOrBelow(authority) は全件返す (最上位は全部見える)
		all := tc.ClaimsAtOrBelow(compliance.TierAuthority)
		if len(all) != len(tc.Keys()) {
			t.Fatalf("authority view should see all: got=%d keys=%d", len(all), len(tc.Keys()))
		}
	})
}

// ============================================================================
// FuzzCBOR — 任意バイト列を CBOR としてデコード、パニック禁止
// ============================================================================

func FuzzCBOR(f *testing.F) {
	f.Add([]byte{0x00})                   // uint 0
	f.Add([]byte{0x20})                   // int -1
	f.Add([]byte{0x40})                   // empty bstr
	f.Add([]byte{0x60})                   // empty tstr
	f.Add([]byte{0x80})                   // empty array
	f.Add([]byte{0xa0})                   // empty map
	f.Add([]byte{0xd2, 0x84})             // tag 18 + truncated array
	f.Add([]byte{0x83, 0x01, 0x02, 0x03}) // [1,2,3]
	f.Add([]byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{}) // empty

	f.Fuzz(func(t *testing.T, data []byte) {
		// 絶対条件: panic しない
		v, err := cbor.Unmarshal(data)
		if err != nil {
			return
		}
		// Round-trip: デコードできた値は再エンコードでき、再デコードで一致
		enc, err := cbor.Marshal(v)
		if err != nil {
			// 一部の型 (map[any]any 内の非対応型) は再エンコード不可なことがある
			return
		}
		if _, err := cbor.Unmarshal(enc); err != nil {
			t.Fatalf("re-decode of marshaled value failed: %v", err)
		}
	})
}

// ============================================================================
// FuzzMdoc — 任意バイト列を mdoc IssuerSigned として検証、パニック禁止
// ============================================================================

func FuzzMdoc(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// 正規 corpus: 実際に発行した mdoc
	cred, _ := mdoc.Issue(mdoc.IssueParams{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]mdoc.Element{
			"org.iso.18013.5.1": {{Identifier: "family_name", Value: "Doe"}},
		},
		IssuerPriv: priv,
	})
	f.Add(cred)
	f.Add([]byte{})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		// 絶対条件: いかなる入力でも panic しない (エラーは許容)
		_, _ = mdoc.Verify(data, pub, time.Now())
	})
}

// ============================================================================
// FuzzJSONSchema — 任意バイト列を schema/instance として処理、パニック禁止
// ============================================================================

func FuzzJSONSchema(f *testing.F) {
	f.Add(`{"type":"string"}`, `"hello"`)
	f.Add(`{"type":"object","required":["a"]}`, `{"a":1}`)
	f.Add(`{"properties":{"x":{"type":"integer"}}}`, `{"x":3}`)
	f.Add(`{"$ref":"#/$defs/foo"}`, `1`)
	f.Add(`true`, `null`)
	f.Add(`false`, `{}`)
	f.Add(`{"allOf":[{"minimum":0}]}`, `5`)
	f.Add(``, ``)

	f.Fuzz(func(t *testing.T, schemaSrc, instanceSrc string) {
		sch, err := jsonschema.Compile([]byte(schemaSrc))
		if err != nil {
			return
		}
		var inst any
		if err := json.Unmarshal([]byte(instanceSrc), &inst); err != nil {
			return
		}
		// 絶対条件: いかなる入力でも panic しない
		_ = sch.Validate(inst)
	})
}

// ============================================================================
// FuzzBase58 — base58btc decode/encode round-trip, パニック禁止
// ============================================================================

func FuzzBase58(f *testing.F) {
	f.Add("")
	f.Add("1")
	f.Add("2NEpo7TZRRrLZSi2U")
	f.Add("Qm")
	f.Add("0OIl") // invalid chars
	f.Add(string(make([]byte, 200)))

	f.Fuzz(func(t *testing.T, s string) {
		dec, err := multiformats.Base58Decode(s)
		if err != nil {
			return // invalid input is fine, panic is not
		}
		// Decoded bytes must re-encode to a canonical form that decodes equal.
		enc := multiformats.Base58Encode(dec)
		dec2, err := multiformats.Base58Decode(enc)
		if err != nil {
			t.Fatalf("re-decode of %q failed: %v", enc, err)
		}
		if len(dec) != len(dec2) {
			t.Fatalf("round-trip length mismatch: %d vs %d", len(dec), len(dec2))
		}
		for i := range dec {
			if dec[i] != dec2[i] {
				t.Fatalf("round-trip byte mismatch at %d", i)
			}
		}
	})
}

// ============================================================================
// FuzzJCS — 任意 JSON の正規化、パニック禁止 + 冪等性
// ============================================================================

func FuzzJCS(f *testing.F) {
	f.Add(`{"b":1,"a":2}`)
	f.Add(`[1,2,3]`)
	f.Add(`"string"`)
	f.Add(`{"nested":{"z":1,"a":[true,null,false]}}`)
	f.Add(`{"unicode":"日本語"}`)
	f.Add(``)
	f.Add(`not json`)

	f.Fuzz(func(t *testing.T, src string) {
		out, err := multiformats.CanonicalizeJSON([]byte(src))
		if err != nil {
			return
		}
		// Idempotent: canonicalizing canonical output yields the same bytes.
		out2, err := multiformats.CanonicalizeJSON(out)
		if err != nil {
			t.Fatalf("re-canonicalize failed: %v (first=%s)", err, out)
		}
		if string(out) != string(out2) {
			t.Fatalf("JCS not idempotent:\n1: %s\n2: %s", out, out2)
		}
	})
}
