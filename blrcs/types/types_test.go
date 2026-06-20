package types

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

// ============================================================================
// DID
// ============================================================================

func TestDIDValid(t *testing.T) {
	cases := []string{
		"did:web:example.com",
		"did:web:factory.blrcs.example/path",
		"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"did:jwk:eyJhbGciOiJFZERTQSJ9",
	}
	for _, s := range cases {
		d, err := NewDID(s)
		if err != nil {
			t.Errorf("NewDID(%q): %v", s, err)
			continue
		}
		if d.String() != s {
			t.Errorf("roundtrip: %s != %s", d.String(), s)
		}
	}
}

func TestDIDInvalid(t *testing.T) {
	cases := []string{
		"",
		"web:example.com",
		"did:web",
		"did::id",
		"did:method:",
		"x:y:z",
	}
	for _, s := range cases {
		if _, err := NewDID(s); err == nil {
			t.Errorf("should reject %q", s)
		}
	}
}

func TestDIDMethodAndIdentifier(t *testing.T) {
	d, _ := NewDID("did:web:factory.example/path/sub")
	if d.Method() != "web" {
		t.Errorf("method: %s", d.Method())
	}
	if d.Identifier() != "factory.example/path/sub" {
		t.Errorf("identifier: %s", d.Identifier())
	}
}

func TestDIDJSON(t *testing.T) {
	type holder struct {
		ID DID `json:"id"`
	}
	in := holder{ID: MustDID("did:web:test")}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"id":"did:web:test"}` {
		t.Errorf("marshal: %s", b)
	}
	var out holder
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID.String() != in.ID.String() {
		t.Errorf("roundtrip: %s != %s", out.ID.String(), in.ID.String())
	}
}

func TestDIDJSONRejectsInvalid(t *testing.T) {
	type holder struct {
		ID DID `json:"id"`
	}
	var out holder
	err := json.Unmarshal([]byte(`{"id":"not-a-did"}`), &out)
	if err == nil {
		t.Fatal("invalid DID should fail unmarshal")
	}
}

// TestDIDMarshalJSONSpecialChars verifies that DID.MarshalJSON properly escapes
// characters that would otherwise break or inject into the containing JSON document.
func TestDIDMarshalJSONSpecialChars(t *testing.T) {
	cases := []string{
		`did:web:foo"bar`,       // double-quote → classic injection candidate
		`did:web:back\slash`,    // backslash
		"did:web:tab\there",     // tab
		"did:web:ctrl\x01chars", // control character
	}
	for _, raw := range cases {
		d, err := NewDID(raw)
		if err != nil {
			t.Fatalf("NewDID(%q): %v", raw, err)
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("MarshalJSON(%q): %v", raw, err)
		}
		var got string
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("MarshalJSON(%q) output not valid JSON string: %v; bytes: %s", raw, err, b)
		}
		if got != raw {
			t.Errorf("round-trip(%q): got %q", raw, got)
		}
	}
}

// TestDIDMarshalJSONInjection verifies that embedding a DID with embedded quotes
// in a struct produces valid, non-injected JSON — the injected key must not appear.
func TestDIDMarshalJSONInjection(t *testing.T) {
	type holder struct {
		ID DID `json:"id"`
	}
	raw := `did:web:a","evil":true`
	d, _ := NewDID(raw)
	b, err := json.Marshal(holder{ID: d})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var h holder
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatalf("output is not valid JSON: %v; bytes: %s", err, b)
	}
	if h.ID.String() != raw {
		t.Errorf("round-trip mismatch: got %q want %q", h.ID.String(), raw)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if _, injected := fields["evil"]; injected {
		t.Errorf("JSON injection succeeded — 'evil' key found in output: %s", b)
	}
}

// ============================================================================
// GTIN
// ============================================================================

func TestGTINValid(t *testing.T) {
	// Computed valid GTIN-14
	cases := []string{
		"04012345678901",
		"09501101530003",
		"00012345678905", // GTIN-12 (UPC-A) padded
	}
	for _, s := range cases {
		g, err := NewGTIN(s)
		if err != nil {
			t.Errorf("NewGTIN(%q): %v", s, err)
			continue
		}
		if len(g.String()) != 14 {
			t.Errorf("not 14-digit: %s", g.String())
		}
	}
}

func TestGTINInvalid(t *testing.T) {
	cases := []string{
		"",
		"123", // too short
		"abc12345678901",
		"04012345678902",  // bad check digit
		"123456789012345", // 15 digits
	}
	for _, s := range cases {
		if _, err := NewGTIN(s); err == nil {
			t.Errorf("should reject %q", s)
		}
	}
}

func TestGTINJSON(t *testing.T) {
	g := MustGTIN("04012345678901")
	b, _ := json.Marshal(g)
	if string(b) != `"04012345678901"` {
		t.Errorf("marshal: %s", b)
	}
}

// ============================================================================
// CountryCode
// ============================================================================

func TestCountryCodeValid(t *testing.T) {
	cases := []struct{ in, want string }{
		{"JP", "JP"},
		{"jp", "JP"}, // case-insensitive input
		{"DE", "DE"},
		{"us", "US"},
	}
	for _, c := range cases {
		got, err := NewCountryCode(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("%q: got %s want %s", c.in, got.String(), c.want)
		}
	}
}

func TestCountryCodeInvalid(t *testing.T) {
	cases := []string{
		"", "J", "JPN", "12", "Z9", "XX", // unknown
	}
	for _, s := range cases {
		if _, err := NewCountryCode(s); err == nil {
			t.Errorf("should reject %q", s)
		}
	}
}

// ============================================================================
// CarbonFootprint
// ============================================================================

func TestCarbonFootprint(t *testing.T) {
	c, err := NewCarbonFootprint(2.47)
	if err != nil {
		t.Fatal(err)
	}
	if c.KgCO2e() != 2.47 {
		t.Errorf("value: %f", c.KgCO2e())
	}
	// Negative
	if _, err := NewCarbonFootprint(-1); err == nil {
		t.Error("negative should fail")
	}
	// Implausibly large
	if _, err := NewCarbonFootprint(1e15); err == nil {
		t.Error(">1e12 should fail")
	}
	// Zero is valid
	z, err := NewCarbonFootprint(0)
	if err != nil {
		t.Fatal(err)
	}
	if !z.IsZero() {
		t.Error("0 should be IsZero")
	}
}

func TestCarbonFootprintJSON(t *testing.T) {
	c := MustCarbonFootprint(48.5)
	b, _ := json.Marshal(c)
	if string(b) != "48.5" {
		t.Errorf("marshal: %s", b)
	}
	var got CarbonFootprint
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.KgCO2e() != 48.5 {
		t.Errorf("roundtrip: %f", got.KgCO2e())
	}
	// Negative JSON should fail
	if err := json.Unmarshal([]byte("-5"), &got); err == nil {
		t.Error("negative JSON should fail")
	}
}

// ============================================================================
// Percent
// ============================================================================

func TestPercent(t *testing.T) {
	for _, v := range []float64{0, 50, 99.99, 100} {
		if _, err := NewPercent(v); err != nil {
			t.Errorf("%f should be valid: %v", v, err)
		}
	}
	for _, v := range []float64{-0.01, 100.01, 1000} {
		if _, err := NewPercent(v); err == nil {
			t.Errorf("%f should fail", v)
		}
	}
}

func TestPercentJSON(t *testing.T) {
	p := MustPercent(16.5)
	b, _ := json.Marshal(p)
	if string(b) != "16.5" {
		t.Errorf("marshal: %s", b)
	}
}

// ============================================================================
// Duration
// ============================================================================

func TestDuration(t *testing.T) {
	d, err := NewDuration(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d.Time() != 5*time.Second {
		t.Errorf("time: %v", d.Time())
	}
	if _, err := NewDuration(-1 * time.Second); err == nil {
		t.Error("negative should fail")
	}
}

// ============================================================================
// IsZero on uninitialized
// ============================================================================

func TestZeroValues(t *testing.T) {
	var d DID
	if !d.IsZero() {
		t.Error("zero DID")
	}
	var g GTIN
	if !g.IsZero() {
		t.Error("zero GTIN")
	}
	var c CountryCode
	if !c.IsZero() {
		t.Error("zero Country")
	}
}

// ============================================================================
// Additional coverage: UnmarshalJSON, String, accessors
// ============================================================================

func TestGTINUnmarshalJSON(t *testing.T) {
	var g GTIN
	if err := json.Unmarshal([]byte(`"04012345678901"`), &g); err != nil {
		t.Fatal(err)
	}
	if g.String() != "04012345678901" {
		t.Errorf("got %q", g.String())
	}
	// invalid value
	if err := json.Unmarshal([]byte(`"notvalid"`), &g); err == nil {
		t.Error("should reject invalid GTIN")
	}
	// not a string
	if err := json.Unmarshal([]byte(`123`), &g); err == nil {
		t.Error("should reject non-string")
	}
}

func TestCountryCodeJSON(t *testing.T) {
	cc := MustCountryCode("DE")
	b, err := json.Marshal(cc)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"DE"` {
		t.Errorf("marshal: %s", b)
	}
	var got CountryCode
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.String() != "DE" {
		t.Errorf("roundtrip: %s", got.String())
	}
	// invalid country
	if err := json.Unmarshal([]byte(`"XX"`), &got); err == nil {
		t.Error("should reject unknown country")
	}
	// not a string
	if err := json.Unmarshal([]byte(`123`), &got); err == nil {
		t.Error("should reject non-string")
	}
}

func TestCarbonFootprintString(t *testing.T) {
	c := MustCarbonFootprint(12.5)
	s := c.String()
	if s == "" {
		t.Error("String should not be empty")
	}
	// zero IsZero
	z := MustCarbonFootprint(0)
	if !z.IsZero() {
		t.Error("0 carbon should be IsZero")
	}
}

func TestPercentAccessors(t *testing.T) {
	p := MustPercent(42.5)
	if p.Value() != 42.5 {
		t.Errorf("Value: %f", p.Value())
	}
	if p.IsZero() {
		t.Error("42.5%% should not be IsZero")
	}
	if p.String() == "" {
		t.Error("String should not be empty")
	}
	// Unmarshal round-trip
	b, _ := json.Marshal(p)
	var got Percent
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Value() != 42.5 {
		t.Errorf("unmarshal roundtrip: %f", got.Value())
	}
	// zero
	z := MustPercent(0)
	if !z.IsZero() {
		t.Error("0%% should be IsZero")
	}
	// invalid JSON
	var p2 Percent
	if err := json.Unmarshal([]byte(`"not-a-number"`), &p2); err == nil {
		t.Error("should reject non-numeric string")
	}
	// out of range
	if err := json.Unmarshal([]byte(`-1`), &p2); err == nil {
		t.Error("should reject negative percent")
	}
}

func TestDurationIsZero(t *testing.T) {
	z, err := NewDuration(0)
	if err != nil {
		t.Fatal(err)
	}
	if !z.IsZero() {
		t.Error("zero duration should be IsZero")
	}
	nz, _ := NewDuration(time.Second)
	if nz.IsZero() {
		t.Error("non-zero duration should not be IsZero")
	}
}

// ============================================================================
// Coverage uplift: Must* panic paths, zero-DID method/identifier,
// UnmarshalJSON non-string inputs, NaN/Inf in NewPercent/NewCarbonFootprint
// ============================================================================

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

func TestMustDIDPanics(t *testing.T) {
	mustPanic(t, "MustDID(empty)", func() { MustDID("") })
}

func TestMustGTINPanics(t *testing.T) {
	mustPanic(t, "MustGTIN(invalid)", func() { MustGTIN("abc") })
}

func TestMustCountryCodePanics(t *testing.T) {
	mustPanic(t, "MustCountryCode(ZZ)", func() { MustCountryCode("ZZ") })
}

func TestMustCarbonFootprintPanics(t *testing.T) {
	mustPanic(t, "MustCarbonFootprint(-1)", func() { MustCarbonFootprint(-1) })
}

func TestMustPercentPanics(t *testing.T) {
	mustPanic(t, "MustPercent(-1)", func() { MustPercent(-1) })
}

// TestDIDZeroValueMethodIdentifier covers the len(parts) < 3 return "" branch.
func TestDIDZeroValueMethodIdentifier(t *testing.T) {
	var d DID // zero value, d.value == ""
	if m := d.Method(); m != "" {
		t.Errorf("zero DID Method: %q", m)
	}
	if id := d.Identifier(); id != "" {
		t.Errorf("zero DID Identifier: %q", id)
	}
}

// TestDIDUnmarshalJSONNonString covers the non-string JSON value path.
func TestDIDUnmarshalJSONNonString(t *testing.T) {
	var d DID
	if err := json.Unmarshal([]byte("42"), &d); err == nil {
		t.Error("non-string JSON should fail DID unmarshal")
	}
}

// TestNewPercentNaN covers the NaN/Inf guard in NewPercent.
func TestNewPercentNaN(t *testing.T) {
	if _, err := NewPercent(math.NaN()); err == nil {
		t.Error("NaN percent should fail")
	}
	if _, err := NewPercent(math.Inf(1)); err == nil {
		t.Error("Inf percent should fail")
	}
}

// TestNewCarbonFootprintNaN covers the NaN/Inf guard in NewCarbonFootprint.
func TestNewCarbonFootprintNaN(t *testing.T) {
	if _, err := NewCarbonFootprint(math.NaN()); err == nil {
		t.Error("NaN carbon should fail")
	}
	if _, err := NewCarbonFootprint(math.Inf(1)); err == nil {
		t.Error("Inf carbon should fail")
	}
}

// TestCarbonFootprintUnmarshalJSONBadFloat covers the ParseFloat error path.
func TestCarbonFootprintUnmarshalJSONBadFloat(t *testing.T) {
	var c CarbonFootprint
	if err := json.Unmarshal([]byte(`"not-a-float"`), &c); err == nil {
		t.Error("non-numeric JSON should fail CarbonFootprint unmarshal")
	}
}

// TestGTINPaddingAndVerifyMod10 covers the padding loop and verifyMod10 wrong-length path.
func TestGTINPaddingAndVerifyMod10(t *testing.T) {
	// 8-digit GTIN (GTIN-8): requires 6 padding zeros.
	// Valid GTIN-8: 04678946 (check digit computed for test)
	// Actually find a known valid 8-digit GTIN: "04678946"
	// A known GTIN-8 from GS1: "73513537"
	g, err := NewGTIN("73513537")
	if err != nil {
		t.Fatalf("valid 8-digit GTIN should succeed: %v", err)
	}
	if len(g.String()) != 14 {
		t.Errorf("padded GTIN not 14 digits: %s", g.String())
	}
	// verifyMod10 wrong-length guard (direct call, same package).
	if verifyMod10("short") {
		t.Error("verifyMod10 should return false for non-14-length input")
	}
}
