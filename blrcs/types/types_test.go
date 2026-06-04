package types

import (
	"encoding/json"
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
