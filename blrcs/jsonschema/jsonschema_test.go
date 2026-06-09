package jsonschema

import (
	"encoding/json"
	"strings"
	"testing"
)

func compile(t *testing.T, s string) *Schema {
	t.Helper()
	sch, err := Compile([]byte(s))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return sch
}

func instance(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("instance parse: %v", err)
	}
	return v
}

func mustValid(t *testing.T, sch *Schema, inst any) {
	t.Helper()
	if err := sch.Validate(inst); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func mustInvalid(t *testing.T, sch *Schema, inst any) {
	t.Helper()
	if err := sch.Validate(inst); err == nil {
		t.Errorf("expected invalid, got valid")
	}
}

// ============================================================================
// type
// ============================================================================

func TestType(t *testing.T) {
	s := compile(t, `{"type":"string"}`)
	mustValid(t, s, "hello")
	mustInvalid(t, s, 42.0)
	mustInvalid(t, s, nil)

	num := compile(t, `{"type":"number"}`)
	mustValid(t, num, 3.14)
	mustValid(t, num, 5.0)
	mustInvalid(t, num, "5")

	integer := compile(t, `{"type":"integer"}`)
	mustValid(t, integer, 5.0)
	mustInvalid(t, integer, 5.5)

	obj := compile(t, `{"type":"object"}`)
	mustValid(t, obj, instance(t, `{"a":1}`))
	mustInvalid(t, obj, instance(t, `[1,2]`))

	arr := compile(t, `{"type":"array"}`)
	mustValid(t, arr, instance(t, `[1,2]`))
	mustInvalid(t, arr, instance(t, `{}`))

	null := compile(t, `{"type":"null"}`)
	mustValid(t, null, nil)
	mustInvalid(t, null, 0.0)

	boolean := compile(t, `{"type":"boolean"}`)
	mustValid(t, boolean, true)
	mustInvalid(t, boolean, "true")
}

func TestTypeUnion(t *testing.T) {
	s := compile(t, `{"type":["string","null"]}`)
	mustValid(t, s, "x")
	mustValid(t, s, nil)
	mustInvalid(t, s, 1.0)
}

// ============================================================================
// enum / const
// ============================================================================

func TestEnum(t *testing.T) {
	s := compile(t, `{"enum":["a","b",3]}`)
	mustValid(t, s, "a")
	mustValid(t, s, 3.0)
	mustInvalid(t, s, "c")
}

func TestConst(t *testing.T) {
	s := compile(t, `{"const":"fixed"}`)
	mustValid(t, s, "fixed")
	mustInvalid(t, s, "other")

	num := compile(t, `{"const":42}`)
	mustValid(t, num, 42.0)
}

// ============================================================================
// string constraints
// ============================================================================

func TestStringLength(t *testing.T) {
	s := compile(t, `{"type":"string","minLength":2,"maxLength":4}`)
	mustValid(t, s, "ab")
	mustValid(t, s, "abcd")
	mustInvalid(t, s, "a")
	mustInvalid(t, s, "abcde")
}

func TestStringPattern(t *testing.T) {
	s := compile(t, `{"type":"string","pattern":"^[0-9]{4}$"}`)
	mustValid(t, s, "1234")
	mustInvalid(t, s, "abc")
	mustInvalid(t, s, "12345")
}

func TestStringFormat(t *testing.T) {
	dt := compile(t, `{"type":"string","format":"date-time"}`)
	mustValid(t, dt, "2026-06-08T12:00:00Z")
	mustInvalid(t, dt, "not-a-date")

	email := compile(t, `{"type":"string","format":"email"}`)
	mustValid(t, email, "a@b.com")
	mustInvalid(t, email, "nope")

	date := compile(t, `{"format":"date"}`)
	mustValid(t, date, "2026-06-08")
	mustInvalid(t, date, "2026-13-99")

	uri := compile(t, `{"format":"uri"}`)
	mustValid(t, uri, "https://example.com/x")
	mustInvalid(t, uri, "/relative")
}

// ============================================================================
// number constraints
// ============================================================================

func TestNumberRange(t *testing.T) {
	s := compile(t, `{"type":"number","minimum":0,"maximum":100}`)
	mustValid(t, s, 0.0)
	mustValid(t, s, 100.0)
	mustInvalid(t, s, -1.0)
	mustInvalid(t, s, 101.0)
}

func TestNumberExclusive(t *testing.T) {
	s := compile(t, `{"exclusiveMinimum":0,"exclusiveMaximum":10}`)
	mustValid(t, s, 5.0)
	mustInvalid(t, s, 0.0)
	mustInvalid(t, s, 10.0)
}

func TestMultipleOf(t *testing.T) {
	s := compile(t, `{"multipleOf":5}`)
	mustValid(t, s, 15.0)
	mustInvalid(t, s, 7.0)
}

// ============================================================================
// object
// ============================================================================

func TestRequired(t *testing.T) {
	s := compile(t, `{"type":"object","required":["a","b"]}`)
	mustValid(t, s, instance(t, `{"a":1,"b":2}`))
	mustInvalid(t, s, instance(t, `{"a":1}`))
}

func TestProperties(t *testing.T) {
	s := compile(t, `{"type":"object","properties":{"age":{"type":"integer","minimum":0}}}`)
	mustValid(t, s, instance(t, `{"age":30}`))
	mustInvalid(t, s, instance(t, `{"age":-5}`))
	mustInvalid(t, s, instance(t, `{"age":"old"}`))
}

func TestAdditionalPropertiesFalse(t *testing.T) {
	s := compile(t, `{"type":"object","properties":{"a":{}},"additionalProperties":false}`)
	mustValid(t, s, instance(t, `{"a":1}`))
	mustInvalid(t, s, instance(t, `{"a":1,"b":2}`))
}

func TestAdditionalPropertiesSchema(t *testing.T) {
	s := compile(t, `{"type":"object","properties":{"a":{}},"additionalProperties":{"type":"string"}}`)
	mustValid(t, s, instance(t, `{"a":1,"b":"ok"}`))
	mustInvalid(t, s, instance(t, `{"a":1,"b":2}`))
}

func TestPatternProperties(t *testing.T) {
	s := compile(t, `{"type":"object","patternProperties":{"^x_":{"type":"number"}}}`)
	mustValid(t, s, instance(t, `{"x_count":5}`))
	mustInvalid(t, s, instance(t, `{"x_count":"five"}`))
}

// ============================================================================
// array
// ============================================================================

func TestArrayItems(t *testing.T) {
	s := compile(t, `{"type":"array","items":{"type":"integer"}}`)
	mustValid(t, s, instance(t, `[1,2,3]`))
	mustInvalid(t, s, instance(t, `[1,"two",3]`))
}

func TestArrayMinMaxItems(t *testing.T) {
	s := compile(t, `{"type":"array","minItems":1,"maxItems":2}`)
	mustValid(t, s, instance(t, `[1]`))
	mustValid(t, s, instance(t, `[1,2]`))
	mustInvalid(t, s, instance(t, `[]`))
	mustInvalid(t, s, instance(t, `[1,2,3]`))
}

func TestUniqueItems(t *testing.T) {
	s := compile(t, `{"type":"array","uniqueItems":true}`)
	mustValid(t, s, instance(t, `[1,2,3]`))
	mustInvalid(t, s, instance(t, `[1,2,2]`))
}

func TestContains(t *testing.T) {
	s := compile(t, `{"type":"array","contains":{"const":7}}`)
	mustValid(t, s, instance(t, `[1,7,3]`))
	mustInvalid(t, s, instance(t, `[1,2,3]`))
}

func TestPrefixItems(t *testing.T) {
	s := compile(t, `{"type":"array","prefixItems":[{"type":"string"},{"type":"number"}]}`)
	mustValid(t, s, instance(t, `["a",1]`))
	mustInvalid(t, s, instance(t, `[1,"a"]`))
}

// ============================================================================
// combinators
// ============================================================================

func TestAllOf(t *testing.T) {
	s := compile(t, `{"allOf":[{"type":"number"},{"minimum":10}]}`)
	mustValid(t, s, 15.0)
	mustInvalid(t, s, 5.0)
	mustInvalid(t, s, "x")
}

func TestAnyOf(t *testing.T) {
	s := compile(t, `{"anyOf":[{"type":"string"},{"type":"number"}]}`)
	mustValid(t, s, "x")
	mustValid(t, s, 1.0)
	mustInvalid(t, s, true)
}

func TestOneOf(t *testing.T) {
	s := compile(t, `{"oneOf":[{"type":"number","minimum":0},{"type":"number","maximum":10}]}`)
	// 15 matches only the first (minimum:0) → exactly one
	mustValid(t, s, 15.0)
	// 5 matches both → invalid for oneOf
	mustInvalid(t, s, 5.0)
}

func TestNot(t *testing.T) {
	s := compile(t, `{"not":{"type":"string"}}`)
	mustValid(t, s, 1.0)
	mustInvalid(t, s, "x")
}

// ============================================================================
// $ref
// ============================================================================

func TestRefLocal(t *testing.T) {
	s := compile(t, `{
		"type":"object",
		"properties":{"shipping":{"$ref":"#/$defs/address"},"billing":{"$ref":"#/$defs/address"}},
		"$defs":{"address":{"type":"object","required":["zip"]}}
	}`)
	mustValid(t, s, instance(t, `{"shipping":{"zip":"100"},"billing":{"zip":"200"}}`))
	mustInvalid(t, s, instance(t, `{"shipping":{"zip":"100"},"billing":{}}`))
}

func TestRefUnresolvable(t *testing.T) {
	s := compile(t, `{"$ref":"#/$defs/missing"}`)
	mustInvalid(t, s, "anything")
}

// ============================================================================
// boolean schemas
// ============================================================================

func TestBooleanSchema(t *testing.T) {
	yes := compile(t, `true`)
	mustValid(t, yes, "anything")
	mustValid(t, yes, 42.0)

	no := compile(t, `false`)
	mustInvalid(t, no, "anything")
}

// ============================================================================
// realistic SD-JWT-VC claim schema
// ============================================================================

func TestSDJWTVCClaimSchema(t *testing.T) {
	schema := `{
		"type":"object",
		"properties":{
			"vct":{"type":"string"},
			"product_id":{"type":"string","pattern":"^[0-9]{14}$"},
			"carbon_kg":{"type":"number","minimum":0},
			"recyclability_pct":{"type":"integer","minimum":0,"maximum":100},
			"origin_country":{"type":"string","minLength":2,"maxLength":2}
		},
		"required":["vct","product_id"]
	}`
	s := compile(t, schema)

	valid := instance(t, `{
		"vct":"https://schema.europa.eu/dpp/v1",
		"product_id":"04012345678901",
		"carbon_kg":48.5,
		"recyclability_pct":82,
		"origin_country":"JP"
	}`)
	mustValid(t, s, valid)

	// bad product_id pattern
	bad1 := instance(t, `{"vct":"x","product_id":"abc"}`)
	mustInvalid(t, s, bad1)

	// recyclability out of range
	bad2 := instance(t, `{"vct":"x","product_id":"04012345678901","recyclability_pct":150}`)
	mustInvalid(t, s, bad2)

	// missing required
	bad3 := instance(t, `{"vct":"x"}`)
	mustInvalid(t, s, bad3)
}

// ============================================================================
// error aggregation
// ============================================================================

func TestMultipleErrors(t *testing.T) {
	s := compile(t, `{"type":"object","required":["a","b","c"]}`)
	err := s.Validate(instance(t, `{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) != 3 {
		t.Errorf("expected 3 errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}

// ============================================================================
// json.Number support
// ============================================================================

func TestJSONNumberInstance(t *testing.T) {
	s := compile(t, `{"type":"integer","minimum":10}`)
	dec := json.NewDecoder(strings.NewReader(`15`))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, v)

	tooSmall := json.Number("5")
	mustInvalid(t, s, tooSmall)
}
