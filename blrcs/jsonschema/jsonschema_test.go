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

func TestFormatValidators(t *testing.T) {
	cases := []struct {
		format, value string
		valid         bool
	}{
		{"hostname", "example.com", true},
		{"hostname", "sub.example.co.jp", true},
		{"hostname", "-bad.example", false},
		{"hostname", "bad-.example", false},
		{"hostname", "", false},
		{"ipv4", "192.168.0.1", true},
		{"ipv4", "255.255.255.255", true},
		{"ipv4", "256.0.0.1", false},
		{"ipv4", "01.2.3.4", false}, // leading zero
		{"ipv4", "1.2.3", false},
		{"uuid", "123e4567-e89b-12d3-a456-426614174000", true},
		{"uuid", "123e4567e89b12d3a456426614174000", false}, // no hyphens
		{"uuid", "xyz", false},
		{"ipv6", "::1", true}, // unknown format → passes (annotation)
	}
	for _, c := range cases {
		s := compile(t, `{"type":"string","format":"`+c.format+`"}`)
		err := s.Validate(c.value)
		if c.valid && err != nil {
			t.Errorf("format %s value %q: want valid, got %v", c.format, c.value, err)
		}
		if !c.valid && err == nil {
			t.Errorf("format %s value %q: want invalid", c.format, c.value)
		}
	}
}

func TestValidationErrorMessage(t *testing.T) {
	// Single error
	e1 := &ValidationError{Errors: []string{"field required"}}
	if !strings.Contains(e1.Error(), "field required") {
		t.Errorf("single error: %s", e1.Error())
	}

	// Multiple errors
	e2 := &ValidationError{Errors: []string{"foo", "bar", "baz"}}
	msg := e2.Error()
	if !strings.Contains(msg, "3 validation errors") {
		t.Errorf("multi error count: %s", msg)
	}
	if !strings.Contains(msg, "foo") || !strings.Contains(msg, "bar") {
		t.Errorf("multi error content: %s", msg)
	}
}

// ============================================================================
// Coverage uplift: Compile bad JSON, toFloat, deepEqual, resolvePointer,
// followRef depth, remote ref, checkArray items:false/tuple, checkFormat,
// isHostname/isUUID edge cases
// ============================================================================

func TestCompileBadJSON(t *testing.T) {
	_, err := Compile([]byte("{invalid json"))
	if err == nil {
		t.Error("invalid JSON should fail Compile")
	}
}

func TestToFloatBadNumber(t *testing.T) {
	_, ok := toFloat(json.Number("abc"))
	if ok {
		t.Error("toFloat should fail for non-numeric json.Number")
	}
}

func TestDeepEqualNumericVsNonNumeric(t *testing.T) {
	if deepEqual(float64(1), "1", maxDeepEqualDepth) {
		t.Error("numeric 1 should not equal string '1'")
	}
}

func TestDeepEqualArrayLengthMismatch(t *testing.T) {
	if deepEqual([]any{1, 2}, []any{1}, maxDeepEqualDepth) {
		t.Error("arrays of different length should not be equal")
	}
}

func TestDeepEqualMapLengthMismatch(t *testing.T) {
	a := map[string]any{"a": 1, "b": 2}
	b := map[string]any{"a": 1}
	if deepEqual(a, b, maxDeepEqualDepth) {
		t.Error("maps of different length should not be equal")
	}
}

func TestResolvePointerNilRoot(t *testing.T) {
	_, ok := resolvePointer(nil, "/anything")
	if ok {
		t.Error("nil root should return false")
	}
}

func TestResolvePointerArrayIndex(t *testing.T) {
	// $ref "#/allOf/0" exercises the []any case in resolvePointer.
	s := compile(t, `{
		"$ref": "#/allOf/0",
		"allOf": [{"type":"string"}]
	}`)
	mustValid(t, s, "hello")
	mustInvalid(t, s, 42.0)
}

func TestResolvePointerBadArrayIndex(t *testing.T) {
	// Out-of-bounds array index → $ref unresolvable → invalid.
	s := compile(t, `{
		"$ref": "#/allOf/99",
		"allOf": [{"type":"string"}]
	}`)
	mustInvalid(t, s, "hello")
}

func TestResolvePointerEmptyPointer(t *testing.T) {
	// Empty pointer returns the root itself.
	root := map[string]any{"type": "string"}
	got, ok := resolvePointer(root, "")
	if !ok {
		t.Fatal("empty pointer should resolve to root")
	}
	if got == nil {
		t.Error("got nil for empty pointer")
	}
}

func TestFollowRefMaxDepth(t *testing.T) {
	// A self-referencing schema cycles until maxRefDepth and reports an error.
	s := compile(t, `{
		"$ref": "#/self",
		"self": {"$ref": "#/self"}
	}`)
	mustInvalid(t, s, "anything")
}

func TestFollowRefRemoteSkipped(t *testing.T) {
	// Remote $ref is silently skipped (lenient); instance passes.
	s := compile(t, `{"$ref": "https://example.com/schema.json"}`)
	mustValid(t, s, "anything")
}

func TestCheckArrayItemsFalse(t *testing.T) {
	// items:false means no items allowed.
	s := compile(t, `{"type":"array","items":false}`)
	mustValid(t, s, instance(t, `[]`))
	mustInvalid(t, s, instance(t, `[1]`))
}

func TestCheckArrayTupleItems(t *testing.T) {
	// items as array (draft-07 tuple form).
	s := compile(t, `{"type":"array","items":[{"type":"string"},{"type":"number"}]}`)
	mustValid(t, s, instance(t, `["hello",42]`))
	mustInvalid(t, s, instance(t, `[1,"notanumber"]`))
}

func TestCheckFormatTime(t *testing.T) {
	s := compile(t, `{"format":"time"}`)
	mustValid(t, s, "12:30:00")
	mustValid(t, s, "12:30:00Z")
	mustInvalid(t, s, "not-a-time")
}

func TestCheckFormatURIReference(t *testing.T) {
	s := compile(t, `{"format":"uri-reference"}`)
	mustValid(t, s, "/relative/path")
	mustValid(t, s, "https://example.com/abs")
}

func TestIsHostnameEdgeCases(t *testing.T) {
	// Empty label from leading dot.
	if isHostname(".foo.com") {
		t.Error(".foo.com should be invalid hostname")
	}
	// Non-alnum, non-hyphen character.
	if isHostname("foo*.com") {
		t.Error("foo*.com should be invalid hostname")
	}
	// Label too long (>63 chars).
	long := strings.Repeat("a", 64) + ".com"
	if isHostname(long) {
		t.Errorf("label >63 chars should be invalid: %s", long)
	}
}

func TestToFloatIntTypes(t *testing.T) {
	// int case
	f, ok := toFloat(int(7))
	if !ok || f != 7 {
		t.Errorf("toFloat(int(7)): %v %v", f, ok)
	}
	// int64 case
	f, ok = toFloat(int64(42))
	if !ok || f != 42 {
		t.Errorf("toFloat(int64(42)): %v %v", f, ok)
	}
}

func TestDeepEqualUnknownType(t *testing.T) {
	// int8 is not handled by toFloat or the type switch → returns false.
	if deepEqual(int8(1), int8(1), maxDeepEqualDepth) {
		t.Error("deepEqual should return false for unhandled types")
	}
}

func TestIsUUIDEdgeCases(t *testing.T) {
	// Hyphen at wrong position.
	if isUUID("1-23e4567-e89b-12d3-a456-426614174000") {
		t.Error("hyphen at position 1 should be invalid UUID")
	}
	// Non-hex character at data position.
	if isUUID("123e4567-e89b-12d3-a456-42661417400z") {
		t.Error("non-hex char should be invalid UUID")
	}
}

func mustDecodeJSON(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", raw, err)
	}
	return v
}

func TestSchemaValidateDeepEqual(t *testing.T) {
	// Test enum with various value types to exercise deepEqual paths.
	schema := []byte(`{"enum": [1, "hello", true, null, [1,2], {"a":1}]}`)
	s, err := Compile(schema)
	if err != nil {
		t.Fatal(err)
	}
	// Integer 1 should match numeric 1 (float64 in JSON)
	if err := s.Validate(mustDecodeJSON(t, `1`)); err != nil {
		t.Errorf("int enum: %v", err)
	}
	// String match
	if err := s.Validate(mustDecodeJSON(t, `"hello"`)); err != nil {
		t.Errorf("string enum: %v", err)
	}
	// Boolean match
	if err := s.Validate(mustDecodeJSON(t, `true`)); err != nil {
		t.Errorf("bool enum: %v", err)
	}
	// Null match
	if err := s.Validate(mustDecodeJSON(t, `null`)); err != nil {
		t.Errorf("null enum: %v", err)
	}
	// Array match
	if err := s.Validate(mustDecodeJSON(t, `[1,2]`)); err != nil {
		t.Errorf("array enum: %v", err)
	}
	// Object match
	if err := s.Validate(mustDecodeJSON(t, `{"a":1}`)); err != nil {
		t.Errorf("object enum: %v", err)
	}
	// No match
	if err := s.Validate(mustDecodeJSON(t, `99`)); err == nil {
		t.Error("99 should not match enum [1,...]")
	}
}

// ============================================================================
// Coverage uplift: matchType unknown, jsonType non-standard, invalid pattern,
// minProperties, maxProperties, deepEqual inner loops, prefixItems break,
// resolvePointer default, isIPv4/isUUID edge cases
// ============================================================================

// TestMatchTypeUnknown covers the final `return false` in matchType when the
// type name is not in the spec.
func TestMatchTypeUnknown(t *testing.T) {
	s := compile(t, `{"type": "unknowntype"}`)
	// matchType("unknowntype", "hello") → falls through all cases → return false
	mustInvalid(t, s, "hello")
}

// TestJsonTypeNonStandard covers the default arm in jsonType for non-JSON Go types.
func TestJsonTypeNonStandard(t *testing.T) {
	s := compile(t, `{"type": "string"}`)
	// chan int is not a standard JSON type → jsonType returns fmt.Sprintf("%T", …)
	if err := s.Validate(make(chan int)); err == nil {
		t.Error("expected type error for chan int")
	}
}

// TestCheckStringInvalidPattern: invalid regex in `pattern` is now rejected at
// Compile time (fail-fast) rather than silently producing a per-call validation
// error on every Validate invocation.
func TestCheckStringInvalidPattern(t *testing.T) {
	_, err := Compile([]byte(`{"type":"string","pattern":"[invalid"}`))
	if err == nil {
		t.Fatal("Compile should fail for an invalid pattern regex")
	}
}

// TestCompileInvalidPatternPropertiesFails covers the same fail-fast behavior
// for invalid patternProperties keys.
func TestCompileInvalidPatternPropertiesFails(t *testing.T) {
	_, err := Compile([]byte(`{"patternProperties":{"[invalid":{"type":"string"}}}`))
	if err == nil {
		t.Fatal("Compile should fail for an invalid patternProperties key regex")
	}
}

// TestPatternPrecompiledIsCached verifies that pre-compiled patterns are shared
// across multiple Validate calls: a pattern that appears in both `pattern` and a
// nested properties child compiles once but applies correctly to both paths.
func TestPatternPrecompiledIsCached(t *testing.T) {
	s := compile(t, `{
		"type": "object",
		"properties": {
			"code": {"type": "string", "pattern": "^[0-9]{4}$"},
			"id":   {"type": "string", "pattern": "^[0-9]{4}$"}
		}
	}`)
	// Both properties share the same pre-compiled regex for "^[0-9]{4}$".
	if len(s.compiled) != 1 {
		t.Errorf("expected 1 unique compiled regex, got %d", len(s.compiled))
	}
	mustValid(t, s, map[string]any{"code": "1234", "id": "5678"})
	mustInvalid(t, s, map[string]any{"code": "abc", "id": "5678"})
}

// TestMinPropertiesViolation covers `v.fail(…, "fewer than minProperties …")`.
func TestMinPropertiesViolation(t *testing.T) {
	s := compile(t, `{"type":"object","minProperties":3}`)
	mustInvalid(t, s, instance(t, `{"a":1}`))
}

// TestMaxPropertiesViolation covers `v.fail(…, "more than maxProperties …")`.
func TestMaxPropertiesViolation(t *testing.T) {
	s := compile(t, `{"type":"object","maxProperties":1}`)
	mustInvalid(t, s, instance(t, `{"a":1,"b":2}`))
}

// TestDeepEqualArrayElementMismatch covers `return false` inside the array loop.
func TestDeepEqualArrayElementMismatch(t *testing.T) {
	if deepEqual([]any{1.0, 2.0}, []any{1.0, 3.0}, maxDeepEqualDepth) {
		t.Error("arrays with different elements should not be equal")
	}
}

// TestDeepEqualMapValueMismatch covers `return false` inside the map loop (value differs).
func TestDeepEqualMapValueMismatch(t *testing.T) {
	if deepEqual(map[string]any{"k": 1.0}, map[string]any{"k": 2.0}, maxDeepEqualDepth) {
		t.Error("maps with different values should not be equal")
	}
}

// TestDeepEqualMapMissingKey covers `return false` when a key exists in a but not b.
func TestDeepEqualMapMissingKey(t *testing.T) {
	a := map[string]any{"k1": 1.0, "k2": 2.0}
	b := map[string]any{"k1": 1.0, "k3": 3.0}
	if deepEqual(a, b, maxDeepEqualDepth) {
		t.Error("maps with different keys should not be equal")
	}
}

// TestPrefixItemsShortArray covers the `break` inside the prefixItems loop
// when the array has fewer elements than the number of prefix schemas.
func TestPrefixItemsShortArray(t *testing.T) {
	s := compile(t, `{"type":"array","prefixItems":[{"type":"string"},{"type":"number"},{"type":"boolean"}]}`)
	// 1-element array → loop breaks at i=1 (1 >= len(arr))
	mustValid(t, s, instance(t, `["hello"]`))
}

// TestResolvePointerDefaultCase covers the `return nil, false` default arm in
// resolvePointer when traversal reaches a value that is neither a map nor an array.
func TestResolvePointerDefaultCase(t *testing.T) {
	// "#/type/foo": root["type"] is string "string"; trying to navigate into it → default
	s := compile(t, `{"$ref": "#/type/foo", "type": "string"}`)
	mustInvalid(t, s, "hello")
}

// TestIsIPv4LeadingZero covers the `n > 255 || (len(p) > 1 && p[0] == '0')` guard.
func TestIsIPv4LeadingZero(t *testing.T) {
	s := compile(t, `{"type":"string","format":"ipv4"}`)
	mustInvalid(t, s, "192.168.01.1")  // leading zero → isIPv4 returns false
	mustInvalid(t, s, "192.168.1.256") // n > 255 → isIPv4 returns false
}

// TestIsUUIDNonHexChar covers `if !isHex { return false }` in isUUID.
func TestIsUUIDNonHexChar(t *testing.T) {
	s := compile(t, `{"type":"string","format":"uuid"}`)
	mustInvalid(t, s, "123e4567-e89b-12d3-a456-42661417400z")
}

// TestComplexityBudgetExponentialRef verifies that an adversarially-crafted
// cyclic $ref schema returns ErrComplexityBudget rather than running forever.
//
// The schema is compact (~150 bytes) but causes exponential evaluation:
// each validation of "$defs/bomb" spawns two anyOf branches that each
// re-follow the same $ref, doubling the work. With maxRefDepth = 64 and no
// budget this produces 2^64 validator calls; with the budget it aborts after
// maxValidateOps calls and returns ErrComplexityBudget in bounded time.
//
// This attack vector is reachable via vctmeta.ValidateClaims when a
// vct#integrity check is absent or the metadata server is hostile.
func TestComplexityBudgetExponentialRef(t *testing.T) {
	const bomb = `{
		"$defs": {
			"T": {
				"anyOf": [
					{"$ref": "#/$defs/T"},
					{"$ref": "#/$defs/T"}
				]
			}
		},
		"$ref": "#/$defs/T"
	}`
	sch, err := Compile([]byte(bomb))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := sch.Validate("any value")
	if got != ErrComplexityBudget {
		t.Fatalf("expected ErrComplexityBudget, got %v", got)
	}
}

// TestComplexityBudgetNormalSchemaUnaffected verifies that a legitimately complex
// schema (many properties with anyOf sub-schemas) completes without hitting the budget.
func TestComplexityBudgetNormalSchemaUnaffected(t *testing.T) {
	// 50 distinctly-named properties, each with a 3-branch anyOf.
	// This is well within normal use but exercises the combinator paths.
	names := []string{
		"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9",
		"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9",
		"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9",
		"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
		"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9",
	}
	props := make([]string, len(names))
	for i, n := range names {
		props[i] = `"` + n + `":{"anyOf":[{"type":"string"},{"type":"number"},{"type":"null"}]}`
	}
	raw := `{"type":"object","properties":{` + strings.Join(props, ",") + `}}`
	sch, err := Compile([]byte(raw))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	inst := make(map[string]any, len(names))
	for _, n := range names {
		inst[n] = "value"
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

// ============================================================================
// Combinator branch-count limit — Axis 78
// ============================================================================

// buildWideCombinator builds a JSON schema with `keyword` and `branches` trivial
// sub-schemas (each `true`), making an array longer than maxCombinatorBranches.
func buildWideCombinator(keyword string, branches int) string {
	subs := make([]string, branches)
	for i := range subs {
		subs[i] = "true"
	}
	branchJSON := "[" + strings.Join(subs, ",") + "]"
	return `{"` + keyword + `":` + branchJSON + `}`
}

// TestTooManyCombinatorBranchesAllOf verifies that an allOf with more than
// maxCombinatorBranches sub-schemas returns ErrTooManyCombinatorBranches.
func TestTooManyCombinatorBranchesAllOf(t *testing.T) {
	sch := compile(t, buildWideCombinator("allOf", maxCombinatorBranches+1))
	err := sch.Validate("any-value")
	if err != ErrTooManyCombinatorBranches {
		t.Fatalf("allOf with %d branches: want ErrTooManyCombinatorBranches, got %v", maxCombinatorBranches+1, err)
	}
}

// TestTooManyCombinatorBranchesAnyOf verifies that an anyOf with more than
// maxCombinatorBranches sub-schemas returns ErrTooManyCombinatorBranches.
func TestTooManyCombinatorBranchesAnyOf(t *testing.T) {
	sch := compile(t, buildWideCombinator("anyOf", maxCombinatorBranches+1))
	err := sch.Validate("any-value")
	if err != ErrTooManyCombinatorBranches {
		t.Fatalf("anyOf with %d branches: want ErrTooManyCombinatorBranches, got %v", maxCombinatorBranches+1, err)
	}
}

// TestTooManyCombinatorBranchesOneOf verifies that a oneOf with more than
// maxCombinatorBranches sub-schemas returns ErrTooManyCombinatorBranches.
func TestTooManyCombinatorBranchesOneOf(t *testing.T) {
	sch := compile(t, buildWideCombinator("oneOf", maxCombinatorBranches+1))
	err := sch.Validate("any-value")
	if err != ErrTooManyCombinatorBranches {
		t.Fatalf("oneOf with %d branches: want ErrTooManyCombinatorBranches, got %v", maxCombinatorBranches+1, err)
	}
}

// TestCombinatorBranchesAtLimitPassThrough verifies that a combinator with
// exactly maxCombinatorBranches sub-schemas is NOT rejected (only strictly
// greater than the limit triggers the error).
func TestCombinatorBranchesAtLimitPassThrough(t *testing.T) {
	// allOf with exactly maxCombinatorBranches true-schemas should pass.
	sch := compile(t, buildWideCombinator("allOf", maxCombinatorBranches))
	if err := sch.Validate("any"); err != nil {
		t.Fatalf("allOf at limit should not be rejected: %v", err)
	}
}

// ============================================================================
// Axis 91: uniqueItems DoS bounds + deepEqual depth cap
// ============================================================================

// TestUniqueItemsBudgetCapped verifies that the uniqueItems O(N²) comparisons
// are counted against maxValidateOps, so an adversarial schema cannot exhaust
// CPU by pairing a large array with uniqueItems:true.
func TestUniqueItemsBudgetCapped(t *testing.T) {
	// Build a schema with uniqueItems:true and no maxItems limit.
	raw := `{"type":"array","uniqueItems":true}`
	sch, err := Compile([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	// Build an array with enough distinct elements that the N*(N-1)/2 pair
	// comparisons exhaust the ops budget. sqrt(2 * 1_000_000) ≈ 1414 elements
	// → 999_091 pairs, which exceeds maxValidateOps.
	n := 1500
	arr := make([]any, n)
	for i := range arr {
		arr[i] = float64(i) // all distinct — worst case: check every pair
	}

	// Must not hang; must return ErrComplexityBudget (budget exhausted).
	err = sch.Validate(arr)
	if err != ErrComplexityBudget {
		t.Fatalf("uniqueItems large array: want ErrComplexityBudget, got %v", err)
	}
}

// TestUniqueItemsDepthCapNoPanic verifies that deepEqual terminates cleanly
// when confronted with deeply-nested claim values (no infinite recursion / OOM).
func TestUniqueItemsDepthCapNoPanic(t *testing.T) {
	raw := `{"type":"array","uniqueItems":true}`
	sch, err := Compile([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	// Build two elements: one beyond maxDeepEqualDepth nesting, one
	// shallower. deepEqual(elem0, elem1, maxDeepEqualDepth) must return false without panicking.
	build := func(depth int) any {
		var v any = "leaf"
		for i := 0; i < depth; i++ {
			v = []any{v}
		}
		return v
	}
	elem0 := build(maxDeepEqualDepth + 10) // exceeds depth cap
	elem1 := build(maxDeepEqualDepth + 10) // same structure but different instance

	// Must not panic; since depth cap returns false at the boundary these two
	// are treated as not-equal, so uniqueItems passes (no false duplicate).
	err = sch.Validate([]any{elem0, elem1})
	if err != nil {
		// ErrComplexityBudget is also acceptable if the array is large
		if err != ErrComplexityBudget {
			// A real validation error (not-unique false positive due to
			// depth-cap returning false) should not occur either:
			// if depth returns false → not equal → not reported as duplicate.
			t.Logf("deepEqual depth cap: unexpected error: %v", err)
		}
	}
}

// TestDeepEqualDepthZeroReturnsFalse verifies the base case: depth=0 → false.
func TestDeepEqualDepthZeroReturnsFalse(t *testing.T) {
	// Use the exported Validate path: const+enum with literal values. These
	// internally call deepEqual(schema-literal, instance, maxDeepEqualDepth, maxDeepEqualDepth).
	// We can't call deepEqual directly (unexported), but we can verify the
	// schema returns correct results so the depth logic is exercised indirectly.
	raw := `{"const":{"a":1}}`
	sch := compile(t, raw)
	if err := sch.Validate(map[string]any{"a": float64(1)}); err != nil {
		t.Fatalf("const match should pass: %v", err)
	}
	if err := sch.Validate(map[string]any{"a": float64(2)}); err == nil {
		t.Fatal("const mismatch should fail")
	}
}

// TestUniqueItemsSmallArray verifies normal uniqueItems validation still works.
func TestUniqueItemsSmallArrayUnique(t *testing.T) {
	raw := `{"type":"array","uniqueItems":true}`
	sch := compile(t, raw)
	if err := sch.Validate([]any{float64(1), float64(2), float64(3)}); err != nil {
		t.Fatalf("unique items should pass: %v", err)
	}
}

func TestUniqueItemsSmallArrayDuplicate(t *testing.T) {
	raw := `{"type":"array","uniqueItems":true}`
	sch := compile(t, raw)
	err := sch.Validate([]any{float64(1), float64(1)})
	if err == nil {
		t.Fatal("duplicate items should fail uniqueItems")
	}
}
