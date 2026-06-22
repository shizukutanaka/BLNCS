// Package jsonschema — a minimal, zero-dependency JSON Schema validator.
//
// Implements the subset of JSON Schema (draft 2020-12 / draft-07 compatible)
// needed to validate SD-JWT-VC claim sets against the `schema` embedded in
// SD-JWT-VC Type Metadata (draft-ietf-oauth-sd-jwt-vc §Type Metadata). It is not
// a general-purpose validator: remote `$ref`, `$dynamicRef`, `$defs` recursion
// guards beyond a depth bound, and `contentEncoding`/`contentMediaType` are not
// supported.
//
// Supported keywords:
//
//	type, enum, const
//	properties, required, additionalProperties, patternProperties
//	items, prefixItems, minItems, maxItems, uniqueItems, contains
//	minLength, maxLength, pattern, format (lenient)
//	minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf
//	allOf, anyOf, oneOf, not
//	$ref (local JSON-pointer "#/..." only)
//
// Instances are decoded-JSON Go values: map[string]any, []any, float64, string,
// bool, nil. json.Number is also accepted for numeric instances.
package jsonschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// maxRefDepth bounds $ref following to prevent infinite recursion on cyclic schemas.
const maxRefDepth = 64

// maxValidateOps is the total number of schema-node evaluations allowed per
// Validate call. It is shared across all child validators spawned during a
// single call (via a pointer) so that adversarial branching (e.g. 60 levels
// of oneOf with N sub-schemas each) cannot multiply past this cap.
// 1 000 000 ops covers schemas with hundreds of properties × dozens of items
// × several combinator branches without triggering the limit in practice.
const maxValidateOps = 1_000_000

// maxCombinatorBranches caps the number of sub-schemas in allOf / anyOf / oneOf.
// Legitimate schemas rarely need more than a handful; huge branch arrays in
// externally-fetched Type Metadata (vctmeta) would multiply the work budget
// before the global maxValidateOps guard fires.
const maxCombinatorBranches = 32

// Schema is a compiled JSON Schema ready for validation.
type Schema struct {
	root     map[string]any            // the parsed root document (for $ref resolution)
	node     any                       // this schema node: map[string]any or bool
	compiled map[string]*regexp.Regexp // pre-compiled patterns (keyed by pattern string)
}

// ValidationError aggregates one or more constraint violations.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 1 {
		return "jsonschema: " + e.Errors[0]
	}
	return fmt.Sprintf("jsonschema: %d validation errors: %s", len(e.Errors), strings.Join(e.Errors, "; "))
}

// Compile parses a JSON Schema document and pre-compiles all regex patterns.
//
// Pre-compilation means Validate never calls regexp.Compile on the hot path,
// and an invalid pattern or patternProperties key is caught here (fail-fast)
// rather than silently producing a per-call validation error.
func Compile(raw []byte) (*Schema, error) {
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("jsonschema: parse schema: %w", err)
	}
	root, _ := node.(map[string]any)
	compiled := make(map[string]*regexp.Regexp)
	if err := walkPatterns(node, compiled); err != nil {
		return nil, fmt.Errorf("jsonschema: %w", err)
	}
	return &Schema{root: root, node: node, compiled: compiled}, nil
}

// walkPatterns traverses the schema tree and pre-compiles every pattern and
// patternProperties key into dest. It recurses into all schema keywords that
// may contain sub-schemas.
func walkPatterns(node any, dest map[string]*regexp.Regexp) error {
	switch n := node.(type) {
	case bool:
		return nil
	case []any:
		for _, sub := range n {
			if err := walkPatterns(sub, dest); err != nil {
				return err
			}
		}
	case map[string]any:
		if p, ok := n["pattern"].(string); ok {
			if _, seen := dest[p]; !seen {
				re, err := regexp.Compile(p)
				if err != nil {
					return fmt.Errorf("invalid pattern %q: %w", p, err)
				}
				dest[p] = re
			}
		}
		if pp, ok := n["patternProperties"].(map[string]any); ok {
			for pat, sub := range pp {
				if _, seen := dest[pat]; !seen {
					re, err := regexp.Compile(pat)
					if err != nil {
						return fmt.Errorf("invalid patternProperties key %q: %w", pat, err)
					}
					dest[pat] = re
				}
				if err := walkPatterns(sub, dest); err != nil {
					return err
				}
			}
		}
		// Recurse into keywords that carry sub-schemas.
		if props, ok := n["properties"].(map[string]any); ok {
			for _, sub := range props {
				if err := walkPatterns(sub, dest); err != nil {
					return err
				}
			}
		}
		for _, key := range []string{"items", "contains", "additionalProperties", "not"} {
			if sub, ok := n[key]; ok {
				if err := walkPatterns(sub, dest); err != nil {
					return err
				}
			}
		}
		for _, key := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
			if arr, ok := n[key].([]any); ok {
				for _, sub := range arr {
					if err := walkPatterns(sub, dest); err != nil {
						return err
					}
				}
			}
		}
		for _, key := range []string{"$defs", "definitions"} {
			if defs, ok := n[key].(map[string]any); ok {
				for _, sub := range defs {
					if err := walkPatterns(sub, dest); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Validate checks instance against the schema, returning a *ValidationError
// listing every violation, or nil if valid.
// Returns ErrComplexityBudget if the schema requires more than maxValidateOps
// node evaluations (adversarial exponential nesting).
// Returns ErrTooManyCombinatorBranches if an allOf/anyOf/oneOf has more than
// maxCombinatorBranches sub-schemas.
func (s *Schema) Validate(instance any) error {
	ops := 0
	tooManyBranches := false
	v := &validator{root: s.root, compiled: s.compiled, ops: &ops, tooManyBranches: &tooManyBranches}
	v.validate(s.node, instance, "")
	if *v.tooManyBranches {
		return ErrTooManyCombinatorBranches
	}
	if ops > maxValidateOps {
		return ErrComplexityBudget
	}
	if len(v.errs) == 0 {
		return nil
	}
	return &ValidationError{Errors: v.errs}
}

// ============================================================================
// validator
// ============================================================================

type validator struct {
	root            map[string]any
	compiled        map[string]*regexp.Regexp
	errs            []string
	depth           int
	ops             *int  // shared across child validators; incremented on every validate call
	tooManyBranches *bool // set to true if any combinator has > maxCombinatorBranches sub-schemas
}

func (v *validator) fail(path, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if path == "" {
		path = "(root)"
	}
	v.errs = append(v.errs, path+": "+msg)
}

// validate dispatches on a schema node (bool or object).
func (v *validator) validate(node, inst any, path string) {
	*v.ops++
	if *v.ops > maxValidateOps {
		return // budget exhausted; Validate will return ErrComplexityBudget
	}
	switch sch := node.(type) {
	case bool:
		// `true` accepts everything; `false` rejects everything.
		if !sch {
			v.fail(path, "schema is false (no value allowed)")
		}
		return
	case map[string]any:
		v.validateObject(sch, inst, path)
	default:
		// Non-schema node — ignore (lenient).
	}
}

func (v *validator) validateObject(sch map[string]any, inst any, path string) {
	// $ref (local only)
	if ref, ok := sch["$ref"].(string); ok {
		v.followRef(ref, inst, path)
		// draft-07 semantics: $ref ignores sibling keywords. We keep it simple.
		return
	}

	v.checkType(sch, inst, path)
	v.checkEnumConst(sch, inst, path)
	v.checkString(sch, inst, path)
	v.checkNumber(sch, inst, path)
	v.checkObjectKeywords(sch, inst, path)
	v.checkArray(sch, inst, path)
	v.checkCombinators(sch, inst, path)
}

func (v *validator) followRef(ref string, inst any, path string) {
	if v.depth >= maxRefDepth {
		v.fail(path, "$ref recursion too deep")
		return
	}
	if !strings.HasPrefix(ref, "#") {
		// Remote refs unsupported — skip (lenient: do not fail closed on metadata
		// that references external definitions we can't fetch).
		return
	}
	target, ok := resolvePointer(v.root, strings.TrimPrefix(ref, "#"))
	if !ok {
		v.fail(path, "cannot resolve $ref %q", ref)
		return
	}
	v.depth++
	v.validate(target, inst, path)
	v.depth--
}

// ============================================================================
// type
// ============================================================================

func (v *validator) checkType(sch map[string]any, inst any, path string) {
	t, ok := sch["type"]
	if !ok {
		return
	}
	switch want := t.(type) {
	case string:
		if !matchType(want, inst) {
			v.fail(path, "expected type %q, got %s", want, jsonType(inst))
		}
	case []any:
		for _, tw := range want {
			if s, ok := tw.(string); ok && matchType(s, inst) {
				return
			}
		}
		v.fail(path, "value %s does not match any allowed type %v", jsonType(inst), want)
	}
}

func matchType(want string, inst any) bool {
	switch want {
	case "null":
		return inst == nil
	case "boolean":
		_, ok := inst.(bool)
		return ok
	case "string":
		_, ok := inst.(string)
		return ok
	case "object":
		_, ok := inst.(map[string]any)
		return ok
	case "array":
		_, ok := inst.([]any)
		return ok
	case "number":
		_, ok := toFloat(inst)
		return ok
	case "integer":
		f, ok := toFloat(inst)
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0)
	}
	return false
}

func jsonType(inst any) string {
	switch inst.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case float64, json.Number, int, int64:
		return "number"
	}
	return fmt.Sprintf("%T", inst)
}

// ============================================================================
// enum / const
// ============================================================================

func (v *validator) checkEnumConst(sch map[string]any, inst any, path string) {
	if c, ok := sch["const"]; ok {
		if !deepEqual(c, inst) {
			v.fail(path, "value must equal const %v", c)
		}
	}
	if e, ok := sch["enum"].([]any); ok {
		for _, opt := range e {
			if deepEqual(opt, inst) {
				return
			}
		}
		v.fail(path, "value %v not in enum", inst)
	}
}

// ============================================================================
// string
// ============================================================================

func (v *validator) checkString(sch map[string]any, inst any, path string) {
	s, ok := inst.(string)
	if !ok {
		return
	}
	if n, ok := toFloat(sch["minLength"]); ok && float64(len([]rune(s))) < n {
		v.fail(path, "string shorter than minLength %v", n)
	}
	if n, ok := toFloat(sch["maxLength"]); ok && float64(len([]rune(s))) > n {
		v.fail(path, "string longer than maxLength %v", n)
	}
	if p, ok := sch["pattern"].(string); ok {
		// Pre-compiled at Compile time; always present for a valid pattern.
		if re, found := v.compiled[p]; found && !re.MatchString(s) {
			v.fail(path, "string does not match pattern %q", p)
		}
	}
	if f, ok := sch["format"].(string); ok {
		if !checkFormat(f, s) {
			v.fail(path, "string is not a valid %s", f)
		}
	}
}

// ============================================================================
// number
// ============================================================================

func (v *validator) checkNumber(sch map[string]any, inst any, path string) {
	f, ok := toFloat(inst)
	if !ok {
		return
	}
	if m, ok := toFloat(sch["minimum"]); ok && f < m {
		v.fail(path, "value %v < minimum %v", f, m)
	}
	if m, ok := toFloat(sch["maximum"]); ok && f > m {
		v.fail(path, "value %v > maximum %v", f, m)
	}
	if m, ok := toFloat(sch["exclusiveMinimum"]); ok && f <= m {
		v.fail(path, "value %v <= exclusiveMinimum %v", f, m)
	}
	if m, ok := toFloat(sch["exclusiveMaximum"]); ok && f >= m {
		v.fail(path, "value %v >= exclusiveMaximum %v", f, m)
	}
	if m, ok := toFloat(sch["multipleOf"]); ok && m > 0 {
		// Float division (f/m) loses integrality for e.g. 0.3/0.1; use a
		// remainder with tolerance instead to avoid spurious failures.
		rem := math.Abs(math.Remainder(f, m))
		if rem > 1e-9*math.Max(1, math.Abs(f)) {
			v.fail(path, "value %v is not a multiple of %v", f, m)
		}
	}
}

// ============================================================================
// object
// ============================================================================

func (v *validator) checkObjectKeywords(sch map[string]any, inst any, path string) {
	obj, ok := inst.(map[string]any)
	if !ok {
		return
	}

	// required
	if req, ok := sch["required"].([]any); ok {
		for _, r := range req {
			name, _ := r.(string)
			if _, present := obj[name]; !present {
				v.fail(path, "missing required property %q", name)
			}
		}
	}

	// minProperties / maxProperties
	if n, ok := toFloat(sch["minProperties"]); ok && float64(len(obj)) < n {
		v.fail(path, "fewer than minProperties %v", n)
	}
	if n, ok := toFloat(sch["maxProperties"]); ok && float64(len(obj)) > n {
		v.fail(path, "more than maxProperties %v", n)
	}

	props, _ := sch["properties"].(map[string]any)
	patternProps, _ := sch["patternProperties"].(map[string]any)

	// Use pre-compiled patternProperties regexes (compiled at Compile time).
	type pp struct {
		re   *regexp.Regexp
		node any
	}
	var compiledPP []pp
	for pat, node := range patternProps {
		if re, found := v.compiled[pat]; found {
			compiledPP = append(compiledPP, pp{re: re, node: node})
		}
	}

	for key, val := range obj {
		matched := false
		childPath := joinPath(path, key)
		if props != nil {
			if pnode, ok := props[key]; ok {
				v.validate(pnode, val, childPath)
				matched = true
			}
		}
		for _, p := range compiledPP {
			if p.re.MatchString(key) {
				v.validate(p.node, val, childPath)
				matched = true
			}
		}
		if !matched {
			if ap, ok := sch["additionalProperties"]; ok {
				switch apv := ap.(type) {
				case bool:
					if !apv {
						v.fail(childPath, "additional property %q not allowed", key)
					}
				default:
					v.validate(ap, val, childPath)
				}
			}
		}
	}
}

// ============================================================================
// array
// ============================================================================

func (v *validator) checkArray(sch map[string]any, inst any, path string) {
	arr, ok := inst.([]any)
	if !ok {
		return
	}
	if n, ok := toFloat(sch["minItems"]); ok && float64(len(arr)) < n {
		v.fail(path, "fewer than minItems %v", n)
	}
	if n, ok := toFloat(sch["maxItems"]); ok && float64(len(arr)) > n {
		v.fail(path, "more than maxItems %v", n)
	}
	if u, ok := sch["uniqueItems"].(bool); ok && u {
		for i := 0; i < len(arr); i++ {
			for j := i + 1; j < len(arr); j++ {
				if deepEqual(arr[i], arr[j]) {
					v.fail(path, "items %d and %d are not unique", i, j)
				}
			}
		}
	}

	// prefixItems (draft 2020-12): positional schemas.
	startIdx := 0
	if prefix, ok := sch["prefixItems"].([]any); ok {
		for i, pnode := range prefix {
			if i >= len(arr) {
				break
			}
			v.validate(pnode, arr[i], joinPath(path, strconv.Itoa(i)))
		}
		startIdx = len(prefix)
	}

	// items: a single schema applied to all (remaining) elements.
	if items, ok := sch["items"]; ok {
		switch it := items.(type) {
		case bool:
			if !it && len(arr) > startIdx {
				v.fail(path, "no additional items allowed")
			}
		case []any: // draft-07 tuple form
			for i, pnode := range it {
				if i < len(arr) {
					v.validate(pnode, arr[i], joinPath(path, strconv.Itoa(i)))
				}
			}
		default:
			for i := startIdx; i < len(arr); i++ {
				v.validate(items, arr[i], joinPath(path, strconv.Itoa(i)))
			}
		}
	}

	// contains: at least one element matches.
	if c, ok := sch["contains"]; ok {
		found := false
		for _, el := range arr {
			sub := &validator{root: v.root, compiled: v.compiled, depth: v.depth, ops: v.ops, tooManyBranches: v.tooManyBranches}
			sub.validate(c, el, path)
			if len(sub.errs) == 0 {
				found = true
				break
			}
		}
		if !found {
			v.fail(path, "no item matches 'contains' schema")
		}
	}
}

// ============================================================================
// combinators
// ============================================================================

func (v *validator) checkCombinators(sch map[string]any, inst any, path string) {
	if all, ok := sch["allOf"].([]any); ok {
		if len(all) > maxCombinatorBranches {
			*v.tooManyBranches = true
			return
		}
		for i, sub := range all {
			child := &validator{root: v.root, compiled: v.compiled, depth: v.depth, ops: v.ops, tooManyBranches: v.tooManyBranches}
			child.validate(sub, inst, path)
			if len(child.errs) > 0 {
				v.fail(path, "allOf[%d] failed: %s", i, strings.Join(child.errs, ", "))
			}
		}
	}
	if any_, ok := sch["anyOf"].([]any); ok {
		if len(any_) > maxCombinatorBranches {
			*v.tooManyBranches = true
			return
		}
		ok := false
		for _, sub := range any_ {
			child := &validator{root: v.root, compiled: v.compiled, depth: v.depth, ops: v.ops, tooManyBranches: v.tooManyBranches}
			child.validate(sub, inst, path)
			if len(child.errs) == 0 {
				ok = true
				break
			}
		}
		if !ok {
			v.fail(path, "value matches none of anyOf")
		}
	}
	if one, ok := sch["oneOf"].([]any); ok {
		if len(one) > maxCombinatorBranches {
			*v.tooManyBranches = true
			return
		}
		matches := 0
		for _, sub := range one {
			child := &validator{root: v.root, compiled: v.compiled, depth: v.depth, ops: v.ops, tooManyBranches: v.tooManyBranches}
			child.validate(sub, inst, path)
			if len(child.errs) == 0 {
				matches++
			}
		}
		if matches != 1 {
			v.fail(path, "value must match exactly one of oneOf, matched %d", matches)
		}
	}
	if not, ok := sch["not"]; ok {
		child := &validator{root: v.root, compiled: v.compiled, depth: v.depth, ops: v.ops, tooManyBranches: v.tooManyBranches}
		child.validate(not, inst, path)
		if len(child.errs) == 0 {
			v.fail(path, "value must not match 'not' schema")
		}
	}
}

// ============================================================================
// helpers
// ============================================================================

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func deepEqual(a, b any) bool {
	// Normalize numbers so 1 (int) == 1.0 (float64) etc.
	if af, aok := toFloat(a); aok {
		if bf, bok := toFloat(b); bok {
			return af == bf
		}
		return false
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !deepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, val := range av {
			bval, present := bv[k]
			if !present || !deepEqual(val, bval) {
				return false
			}
		}
		return true
	}
	return false
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

// resolvePointer resolves a JSON Pointer ("/a/b/0") against root.
func resolvePointer(root map[string]any, pointer string) (any, bool) {
	if root == nil {
		return nil, false
	}
	if pointer == "" || pointer == "/" {
		return root, true
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var cur any = root
	for _, raw := range parts {
		tok := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[tok]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// ErrUnknownFormat is returned for clarity in tests when needed.
var ErrUnknownFormat = errors.New("jsonschema: unknown format")

// ErrComplexityBudget is returned by Validate when the total number of
// schema-node evaluations exceeds maxValidateOps. Legitimate schemas over
// realistic claim sets stay well under this limit; it exists to bound
// exponential blowup from adversarially-crafted nested oneOf/anyOf/allOf
// schemas reachable via vctmeta.ValidateClaims from externally-fetched
// Type Metadata documents.
var ErrComplexityBudget = errors.New("jsonschema: complexity budget exceeded")

// ErrTooManyCombinatorBranches is returned by Validate when an allOf, anyOf,
// or oneOf combinator carries more than maxCombinatorBranches sub-schemas.
// It exists to reject adversarial schemas whose branch count alone (even with
// trivial sub-schemas) can produce O(N^depth) work across nested combinators
// before the global op-budget fires.
var ErrTooManyCombinatorBranches = errors.New("jsonschema: too many combinator branches")
