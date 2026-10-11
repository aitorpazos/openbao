// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package sentinel

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// The policy document is a documented declarative condition subset, NOT the
// Sentinel language (a documented deviation; see notes.md). Grammar:
//
//	{
//	  "when": <condition>
//	}
//
// condition is one of:
//
//	{"all": [<condition>...]}          — every sub-condition passes
//	{"any": [<condition>...]}          — at least one sub-condition passes
//	{"not": <condition>}               — negation
//	{"<subject>": <value-or-expr>}     — subject comparison
//
// subject is one of:
//
//	request.path            — request path (no "v1/" prefix)
//	request.operation       — logical operation name (read, create, ...)
//	request.mount_point     — mount point, when known
//	request.data.<key>      — request body parameter (dotted keys index
//	                          nested objects)
//	token.policies          — policy names on the requesting token
//	token.metadata.<key>    — token metadata entry
//
// value-or-expr is either a bare JSON value (equality) or a single-key
// operator object:
//
//	{"equals": v}  {"not_equals": v}  {"matches": "glob*"}
//	{"in": [v...]} {"contains": v}    {"exists": true|false}
//	{"less_than": n} {"greater_than": n}
//	{"less_than_equal": n} {"greater_than_equal": n}
//
// "matches" supports a trailing glob ("*" suffix = prefix match); other
// characters are compared literally. A request with no token (unauthenticated)
// fails token.* subjects unless the condition is {"exists": false}.

// subjectKeys enumerates supported subjects for validation errors.
const (
	subjectRequestPath      = "request.path"
	subjectRequestOperation = "request.operation"
	subjectRequestMount     = "request.mount_point"
	subjectRequestData      = "request.data."
	subjectTokenPolicies    = "token.policies"
	subjectTokenMeta        = "token.metadata."
)

// EvaluateContext carries the request-time facts the evaluator consults.
type EvaluateContext struct {
	Req        *logical.Request
	TokenEntry *logical.TokenEntry
}

// Rule is the decoded policy document.
type Rule struct {
	When Condition `json:"when"`
}

// ValidateDocument checks that doc parses as the documented subset and that
// every condition is well-formed. It returns a descriptive error for
// anything the evaluator does not support.
func ValidateDocument(doc string) error {
	if strings.TrimSpace(doc) == "" {
		return fmt.Errorf("policy document is empty")
	}
	rule := new(Rule)
	if err := json.Unmarshal([]byte(doc), rule); err != nil {
		return fmt.Errorf("policy document must be a JSON object with a \"when\" condition: %w", err)
	}
	return validateCondition(rule.When)
}

func validateCondition(c Condition) error {
	if len(c) == 0 {
		return fmt.Errorf("condition must not be empty")
	}
	if len(c) > 1 {
		return fmt.Errorf("condition must contain exactly one of all/any/not or one subject")
	}
	for key, val := range c {
		switch {
		case key == "all", key == "any":
			items, ok := val.([]any)
			if !ok {
				return fmt.Errorf("%q must be an array of conditions", key)
			}
			if len(items) == 0 {
				return fmt.Errorf("%q must contain at least one condition", key)
			}
			for _, item := range items {
				sub, ok := item.(map[string]any)
				if !ok {
					return fmt.Errorf("%q entries must be conditions", key)
				}
				if err := validateCondition(sub); err != nil {
					return err
				}
			}
		case key == "not":
			sub, ok := val.(map[string]any)
			if !ok {
				return fmt.Errorf("%q must be a condition", key)
			}
			if err := validateCondition(sub); err != nil {
				return err
			}
		case isSubject(key):
			if _, err := parseExpr(key, val); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported policy subject %q (supported: request.path, request.operation, request.mount_point, request.data.*, token.policies, token.metadata.*)", key)
		}
	}
	return nil
}

func isSubject(key string) bool {
	switch {
	case key == subjectRequestPath, key == subjectRequestOperation, key == subjectRequestMount,
		key == subjectTokenPolicies:
		return true
	case strings.HasPrefix(key, subjectRequestData), strings.HasPrefix(key, subjectTokenMeta):
		return strings.TrimPrefix(key, subjectRequestData) != "" &&
			strings.TrimPrefix(key, subjectTokenMeta) != ""
	}
	return false
}

// Operator keys accepted inside expression objects.
var operatorKeys = map[string]struct{}{
	"equals":              {},
	"not_equals":          {},
	"matches":             {},
	"in":                  {},
	"contains":            {},
	"exists":              {},
	"less_than":           {},
	"greater_than":        {},
	"less_than_equal":     {},
	"greater_than_equal":  {},
}

// Condition is a decoded condition (object of one key).
type Condition map[string]any

// Evaluate reports whether the condition holds for the request context.
func (c Condition) Evaluate(ctx *EvaluateContext) bool {
	if len(c) == 0 {
		return true
	}
	for key, val := range c {
		switch key {
		case "all":
			for _, item := range val.([]any) {
				if !(Condition(item.(map[string]any))).Evaluate(ctx) {
					return false
				}
			}
			return true
		case "any":
			for _, item := range val.([]any) {
				if (Condition(item.(map[string]any))).Evaluate(ctx) {
					return true
				}
			}
			return false
		case "not":
			return !(Condition(val.(map[string]any))).Evaluate(ctx)
		default:
			passed, _ := evalSubject(key, val, ctx)
			return passed
		}
	}
	return true
}

// expr is a parsed subject expression.
type expr struct {
	subject string
	op      string
	value   any
}

func parseExpr(key string, val any) (*expr, error) {
	e := &expr{subject: key}
	if obj, ok := val.(map[string]any); ok {
		if len(obj) != 1 {
			return nil, fmt.Errorf("subject %q expression must contain exactly one operator", key)
		}
		for op, v := range obj {
			if _, ok := operatorKeys[op]; !ok {
				return nil, fmt.Errorf("unsupported operator %q (supported: equals, not_equals, matches, in, contains, exists, less_than, greater_than, less_than_equal, greater_than_equal)", op)
			}
			e.op = op
			e.value = v
		}
	} else {
		e.op = "equals"
		e.value = val
	}
	// Additional validation per operator.
	switch e.op {
	case "in", "contains":
		switch e.value.(type) {
		case []any, string, float64, int, bool:
		default:
			return nil, fmt.Errorf("operator %q requires an array or scalar value", e.op)
		}
	case "less_than", "greater_than", "less_than_equal", "greater_than_equal":
		switch e.value.(type) {
		case float64, int:
		default:
			return nil, fmt.Errorf("operator %q requires a numeric value", e.op)
		}
	}
	return e, nil
}

// evalSubject returns (passed, found).
func evalSubject(key string, val any, ctx *EvaluateContext) (bool, bool) {
	e, err := parseExpr(key, val)
	if err != nil {
		return false, false
	}

	var actual any
	found := true
	switch {
	case e.subject == subjectRequestPath:
		if ctx.Req == nil {
			return false, false
		}
		// Path patterns and request paths are compared without leading or
		// trailing slashes; a trailing glob is a prefix match.
		actual = strings.Trim(ctx.Req.Path, "/")
	case e.subject == subjectRequestOperation:
		if ctx.Req == nil {
			return false, false
		}
		actual = string(ctx.Req.Operation)
	case e.subject == subjectRequestMount:
		if ctx.Req == nil || ctx.Req.MountPoint == "" {
			found = false
		} else {
			actual = ctx.Req.MountPoint
		}
	case strings.HasPrefix(e.subject, subjectRequestData):
		keyPath := strings.TrimPrefix(e.subject, subjectRequestData)
		actual, found = lookupRequestData(ctx.Req, keyPath)
	case e.subject == subjectTokenPolicies:
		if ctx.TokenEntry == nil {
			found = false
			actual = []any{}
		} else {
			policies := make([]any, 0, len(ctx.TokenEntry.Policies))
			for _, p := range ctx.TokenEntry.Policies {
				policies = append(policies, p)
			}
			actual = policies
		}
	case strings.HasPrefix(e.subject, subjectTokenMeta):
		metaKey := strings.TrimPrefix(e.subject, subjectTokenMeta)
		if ctx.TokenEntry == nil || ctx.TokenEntry.Meta == nil {
			found = false
		} else if v, ok := ctx.TokenEntry.Meta[metaKey]; ok {
			actual = v
		} else {
			found = false
		}
	default:
		found = false
	}

	return evalExpr(e, actual, found)
}

func normalizePath(p string) string {
	return "/" + strings.Trim(p, "/")
}

// lookupRequestData indexes req.Data with dotted keys. Top-level keys are
// matched case-insensitively (request parameters are case-insensitive in
// Vault's data model); nested map keys are matched exactly.
func lookupRequestData(req *logical.Request, keyPath string) (any, bool) {
	if req == nil || req.Data == nil {
		return nil, false
	}
	parts := strings.Split(keyPath, ".")
	current := any(req.Data)
	for i, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if i == 0 {
			// Case-insensitive top-level lookup.
			var found bool
			var val any
			for k, v := range m {
				if strings.EqualFold(k, part) {
					val, found = v, true
					break
				}
			}
			if !found {
				return nil, false
			}
			current = val
			continue
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		current = v
	}
	return current, true
}

func evalExpr(e *expr, actual any, found bool) (bool, bool) {
	switch e.op {
	case "exists":
		want, ok := e.value.(bool)
		if !ok {
			return false, found
		}
		if want {
			return found, found
		}
		return !found, found
	}

	if !found {
		return false, found
	}

	switch e.op {
	case "equals":
		if e.subject == subjectRequestPath {
			// Bare values on request.path use the documented glob
			// semantics (trailing "*" = prefix match).
			return globMatch(strings.Trim(toString(e.value), "/"), toString(actual)), found
		}
		return valuesEqual(actual, e.value), found
	case "not_equals":
		if e.subject == subjectRequestPath {
			return !globMatch(strings.Trim(toString(e.value), "/"), toString(actual)), found
		}
		return !valuesEqual(actual, e.value), found
	case "matches":
		pattern, ok := e.value.(string)
		if !ok {
			return false, found
		}
		if e.subject == subjectRequestPath {
			pattern = strings.Trim(pattern, "/")
		}
		return globMatch(pattern, toString(actual)), found
	case "in":
		items, ok := e.value.([]any)
		if !ok {
			return false, found
		}
		for _, item := range items {
			if valuesEqual(actual, item) {
				return true, found
			}
		}
		return false, found
	case "contains":
		// Scalar argument: does the list-valued subject contain the value?
		// Array argument: does the list-valued subject contain all entries?
		containsItems, isList := e.value.([]any)
		if !isList {
			containsItems = []any{e.value}
		}
		list := asList(actual)
		for _, item := range containsItems {
			matched := false
			for _, entry := range list {
				if valuesEqual(entry, item) {
					matched = true
					break
				}
			}
			if !matched {
				return false, found
			}
		}
		return true, found
	case "less_than", "greater_than", "less_than_equal", "greater_than_equal":
		return numericCompare(e.op, actual, e.value), found
	}
	return false, found
}

func asList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, 0, len(t))
		for _, s := range t {
			out = append(out, s)
		}
		return out
	default:
		return []any{v}
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", v)
	}
}

func valuesEqual(a, b any) bool {
	return compareScalars(a, b) == 0
}

// compareScalars compares JSON scalars of mixed types: numbers numerically,
// booleans by value, everything else by string form.
func compareScalars(a, b any) int {
	af, aIsNum := number(a)
	bf, bIsNum := number(b)
	if aIsNum && bIsNum {
		switch {
		case af < bf:
			return -1
		case af > bf:
			return 1
		}
		return 0
	}
	as, bs := toString(a), toString(b)
	return strings.Compare(as, bs)
}

func number(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err == nil {
			return f, true
		}
	}
	return 0, false
}

func numericCompare(op string, actual, want any) bool {
	af, aOk := number(actual)
	bf, bOk := number(want)
	if !aOk || !bOk {
		return false
	}
	switch op {
	case "less_than":
		return af < bf
	case "greater_than":
		return af > bf
	case "less_than_equal":
		return af <= bf
	case "greater_than_equal":
		return af >= bf
	}
	return false
}

// globMatch implements the documented matching semantics: a pattern ending
// in "*" is a prefix match; otherwise it is an exact match.
func globMatch(pattern, subject string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(subject, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == subject
}

// PathMatches reports whether an EGP path pattern applies to a request path,
// using the documented semantics: a trailing glob performs a prefix match, a
// path of "*" applies to all requests, other patterns match exactly. Both
// sides are normalized to have no leading or trailing slashes.
func PathMatches(pattern, path string) bool {
	pattern = strings.Trim(pattern, "/")
	path = strings.Trim(path, "/")
	if pattern == "" {
		return path == ""
	}
	return globMatch(pattern, path)
}

// Unmarshal decodes a policy document into a rule, applying the documented
// optional base64 decoding.
func (r *Rule) Unmarshal(doc string) error {
	decoded, err := DecodePolicyDocument(doc)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(decoded), r)
}
