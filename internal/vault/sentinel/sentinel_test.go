// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package sentinel

import (
	"encoding/base64"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testContext(path, operation string, data map[string]any, policies []string, meta map[string]string) *EvaluateContext {
	req := &logical.Request{Path: path}
	req.Operation = logical.Operation(operation)
	req.Data = data
	te := &logical.TokenEntry{Policies: policies}
	if meta != nil {
		te.Meta = meta
	}
	return &EvaluateContext{Req: req, TokenEntry: te}
}

func mustRun(t *testing.T, doc string, ctx *EvaluateContext) bool {
	t.Helper()
	require.NoError(t, ValidateDocument(doc))
	rule := new(Rule)
	require.NoError(t, rule.Unmarshal(doc))
	return rule.When.Evaluate(ctx)
}

func TestValidateDocument(t *testing.T) {
	valid := []string{
		`{"when": {"request.operation": "read"}}`,
		`{"when": {"all": [{"request.path": "secret/*"}, {"not": {"request.operation": "delete"}}]}}`,
		`{"when": {"any": [{"request.data.ttl": {"less_than": 3600}}, {"request.data.ttl": {"exists": false}}]}}`,
		`{"when": {"token.policies": {"contains": "reader"}}}`,
		`{"when": {"request.data.a.b": {"equals": 3}}}`,
		`{"when": {"token.metadata.team": "platform"}}`,
	}
	for _, doc := range valid {
		require.NoError(t, ValidateDocument(doc), doc)
	}

	invalid := []string{
		`not json`,
		`{"no_when": 1}`,
		`{"when": {}}`,
		`{"when": {"request.path": "a", "request.operation": "read"}}`,
		`{"when": {"request.foo": "bar"}}`,
		`{"when": {"request.operation": {"regex": "^x$"}}}`,
		`{"when": {"request.data.ttl": {"less_than": "soon"}}}`,
		`{"when": {"all": []}}`,
		`{"when": {"all": "one"}}`,
		`{"when": {"not": {"request.path": "a", "request.operation": "b"}}}`,
	}
	for _, doc := range invalid {
		require.Error(t, ValidateDocument(doc), doc)
	}
}

func TestEvaluateBasics(t *testing.T) {
	ctx := testContext("secret/data/foo", "read", map[string]any{
		"ttl":  3600,
		"kind": "secret",
	}, []string{"reader", "default"}, map[string]string{"team": "platform"})

	require.True(t, mustRun(t, `{"when": {"request.path": "secret/data/foo"}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"request.path": "secret/data/bar"}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"request.path": "secret/*"}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"request.operation": "read"}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"request.operation": "delete"}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"request.data.ttl": 3600}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"request.data.ttl": {"greater_than": 100}}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"request.data.TTL": 3600}}`, ctx), "top-level data keys are case-insensitive")
	require.True(t, mustRun(t, `{"when": {"request.data.missing": {"exists": false}}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"request.data.missing": {"exists": true}}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"token.policies": {"contains": "reader"}}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"token.policies": {"contains": "admin"}}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"token.metadata.team": {"in": ["platform", "dev"]}}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"token.metadata.team": "other"}}`, ctx))
}

func TestEvaluateCombinators(t *testing.T) {
	ctx := testContext("secret/data/foo", "read", map[string]any{"ttl": 3600}, []string{"reader"}, nil)

	require.True(t, mustRun(t, `{"when": {"all": [{"request.path": "secret/*"}, {"request.operation": "read"}]}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"all": [{"request.path": "secret/*"}, {"request.operation": "delete"}]}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"any": [{"request.operation": "delete"}, {"request.operation": "read"}]}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"not": {"request.operation": "delete"}}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"not": {"any": [{"request.operation": "read"}]}}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"all": [{"request.path": "secret/*"}, {"not": {"any": [{"request.operation": "delete"}, {"request.operation": "update"}]}}]}}`, ctx))
}

func TestEvaluateUnauthenticated(t *testing.T) {
	// Unauthenticated requests have no token entry; token subjects fail
	// unless negated with exists:false.
	ctx := &EvaluateContext{Req: &logical.Request{Path: "auth/userpass/login"}}
	ctx.Req.Operation = logical.CreateOperation
	ctx.Req.Data = map[string]any{"username": "alice"}

	require.True(t, mustRun(t, `{"when": {"request.path": "auth/userpass/login"}}`, ctx))
	require.False(t, mustRun(t, `{"when": {"token.policies": {"exists": true}}}`, ctx))
	require.True(t, mustRun(t, `{"when": {"token.policies": {"exists": false}}}`, ctx))
}

func TestPathMatches(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "anything", true},
		{"*", "secret/data/foo", true},
		{"secret/*", "secret/data/foo", true},
		{"secret/*", "other/data/foo", false},
		{"secret/data/foo", "secret/data/foo", true},
		{"secret/data/foo", "secret/data/foo/bar", false},
		{"/secret/*", "secret/data/foo", true},
		{"secret/*/", "secret/data", true},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, PathMatches(tc.pattern, tc.path), "%q vs %q", tc.pattern, tc.path)
	}
}

func TestDecodePolicyDocument(t *testing.T) {
	plain := `{"when": {"request.path": "secret/*"}}`
	got, err := DecodePolicyDocument(plain)
	require.NoError(t, err)
	require.Equal(t, plain, got)

	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	got, err = DecodePolicyDocument(encoded)
	require.NoError(t, err)
	require.Equal(t, plain, got)

	// A plain string that is not valid base64 passes through unchanged.
	got, err = DecodePolicyDocument(`{"when": {"request.path": "%%"}}`)
	require.NoError(t, err)
	require.Equal(t, `{"when": {"request.path": "%%"}}`, got)
}

func TestPolicyValidate(t *testing.T) {
	base := func() *Policy {
		return &Policy{
			Name:             "breakglass",
			Policy:           `{"when": {"request.path": "*"}}`,
			EnforcementLevel: EnforcementSoftMandatory,
		}
	}

	// Valid EGP.
	p := base()
	p.Paths = []string{"*"}
	require.NoError(t, p.Validate(true, nil))

	// EGP requires paths.
	p = base()
	err := p.Validate(true, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "paths is required")

	// EGP path glob must be a suffix.
	p = base()
	p.Paths = []string{"secret/*/keys"}
	err = p.Validate(true, nil)
	require.Error(t, err)

	// RGP must not have paths.
	p = base()
	p.Paths = []string{"*"}
	err = p.Validate(false, func() ([]string, error) { return nil, nil })
	require.Error(t, err)
	require.Contains(t, err.Error(), "RGP policies do not take paths")

	// RGP name cannot collide with an ACL policy.
	p = base()
	err = p.Validate(false, func() ([]string, error) { return []string{"breakglass"}, nil })
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot share names")

	// RGP without collision is fine.
	p = base()
	require.NoError(t, p.Validate(false, func() ([]string, error) { return []string{"other"}, nil }))

	// Enforcement level is required and enumerated.
	p = base()
	p.Paths = []string{"*"}
	p.EnforcementLevel = "always"
	err = p.Validate(true, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enforcement_level")

	// Policy document must be valid under the documented subset.
	p = base()
	p.Paths = []string{"*"}
	p.Policy = `rule main = { when true }`
	err = p.Validate(true, nil)
	require.Error(t, err)

	// Base64-encoded documents decode before validation.
	p = base()
	p.Paths = []string{"*"}
	p.Policy = base64.StdEncoding.EncodeToString([]byte(`{"when": {"request.path": "*"}}`))
	require.NoError(t, p.Validate(true, nil))
}

func TestPathGlobValidation(t *testing.T) {
	require.Error(t, ValidateEGPPath(""))
	require.Error(t, ValidateEGPPath("secret/*/keys"))
	require.NoError(t, ValidateEGPPath("secret/*"))
	require.NoError(t, ValidateEGPPath("*"))
}
