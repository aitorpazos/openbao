// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestValidator(t *testing.T) {
	tests := []struct {
		name, schema, body string
		valid              bool
	}{
		{"object", `{type: object, required: [n], properties: {n: {type: number, const: 2}}, additionalProperties: false}`, `{"n":2,"extra":true}`, true},
		{"missing", `{type: object, required: [n]}`, `{}`, false},
		{"nested", `{type: object, properties: {a: {type: array, items: {type: string, pattern: '^a'}}}}`, `{"a":["abc","ax"]}`, true},
		{"nested-mismatch", `{type: object, properties: {a: {type: array, items: {type: string, pattern: '^a'}}}}`, `{"a":["abc","bad"]}`, false},
		{"string", `{type: string}`, `"abc"`, true},
		{"wrong-string", `{type: string}`, `3`, false},
		{"boolean", `{type: boolean, const: false}`, `false`, true},
		{"wrong-boolean", `{type: boolean}`, `"false"`, false},
		{"null", `{type: 'null', const: null}`, `null`, true},
		{"wrong-null", `{const: null}`, `{}`, false},
		{"array", `{type: array, items: {enum: [1, 2]}}`, `[1,2]`, true},
		{"enum-mismatch", `{enum: [1, 2]}`, `3`, false},
		{"object-const", `{const: {x: [1, true]}}`, `{"x":[1,true]}`, true},
		{"wrong-object", `{type: object}`, `[]`, false},
		{"wrong-array", `{type: array}`, `{}`, false},
		{"wrong-number", `{type: number}`, `true`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var schema map[string]any
			if err := yaml.Unmarshal([]byte(tt.schema), &schema); err != nil {
				t.Fatal(err)
			}
			n, err := normalize(schema)
			if err != nil {
				t.Fatal(err)
			}
			schema = n.(map[string]any)
			if err = checkSchema(schema); err != nil {
				t.Fatal(err)
			}
			var body any
			if err = json.Unmarshal([]byte(tt.body), &body); err != nil {
				t.Fatal(err)
			}
			if err = validate(schema, body, "$"); (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}
func TestSchemaErrors(t *testing.T) {
	for _, s := range []string{`{pattern: '['}`, `{required: [1]}`, `{items: []}`, `{properties: {x: 1}}`, `{unknown: true}`} {
		t.Run(s, func(t *testing.T) {
			var m map[string]any
			yaml.Unmarshal([]byte(s), &m)
			v, _ := normalize(m)
			if checkSchema(v.(map[string]any)) == nil {
				t.Fatal("accepted invalid schema")
			}
		})
	}
}

func TestAbsent(t *testing.T) {
	tests := []struct {
		name  string
		keys  []string
		body  string
		valid bool
	}{
		{"key-present", []string{"data.nskv/"}, `{"data":{"nskv/":{"type":"kv"}}}`, false},
		{"key-absent", []string{"data.nskv/"}, `{"data":{"sys/":{}}}`, true},
		{"ancestor-missing", []string{"data.nskv/"}, `{"other":{}}`, true},
		{"top-level-present", []string{"nskv/"}, `{"nskv/":{},"sys/":{}}`, false},
		{"top-level-absent", []string{"nskv/"}, `{"sys/":{}}`, true},
		{"ancestor-not-object", []string{"data.nskv/"}, `{"data":"scalar"}`, true},
		{"empty-body-trivially-absent", []string{"data.nskv/"}, `null`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body any
			if err := json.Unmarshal([]byte(tt.body), &body); err != nil {
				t.Fatal(err)
			}
			if err := matchAbsent(tt.keys, body); (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}
func testCase() Case {
	return Case{ID: "one", Request: Request{Method: "GET", Path: "/v1/test"}, Expect: Expect{Status: Statuses{200}}}
}
func TestVerdicts(t *testing.T) {
	tests := []struct {
		name                string
		status              int
		body, feature, want string
	}{
		{"ok", 200, `{}`, "core", "PASS"}, {"missing", 404, `{}`, "core", "FEATURE_ABSENT"},
		{"missing-non-json", 404, `not JSON`, "core", "FEATURE_ABSENT"}, {"unfeatured", 404, `{}`, "", "FAIL"},
		{"server-error", 500, `{"errors":["bad"]}`, "core", "FAIL"}, {"bad-json", 200, `oops`, "core", "ERROR"},
		{"trailing-json", 200, `{} {}`, "core", "ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Vault-Token") != "secret" {
					t.Error("missing token")
				}
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()
			v, status, _, _ := runCase(srv.Client(), srv.URL, "secret", map[string]string{}, tt.feature, testCase())
			if v != tt.want || status != tt.status {
				t.Fatalf("%s %d", v, status)
			}
		})
	}
}
func TestTransport(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		s.Close()
		v, _, _, _ := runCase(&http.Client{Timeout: time.Second}, s.URL, "", map[string]string{}, "", testCase())
		if v != "ERROR" {
			t.Fatal(v)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(40 * time.Millisecond); fmt.Fprint(w, `{}`) }))
		defer s.Close()
		v, _, _, _ := runCase(&http.Client{Timeout: time.Millisecond}, s.URL, "", map[string]string{}, "", testCase())
		if v != "ERROR" {
			t.Fatal(v)
		}
	})
}
func TestAssertions(t *testing.T) {
	tests := []struct {
		name, expect, body string
		status             int
		want               string
	}{
		{"exact-dotted", "status: [200, 201]\nexact: {data.x: [1, 2]}", `{"data":{"x":[1,2],"extra":3}}`, 201, "PASS"},
		{"exact-deep", "status: 200\nexact: {data: {x: 1}}", `{"data":{"x":1,"y":2}}`, 200, "FAIL"},
		{"exact-missing", "status: 200\nexact: {missing: null}", `{}`, 200, "FAIL"},
		{"errors", "status: 400\nerrors_contain: ['^bad', 'denied$']", `{"errors":["bad input","permission denied"]}`, 400, "PASS"},
		{"errors-mismatch", "status: 400\nerrors_contain: ['^bad']", `{"errors":["good"]}`, 400, "FAIL"},
		{"empty", "status: 204\nbody: null", "", 204, "PASS"},
		{"json-null-not-empty", "status: 200\nbody: null", "null", 200, "FAIL"},
		{"empty-not-null-schema", "status: 200\nbody_schema: {type: 'null'}", "", 200, "FAIL"},
		{"schema-mismatch", "status: 200\nbody_schema: {type: object, required: [x]}", `{}`, 200, "FAIL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testCase()
			if err := yaml.Unmarshal([]byte(tt.expect), &c.Expect); err != nil {
				t.Fatal(err)
			}
			spec := Spec{API: "a", Source: "https://example.com", Cases: []Case{c}}
			if err := checkSpec(&spec); err != nil {
				t.Fatal(err)
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tt.status); fmt.Fprint(w, tt.body) }))
			defer s.Close()
			v, _, d, _ := runCase(s.Client(), s.URL, "", map[string]string{}, "", spec.Cases[0])
			if v != tt.want {
				t.Fatalf("%s: %s", v, d)
			}
		})
	}
}

const fixture = "api: a\nfeature: core\nsource: https://developer.hashicorp.com/vault/api-docs/system/health\ncases:\n  - id: first\n    request: {method: GET, path: /v1/test}\n    expect: {status: 200}\n"

func put(t *testing.T, dir, name, text string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestLoadSpecs(t *testing.T) {
	t.Run("recursive-filter-order", func(t *testing.T) {
		dir := t.TempDir()
		put(t, dir, "b/nested.yml", strings.Replace(fixture, "feature: core", "feature: other", 1))
		put(t, dir, "a.yaml", fixture)
		put(t, dir, "ignored.txt", "bad")
		s, e := loadSpecs(dir, "")
		if e != nil || len(s) != 2 || s[0].Feature != "core" {
			t.Fatalf("%v %v", s, e)
		}
		s, e = loadSpecs(dir, "feature=core")
		if e != nil || len(s) != 1 {
			t.Fatalf("%v %v", s, e)
		}
		s, e = loadSpecs(dir, "feature=none")
		if e != nil || len(s) != 0 {
			t.Fatalf("%v %v", s, e)
		}
		if _, e = loadSpecs(dir, "other=core"); e == nil {
			t.Fatal("bad filter accepted")
		}
	})
	for name, text := range map[string]string{"bad-yaml": "api: [", "duplicate": fixture + "  - id: first\n    request: {method: GET, path: /v1/test}\n    expect: {status: 200}\n", "unknown": fixture + "typo: true\n", "multi-document": fixture + "---\n" + fixture, "bad-dependency": strings.Replace(fixture, "id: first", "id: first\n    depends: [unknown]", 1), "missing-status": strings.Replace(fixture, "status: 200", "", 1)} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			put(t, dir, "s.yaml", text)
			if _, err := loadSpecs(dir, ""); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
func TestDepends(t *testing.T) {
	for _, first := range []struct {
		status int
		want   string
	}{{500, "SKIP"}, {200, "PASS"}, {404, "PASS"}} {
		t.Run(fmt.Sprint(first.status), func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/v1/first" {
					w.WriteHeader(first.status)
				}
				fmt.Fprint(w, `{}`)
			}))
			defer s.Close()
			a, b := testCase(), testCase()
			a.ID = "first"
			a.Request.Path = "/v1/first"
			b.ID = "second"
			b.Depends = []string{"first"}
			rs := runSpecs(s.Client(), s.URL, "", []Spec{{Feature: "core", Cases: []Case{a, b}}})
			if rs[1].Verdict != first.want {
				t.Fatal(rs)
			}
			if first.want == "SKIP" && calls != 1 {
				t.Fatal("skip issued HTTP request")
			}
		})
	}
}
func TestExitCodes(t *testing.T) {
	for _, v := range []string{"PASS", "FAIL", "FEATURE_ABSENT", "SKIP", "ERROR"} {
		for _, strict := range []bool{false, true} {
			want := 0
			if v == "FAIL" || v == "ERROR" || (v == "FEATURE_ABSENT" && strict) {
				want = 1
			}
			if got := exitCode([]Result{{Verdict: v}}, strict); got != want {
				t.Fatalf("%s strict=%v got %d", v, strict, got)
			}
		}
	}
}
func TestCLI(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "a.yaml", fixture)
	t.Setenv("BAO_TOKEN", "bao")
	t.Setenv("VAULT_TOKEN", "vault")
	for _, tt := range []struct {
		name, token string
		args        []string
	}{{"bao", "bao", nil}, {"explicit", "explicit", []string{"--token", "explicit"}}, {"vault", "vault", nil}} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "vault" {
				t.Setenv("BAO_TOKEN", "")
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Vault-Token") != tt.token {
					t.Error("wrong token")
				}
				fmt.Fprint(w, `{}`)
			}))
			defer s.Close()
			var out, errout bytes.Buffer
			args := append([]string{"--target", s.URL, "--specs", dir, "--format", "json"}, tt.args...)
			if code := cli(args, &out, &errout); code != 0 {
				t.Fatalf("%d %s", code, &errout)
			}
			var rs []Result
			if err := json.Unmarshal(out.Bytes(), &rs); err != nil || len(rs) != 1 || rs[0].Verdict != "PASS" {
				t.Fatalf("%s %v", &out, err)
			}
		})
	}
}

// TestCaptureFlow verifies named capture slots, $name body substitution and
// named-token selection across two cases.
func TestCaptureFlow(t *testing.T) {
	var gotAuth, gotBody string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/login" {
			fmt.Fprint(w, `{"auth":{"client_token":"tok-1","entity_id":"ent-1"}}`)
			return
		}
		gotAuth = r.Header.Get("X-Vault-Token")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		fmt.Fprint(w, `{"data":{"ok":true}}`)
	}))
	defer s.Close()
	data := map[string]string{}
	login := Case{ID: "login", Request: Request{Method: "POST", Path: "/v1/login"}, Expect: Expect{Status: Statuses{200}},
		Capture: map[string]string{"alice": "auth.client_token", "ent": "auth.entity_id"}}
	if v, _, d, _ := runCase(s.Client(), s.URL, "root", data, "", login); v != "PASS" {
		t.Fatal(d)
	}
	if data["alice"] != "tok-1" || data["ent"] != "ent-1" {
		t.Fatalf("capture: %v", data)
	}
	var node yaml.Node
	yaml.Unmarshal([]byte(`{"accessor":"$ent"}`), &node)
	use := Case{ID: "use", Request: Request{Method: "POST", Path: "/v1/do", Body: *node.Content[0]},
		Expect: Expect{Status: Statuses{200}}, UseCapturedToken: "alice"}
	if v, _, d, _ := runCase(s.Client(), s.URL, "root", data, "", use); v != "PASS" {
		t.Fatal(d)
	}
	if gotAuth != "tok-1" || gotBody != `{"accessor":"ent-1"}` {
		t.Fatalf("auth=%q body=%q", gotAuth, gotBody)
	}
}
func TestRequest(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("X-Test") != "yes" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("bad request")
		}
		var b map[string]any
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b["n"] != float64(1) {
			t.Errorf("bad body: %v %v", b, err)
		}
		fmt.Fprint(w, `{}`)
	}))
	defer s.Close()
	c := testCase()
	c.Request.Method = "POST"
	c.Request.Headers = map[string]string{"X-Test": "yes"}
	var node yaml.Node
	yaml.Unmarshal([]byte("{n: 1}"), &node)
	c.Request.Body = *node.Content[0]
	v, _, d, _ := runCase(s.Client(), s.URL, "", map[string]string{}, "", c)
	if v != "PASS" {
		t.Fatalf("%s %s", v, d)
	}
}

func TestExpected404NotFeatureAbsent(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, `{"errors":[]}`)
	}))
	defer s.Close()
	c := testCase()
	c.Expect.Status = Statuses{200, 404}
	v, _, d, _ := runCase(&http.Client{Timeout: time.Second}, s.URL, "", map[string]string{}, "mfa-stepup", c)
	if v != "PASS" {
		t.Fatalf("expected PASS, got %s %s", v, d)
	}
}
