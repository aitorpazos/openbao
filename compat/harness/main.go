// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type Result struct {
	File    string `json:"file"`
	API     string `json:"api"`
	Feature string `json:"feature"`
	Case    string `json:"case"`
	Verdict string `json:"verdict"`
	Status  int    `json:"status,omitempty"`
	Detail  string `json:"detail"`
}

func runSpecs(client *http.Client, target, token string, specs []Spec) []Result {
	out := []Result{}
	for _, s := range specs {
		verdicts := map[string]string{}
		capturedToken := ""
		for _, c := range s.Cases {
			r := Result{File: s.File, API: s.API, Feature: s.Feature, Case: c.ID}
			for _, dep := range c.Depends {
				if verdicts[dep] == "FAIL" {
					r.Verdict = "SKIP"
					r.Detail = "dependency " + dep + " failed"
					break
				}
			}
			if r.Verdict == "" {
				var verdict, newCaptured string
				verdict, r.Status, r.Detail, newCaptured = runCase(client, target, token, capturedToken, s.Feature, c)
				r.Verdict = verdict
				// Only capture cases produce a token; other cases must not
				// erase a previously captured one.
				if newCaptured != "" {
					capturedToken = newCaptured
				}
			}
			verdicts[c.ID] = r.Verdict
			out = append(out, r)
		}
	}
	return out
}

// runCase executes one case. It returns the verdict, HTTP status, detail,
// and the token captured from this response (auth.client_token) when the
// case requests capture.
func runCase(client *http.Client, target, token, capturedToken, feature string, c Case) (string, int, string, string) {
	captured := ""
	var payload []byte
	if c.Request.Body.Kind != 0 {
		var v any
		if err := c.Request.Body.Decode(&v); err != nil {
			return "ERROR", 0, err.Error(), captured
		}
		var err error
		payload, err = json.Marshal(v)
		if err != nil {
			return "ERROR", 0, err.Error(), captured
		}
	}
	req, err := http.NewRequest(c.Request.Method, strings.TrimRight(target, "/")+c.Request.Path, bytes.NewReader(payload))
	if err != nil {
		return "ERROR", 0, err.Error(), captured
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.Request.Headers {
		req.Header.Set(k, v)
	}
	effectiveToken := token
	if c.UseCapturedToken && capturedToken != "" {
		effectiveToken = capturedToken
	}
	if effectiveToken != "" && !c.NoAuth {
		req.Header.Set("X-Vault-Token", effectiveToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "ERROR", 0, err.Error(), captured
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	expected404 := false
	for _, want := range c.Expect.Status {
		if want == 404 {
			expected404 = true
			break
		}
	}
	if status == 404 && feature != "" && !expected404 {
		return "FEATURE_ABSENT", status, "HTTP 404 (feature " + feature + ")", captured
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "ERROR", status, err.Error(), captured
	}
	var body any
	if len(bytes.TrimSpace(b)) != 0 {
		if err = json.Unmarshal(b, &body); err != nil {
			return "ERROR", status, "bad JSON: " + err.Error(), captured
		}
	}
	accepted := false
	for _, want := range c.Expect.Status {
		if status == want {
			accepted = true
		}
	}
	if !accepted {
		return "FAIL", status, fmt.Sprintf("HTTP %d; expected %v", status, c.Expect.Status), captured
	}
	if c.Expect.Body.Kind != 0 && len(b) != 0 {
		return "FAIL", status, "expected empty body", captured
	}
	if len(bytes.TrimSpace(b)) == 0 && (c.Expect.Schema != nil || len(c.Expect.Exact) > 0 || len(c.Expect.Contains) > 0 || len(c.Expect.Errors) > 0) {
		return "FAIL", status, "empty body cannot satisfy JSON assertions", captured
	}
	if err = validate(c.Expect.Schema, body, "$"); err != nil {
		return "FAIL", status, err.Error(), captured
	}
	if err = matchExact(c.Expect.Exact, body); err != nil {
		return "FAIL", status, err.Error(), captured
	}
	if err = matchContains(c.Expect.Contains, body); err != nil {
		return "FAIL", status, err.Error(), captured
	}
	if err = matchErrors(c.Expect.Errors, body); err != nil {
		return "FAIL", status, err.Error(), captured
	}
	if c.CaptureToken {
		if authMap, ok := body.(map[string]any)["auth"].(map[string]any); ok {
			if tok, ok := authMap["client_token"].(string); ok {
				captured = tok
			}
		}
	}
	return "PASS", status, fmt.Sprintf("HTTP %d; all assertions matched", status), captured
}
func exitCode(results []Result, strict bool) int {
	for _, r := range results {
		if r.Verdict == "FAIL" || r.Verdict == "ERROR" || (strict && r.Verdict == "FEATURE_ABSENT") {
			return 1
		}
	}
	return 0
}
func cli(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("harness", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("target", "http://127.0.0.1:8200", "target URL")
	defaultToken := os.Getenv("BAO_TOKEN")
	if defaultToken == "" {
		defaultToken = os.Getenv("VAULT_TOKEN")
	}
	token := fs.String("token", defaultToken, "authentication token (or BAO_TOKEN/VAULT_TOKEN)")
	dir := fs.String("specs", "../specs", "spec directory")
	filter := fs.String("filter", "", "feature=NAME")
	format := fs.String("format", "table", "table or json")
	strict := fs.Bool("strict", false, "fail on FEATURE_ABSENT")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(stderr, err); return 2 }
	u, err := url.Parse(*target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
		return fail(fmt.Errorf("target must be an HTTP(S) URL without query or fragment"))
	}
	if *timeout <= 0 || fs.NArg() != 0 {
		return fail(fmt.Errorf("positive timeout and no positional arguments required"))
	}
	if *format != "table" && *format != "json" {
		return fail(fmt.Errorf("format must be table or json"))
	}
	specs, err := loadSpecs(*dir, *filter)
	if err != nil {
		return fail(err)
	}
	client := &http.Client{Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	results := runSpecs(client, *target, *token, specs)
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(results)
	} else {
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "VERDICT\tAPI/CASE\tDETAIL")
		for _, r := range results {
			detail := strings.Join(strings.Fields(r.Detail), " ")
			fmt.Fprintf(w, "%s\t%s/%s\t%s\n", r.Verdict, r.API, r.Case, detail)
		}
		err = w.Flush()
	}
	if err != nil {
		return fail(err)
	}
	return exitCode(results, *strict)
}
func main() { os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr)) }
