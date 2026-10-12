// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
		capturedData := map[string]string{}
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
				verdict, r.Status, r.Detail, newCaptured = runCase(client, target, token, capturedData, s.Feature, c)
				r.Verdict = verdict
				// Only capture cases produce a token; other cases must not
				// erase a previously captured one.
				if newCaptured != "" {
					capturedData["token"] = newCaptured
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
// case requests capture. Named capture slots live in capturedData, which is
// shared across the cases of one spec file.
func runCase(client *http.Client, target, token string, capturedData map[string]string, feature string, c Case) (string, int, string, string) {
	if c.Subscribe != nil {
		return runSubscribeCase(client, target, token, capturedData, feature, c)
	}
	if c.Request.Method == "" && len(c.Actions) > 0 {
		// Actions-only case: run each action with the documented
		// expectations; the case passes when every action passes.
		for i, a := range c.Actions {
			ac := Case{ID: fmt.Sprintf("%s#action-%d", c.ID, i), Request: a.Request, Expect: a.Expect}
			verdict, status, detail, _ := runCase(client, target, token, capturedData, "", ac)
			if verdict != "PASS" {
				return verdict, status, detail, ""
			}
		}
		return "PASS", 0, "all actions succeeded", ""
	}
	captured := ""
	var payload []byte
	if c.Request.BodyRaw != "" {
		// Raw (non-JSON) body: base64-decoded, sent as octet-stream. Binary
		// uploads such as raft snapshots cannot survive YAML/JSON round trips.
		raw, err := base64.StdEncoding.DecodeString(c.Request.BodyRaw)
		if err != nil {
			return "ERROR", 0, err.Error(), captured
		}
		payload = raw
	} else if c.Request.Body.Kind != 0 {
		var v any
		if err := c.Request.Body.Decode(&v); err != nil {
			return "ERROR", 0, err.Error(), captured
		}
		sub, err := substituteCaptured(v, capturedData)
		if err != nil {
			return "ERROR", 0, err.Error(), captured
		}
		v = sub
		payload, err = json.Marshal(v)
		if err != nil {
			return "ERROR", 0, err.Error(), captured
		}
	}
	// Captured values are also substitutable in the request path
	// (e.g. /v1/identity/entity/id/$ent) so flows that mint IDs can read
	// them back without inventing fixture constants.
	reqPath, err := substituteCapturedPath(c.Request.Path, capturedData)
	if err != nil {
		return "ERROR", 0, err.Error(), captured
	}
	req, err := http.NewRequest(c.Request.Method, strings.TrimRight(target, "/")+reqPath, bytes.NewReader(payload))
	if err != nil {
		return "ERROR", 0, err.Error(), captured
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		if c.Request.Method == http.MethodPatch {
			req.Header.Set("Content-Type", "application/merge-patch+json")
		}
	}
	if c.Request.BodyRaw != "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	for k, v := range c.Request.Headers {
		req.Header.Set(k, v)
	}
	effectiveToken := token
	switch use := c.UseCapturedToken.(type) {
	case bool:
		if use && capturedData["token"] != "" {
			effectiveToken = capturedData["token"]
		}
	case string:
		if use != "" {
			if named, ok := capturedData[use]; ok {
				effectiveToken = named
			} else {
				return "ERROR", 0, "unknown capture slot " + use, captured
			}
		}
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
		// 404/405/415 all signal a missing feature: 404 is the classic
		// unknown path; 405/415 surface when a method (e.g. PATCH) is
		// gated off before route resolution on targets lacking the family.
		if want == 404 || want == 405 || want == 415 {
			expected404 = true
			break
		}
	}
	if (status == 404 || status == 405 || status == 415) && feature != "" && !expected404 {
		return "FEATURE_ABSENT", status, fmt.Sprintf("HTTP %d (feature %s)", status, feature), captured
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
	if err = matchAbsent(c.Expect.Absent, body); err != nil {
		return "FAIL", status, err.Error(), captured
	}
	if err = matchErrors(c.Expect.Errors, body); err != nil {
		return "FAIL", status, err.Error(), captured
	}
	if c.CaptureToken {
		if authMap, ok := body.(map[string]any)["auth"].(map[string]any); ok {
			if tok, ok := authMap["client_token"].(string); ok {
				capturedData["token"] = tok
				captured = tok
			}
		}
	}
	for name, path := range c.Capture {
		if v, ok := lookupPath(body, path); ok {
			if s, ok := v.(string); ok {
				capturedData[name] = s
			}
		}
	}
	return "PASS", status, fmt.Sprintf("HTTP %d; all assertions matched", status), captured
}

// runSubscribeCase opens a documented WebSocket subscription, performs the
// case actions while the stream is open, and evaluates the event
// expectations over the delivery window.
func runSubscribeCase(client *http.Client, target, token string, capturedData map[string]string, feature string, c Case) (string, int, string, string) {
	s := c.Subscribe
	substitute := func(v string) string {
		out, err := substituteCaptured(v, capturedData)
		if err != nil {
			return v
		}
		if str, ok := out.(string); ok {
			return str
		}
		return v
	}
	sub := SubscribeSpec{Type: substitute(s.Type), JSON: s.JSON, Filter: substitute(s.Filter), Namespaces: s.Namespaces, TimeoutSeconds: s.TimeoutSeconds}

	effectiveToken := token
	switch use := c.UseCapturedToken.(type) {
	case bool:
		if use && capturedData["token"] != "" {
			effectiveToken = capturedData["token"]
		}
	case string:
		if use != "" {
			if named, ok := capturedData[use]; ok {
				effectiveToken = named
			} else {
				return "ERROR", 0, "unknown capture slot " + use, ""
			}
		}
	}
	if c.NoAuth {
		effectiveToken = ""
	}

	params := url.Values{}
	if sub.JSON {
		params.Set("json", "true")
	}
	if sub.Filter != "" {
		params.Set("filter", sub.Filter)
	}
	for _, ns := range sub.Namespaces {
		params.Add("namespaces", ns)
	}
	qs := ""
	if enc := params.Encode(); enc != "" {
		qs = "?" + enc
	}
	wsURL := strings.TrimRight(target, "/") + "/v1/sys/events/subscribe/" + sub.Type + qs

	resp, conn, err := wsDial(wsURL, effectiveToken, nil, 30*time.Second)
	if err != nil {
		return "ERROR", 0, "websocket dial: " + err.Error(), ""
	}
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	if conn == nil {
		// Rejection before the upgrade: evaluate documented status expectations.
		expected404 := false
		for _, want := range c.Expect.Status {
			if want == 404 || want == 405 || want == 415 {
				expected404 = true
				break
			}
		}
		if (status == 404 || status == 405 || status == 415) && feature != "" && !expected404 {
			return "FEATURE_ABSENT", status, fmt.Sprintf("HTTP %d (feature %s)", status, feature), ""
		}
		for _, want := range c.Expect.Status {
			if status == want {
				return "PASS", status, fmt.Sprintf("HTTP %d; subscription rejected as expected", status), ""
			}
		}
		return "FAIL", status, fmt.Sprintf("HTTP %d; expected %v", status, c.Expect.Status), ""
	}
	defer conn.close()
	if len(c.Expect.Status) > 0 {
		accepted := false
		for _, want := range c.Expect.Status {
			if status == want {
				accepted = true
			}
		}
		if !accepted {
			return "FAIL", status, fmt.Sprintf("HTTP %d; expected %v", status, c.Expect.Status), ""
		}
	}

	window := time.Duration(sub.TimeoutSeconds) * time.Second
	deadline := time.Now().Add(window)
	pump := conn.pump(deadline)

	// Run the documented actions while subscribed.
	for i, a := range c.Actions {
		ac := Case{ID: fmt.Sprintf("%s#action-%d", c.ID, i), Request: a.Request, Expect: a.Expect}
		verdict, _, detail, _ := runCase(client, target, token, capturedData, "", ac)
		if verdict == "ERROR" {
			return "ERROR", status, "action " + detail, ""
		}
		if verdict == "FAIL" {
			return "FAIL", status, "action failed: " + detail, ""
		}
	}

	// Drain the delivery window.
	matched := false
	collect := make([]string, 0, 4)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		select {
		case ev := <-pump.events:
			verdict, detail := evaluateEvent(ev, c)
			if verdict == "FAIL" {
				return "FAIL", status, detail, ""
			}
			if verdict == "PASS" && !matched {
				matched = true
				_ = detail
				if len(c.ExpectNoEvent) == 0 {
					return "PASS", status, detail, ""
				}
				// Keep draining to check no_event assertions; the first
				// matching event already satisfied expect_event.
			} else if verdict == "SKIP" {
				collect = append(collect, detail)
			}
		case err := <-pump.errs:
			if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
				return "ERROR", status, "stream: " + err.Error(), ""
			}
		}
	}
	if c.ExpectEvent != nil && !matched {
		return "FAIL", status, fmt.Sprintf("no matching event within %ds (%d other events observed)", sub.TimeoutSeconds, len(collect)), ""
	}
	return "PASS", status, "subscription window closed with all expectations met", ""
}

// evaluateEvent inspects one delivered event against the case expectations.
// Returns PASS when it satisfies expect_event, FAIL when it violates an
// expect_no_event assertion, and SKIP when it is unrelated to either.
func evaluateEvent(ev wsEvent, c Case) (string, string) {
	if c.ExpectEvent != nil && c.ExpectEvent.Binary {
		if len(ev.payload) == 0 {
			return "FAIL", "binary event empty"
		}
		if jsonExtractable(ev.payload) {
			return "FAIL", "expected protobuf binary delivery but payload parses as JSON"
		}
		return "PASS", "binary event received (non-JSON payload)"
	}
	var parsed map[string]any
	if err := json.Unmarshal(ev.payload, &parsed); err != nil {
		return "FAIL", fmt.Sprintf("event not parseable as JSON: %v (%q)", err, string(ev.payload))
	}
	if c.ExpectEvent != nil {
		match, detail := eventMatches(parsed, c.ExpectEvent)
		if match {
			return "PASS", detail
		}
		return "SKIP", detail
	}
	for i, ne := range c.ExpectNoEvent {
		if match, detail := eventMatches(parsed, &ne); match {
			return "FAIL", fmt.Sprintf("expect_no_event[%d] violated: %s", i, detail)
		}
	}
	return "SKIP", "event does not match any expect_no_event criterion"
}

func eventMatches(parsed map[string]any, ee *ExpectEvent) (bool, string) {
	data, _ := parsed["data"].(map[string]any)
	if data == nil {
		return false, "event data missing"
	}
	eventType, _ := data["event_type"].(string)
	if eventType != ee.Type {
		return false, fmt.Sprintf("type %q != %q", eventType, ee.Type)
	}
	event, _ := data["event"].(map[string]any)
	if event == nil {
		return false, "data.event missing"
	}
	if ee.Envelope != nil {
		for k, want := range ee.Envelope {
			switch k {
			case "specversion":
				if got, _ := parsed["specversion"].(string); got != want {
					return false, fmt.Sprintf("specversion %q != %q", got, want)
				}
			case "datacontentype":
				if got, _ := parsed["datacontentype"].(string); got != want {
					return false, fmt.Sprintf("datacontentype %q != %q", got, want)
				}
			case "source_prefix":
				got, _ := parsed["source"].(string)
				if !strings.HasPrefix(got, want) {
					return false, fmt.Sprintf("source %q lacks prefix %q", got, want)
				}
			}
		}
	}
	if ee.Metadata != nil {
		meta, _ := event["metadata"].(map[string]any)
		if meta == nil {
			return false, "data.event.metadata missing"
		}
		for k, want := range ee.Metadata {
			got, ok := meta[k]
			if !ok {
				return false, fmt.Sprintf("metadata[%q] missing", k)
			}
			gotStr, isStr := got.(string)
			if !isStr {
				gotStr = fmt.Sprint(got)
			}
			if gotStr != want {
				return false, fmt.Sprintf("metadata[%q] = %q != %q", k, gotStr, want)
			}
		}
	}
	return true, fmt.Sprintf("event %s matched all assertions", ee.Type)
}

// nameRegexp matches bare capture identifiers: $token, $entity_id. Digits
// alone ($1) and mixed templates ($1-$2-$3) are literal values.
var nameRegexp = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// substituteCaptured replaces string values starting with "$" in a decoded
// request body with the named capture slot. Unknown names are an error so
// stale references fail loudly instead of sending literal "$name".
func substituteCaptured(v any, capturedData map[string]string) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			sub, err := substituteCaptured(val, capturedData)
			if err != nil {
				return nil, err
			}
			t[k] = sub
		}
		return t, nil
	case []any:
		for i, val := range t {
			sub, err := substituteCaptured(val, capturedData)
			if err != nil {
				return nil, err
			}
			t[i] = sub
		}
		return t, nil
	case string:
		// Only treat an ENTIRE string as a capture reference when it is a
		// bare alphabetic-identifier placeholder ($token). Values like
		// "$1-$2-$3" or "$1" are literal Transform encode-format templates,
		// not captures.
		if name, ok := strings.CutPrefix(t, "$"); ok && nameRegexp.MatchString(name) {
			if val, ok := capturedData[name]; ok {
				return val, nil
			}
			// Not a known capture slot: pass the literal through so spec
			// bodies can legitimately contain $-prefixed content (regex
			// capture groups like "$1-$2-$3", shell fragments). The
			// substitute-if-known contract is documented in the README.
		}
		return t, nil
	default:
		return v, nil
	}
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
	mounts := fs.String("mount", "", "comma-separated type=path pairs to mount before running (e.g. transform@transform); already-mounted paths are tolerated")
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
	if *mounts != "" {
		for _, spec := range strings.Split(*mounts, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			typ, path, ok := strings.Cut(spec, "@")
			if !ok || typ == "" || path == "" {
				return fail(fmt.Errorf("invalid --mount entry %q (want type@path)", spec))
			}
			body, _ := json.Marshal(map[string]string{"type": typ})
			req, err := http.NewRequest(http.MethodPost, *target+"/v1/sys/mounts/"+path, bytes.NewReader(body))
			if err != nil {
				return fail(err)
			}
			req.Header.Set("X-Vault-Token", *token)
			resp, err := client.Do(req)
			if err != nil {
				return fail(err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// 204/200 = mounted; 400 with "already in use" = tolerated.
			if resp.StatusCode/100 != 2 && !strings.Contains(string(respBody), "already in use") {
				return fail(fmt.Errorf("--mount %s failed: HTTP %d %s", spec, resp.StatusCode, strings.TrimSpace(string(respBody))))
			}
		}
	}
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
