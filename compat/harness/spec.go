// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Spec struct {
	API           string `yaml:"api"`
	Feature       string `yaml:"feature"`
	Source        string `yaml:"source"`
	SourceVersion string `yaml:"source_version"`
	Notes         string `yaml:"notes"`
	Cases         []Case `yaml:"cases"`
	File          string `yaml:"-"`
}
type Case struct {
	ID      string   `yaml:"id"`
	Depends []string `yaml:"depends"`
	// CaptureToken stores auth.client_token from a successful response so
	// later cases can act as the created identity (e.g. token-based
	// enforcement checks).
	CaptureToken bool `yaml:"capture_token"`
	// UseCapturedToken sends the previously captured token instead of the
	// run token for this case.
	UseCapturedToken bool `yaml:"use_captured_token"`
	// NoAuth sends the request without any X-Vault-Token header (for
	// verifying documented unauthenticated endpoints).
	NoAuth           bool `yaml:"no_auth"`
	Request          Request   `yaml:"request"`
	Expect           Expect    `yaml:"expect"`
}
type Request struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Body    yaml.Node         `yaml:"body"`
	Headers map[string]string `yaml:"headers"`
}
type Expect struct {
	Status Statuses       `yaml:"status"`
	Schema map[string]any `yaml:"body_schema"`
	Exact  map[string]any `yaml:"exact"`
	// Contains asserts list membership at dotted keys without requiring the
	// whole list to match.
	Contains map[string]any `yaml:"contains"`
	Errors   []string       `yaml:"errors_contain"`
	Body     yaml.Node      `yaml:"body"`
}
type Statuses []int

func (s *Statuses) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var v int
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = []int{v}
		return nil
	}
	var v []int
	if err := n.Decode(&v); err != nil {
		return err
	}
	*s = v
	return nil
}

// Normalize YAML numeric values to the same representation used by JSON responses.
func normalize(v any) (any, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var out any
	e = json.Unmarshal(b, &out)
	return out, e
}
func loadSpecs(dir, filter string) ([]Spec, error) {
	if filter != "" && !strings.HasPrefix(filter, "feature=") {
		return nil, fmt.Errorf("filter must be feature=NAME")
	}
	specs := []Spec{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		var s Spec
		if err = dec.Decode(&s); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var extra any
		if err = dec.Decode(&extra); err != io.EOF {
			return fmt.Errorf("%s: expected one YAML document", path)
		}
		s.File = path
		if err = checkSpec(&s); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if filter == "" || s.Feature == strings.TrimPrefix(filter, "feature=") {
			specs = append(specs, s)
		}
		return nil
	})
	return specs, err
}
func checkSpec(s *Spec) error {
	if s.API == "" || s.Source == "" || len(s.Cases) == 0 {
		return fmt.Errorf("api, source, and cases are required")
	}
	seen := map[string]bool{}
	for _, c := range s.Cases {
		if c.ID == "" || seen[c.ID] {
			return fmt.Errorf("empty or duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
	}
	for i := range s.Cases {
		c := &s.Cases[i]
		for _, dep := range c.Depends {
			if !seen[dep] {
				return fmt.Errorf("case %s: dependency %q must name a case in this file", c.ID, dep)
			}
		}
		if c.Request.Method == "" || !strings.HasPrefix(c.Request.Path, "/v1/") {
			return fmt.Errorf("case %s: method and /v1/ path required", c.ID)
		}
		if len(c.Expect.Status) == 0 {
			return fmt.Errorf("case %s: status required", c.ID)
		}
		for _, status := range c.Expect.Status {
			if status < 100 || status > 599 {
				return fmt.Errorf("invalid status %d", status)
			}
		}
		if c.Expect.Body.Kind != 0 && c.Expect.Body.Tag != "!!null" {
			return fmt.Errorf("expect.body supports only null")
		}
		for _, p := range c.Expect.Errors {
			if _, err := regexp.Compile(p); err != nil {
				return err
			}
		}
		if c.Expect.Schema != nil {
			v, err := normalize(c.Expect.Schema)
			if err != nil {
				return err
			}
			c.Expect.Schema = v.(map[string]any)
			if err = checkSchema(c.Expect.Schema); err != nil {
				return err
			}
		}
		if c.Expect.Exact != nil {
			v, err := normalize(c.Expect.Exact)
			if err != nil {
				return err
			}
			c.Expect.Exact = v.(map[string]any)
		}
	}
	return nil
}
