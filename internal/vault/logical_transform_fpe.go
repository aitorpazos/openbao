// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type transformFPEConfig struct {
	Type            string   `json:"type"`
	Template        string   `json:"template"`
	TweakSource     string   `json:"tweak_source"`
	AllowedRoles    []string `json:"allowed_roles"`
	DeletionAllowed bool     `json:"deletion_allowed"`
	Key             []byte   `json:"key"`
	Tweak           []byte   `json:"tweak"`
}

func (b *transformBackend) fpePaths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "type": {Type: framework.TypeString}, "template": {Type: framework.TypeString}, "tweak_source": {Type: framework.TypeString}, "allowed_roles": {Type: framework.TypeCommaStringSlice}, "deletion_allowed": {Type: framework.TypeBool}}
	for k, v := range transformTokenFields() {
		fields[k] = v
	}
	out := []*framework.Path{{Pattern: "transformation/?", Fields: map[string]*framework.FieldSchema{"filter": {Type: framework.TypeString}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.list("transformation")}}}
	for _, prefix := range []string{"transformation/", "transformations/fpe/"} {
		out = append(out, &framework.Path{Pattern: prefix + framework.GenericNameRegex("name"), Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.transformationResource, logical.UpdateOperation: b.transformationResource, logical.DeleteOperation: b.transformationResource}})
	}
	for _, op := range []string{"encode", "decode", "validate", "metadata"} {
		out = append(out, &framework.Path{Pattern: op + "/" + framework.GenericNameRegex("role"), Fields: map[string]*framework.FieldSchema{"role": {Type: framework.TypeString}, "value": {Type: framework.TypeString}, "transformation": {Type: framework.TypeString}, "tweak": {Type: framework.TypeString}, "batch_input": {Type: framework.TypeSlice}, "reference": {Type: framework.TypeString}, "ttl": {Type: framework.TypeDurationSecond}, "expiration": {Type: framework.TypeString}, "source_id": {Type: framework.TypeString}, "metadata": {Type: framework.TypeKVPairs}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.fpeOperation}})
	}
	return out
}
func transformLoad(ctx context.Context, s logical.Storage, key string, out interface{}) (bool, error) {
	e, err := s.Get(ctx, key)
	if err != nil || e == nil {
		return false, err
	}
	return true, e.DecodeJSON(out)
}
func transformSave(ctx context.Context, s logical.Storage, key string, value interface{}) error {
	e, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return err
	}
	return s.Put(ctx, e)
}
func transformTemplate(ctx context.Context, s logical.Storage, name string) (map[string]interface{}, error) {
	if name == "builtin/creditcardnumber" {
		return map[string]interface{}{"pattern": `(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})`, "alphabet": "builtin/numeric"}, nil
	}
	if name == "builtin/socialsecuritynumber" {
		return map[string]interface{}{"pattern": `(\d{3})-?(\d{2})-?(\d{4})`, "alphabet": "builtin/numeric"}, nil
	}
	var t map[string]interface{}
	ok, err := transformLoad(ctx, s, "template/"+name, &t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("template does not exist")
	}
	return t, nil
}
func (b *transformBackend) fpeResource(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := "transformation/" + d.Get("name").(string)
	c := transformFPEConfig{Type: "fpe", TweakSource: "supplied", AllowedRoles: []string{}}
	exists, err := transformLoad(ctx, req.Storage, key, &c)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case logical.ReadOperation:
		if !exists {
			return nil, nil
		}
		return &logical.Response{Data: map[string]interface{}{"type": c.Type, "template": c.Template, "tweak_source": c.TweakSource, "allowed_roles": c.AllowedRoles, "deletion_allowed": c.DeletionAllowed}}, nil
	case logical.DeleteOperation:
		if !exists {
			return nil, nil
		}
		if !c.DeletionAllowed {
			return logical.ErrorResponse("deletion is not allowed"), nil
		}
		roles, err := req.Storage.List(ctx, "role/")
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			var r struct {
				Transformations []string `json:"transformations"`
			}
			if _, err := transformLoad(ctx, req.Storage, "role/"+role, &r); err != nil {
				return nil, err
			}
			for _, n := range r.Transformations {
				if n == d.Get("name").(string) {
					return logical.ErrorResponse("transformation is still in use by a role"), nil
				}
			}
		}
		if c.Type == "tokenization" {
			var tokenConfig transformTokenConfig
			if _, err := transformLoad(ctx, req.Storage, key, &tokenConfig); err != nil {
				return nil, err
			}
			prefix := "tokenization/" + tokenConfig.ID + "/"
			keys, err := req.Storage.List(ctx, prefix)
			if err != nil {
				return nil, err
			}
			for _, token := range keys {
				if err := req.Storage.Delete(ctx, prefix+token); err != nil {
					return nil, err
				}
			}
		}
		return nil, req.Storage.Delete(ctx, key)
	}
	if v, ok := d.GetOk("type"); ok && v.(string) != "fpe" {
		return logical.ErrorResponse("only fpe transformations are supported"), nil
	}
	if c.Type != "fpe" {
		return logical.ErrorResponse("transformation type cannot be changed"), nil
	}
	if _, ok := d.Raw["template"]; ok {
		c.Template = d.Get("template").(string)
	}
	if _, ok := d.Raw["tweak_source"]; ok {
		c.TweakSource = d.Get("tweak_source").(string)
	}
	if _, ok := d.Raw["allowed_roles"]; ok {
		c.AllowedRoles = d.Get("allowed_roles").([]string)
	}
	if _, ok := d.Raw["deletion_allowed"]; ok {
		c.DeletionAllowed = d.Get("deletion_allowed").(bool)
	}
	if c.Template == "" {
		return logical.ErrorResponse("template is required"), nil
	}
	if _, err := transformTemplate(ctx, req.Storage, c.Template); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if c.TweakSource != "internal" && c.TweakSource != "supplied" && c.TweakSource != "generated" {
		return logical.ErrorResponse("invalid tweak_source"), nil
	}
	if !exists {
		c.Key = make([]byte, 32)
		c.Tweak = make([]byte, 16)
		if _, err := rand.Read(c.Key); err != nil {
			return nil, err
		}
		if _, err := rand.Read(c.Tweak); err != nil {
			return nil, err
		}
	}
	return nil, transformSave(ctx, req.Storage, key, c)
}
func (b *transformBackend) fpeOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	role := d.Get("role").(string)
	var r struct {
		Transformations []string `json:"transformations"`
	}
	ok, err := transformLoad(ctx, req.Storage, "role/"+role, &r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return logical.ErrorResponse("role does not exist"), nil
	}
	decrypt := strings.HasPrefix(req.Path, "decode/")
	run := func(input map[string]interface{}) (map[string]interface{}, error) {
		name, _ := input["transformation"].(string)
		if name == "" {
			name = d.Get("transformation").(string)
		}
		if name == "" && len(r.Transformations) == 1 {
			name = r.Transformations[0]
		}
		authorized := false
		for _, n := range r.Transformations {
			if n == name {
				authorized = true
			}
		}
		if !authorized {
			return nil, fmt.Errorf("select a transformation assigned to the role")
		}
		var c transformFPEConfig
		exists, err := transformLoad(ctx, req.Storage, "transformation/"+name, &c)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("transformation does not exist")
		}
		authorized = false
		for _, pattern := range c.AllowedRoles {
			if match, _ := path.Match(pattern, role); match {
				authorized = true
			}
		}
		if !authorized {
			return nil, fmt.Errorf("transformation does not allow this role")
		}
		value, ok := input["value"].(string)
		if !ok || value == "" {
			return nil, fmt.Errorf("value is required")
		}
		if len(value) > 65536 {
			return nil, fmt.Errorf("value too long")
		}
		if c.Type == "tokenization" {
			result, err := b.tokenizationRun(ctx, req, name, value, input)
			if err == nil {
				if ref, ok := input["reference"]; ok {
					result["reference"] = ref
				}
			}
			return result, err
		}
		if strings.HasPrefix(req.Path, "validate/") || strings.HasPrefix(req.Path, "metadata/") {
			return nil, fmt.Errorf("operation requires tokenization")
		}
		tweak := c.Tweak
		result := map[string]interface{}{}
		if c.TweakSource != "internal" {
			text, _ := input["tweak"].(string)
			if c.TweakSource == "generated" && !decrypt {
				tweak = make([]byte, 16)
				if _, err := rand.Read(tweak); err != nil {
					return nil, err
				}
				result["tweak"] = base64.StdEncoding.EncodeToString(tweak)
			} else {
				if text == "" {
					return nil, fmt.Errorf("base64 tweak is required")
				}
				tweak, err = base64.StdEncoding.DecodeString(text)
				if err != nil {
					return nil, fmt.Errorf("invalid base64 tweak")
				}
			}
		}
		t, err := transformTemplate(ctx, req.Storage, c.Template)
		if err != nil {
			return nil, err
		}
		// Formatting templates require a separate reversible format parser. Reject
		// rather than silently producing a value that cannot be decoded.
		if f, _ := t["encode_format"].(string); f != "" {
			return nil, fmt.Errorf("encode_format is not supported")
		}
		alphabetName, _ := t["alphabet"].(string)
		alphabet := transformBuiltinAlphabets[alphabetName]
		if alphabet == "" {
			var a struct {
				Alphabet string `json:"alphabet"`
			}
			if _, err := transformLoad(ctx, req.Storage, "alphabet/"+alphabetName, &a); err != nil {
				return nil, err
			}
			alphabet = a.Alphabet
		}
		chars := []rune(alphabet)
		if len(chars) < 2 {
			return nil, fmt.Errorf("template requires an alphabet")
		}
		lookup := map[rune]int{}
		for i, ch := range chars {
			lookup[ch] = i
		}
		pattern, _ := t["pattern"].(string)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		matches := re.FindAllStringSubmatchIndex(value, -1)
		if len(matches) == 0 {
			return nil, fmt.Errorf("value does not match template")
		}
		var out strings.Builder
		last := 0
		for _, match := range matches {
			spans := match[2:]
			if len(spans) == 0 {
				spans = match[:2]
			}
			digits := []int{}
			end := -1
			for i := 0; i < len(spans); i += 2 {
				start, stop := spans[i], spans[i+1]
				if start < 0 {
					continue
				}
				if start < end {
					return nil, fmt.Errorf("overlapping capture groups are not supported")
				}
				end = stop
				for _, ch := range value[start:stop] {
					digit, ok := lookup[ch]
					if !ok {
						return nil, fmt.Errorf("value contains characters outside alphabet")
					}
					digits = append(digits, digit)
				}
			}
			encrypted, err := transformFF1(c.Key, tweak, len(chars), digits, decrypt)
			if err != nil {
				return nil, err
			}
			j := 0
			for i := 0; i < len(spans); i += 2 {
				start, stop := spans[i], spans[i+1]
				if start < 0 {
					continue
				}
				out.WriteString(value[last:start])
				for range []rune(value[start:stop]) {
					out.WriteRune(chars[encrypted[j]])
					j++
				}
				last = stop
			}
		}
		out.WriteString(value[last:])
		field := "encoded_value"
		if decrypt {
			field = "decoded_value"
		}
		result[field] = out.String()
		if ref, ok := input["reference"]; ok {
			result["reference"] = ref
		}
		return result, nil
	}
	if raw, ok := d.Raw["batch_input"]; ok {
		items, ok := raw.([]interface{})
		if !ok || len(items) == 0 {
			return logical.ErrorResponse("batch_input must be a nonempty array"), nil
		}
		results := make([]interface{}, 0, len(items))
		for _, item := range items {
			input, ok := item.(map[string]interface{})
			if !ok {
				return logical.ErrorResponse("invalid batch item"), nil
			}
			result, err := run(input)
			if err != nil {
				result = map[string]interface{}{"error": err.Error()}
				if ref, ok := input["reference"]; ok {
					result["reference"] = ref
				}
			}
			results = append(results, result)
		}
		return &logical.Response{Data: map[string]interface{}{"batch_results": results}}, nil
	}
	result, err := run(d.Raw)
	if err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	return &logical.Response{Data: result}, nil
}
