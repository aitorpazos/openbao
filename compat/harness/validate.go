// SPDX-License-Identifier: MPL-2.0
package main

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

func keys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
func checkSchema(s map[string]any) error {
	for k, v := range s {
		switch k {
		case "type":
			if v != "object" && v != "string" && v != "number" && v != "integer" && v != "boolean" && v != "array" && v != "null" {
				return fmt.Errorf("unsupported schema type %v", v)
			}
		case "properties":
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("properties must be an object")
			}
			for _, v := range m {
				sub, ok := v.(map[string]any)
				if !ok {
					return fmt.Errorf("property schema must be an object")
				}
				if err := checkSchema(sub); err != nil {
					return err
				}
			}
		case "items":
			sub, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("items must be a schema object")
			}
			if err := checkSchema(sub); err != nil {
				return err
			}
		case "required", "enum":
			a, ok := v.([]any)
			if !ok {
				return fmt.Errorf("%s must be an array", k)
			}
			if k == "required" {
				for _, x := range a {
					if _, ok := x.(string); !ok {
						return fmt.Errorf("required entries must be strings")
					}
				}
			}
		case "pattern":
			p, ok := v.(string)
			if !ok {
				return fmt.Errorf("pattern must be string")
			}
			if _, err := regexp.Compile(p); err != nil {
				return err
			}
		case "const", "additionalProperties":
		default:
			return fmt.Errorf("unsupported schema keyword %q", k)
		}
	}
	return nil
}
func validate(s map[string]any, v any, path string) error {
	if typ, ok := s["type"]; ok {
		match := false
		switch typ {
		case "object":
			_, match = v.(map[string]any)
		case "array":
			_, match = v.([]any)
		case "number", "integer":
			_, match = v.(float64)
		case "boolean":
			_, match = v.(bool)
		case "string":
			_, match = v.(string)
		case "null":
			match = v == nil
		}
		if !match {
			return fmt.Errorf("%s: expected %s", path, typ)
		}
	}
	if want, ok := s["const"]; ok && !reflect.DeepEqual(want, v) {
		return fmt.Errorf("%s: const mismatch (want %v, got %v)", path, want, v)
	}
	if enum, ok := s["enum"].([]any); ok {
		found := false
		for _, want := range enum {
			if reflect.DeepEqual(want, v) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s: value not in enum", path)
		}
	}
	if str, ok := v.(string); ok {
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			return fmt.Errorf("%s: pattern %q did not match", path, p)
		}
	}
	if obj, ok := v.(map[string]any); ok {
		if req, ok := s["required"].([]any); ok {
			for _, k := range req {
				if _, exists := obj[k.(string)]; !exists {
					return fmt.Errorf("%s: missing required property %s", path, k)
				}
			}
		}
		if props, ok := s["properties"].(map[string]any); ok {
			for _, k := range keys(props) {
				if value, exists := obj[k]; exists {
					if err := validate(props[k].(map[string]any), value, path+"."+k); err != nil {
						return err
					}
				}
			}
		}
	}
	if arr, ok := v.([]any); ok {
		if sub, ok := s["items"].(map[string]any); ok {
			for i, value := range arr {
				if err := validate(sub, value, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func matchExact(exact map[string]any, body any) error {
	for _, key := range keys(exact) {
		v := body
		for _, part := range strings.Split(key, ".") {
			obj, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("exact %s: not an object", key)
			}
			var exists bool
			v, exists = obj[part]
			if !exists {
				return fmt.Errorf("exact %s: missing", key)
			}
		}
		if !reflect.DeepEqual(v, exact[key]) {
			return fmt.Errorf("exact %s: mismatch", key)
		}
	}
	return nil
}
func matchErrors(patterns []string, body any) error {
	if len(patterns) == 0 {
		return nil
	}
	obj, ok := body.(map[string]any)
	if !ok {
		return fmt.Errorf("errors: expected object")
	}
	arr, ok := obj["errors"].([]any)
	if !ok {
		return fmt.Errorf("errors: expected array")
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		found := false
		for _, v := range arr {
			if str, ok := v.(string); ok && re.MatchString(str) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("errors: no entry matches %q", p)
		}
	}
	return nil
}
