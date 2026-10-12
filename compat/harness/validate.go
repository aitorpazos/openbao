// SPDX-License-Identifier: MPL-2.0
package main

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
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

// descendSegment steps one dotted-path segment. An all-digit segment
// indexes an array; any other segment indexes an object by key.
func descendSegment(cur any, seg string) (any, bool) {
	if n, err := strconv.Atoi(seg); err == nil {
		arr, ok := cur.([]any)
		if !ok {
			return nil, false
		}
		if n < 0 || n >= len(arr) {
			return nil, false
		}
		return arr[n], true
	}
	obj, ok := cur.(map[string]any)
	if !ok {
		return nil, false
	}
	v, exists := obj[seg]
	if !exists {
		return nil, false
	}
	return v, true
}

func matchExact(exact map[string]any, body any) error {
	for _, key := range keys(exact) {
		v := body
		for _, part := range strings.Split(key, ".") {
			next, ok := descendSegment(v, part)
			if !ok {
				if _, isArr := v.([]any); isArr {
					return fmt.Errorf("exact %s: missing index %s", key, part)
				}
				if _, isObj := v.(map[string]any); !isObj {
					return fmt.Errorf("exact %s: not an object", key)
				}
				return fmt.Errorf("exact %s: missing", key)
			}
			v = next
		}
		if !reflect.DeepEqual(v, exact[key]) {
			return fmt.Errorf("exact %s: mismatch", key)
		}
	}
	return nil
}

// matchContains asserts that, at each dotted key, the response value is an
// array containing every listed entry (list membership without ordering or
// equality on the whole list). A key ending with "[].field" first projects
// each array element's named field, so object entries can be asserted by
// one of their fields (e.g. data.months.0.usage_metrics[].metric_name).
func matchContains(contains map[string]any, body any) error {
	for _, key := range keys(contains) {
		resolveKey := key
		projection := ""
		if idx := strings.Index(key, "[]."); idx >= 0 {
			resolveKey = key[:idx]
			projection = key[idx+3:]
		}
		v := body
		for _, part := range strings.Split(resolveKey, ".") {
			next, ok := descendSegment(v, part)
			if !ok {
				if _, isArr := v.([]any); isArr {
					return fmt.Errorf("contains %s: missing index %s", key, part)
				}
				if _, isObj := v.(map[string]any); !isObj {
					return fmt.Errorf("contains %s: not an object", key)
				}
				return fmt.Errorf("contains %s: missing", key)
			}
			v = next
		}
		if projection != "" {
			arr, ok := v.([]any)
			if !ok {
				return fmt.Errorf("contains %s: [] projection requires an array", key)
			}
			projected := make([]any, len(arr))
			for i, elem := range arr {
				fieldVal, ok := descendSegment(elem, projection)
				if !ok {
					return fmt.Errorf("contains %s: element %d missing projection field %s", key, i, projection)
				}
				projected[i] = fieldVal
			}
			v = projected
		}
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("contains %s: expected array", key)
		}
		norm, err := normalize(contains[key])
		if err != nil {
			return err
		}
		want, ok := norm.([]any)
		if !ok {
			return fmt.Errorf("contains %s: expected array", key)
		}
		for _, w := range want {
			found := false
			for _, entry := range arr {
				if reflect.DeepEqual(entry, w) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("contains %s: missing entry %v", key, w)
			}
		}
	}
	return nil
}

// lookupPath resolves a dotted path against a decoded response body.
// Segments index objects by key; the second value indicates whether the
// final segment existed.
func lookupPath(body any, path string) (any, bool) {
	cur := body
	for _, seg := range strings.Split(path, ".") {
		next, ok := descendSegment(cur, seg)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// matchAbsent asserts that, at each dotted key, the response body does NOT
// contain a populated value for the final key segment. Namespace isolation
// specs use this to prove a namespaced object does not leak into a
// root-scoped response. If an ancestor key along the dotted path is missing
// (or not an object), the target key cannot exist and the check passes for
// that key. A key that is present but null counts as absent: the logical
// response envelope always serializes optional fields (e.g. wrap_info) as
// null rather than omitting them, and a null field carries no data.
func matchAbsent(keys []string, body any) error {
	for _, key := range keys {
		parts := strings.Split(key, ".")
		last := parts[len(parts)-1]
		parent := body
		walkable := true
		for i := 0; i < len(parts)-1; i++ {
			obj, ok := parent.(map[string]any)
			if !ok {
				walkable = false
				break
			}
			v, exists := obj[parts[i]]
			if !exists {
				walkable = false
				break
			}
			parent = v
		}
		if !walkable {
			continue
		}
		if obj, ok := parent.(map[string]any); ok {
			if v, exists := obj[last]; exists && v != nil {
				return fmt.Errorf("absent %s: key is present", key)
			}
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

// pathCapturedRefRegexp matches $name tokens inside paths.
var pathCapturedRefRegexp = regexp.MustCompile(`\$([A-Za-z][A-Za-z0-9_-]*)`)

// substituteCapturedPath replaces $name tokens in a request path with the
// named capture slot. Unknown names pass through literally.
func substituteCapturedPath(path string, capturedData map[string]string) (string, error) {
	if len(capturedData) == 0 || !strings.Contains(path, "$") {
		return path, nil
	}
	out := path
	for _, match := range pathCapturedRefRegexp.FindAllStringSubmatch(path, -1) {
		name := match[1]
		val, ok := capturedData[name]
		if !ok {
			// Unknown names pass through literally so paths that contain
			// $-prefixed literals are unaffected.
			continue
		}
		out = strings.Replace(out, "$"+name, val, 1)
	}
	return out, nil
}
