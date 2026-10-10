// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestTransformCRUD(t *testing.T) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	b, err := TransformBackendFactory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	call := func(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
		t.Helper()
		r, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, Storage: storage})
		if err != nil || (r != nil && r.IsError()) {
			t.Fatalf("%s %s: %#v %v", op, path, r, err)
		}
		return r
	}
	for name, alphabet := range transformBuiltinAlphabets {
		r := call(logical.ReadOperation, "alphabet/"+name, nil)
		if r.Data["alphabet"] != alphabet {
			t.Fatal(r)
		}
	}
	if r := call(logical.ListOperation, "alphabet", nil); len(r.Data["keys"].([]string)) != 6 {
		t.Fatal(r)
	}
	fixtures := map[string]map[string]interface{}{
		"alphabet/custom": {"alphabet": "abc"},
		"template/custom": {"type": "regex", "pattern": "([0-9]+)", "alphabet": "builtin/numeric", "decode_formats": map[string]interface{}{"all": "$1"}},
		"role/custom":     {"transformations": []string{"not-created-yet"}},
	}
	for path, data := range fixtures {
		call(logical.UpdateOperation, path, data)
		entry, err := storage.Get(ctx, path)
		if err != nil || entry == nil {
			t.Fatalf("storage %s: %v", path, err)
		}
		if call(logical.ReadOperation, path, nil) == nil {
			t.Fatal("missing resource", path)
		}
	}
	call(logical.UpdateOperation, "template/custom", map[string]interface{}{"encode_format": "$1"})
	if r := call(logical.ReadOperation, "template/custom", nil); r.Data["type"] != "regex" || r.Data["encode_format"] != "$1" {
		t.Fatal(r)
	}
	call(logical.UpdateOperation, "alphabet/custom", map[string]interface{}{"alphabet": "xyz"})
	if r := call(logical.ReadOperation, "alphabet/custom", nil); r.Data["alphabet"] != "xyz" {
		t.Fatal(r)
	}
	call(logical.UpdateOperation, "role/custom", map[string]interface{}{"transformations": []string{"other"}})
	if r := call(logical.ReadOperation, "role/custom", nil); !reflect.DeepEqual(r.Data["transformations"], []interface{}{"other"}) {
		t.Fatal(r)
	}
	call(logical.UpdateOperation, "role/empty", nil)
	if r := call(logical.ReadOperation, "role/empty", nil); !reflect.DeepEqual(r.Data["transformations"], []interface{}{}) {
		t.Fatal(r)
	}
	if r := call(logical.ListOperation, "role", map[string]interface{}{"filter": "custom"}); !reflect.DeepEqual(r.Data["keys"], []string{"custom"}) {
		t.Fatal(r)
	}
	// A new backend reads the same mount storage, without process-local state.
	b, err = TransformBackendFactory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	for path := range fixtures {
		if call(logical.ReadOperation, path, nil) == nil {
			t.Fatal("not persisted")
		}
		call(logical.DeleteOperation, path, nil)
		if call(logical.ReadOperation, path, nil) != nil {
			t.Fatal("not deleted")
		}
		if entry, err := storage.Get(ctx, path); err != nil || entry != nil {
			t.Fatal("storage not deleted", err)
		}
		call(logical.DeleteOperation, path, nil)
	}
}

func TestTransformValidation(t *testing.T) {
	b, err := TransformBackendFactory(t.Context(), &logical.BackendConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		data map[string]interface{}
	}{
		{"alphabet/bad", nil},
		{"alphabet/bad", map[string]interface{}{"alphabet": "aba"}},
		{"alphabet/builtin/numeric", map[string]interface{}{"alphabet": "ab"}},
		{"template/bad", map[string]interface{}{"pattern": "(a)"}},
		{"template/bad", map[string]interface{}{"type": "regex"}},
		{"template/bad", map[string]interface{}{"type": "other", "pattern": "(a)"}},
		{"template/bad", map[string]interface{}{"type": "regex", "pattern": "("}},
		{"template/bad", map[string]interface{}{"type": "regex", "pattern": "(a)", "alphabet": "missing"}},
		{"template/bad", map[string]interface{}{"type": "regex", "pattern": "(a)", "decode_formats": map[string]interface{}{"bad": true}}},
		{"role/bad", map[string]interface{}{"transformations": map[string]interface{}{"bad": true}}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			s := &logical.InmemStorage{}
			r, err := b.HandleRequest(t.Context(), &logical.Request{Operation: logical.UpdateOperation, Path: tc.path, Data: tc.data, Storage: s})
			if err == nil && (r == nil || !r.IsError()) {
				t.Fatalf("accepted invalid input: %#v", tc)
			}
			if entry, err := s.Get(t.Context(), tc.path); err != nil || entry != nil {
				t.Fatal("invalid input persisted", err)
			}
		})
	}
	r, err := b.HandleRequest(t.Context(), &logical.Request{Operation: logical.DeleteOperation, Path: "alphabet/builtin/numeric", Storage: &logical.InmemStorage{}})
	if err == nil && (r == nil || !r.IsError()) {
		t.Fatal("deleted builtin")
	}
}
