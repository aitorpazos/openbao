// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TransformBackendFactory provides the configuration resources for Transform.
// Cryptographic transformations and encode/decode routes are intentionally absent.
// Templates use the documented singular pattern field. deletion_allowed is a
// transformation setting, not a template or role setting; resource deletion here
// is unconditional (except for the reserved builtin namespace).
func TransformBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	if conf == nil {
		return nil, errors.New("configuration passed into backend is nil")
	}
	b := &transformBackend{}
	b.Backend = &framework.Backend{BackendType: logical.TypeLogical, Help: "Manage Transform alphabets, templates, and roles."}
	for _, kind := range []string{"alphabet", "template", "role"} {
		fields := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}}
		switch kind {
		case "alphabet":
			fields["alphabet"] = &framework.FieldSchema{Type: framework.TypeString}
		case "template":
			for _, key := range []string{"type", "pattern", "alphabet", "encode_format"} {
				fields[key] = &framework.FieldSchema{Type: framework.TypeString}
			}
			fields["decode_formats"] = &framework.FieldSchema{Type: framework.TypeMap}
		case "role":
			fields["transformations"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
		}
		b.Paths = append(b.Paths, &framework.Path{
			Pattern: kind + "/?", Fields: map[string]*framework.FieldSchema{"filter": {Type: framework.TypeString}},
			Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.list(kind)},
		}, &framework.Path{
			Pattern: kind + "/(?P<name>(?:builtin/)?[A-Za-z0-9_-]+)", Fields: fields,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.resource(kind), logical.UpdateOperation: b.resource(kind), logical.DeleteOperation: b.resource(kind),
			},
		})
	}
	return b, b.Setup(ctx, conf)
}

type transformBackend struct {
	*framework.Backend
	mu sync.RWMutex
}

// Builtins are immutable and are never written to mount storage.
var transformBuiltinAlphabets = map[string]string{
	"builtin/numeric":           "0123456789",
	"builtin/alphalower":        "abcdefghijklmnopqrstuvwxyz",
	"builtin/alphaupper":        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"builtin/alphanumericlower": "0123456789abcdefghijklmnopqrstuvwxyz",
	"builtin/alphanumericupper": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"builtin/alphanumeric":      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
}

func (b *transformBackend) list(kind string) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		b.mu.RLock()
		defer b.mu.RUnlock()
		keys, err := req.Storage.List(ctx, kind+"/")
		if err != nil {
			return nil, err
		}
		if kind == "alphabet" {
			for name := range transformBuiltinAlphabets {
				keys = append(keys, name)
			}
		}
		filtered := make([]string, 0, len(keys))
		for _, key := range keys {
			if strings.HasPrefix(key, d.Get("filter").(string)) {
				filtered = append(filtered, key)
			}
		}
		sort.Strings(filtered)
		return logical.ListResponse(filtered), nil
	}
}

func (b *transformBackend) resource(kind string) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		name := d.Get("name").(string)
		if strings.HasPrefix(name, "builtin/") {
			if req.Operation != logical.ReadOperation {
				return logical.ErrorResponse("builtin resources are read-only"), nil
			}
			if alphabet, ok := transformBuiltinAlphabets[name]; kind == "alphabet" && ok {
				return &logical.Response{Data: map[string]interface{}{"alphabet": alphabet}}, nil
			}
			return nil, nil
		}
		key := kind + "/" + name
		if req.Operation == logical.DeleteOperation {
			return nil, req.Storage.Delete(ctx, key)
		}
		entry, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		data := map[string]interface{}{}
		if entry != nil {
			if err := entry.DecodeJSON(&data); err != nil {
				return nil, err
			}
		}
		if req.Operation == logical.ReadOperation {
			if entry == nil {
				return nil, nil
			}
			return &logical.Response{Data: data}, nil
		}
		for field := range d.Schema {
			if field != "name" {
				if _, ok := d.Raw[field]; ok {
					data[field] = d.Get(field)
				}
			}
		}
		switch kind {
		case "alphabet":
			alphabet, _ := data["alphabet"].(string)
			seen := map[rune]bool{}
			for _, char := range alphabet {
				if seen[char] {
					return logical.ErrorResponse("alphabet characters must be unique"), nil
				}
				seen[char] = true
			}
			if len(seen) < 2 || len(seen) > 65536 {
				return logical.ErrorResponse("alphabet requires between 2 and 65536 distinct characters"), nil
			}
		case "template":
			if data["type"] != "regex" {
				return logical.ErrorResponse("type must be regex"), nil
			}
			pattern, _ := data["pattern"].(string)
			if pattern == "" {
				return logical.ErrorResponse("pattern is required"), nil
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return logical.ErrorResponse("invalid pattern: %s", err), nil
			}
			alphabet, _ := data["alphabet"].(string)
			if alphabet != "" {
				if _, builtin := transformBuiltinAlphabets[alphabet]; !builtin {
					if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(alphabet) {
						return logical.ErrorResponse("invalid alphabet name"), nil
					}
					a, err := req.Storage.Get(ctx, "alphabet/"+alphabet)
					if err != nil {
						return nil, err
					}
					if a == nil {
						return logical.ErrorResponse("alphabet does not exist"), nil
					}
				}
			}
			if data["alphabet"] == nil {
				data["alphabet"] = ""
			}
			if data["encode_format"] == nil {
				data["encode_format"] = ""
			}
			if data["decode_formats"] == nil {
				data["decode_formats"] = map[string]interface{}{}
			}
			formats, ok := data["decode_formats"].(map[string]interface{})
			if !ok {
				return logical.ErrorResponse("decode_formats must be a string map"), nil
			}
			for _, format := range formats {
				if _, ok := format.(string); !ok {
					return logical.ErrorResponse("decode_formats values must be strings"), nil
				}
			}
		case "role":
			// References may precede transformation creation, as documented by setup.
			if data["transformations"] == nil {
				data["transformations"] = []string{}
			}
		}
		entry, err = logical.StorageEntryJSON(key, data)
		if err != nil {
			return nil, err
		}
		return nil, req.Storage.Put(ctx, entry)
	}
}
