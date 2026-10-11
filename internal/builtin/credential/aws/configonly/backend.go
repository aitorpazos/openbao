// SPDX-License-Identifier: MPL-2.0

// Package configonly provides local storage for the public cloud configuration
// APIs. It intentionally has no cloud clients, credential discovery, or scheduler.
package configonly

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const Limitation = "Configuration only: cloud connection verification, authentication, identity token exchange, credential issuance, resource provisioning and rotation are not implemented; no cloud operation was performed."

type Backend struct {
	*framework.Backend
	mu       sync.Mutex
	provider string
	secret   bool
}

func New(provider string, secret bool) *Backend {
	b := &Backend{provider: provider, secret: secret}
	b.Backend = &framework.Backend{BackendType: logical.TypeCredential, Help: Limitation, PathsSpecial: &logical.Paths{SealWrapStorage: []string{"config", "config/"}}}
	if secret {
		b.BackendType = logical.TypeLogical
	}
	b.routes()
	return b
}
func fields(t framework.FieldType, names string) map[string]*framework.FieldSchema {
	f := map[string]*framework.FieldSchema{}
	add(f, t, names)
	return f
}
func add(f map[string]*framework.FieldSchema, t framework.FieldType, names string) {
	for _, n := range strings.Fields(names) {
		f[n] = &framework.FieldSchema{Type: t, Description: "Local configuration value; no cloud operation is performed."}
	}
}
func (b *Backend) singleton(path string, f map[string]*framework.FieldSchema) {
	b.Paths = append(b.Paths, &framework.Path{Pattern: path, Fields: f, HelpSynopsis: Limitation, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.record(path, false), logical.UpdateOperation: b.record(path, false), logical.DeleteOperation: b.record(path, false)}})
}
func (b *Backend) collection(path, list string, f map[string]*framework.FieldSchema) {
	add(f, framework.TypeString, "name")
	b.Paths = append(b.Paths, &framework.Path{Pattern: list + "/?", HelpSynopsis: Limitation, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: func(ctx context.Context, r *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		keys, err := r.Storage.List(ctx, path+"/")
		return logical.ListResponse(keys), err
	}}})
	b.Paths = append(b.Paths, &framework.Path{Pattern: path + "/" + framework.GenericNameRegex("name"), Fields: f, HelpSynopsis: Limitation, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.record(path, true), logical.UpdateOperation: b.record(path, true), logical.DeleteOperation: b.record(path, true)}})
}
func (b *Backend) reject(path string) {
	b.Paths = append(b.Paths, &framework.Path{Pattern: path, HelpSynopsis: Limitation, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: reject, logical.UpdateOperation: reject}})
}
func reject(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
	r := logical.ErrorResponse(Limitation)
	r.Warnings = []string{Limitation}
	return r, nil
}
func (b *Backend) record(path string, named bool) framework.OperationFunc {
	return func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		key := path
		if named {
			name := d.Get("name").(string)
			if b.provider == "aws" && !b.secret && path == "role" {
				name = strings.ToLower(name)
			}
			key += "/" + name
		}
		if r.Operation == logical.DeleteOperation {
			return &logical.Response{Warnings: []string{Limitation}}, r.Storage.Delete(ctx, key)
		}
		entry, err := r.Storage.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		var old map[string]interface{}
		if entry != nil {
			if err = entry.DecodeJSON(&old); err != nil {
				return nil, err
			}
		}
		if r.Operation == logical.ReadOperation {
			if old == nil {
				return nil, nil
			}
			if path == "config" || path == "config/client" || path == "config/root" {
				for _, k := range []string{"access_key", "secret_key", "token", "session_token", "client_secret", "credentials", "subscription_id", "resource_group_name", "verify_connection"} {
					delete(old, k)
				}
			}
			return &logical.Response{Data: old, Warnings: []string{Limitation}}, nil
		}
		m := map[string]interface{}{}
		for k := range d.Schema {
			if k == "name" {
				continue
			}
			if v, ok := old[k]; ok {
				m[k] = v
			} else {
				m[k] = d.Get(k)
			}
			if _, ok := d.Raw[k]; ok {
				m[k] = d.Get(k)
			}
		}
		fd := &framework.FieldData{Raw: m, Schema: d.Schema}
		// Normalize persisted JSON numbers and slices through the same input schema.
		for k := range m {
			v, _, e := fd.GetOkErr(k)
			if e != nil {
				return logical.ErrorResponse("invalid %s: %s", k, e), nil
			}
			m[k] = v
		}
		if m["verify_connection"] == true {
			return reject(ctx, r, d)
		}
		if err := b.validate(path, m, old, r, fd); err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		entry, err = logical.StorageEntryJSON(key, m)
		if err != nil {
			return nil, err
		}
		if err = r.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
		return &logical.Response{Warnings: []string{Limitation}}, nil
	}
}
func str(m map[string]interface{}, k string) string { s, _ := m[k].(string); return s }
func number(m map[string]interface{}, k string) int { v, _ := m[k].(int); return v }
func count(m map[string]interface{}, k string) int {
	switch v := m[k].(type) {
	case []string:
		return len(v)
	case []interface{}:
		return len(v)
	}
	return 0
}
func required(m map[string]interface{}, keys ...string) error {
	for _, k := range keys {
		if str(m, k) == "" {
			return fmt.Errorf("%s is required", k)
		}
	}
	return nil
}
