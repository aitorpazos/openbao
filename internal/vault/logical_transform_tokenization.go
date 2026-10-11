// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// SQL stores are configuration-only: no connections or schema changes are made.
// Only builtin/internal is usable by tokenization operations in this implementation.
func (b *transformBackend) tokenizationPaths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}}
	for _, k := range []string{"type", "driver", "connection_string", "username", "password", "schema"} {
		fields[k] = &framework.FieldSchema{Type: framework.TypeString}
	}
	fields["supported_transformations"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
	for _, k := range []string{"max_open_connections", "max_idle_connections"} {
		fields[k] = &framework.FieldSchema{Type: framework.TypeInt}
	}
	fields["max_connection_lifetime"] = &framework.FieldSchema{Type: framework.TypeDurationSecond}
	out := []*framework.Path{
		{Pattern: "stores/?", Fields: map[string]*framework.FieldSchema{"filter": {Type: framework.TypeString}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.list("stores")}},
		{Pattern: "stores/" + framework.GenericNameRegex("name"), Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.tokenizationStore, logical.UpdateOperation: b.tokenizationStore, logical.DeleteOperation: b.tokenizationStore}},
		{Pattern: "transformations/tokenization/" + framework.GenericNameRegex("name"), Fields: transformTokenFields(), Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.tokenizationResource}},
	}
	return out
}
func transformTokenFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {Type: framework.TypeString}, "type": {Type: framework.TypeString},
		"mapping_mode": {Type: framework.TypeString}, "convergent": {Type: framework.TypeBool},
		"max_ttl": {Type: framework.TypeDurationSecond}, "stores": {Type: framework.TypeCommaStringSlice},
		"allowed_roles": {Type: framework.TypeCommaStringSlice}, "deletion_allowed": {Type: framework.TypeBool},
	}
}
func (b *transformBackend) tokenizationStore(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := "stores/" + d.Get("name").(string)
	if req.Operation == logical.DeleteOperation {
		return nil, req.Storage.Delete(ctx, key)
	}
	data := map[string]interface{}{"schema": "public", "supported_transformations": []string{"tokenization"}, "max_open_connections": 4, "max_idle_connections": 4, "max_connection_lifetime": 0}
	exists, err := transformLoad(ctx, req.Storage, key, &data)
	if err != nil {
		return nil, err
	}
	if req.Operation == logical.ReadOperation {
		if !exists {
			return nil, nil
		}
		delete(data, "password")
		return &logical.Response{Data: data}, nil
	}
	for field := range d.Schema {
		if field != "name" {
			if _, ok := d.Raw[field]; ok {
				data[field] = d.Get(field)
			}
		}
	}
	for _, field := range []string{"type", "driver", "connection_string", "username", "password"} {
		v, _ := data[field].(string)
		if strings.TrimSpace(v) == "" {
			return logical.ErrorResponse("%s is required", field), nil
		}
	}
	if data["type"] != "sql" {
		return logical.ErrorResponse("type must be sql"), nil
	}
	driver := data["driver"].(string)
	if driver != "postgres" && driver != "mysql" && driver != "mssql" {
		return logical.ErrorResponse("unsupported SQL driver"), nil
	}
	connection := data["connection_string"].(string)
	if driver == "mysql" && !strings.Contains(connection, "parseTime=true") {
		return logical.ErrorResponse("mysql connection_string requires parseTime=true"), nil
	}
	if strings.HasPrefix(connection, "postgres") && driver != "postgres" || strings.HasPrefix(connection, "sqlserver://") && driver != "mssql" {
		return logical.ErrorResponse("connection_string does not match driver"), nil
	}
	for _, field := range []string{"max_open_connections", "max_idle_connections", "max_connection_lifetime"} {
		switch v := data[field].(type) {
		case int:
			if v < 0 {
				return logical.ErrorResponse("%s must not be negative", field), nil
			}
		case float64:
			if v < 0 {
				return logical.ErrorResponse("%s must not be negative", field), nil
			}
		}
	}
	if raw, ok := d.Raw["supported_transformations"]; ok && raw != nil {
		for _, v := range d.Get("supported_transformations").([]string) {
			if v != "tokenization" {
				return logical.ErrorResponse("only tokenization is supported"), nil
			}
		}
	}
	if err := transformSave(ctx, req.Storage, key, data); err != nil {
		return nil, err
	}
	return &logical.Response{Warnings: []string{"SQL store configuration saved; external SQL token storage is not implemented."}}, nil
}

type transformTokenConfig struct {
	Type            string   `json:"type"`
	MappingMode     string   `json:"mapping_mode"`
	Convergent      bool     `json:"convergent"`
	MaxTTL          int      `json:"max_ttl"`
	Stores          []string `json:"stores"`
	AllowedRoles    []string `json:"allowed_roles"`
	DeletionAllowed bool     `json:"deletion_allowed"`
	ID              string   `json:"id"`
}

func transformRandomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// Generic transformation routes dispatch by persisted type; FPE deletion already
// enforces deletion_allowed and role references for both transformation types.
func (b *transformBackend) transformationResource(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if strings.HasPrefix(req.Path, "transformations/fpe/") {
		return b.fpeResource(ctx, req, d)
	}
	var c struct {
		Type string `json:"type"`
	}
	_, err := transformLoad(ctx, req.Storage, "transformation/"+d.Get("name").(string), &c)
	if err != nil {
		return nil, err
	}
	requested, _ := d.Raw["type"].(string)
	if req.Operation != logical.DeleteOperation && (c.Type == "tokenization" || requested == "tokenization") {
		return b.tokenizationResource(ctx, req, d)
	}
	return b.fpeResource(ctx, req, d)
}
func (b *transformBackend) tokenizationResource(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := "transformation/" + d.Get("name").(string)
	c := transformTokenConfig{Type: "tokenization", MappingMode: "default", Stores: []string{"builtin/internal"}, AllowedRoles: []string{}}
	exists, err := transformLoad(ctx, req.Storage, key, &c)
	if err != nil {
		return nil, err
	}
	if c.Type != "tokenization" {
		return logical.ErrorResponse("transformation type cannot be changed"), nil
	}
	if req.Operation == logical.ReadOperation {
		if !exists {
			return nil, nil
		}
		return &logical.Response{Data: map[string]interface{}{"type": c.Type, "mapping_mode": c.MappingMode, "convergent": c.Convergent, "max_ttl": c.MaxTTL, "stores": c.Stores, "allowed_roles": c.AllowedRoles, "deletion_allowed": c.DeletionAllowed}}, nil
	}
	if v, ok := d.Raw["type"]; ok && v != "tokenization" {
		return logical.ErrorResponse("type must be tokenization"), nil
	}
	if _, ok := d.Raw["mapping_mode"]; ok {
		c.MappingMode = d.Get("mapping_mode").(string)
	}
	if c.MappingMode != "default" {
		return logical.ErrorResponse("only default mapping_mode is implemented"), nil
	}
	if _, ok := d.Raw["convergent"]; ok {
		v := d.Get("convergent").(bool)
		if exists && v != c.Convergent {
			return logical.ErrorResponse("convergent cannot be changed"), nil
		}
		c.Convergent = v
	}
	if _, ok := d.Raw["max_ttl"]; ok {
		c.MaxTTL = d.Get("max_ttl").(int)
	}
	if c.MaxTTL < 0 {
		return logical.ErrorResponse("max_ttl must not be negative"), nil
	}
	if _, ok := d.Raw["stores"]; ok {
		c.Stores = d.Get("stores").([]string)
	}
	if len(c.Stores) == 0 {
		c.Stores = []string{"builtin/internal"}
	}
	for _, s := range c.Stores {
		if s != "builtin/internal" {
			return logical.ErrorResponse("external token stores are not implemented"), nil
		}
	}
	if _, ok := d.Raw["allowed_roles"]; ok {
		c.AllowedRoles = d.Get("allowed_roles").([]string)
	}
	if _, ok := d.Raw["deletion_allowed"]; ok {
		c.DeletionAllowed = d.Get("deletion_allowed").(bool)
	}
	if !exists {
		c.ID, err = transformRandomToken()
		if err != nil {
			return nil, err
		}
	}
	return nil, transformSave(ctx, req.Storage, key, c)
}

type transformTokenRecord struct {
	Value    string                 `json:"value"`
	Source   string                 `json:"source"`
	Expires  time.Time              `json:"expires"`
	Metadata map[string]string `json:"metadata"`
}

// Called with b.mu held after role/transformation authorization and value checks.
// Barrier-backed mount storage protects plaintext records at rest. Random tokens
// are scoped to an unguessable generation ID so delete/recreate cannot revive them.
func (b *transformBackend) tokenizationRun(ctx context.Context, req *logical.Request, name, value string, input map[string]interface{}) (map[string]interface{}, error) {
	var c transformTokenConfig
	if _, err := transformLoad(ctx, req.Storage, "transformation/"+name, &c); err != nil {
		return nil, err
	}
	prefix := "tokenization/" + c.ID + "/"
	source, _ := input["source_id"].(string)
	op := strings.SplitN(req.Path, "/", 2)[0]
	if op == "encode" {
		ttl := c.MaxTTL
		if raw, ok := input["ttl"]; ok {
			fd := &framework.FieldData{Raw: map[string]interface{}{"ttl": raw}, Schema: map[string]*framework.FieldSchema{"ttl": {Type: framework.TypeDurationSecond}}}
			if err := fd.Validate(); err != nil {
				return nil, err
			}
			ttl = fd.Get("ttl").(int)
		}
		if ttl < 0 { return nil, fmt.Errorf("ttl must not be negative") }
		if c.MaxTTL > 0 && (ttl == 0 || ttl > c.MaxTTL) { ttl = c.MaxTTL }
		var expires time.Time
		if ttl > 0 { expires = time.Now().Add(time.Duration(ttl)*time.Second) }
		if raw, ok := input["expiration"]; ok && raw != "" {
			if _, ok := input["ttl"]; ok { return nil, fmt.Errorf("ttl and expiration are mutually exclusive") }
			text, ok := raw.(string); if !ok { return nil, fmt.Errorf("expiration must be a string") }
			parsed, err := time.Parse(time.RFC3339, text); if err != nil { return nil, fmt.Errorf("invalid expiration") }
			if !parsed.After(time.Now()) { return nil, fmt.Errorf("expiration must be in the future") }
			if expires.IsZero() || parsed.Before(expires) { expires = parsed }
		}
		metadata := map[string]string{}
		if raw, ok := input["metadata"]; ok && raw != "" {
			m, valid := raw.(map[string]interface{})
			if !valid {
				return nil, fmt.Errorf("metadata must be a map of strings")
			}
			for k, v := range m {
				s, valid := v.(string)
				if !valid {
					return nil, fmt.Errorf("metadata must be a map of strings")
				}
				metadata[k] = s
			}
		}
		if c.Convergent {
			keys, err := req.Storage.List(ctx, prefix)
			if err != nil {
				return nil, err
			}
			for _, token := range keys {
				var record transformTokenRecord
				if _, err := transformLoad(ctx, req.Storage, prefix+token, &record); err != nil {
					return nil, err
				}
				if record.Value == value && record.Source == source && (record.Expires.IsZero() || time.Now().Before(record.Expires)) {
					return map[string]interface{}{"encoded_value": token}, nil
				}
			}
		}
		token, err := transformRandomToken()
		if err != nil {
			return nil, err
		}
		record := transformTokenRecord{Value: value, Source: source, Metadata: metadata, Expires: expires}
		if err := transformSave(ctx, req.Storage, prefix+token, record); err != nil {
			return nil, err
		}
		return map[string]interface{}{"encoded_value": token}, nil
	}
	var record transformTokenRecord
	valid := len(value) == 64
	if _, err := hex.DecodeString(value); err != nil {
		valid = false
	}
	if valid {
		exists, err := transformLoad(ctx, req.Storage, prefix+value, &record)
		if err != nil {
			return nil, err
		}
		valid = exists && record.Source == source && (record.Expires.IsZero() || time.Now().Before(record.Expires))
	}
	if op == "validate" {
		return map[string]interface{}{"valid": valid}, nil
	}
	if !valid {
		return nil, fmt.Errorf("invalid or expired token")
	}
	if op == "metadata" {
		expiration := ""
		if !record.Expires.IsZero() { expiration = record.Expires.UTC().Format(time.RFC3339) }
		return map[string]interface{}{"metadata": record.Metadata, "expiration_time": expiration}, nil
	}
	return map[string]interface{}{"decoded_value": record.Value}, nil
}
