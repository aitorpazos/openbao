// SPDX-License-Identifier: MPL-2.0

// Package ldap implements local LDAP configuration only. It never connects to LDAP.
// Contracts: public Vault v2.x auth/ldap and secret/ldap API documentation.
package ldap

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const limitation = "Configuration only: LDAP connection verification, authentication, password rotation and migration are not implemented; no remote LDAP operation was performed."

type backend struct {
	*framework.Backend
	mu     sync.RWMutex
	secret bool
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	return b, b.Setup(ctx, conf)
}

// SecretsFactory exposes the separately documented LDAP secrets configuration
// surface. Static roles and migration are deliberately not auth routes.
func SecretsFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend(true)
	return b, b.Setup(ctx, conf)
}

func Backend() *backend { return newBackend(false) }
func newBackend(secret bool) *backend {
	b := &backend{secret: secret}
	b.Backend = &framework.Backend{BackendType: logical.TypeCredential, Help: limitation,
		PathsSpecial: &logical.Paths{SealWrapStorage: []string{"config", "static-role/"}}}
	fields := ldaputil.ConfigFields()
	add(fields, framework.TypeString, "rotation_url", "rotation_schedule", "schema", "password_policy")
	fields["schema"].Default = "openldap"
	add(fields, framework.TypeDurationSecond, "rotation_period", "rotation_window")
	add(fields, framework.TypeBool, "disable_automated_rotation", "verify_connection", "enable_samaccountname_login")
	fields["alias_metadata"] = &framework.FieldSchema{Type: framework.TypeKVPairs}
	tokenutil.AddTokenFields(fields)
	add(fields, framework.TypeCommaStringSlice, "policies")
	fields["token_type"].Default = "default"
	if secret {
		add(fields, framework.TypeBool, "self_managed", "skip_static_role_import_rotation")
		b.BackendType = logical.TypeLogical
	}
	b.Paths = append(b.Paths, &framework.Path{Pattern: "config", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.config, logical.UpdateOperation: b.config}})
	if !secret {
		b.PathsSpecial.Unauthenticated = []string{"login/*"}
		for _, kind := range []string{"users", "groups"} {
			f := map[string]*framework.FieldSchema{}
			add(f, framework.TypeCommaStringSlice, "policies")
			if kind == "users" {
				add(f, framework.TypeCommaStringSlice, "groups")
			}
			b.addCRUD(kind, f)
		}
		b.Paths = append(b.Paths, &framework.Path{Pattern: "login/" + framework.GenericNameRegex("username"), Fields: map[string]*framework.FieldSchema{"username": {Type: framework.TypeString}, "password": {Type: framework.TypeString}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: rejectRemote}})
	} else {
		f := map[string]*framework.FieldSchema{}
		add(f, framework.TypeString, "username", "dn", "password", "rotation_policy", "rotation_schedule")
		add(f, framework.TypeDurationSecond, "rotation_period", "rotation_window")
		add(f, framework.TypeBool, "skip_import_rotation", "disable_automated_rotation")
		b.addCRUD("static-role", f)
		b.Paths = append(b.Paths, &framework.Path{Pattern: "static-migration", Fields: map[string]*framework.FieldSchema{"include_role_names": {Type: framework.TypeBool}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.migration, logical.UpdateOperation: b.migration}}, &framework.Path{Pattern: "static-migration/stop", Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.migration}})
	}
	root := "config/rotate-root"
	if secret {
		root = "rotate-root"
	}
	b.Paths = append(b.Paths, &framework.Path{Pattern: root, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: rejectRemote}})
	if secret {
		b.Paths = append(b.Paths, &framework.Path{Pattern: "rotate-role/" + framework.GenericNameRegex("name"), Fields: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: rejectRemote}})
	}
	return b
}
func add(f map[string]*framework.FieldSchema, t framework.FieldType, names ...string) {
	for _, n := range names {
		f[n] = &framework.FieldSchema{Type: t}
	}
}
func rejectRemote(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse(limitation), nil
}
func load(ctx context.Context, s logical.Storage, key string) (map[string]interface{}, error) {
	e, err := s.Get(ctx, key)
	if err != nil || e == nil {
		return nil, err
	}
	var m map[string]interface{}
	err = e.DecodeJSON(&m)
	return m, err
}
func save(ctx context.Context, s logical.Storage, key string, m map[string]interface{}) error {
	e, err := logical.StorageEntryJSON(key, m)
	if err != nil {
		return err
	}
	return s.Put(ctx, e)
}
func merged(old map[string]interface{}, d *framework.FieldData) map[string]interface{} {
	m := map[string]interface{}{}
	for k := range d.Schema {
		if k == "name" {
			continue
		}
		if _, ok := d.Raw[k]; ok || old == nil {
			m[k] = d.Get(k)
		} else {
			m[k] = old[k]
		}
	}
	return m
}
func (b *backend) config(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	old, err := load(ctx, r.Storage, "config")
	if err != nil {
		return nil, err
	}
	if r.Operation == logical.ReadOperation {
		if old == nil {
			return nil, nil
		}
		delete(old, "bindpass")
		delete(old, "client_tls_key")
		delete(old, "verify_connection")
		return &logical.Response{Data: old}, nil
	}
	m := merged(old, d)
	if _, present := d.Raw["policies"]; present {
		if _, modern := d.Raw["token_policies"]; !modern {
			m["token_policies"] = m["policies"]
		}
	}
	m["policies"] = m["token_policies"]
	fd := &framework.FieldData{Raw: m, Schema: d.Schema}
	for _, key := range []string{"connection_timeout", "request_timeout", "max_page_size", "token_explicit_max_ttl"} {
		if fd.Get(key).(int) < 0 {
			return logical.ErrorResponse("%s cannot be negative", key), nil
		}
	}
	switch fd.Get("dereference_aliases").(string) {
	case "never", "finding", "searching", "always":
	default:
		return logical.ErrorResponse("invalid dereference_aliases"), nil
	}
	if _, err := ldaputil.NewConfigEntry(nil, fd); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	var tokens tokenutil.TokenParams
	if err := tokens.ParseTokenFields(r, fd); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	for _, key := range []string{"url", "rotation_url"} {
		for _, raw := range strings.Split(m[key].(string), ",") {
			if raw == "" {
				continue
			}
			u, e := url.Parse(strings.TrimSpace(raw))
			if e != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
				return logical.ErrorResponse("invalid %s", key), nil
			}
		}
	}
	if err := validateRotation(fd); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if m["schema"] != "openldap" && m["schema"] != "ad" && !(b.secret && m["schema"] == "racf") {
		return logical.ErrorResponse("invalid schema"), nil
	}
	if b.secret {
		if old != nil && old["self_managed"] != m["self_managed"] {
			return logical.ErrorResponse("self_managed cannot be changed"), nil
		}
		if m["self_managed"] == true && m["bindpass"] != "" {
			return logical.ErrorResponse("self_managed excludes bindpass"), nil
		}
	}
	if m["verify_connection"] == true {
		return rejectRemote(ctx, r, d)
	}
	if err := save(ctx, r.Storage, "config", m); err != nil {
		return nil, err
	}
	return &logical.Response{Warnings: []string{limitation}}, nil
}
func validateRotation(d *framework.FieldData) error {
	p := d.Get("rotation_period").(int)
	w := d.Get("rotation_window").(int)
	s := d.Get("rotation_schedule").(string)
	if p < 0 || (p > 0 && p < 10) {
		return fmt.Errorf("rotation_period must be zero or at least 10 seconds")
	}
	if p > 0 && s != "" {
		return fmt.Errorf("rotation_period and rotation_schedule are mutually exclusive")
	}
	if w < 0 || (w > 0 && w < 3600) || (w > 0 && (p > 0 || s == "")) {
		return fmt.Errorf("rotation_window requires a schedule and must be zero or at least 3600 seconds")
	}
	if s != "" {
		if err := validateSchedule(s); err != nil {
			return err
		}
	}
	return nil
}
func (b *backend) addCRUD(kind string, f map[string]*framework.FieldSchema) {
	add(f, framework.TypeString, "name")
	b.Paths = append(b.Paths, &framework.Path{Pattern: kind + "/?", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: func(ctx context.Context, r *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		keys, err := r.Storage.List(ctx, kind+"/")
		return logical.ListResponse(keys), err
	}}}, &framework.Path{Pattern: kind + "/" + framework.GenericNameRegex("name"), Fields: f, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.record(kind), logical.UpdateOperation: b.record(kind), logical.DeleteOperation: b.record(kind)}})
}
func (b *backend) record(kind string) framework.OperationFunc {
	return func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		cfg, err := load(ctx, r.Storage, "config")
		if err != nil {
			return nil, err
		}
		name := d.Get("name").(string)
		if kind != "static-role" && cfg["case_sensitive_names"] != true {
			name = strings.ToLower(name)
		}
		key := kind + "/" + name
		if r.Operation == logical.DeleteOperation {
			return nil, r.Storage.Delete(ctx, key)
		}
		old, err := load(ctx, r.Storage, key)
		if err != nil {
			return nil, err
		}
		if r.Operation == logical.ReadOperation {
			if old == nil {
				return nil, nil
			}
			delete(old, "password")
			return &logical.Response{Data: old}, nil
		}
		m := merged(old, d)
		if kind == "static-role" {
			if cfg == nil {
				return logical.ErrorResponse("LDAP is not configured"), nil
			}
			if m["username"] == "" {
				return logical.ErrorResponse("username is required"), nil
			}
			if old != nil && (m["username"] != old["username"] || m["dn"] != old["dn"]) {
				return logical.ErrorResponse("username and dn cannot be changed"), nil
			}
			if cfg["self_managed"] == true && (m["dn"] == "" || m["password"] == "") {
				return logical.ErrorResponse("self-managed roles require dn and password"), nil
			}
			fd := &framework.FieldData{Raw: m, Schema: d.Schema}
			if err := validateRotation(fd); err != nil {
				return logical.ErrorResponse("%s", err), nil
			}
			if fd.Get("rotation_period").(int) == 0 && fd.Get("rotation_schedule").(string) == "" {
				return logical.ErrorResponse("rotation_period or rotation_schedule is required"), nil
			}
			skip := cfg["skip_static_role_import_rotation"] == true
			if _, ok := d.Raw["skip_import_rotation"]; ok {
				skip = d.Get("skip_import_rotation").(bool)
			}
			if old == nil && !skip {
				return rejectRemote(ctx, r, d)
			}
		}
		if err := save(ctx, r.Storage, key, m); err != nil {
			return nil, err
		}
		if kind == "static-role" {
			return &logical.Response{Warnings: []string{limitation}}, nil
		}
		return nil, nil
	}
}
func (b *backend) migration(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if r.Operation == logical.ReadOperation {
		if _, ok := d.Raw["include_role_names"]; !ok {
			return logical.ErrorResponse("include_role_names is required"), nil
		}
	}
	keys, err := r.Storage.List(ctx, "static-role/")
	if err != nil {
		return nil, err
	}
	if len(keys) > 0 {
		return rejectRemote(ctx, r, d)
	}
	// No legacy roles exist on an empty mount; report the empty migration
	// status rather than returning a nil response (which the HTTP layer
	// renders as 404 for reads).
	return &logical.Response{Data: map[string]interface{}{}}, nil
}
