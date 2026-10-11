// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// These backends persist configuration only. They deliberately issue no tokens.
type authConfigBackend struct {
	*framework.Backend
	mu   sync.Mutex
	saml bool
}
type authConfigRole struct {
	tokenutil.TokenParams
	Values map[string]interface{} `json:"values"`
}

func SamlBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return newAuthConfigBackend(ctx, conf, true)
}
func ScepBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return newAuthConfigBackend(ctx, conf, false)
}
func newAuthConfigBackend(ctx context.Context, conf *logical.BackendConfig, saml bool) (logical.Backend, error) {
	b := &authConfigBackend{Backend: &framework.Backend{BackendType: logical.TypeCredential, Help: "Configuration-only SAML/SCEP compatibility. Authentication is not implemented.", PathsSpecial: &logical.Paths{SealWrapStorage: []string{"role/"}}}, saml: saml}
	f := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}}
	f["alias_metadata"] = &framework.FieldSchema{Type: framework.TypeKVPairs}
	if saml {
		addConfigFields(f, framework.TypeString, "bound_subjects_type bound_attributes_type groups_attribute")
		f["bound_subjects"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
		f["bound_attributes"] = &framework.FieldSchema{Type: framework.TypeMap}
	} else {
		addConfigFields(f, framework.TypeString, "auth_type challenge display_name")
	}
	tokenutil.AddTokenFields(f)
	b.Paths = append(b.Paths, &framework.Path{Pattern: "role/?", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.role}}, &framework.Path{Pattern: "role/" + framework.GenericNameRegex("name"), Fields: f, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.role, logical.UpdateOperation: b.role, logical.DeleteOperation: b.role}})
	if saml {
		fields := map[string]*framework.FieldSchema{}
		addConfigFields(fields, framework.TypeString, "entity_id idp_metadata_url idp_sso_url idp_entity_id idp_cert default_role")
		addConfigFields(fields, framework.TypeBool, "verbose_logging validate_response_signature validate_assertion_signature")
		fields["acs_urls"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
		b.Paths = append(b.Paths, &framework.Path{Pattern: "config", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.config, logical.UpdateOperation: b.config}})
		// Validation-only entrypoints; no browser state, callback or login is implemented.
		for _, p := range []string{"sso_service_url", "token"} {
			input := map[string]*framework.FieldSchema{}
			addConfigFields(input, framework.TypeString, "role client_type acs_url client_challenge client_verifier token_poll_id")
			b.Paths = append(b.Paths, &framework.Path{Pattern: p, Fields: input, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: func(_ context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
				if r.Path == "sso_service_url" {
					challenge := d.Get("client_challenge").(string)
					digest, err := base64.StdEncoding.DecodeString(challenge)
					if len(challenge) < 44 || err != nil || len(digest) != 32 {
						return logical.ErrorResponse("client_challenge must be a base64 SHA-256 digest"), nil
					}
					if ct := d.Get("client_type").(string); ct != "cli" && ct != "browser" {
						return logical.ErrorResponse("client_type must be cli or browser"), nil
					}
					if !validAuthURL(d.Get("acs_url").(string)) {
						return logical.ErrorResponse("acs_url is required and must be a valid URL"), nil
					}
				} else if d.Get("client_verifier").(string) == "" || d.Get("token_poll_id").(string) == "" {
					return logical.ErrorResponse("client_verifier and token_poll_id are required"), nil
				}
				return logical.ErrorResponse("SAML browser authentication is not implemented"), nil
			}}})
		}
	}
	return b, b.Setup(ctx, conf)
}
func addConfigFields(f map[string]*framework.FieldSchema, t framework.FieldType, names string) {
	for _, n := range strings.Fields(names) {
		f[n] = &framework.FieldSchema{Type: t}
	}
}
func authOSSave(ctx context.Context, s logical.Storage, k string, v interface{}) error {
	e, err := logical.StorageEntryJSON(k, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, e)
}
func authOSLoad(ctx context.Context, s logical.Storage, k string, v interface{}) (bool, error) {
	e, err := s.Get(ctx, k)
	if err != nil || e == nil {
		return false, err
	}
	return true, e.DecodeJSON(v)
}
func authOSMerge(m map[string]interface{}, d *framework.FieldData) {
	for k := range d.Schema {
		if k == "name" || k == "host_ref" || k == "version_id" {
			continue
		}
		if v, ok := d.GetOk(k); ok {
			m[k] = v
		}
	}
}
func authOSDefaults(m map[string]interface{}, d *framework.FieldData) {
	for k := range d.Schema {
		if k != "name" && k != "host_ref" && k != "version_id" {
			if _, ok := m[k]; !ok {
				m[k] = d.Get(k)
			}
		}
	}
}
func validAuthURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
func (b *authConfigBackend) config(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := map[string]interface{}{}
	ok, err := authOSLoad(ctx, r.Storage, "config", &m)
	if err != nil {
		return nil, err
	}
	if r.Operation == logical.ReadOperation {
		if !ok {
			return nil, nil
		}
		return &logical.Response{Data: m}, nil
	}
	authOSDefaults(m, d)
	authOSMerge(m, d)
	if m["entity_id"] == "" {
		return logical.ErrorResponse("entity_id is required"), nil
	}
	acs := &framework.FieldData{Raw: m, Schema: d.Schema}
	urls := acs.Get("acs_urls").([]string)
	if len(urls) == 0 {
		return logical.ErrorResponse("acs_urls is required"), nil
	}
	for _, u := range urls {
		if !validAuthURL(u) {
			return logical.ErrorResponse("acs_urls must contain valid HTTP(S) URLs"), nil
		}
	}
	if m["idp_metadata_url"] != "" {
		if !validAuthURL(m["idp_metadata_url"].(string)) {
			return logical.ErrorResponse("invalid idp_metadata_url"), nil
		}
		if m["idp_sso_url"] != "" || m["idp_entity_id"] != "" || m["idp_cert"] != "" {
			return logical.ErrorResponse("metadata URL and static IdP configuration are mutually exclusive"), nil
		}
	} else {
		if !validAuthURL(m["idp_sso_url"].(string)) || m["idp_entity_id"] == "" {
			return logical.ErrorResponse("idp_sso_url and idp_entity_id are required"), nil
		}
		block, _ := pem.Decode([]byte(m["idp_cert"].(string)))
		if block == nil || block.Type != "CERTIFICATE" {
			return logical.ErrorResponse("idp_cert must be a PEM certificate"), nil
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return logical.ErrorResponse("invalid idp_cert: %s", err), nil
		}
	}
	if err := authOSSave(ctx, r.Storage, "config", m); err != nil {
		return nil, err
	}
	resp := &logical.Response{Warnings: []string{"Configuration stored only; SAML authentication and metadata fetching are not implemented."}}
	for _, u := range urls {
		if strings.HasPrefix(u, "http:") {
			resp.AddWarning("ACS URL lacks TLS protection")
		}
	}
	return resp, nil
}
func (b *authConfigBackend) role(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Operation == logical.ListOperation {
		keys, err := r.Storage.List(ctx, "role/")
		return logical.ListResponse(keys), err
	}
	name := d.Get("name").(string)
	key := "role/" + name
	if r.Operation == logical.DeleteOperation {
		return nil, r.Storage.Delete(ctx, key)
	}
	role := authConfigRole{Values: map[string]interface{}{}}
	ok, err := authOSLoad(ctx, r.Storage, key, &role)
	if err != nil {
		return nil, err
	}
	if r.Operation == logical.ReadOperation {
		if !ok {
			return nil, nil
		}
		return authRoleResponse(&role), nil
	}
	// TokenParams is the shared OpenBao validation/serialization contract.
	if err := role.ParseTokenFields(r, d); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	for k := range d.Schema {
		if strings.HasPrefix(k, "token_") || k == "name" {
			continue
		}
		if v, ok := d.GetOk(k); ok {
			role.Values[k] = v
		}
	}
	if b.saml {
		for _, k := range []string{"bound_subjects_type", "bound_attributes_type"} {
			v := role.Values[k]
			if v == nil || v == "" {
				role.Values[k] = "string"
			} else if v != "string" && v != "glob" {
				return logical.ErrorResponse("%s must be string or glob", k), nil
			}
		}
		if attrs, ok := role.Values["bound_attributes"]; ok {
			m, ok := attrs.(map[string]interface{})
			if !ok {
				return logical.ErrorResponse("bound_attributes must be a map"), nil
			}
			normalized := map[string]interface{}{}
			for k, v := range m {
				switch v := v.(type) {
				case string:
					values := strings.Split(v, ",")
					for i := range values {
						values[i] = strings.TrimSpace(values[i])
					}
					normalized[k] = values
				case []string:
					normalized[k] = v
				case []interface{}:
					for _, item := range v {
						if _, ok := item.(string); !ok {
							return logical.ErrorResponse("bound_attributes values must be strings"), nil
						}
					}
					normalized[k] = v
				default:
					return logical.ErrorResponse("bound_attributes values must be strings or string lists"), nil
				}
			}
			role.Values["bound_attributes"] = normalized
		}
	} else {
		t := role.Values["auth_type"]
		if t != "static-challenge" && t != "intune" {
			return logical.ErrorResponse("auth_type must be static-challenge or intune"), nil
		}
		if t == "static-challenge" && (role.Values["challenge"] == nil || role.Values["challenge"] == "") {
			return logical.ErrorResponse("challenge is required for static-challenge"), nil
		}
		role.Values["name"] = name
		if role.Values["display_name"] == nil || role.Values["display_name"] == "" {
			role.Values["display_name"] = name
		}
	}
	if err := authOSSave(ctx, r.Storage, key, &role); err != nil {
		return nil, err
	}
	resp := authRoleResponse(&role)
	resp.AddWarning(fmt.Sprintf("Configuration stored only; %s authentication is not implemented.", map[bool]string{true: "SAML", false: "SCEP"}[b.saml]))
	return resp, nil
}
func authRoleResponse(r *authConfigRole) *logical.Response {
	m := map[string]interface{}{}
	for k, v := range r.Values {
		if k != "challenge" {
			m[k] = v
		}
	}
	r.PopulateTokenData(m)
	return &logical.Response{Data: m}
}
