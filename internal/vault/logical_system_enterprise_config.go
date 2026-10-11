// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

const (
	groupPolicyApplicationPath = "config/group-policy-application"
	uiCustomMessagePath        = "config/ui/custom-messages"
	uiDefaultAuthPath          = "config/ui/login/default-auth"
)

// enterpriseConfigPaths implements only the documented configuration APIs.
// Storage is the router-provided namespace-local system barrier view. The lock
// belongs to this backend, serializing capacity and uniqueness checks with writes.
func (b *SystemBackend) enterpriseConfigPaths() []*framework.Path {
	var lock sync.Mutex
	wrap := func(f framework.OperationFunc) framework.OperationFunc {
		return func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
			lock.Lock()
			defer lock.Unlock()
			return f(ctx, r, d)
		}
	}
	group, message, login := wrap(handleGroupPolicyApplication), wrap(handleUICustomMessage), wrap(handleUIDefaultAuth)
	messageFields := map[string]*framework.FieldSchema{
		"id": {Type: framework.TypeString}, "title": {Type: framework.TypeString},
		"message": {Type: framework.TypeString}, "start_time": {Type: framework.TypeString},
		"end_time": {Type: framework.TypeString}, "authenticated": {Type: framework.TypeBool},
		"active": {Type: framework.TypeBool}, "type": {Type: framework.TypeString},
		"link": {Type: framework.TypeMap}, "options": {Type: framework.TypeMap},
	}
	loginFields := map[string]*framework.FieldSchema{
		"name": {Type: framework.TypeString}, "namespace_path": {Type: framework.TypeString},
		"default_auth_type": {Type: framework.TypeString}, "backup_auth_types": {Type: framework.TypeStringSlice},
		"disable_inheritance": {Type: framework.TypeBool},
	}
	return []*framework.Path{
		{Pattern: groupPolicyApplicationPath + "$", Fields: map[string]*framework.FieldSchema{"group_policy_application_mode": {Type: framework.TypeString}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: group, logical.UpdateOperation: group}},
		{Pattern: uiCustomMessagePath + "/?$", Fields: messageFields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: message, logical.UpdateOperation: message}},
		{Pattern: uiCustomMessagePath + "/(?P<id>[^/]+)$", Fields: messageFields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: message, logical.UpdateOperation: message, logical.DeleteOperation: message}},
		{Pattern: uiDefaultAuthPath + "/?$", Fields: loginFields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: login}},
		{Pattern: uiDefaultAuthPath + "/(?P<name>[a-zA-Z0-9_-]+)$", Fields: loginFields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: login, logical.UpdateOperation: login, logical.DeleteOperation: login}},
	}
}

func enterpriseConfigRoot(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	// OpenBao does not currently configure an administrative namespace.
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrPermissionDenied
	}
	return nil
}

func enterpriseConfigInvalid(err error) (*logical.Response, error) {
	return logical.ErrorResponse("%s", err), logical.ErrInvalidRequest
}

func enterpriseConfigPut(ctx context.Context, s logical.Storage, key string, v any) error {
	entry, err := logical.StorageEntryJSON(key, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// Decode the original input, rather than coercing numbers/maps to strings or
// strings to booleans. Query-string filters use framework's bool conversion.
func enterpriseConfigDecode(data map[string]interface{}, v any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func handleGroupPolicyApplication(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := enterpriseConfigRoot(ctx); err != nil {
		return nil, err
	}
	config := struct {
		Mode string `json:"group_policy_application_mode"`
	}{Mode: "within_namespace_hierarchy"}
	if r.Operation == logical.ReadOperation {
		entry, err := r.Storage.Get(ctx, groupPolicyApplicationPath)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&config); err != nil {
				return nil, err
			}
		}
		return &logical.Response{Data: map[string]interface{}{"group_policy_application_mode": config.Mode}}, nil
	}
	if err := enterpriseConfigDecode(r.Data, &config); err != nil {
		return enterpriseConfigInvalid(err)
	}
	if config.Mode != "any" && config.Mode != "within_namespace_hierarchy" {
		return enterpriseConfigInvalid(fmt.Errorf("invalid group_policy_application_mode"))
	}
	return nil, enterpriseConfigPut(ctx, r.Storage, groupPolicyApplicationPath, config)
}

type uiCustomMessage struct {
	Title         string                 `json:"title"`
	Message       string                 `json:"message"`
	Authenticated bool                   `json:"authenticated"`
	Type          string                 `json:"type"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time"`
	Link          map[string]string      `json:"link"`
	Options       map[string]interface{} `json:"options"`
}

func (m *uiCustomMessage) data(id string, now time.Time) map[string]interface{} {
	var end interface{}
	if m.EndTime != nil {
		end = m.EndTime.Format(time.RFC3339Nano)
	}
	return map[string]interface{}{"id": id, "title": m.Title, "message": m.Message, "authenticated": m.Authenticated, "type": m.Type, "start_time": m.StartTime.Format(time.RFC3339Nano), "end_time": end, "link": m.Link, "options": m.Options, "active": !now.Before(m.StartTime) && (m.EndTime == nil || now.Before(*m.EndTime))}
}

func handleUICustomMessage(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Derive item identity from the path, never a client-supplied collection ID.
	id := strings.TrimPrefix(strings.TrimSuffix(r.Path, "/"), uiCustomMessagePath)
	id = strings.TrimPrefix(id, "/")
	prefix := uiCustomMessagePath + "/"
	if r.Operation == logical.ListOperation {
		typ := d.Get("type").(string)
		if typ != "" && typ != "banner" && typ != "modal" {
			return enterpriseConfigInvalid(fmt.Errorf("type must be banner or modal"))
		}
		ids, err := r.Storage.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		keys, info := []string{}, map[string]interface{}{}
		now := time.Now()
		for _, key := range ids {
			entry, err := r.Storage.Get(ctx, prefix+key)
			if err != nil {
				return nil, err
			}
			if entry == nil {
				continue
			}
			var m uiCustomMessage
			if err := entry.DecodeJSON(&m); err != nil {
				return nil, err
			}
			data := m.data(key, now)
			if typ != "" && typ != m.Type {
				continue
			}
			if v, ok := d.GetOk("active"); ok && v != data["active"] {
				continue
			}
			if v, ok := d.GetOk("authenticated"); ok && v != m.Authenticated {
				continue
			}
			keys = append(keys, key)
			info[key] = map[string]interface{}{"title": m.Title, "type": m.Type, "authenticated": m.Authenticated, "start_time": data["start_time"], "end_time": data["end_time"]}
		}
		return &logical.Response{Data: map[string]interface{}{"keys": keys, "key_info": info}}, nil
	}
	if r.Operation == logical.DeleteOperation {
		return nil, r.Storage.Delete(ctx, prefix+id)
	}
	if id != "" {
		entry, err := r.Storage.Get(ctx, prefix+id)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, nil
		}
		if r.Operation == logical.ReadOperation {
			var m uiCustomMessage
			if err := entry.DecodeJSON(&m); err != nil {
				return nil, err
			}
			return &logical.Response{Data: m.data(id, time.Now())}, nil
		}
	}
	m := uiCustomMessage{Authenticated: true, Type: "banner"}
	if err := enterpriseConfigDecode(r.Data, &m); err != nil {
		return enterpriseConfigInvalid(err)
	}
	if m.Title == "" || m.Message == "" || m.StartTime.IsZero() {
		return enterpriseConfigInvalid(fmt.Errorf("title, message and start_time are required"))
	}
	if _, err := base64.StdEncoding.DecodeString(m.Message); err != nil {
		return enterpriseConfigInvalid(fmt.Errorf("message must be base64 encoded"))
	}
	if m.Type != "banner" && m.Type != "modal" {
		return enterpriseConfigInvalid(fmt.Errorf("type must be banner or modal"))
	}
	if _, ok := r.Data["link"]; ok && len(m.Link) != 1 {
		return enterpriseConfigInvalid(fmt.Errorf("link must contain exactly one property"))
	}
	if id == "" {
		ids, err := r.Storage.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		if len(ids) >= 100 {
			return enterpriseConfigInvalid(fmt.Errorf("at most 100 custom messages are allowed per namespace"))
		}
		id, err = uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
	}
	if err := enterpriseConfigPut(ctx, r.Storage, prefix+id, m); err != nil {
		return nil, err
	}
	return &logical.Response{Data: m.data(id, time.Now())}, nil
}

type uiDefaultAuth struct {
	NamespacePath      string   `json:"namespace_path"`
	DefaultAuthType    string   `json:"default_auth_type"`
	BackupAuthTypes    []string `json:"backup_auth_types"`
	DisableInheritance bool     `json:"disable_inheritance"`
}

func validUIDefaultAuthType(s string) bool {
	switch s {
	case "github", "jwt", "ldap", "oidc", "okta", "radius", "saml", "token", "userpass":
		return true
	}
	return false
}

func handleUIDefaultAuth(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := enterpriseConfigRoot(ctx); err != nil {
		return nil, err
	}
	name := d.Get("name").(string)
	prefix := uiDefaultAuthPath + "/"
	if r.Operation == logical.DeleteOperation {
		return nil, r.Storage.Delete(ctx, prefix+name)
	}
	if r.Operation == logical.ReadOperation {
		entry, err := r.Storage.Get(ctx, prefix+name)
		if err != nil || entry == nil {
			return nil, err
		}
		var data map[string]interface{}
		if err := entry.DecodeJSON(&data); err != nil {
			return nil, err
		}
		return &logical.Response{Data: data}, nil
	}
	names, err := r.Storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	configs := map[string]uiDefaultAuth{}
	for _, key := range names {
		entry, err := r.Storage.Get(ctx, prefix+key)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		var c uiDefaultAuth
		if err := entry.DecodeJSON(&c); err != nil {
			return nil, err
		}
		configs[key] = c
	}
	if r.Operation == logical.ListOperation {
		keys, info := []string{}, map[string]interface{}{}
		for _, key := range names {
			if c, ok := configs[key]; ok {
				keys = append(keys, key)
				info[key] = map[string]interface{}{"name": key, "namespace_path": c.NamespacePath, "disable_inheritance": c.DisableInheritance}
			}
		}
		return &logical.Response{Data: map[string]interface{}{"keys": keys, "key_info": info}}, nil
	}
	c := uiDefaultAuth{BackupAuthTypes: []string{}}
	if err := enterpriseConfigDecode(r.Data, &c); err != nil {
		return enterpriseConfigInvalid(err)
	}
	if c.BackupAuthTypes == nil {
		c.BackupAuthTypes = []string{}
	}
	if c.DefaultAuthType == "" && len(c.BackupAuthTypes) == 0 {
		return enterpriseConfigInvalid(fmt.Errorf("default_auth_type or backup_auth_types is required"))
	}
	if c.DefaultAuthType != "" && !validUIDefaultAuthType(c.DefaultAuthType) {
		return enterpriseConfigInvalid(fmt.Errorf("invalid default_auth_type"))
	}
	for _, method := range c.BackupAuthTypes {
		if !validUIDefaultAuthType(method) {
			return enterpriseConfigInvalid(fmt.Errorf("invalid backup_auth_types"))
		}
	}
	for key, existing := range configs {
		if key != name && strings.Trim(existing.NamespacePath, "/") == strings.Trim(c.NamespacePath, "/") {
			return enterpriseConfigInvalid(fmt.Errorf("a login configuration already exists for this namespace"))
		}
	}
	return nil, enterpriseConfigPut(ctx, r.Storage, prefix+name, c)
}
