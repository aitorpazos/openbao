// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/ssh"
)

type osEngineBackend struct {
	*framework.Backend
	mu sync.Mutex
}
type osEngineConfig struct {
	MaxVersions int  `json:"max_versions"`
	Trust       bool `json:"ssh_host_key_trust_on_first_use"`
}
type osAccountVersion struct {
	Password    string `json:"password"`
	CreatedTime string `json:"created_time"`
}
type osAccount struct {
	Values         map[string]interface{}      `json:"values"`
	CurrentVersion int                         `json:"current_version"`
	Versions       map[string]osAccountVersion `json:"versions"`
}

// OsEngineBackendFactory provides offline local-account storage, never SSH execution.
func OsEngineBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &osEngineBackend{Backend: &framework.Backend{BackendType: logical.TypeLogical, Help: "Offline OS account storage. Remote verification and rotation are not implemented.", PathsSpecial: &logical.Paths{SealWrapStorage: []string{"accounts/"}}}}
	add := func(p string, f map[string]*framework.FieldSchema, h framework.OperationFunc, ops ...logical.Operation) {
		c := map[logical.Operation]framework.OperationFunc{}
		for _, o := range ops {
			c[o] = h
		}
		b.Paths = append(b.Paths, &framework.Path{Pattern: p, Fields: f, Callbacks: c})
	}
	add("config", map[string]*framework.FieldSchema{"max_versions": {Type: framework.TypeInt, Default: 10}, "ssh_host_key_trust_on_first_use": {Type: framework.TypeBool}}, b.config, logical.ReadOperation, logical.UpdateOperation)
	host := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "port": {Type: framework.TypeInt, Default: 22}}
	addConfigFields(host, framework.TypeString, "address ssh_host_key password_policy rotation_schedule")
	addConfigFields(host, framework.TypeDurationSecond, "rotation_period rotation_window")
	addConfigFields(host, framework.TypeBool, "disable_automated_rotation")
	host["custom_metadata"] = &framework.FieldSchema{Type: framework.TypeKVPairs}
	add("hosts/?", nil, b.host, logical.ListOperation)
	add("hosts/"+framework.GenericNameRegex("name"), host, b.host, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	account := map[string]*framework.FieldSchema{"verify_connection": {Type: framework.TypeBool, Default: true}}
	addConfigFields(account, framework.TypeString, "host_ref name username password parent_account_ref password_policy rotation_schedule")
	addConfigFields(account, framework.TypeDurationSecond, "rotation_period rotation_window")
	addConfigFields(account, framework.TypeBool, "disable_automated_rotation")
	account["custom_metadata"] = &framework.FieldSchema{Type: framework.TypeKVPairs}
	base := "hosts/" + framework.GenericNameRegex("host_ref") + "/accounts"
	add(base+"/?", map[string]*framework.FieldSchema{"host_ref": {Type: framework.TypeString}}, b.account, logical.ListOperation)
	base += "/" + framework.GenericNameRegex("name")
	add(base, account, b.account, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	refs := map[string]*framework.FieldSchema{"host_ref": {Type: framework.TypeString}, "name": {Type: framework.TypeString}}
	add(base+"/creds", refs, b.credentials, logical.ReadOperation)
	add(base+"/versions", refs, b.credentials, logical.ReadOperation)
	add(base+"/reset", map[string]*framework.FieldSchema{"host_ref": {Type: framework.TypeString}, "name": {Type: framework.TypeString}, "password": {Type: framework.TypeString}}, b.credentials, logical.UpdateOperation)
	add(base+"/versions/(?P<version_id>[0-9]+)/restore", map[string]*framework.FieldSchema{"host_ref": {Type: framework.TypeString}, "name": {Type: framework.TypeString}, "version_id": {Type: framework.TypeString}}, b.credentials, logical.UpdateOperation)
	return b, b.Setup(ctx, conf)
}
func osLoadConfig(ctx context.Context, s logical.Storage) (osEngineConfig, error) {
	c := osEngineConfig{MaxVersions: 10}
	_, err := authOSLoad(ctx, s, "config", &c)
	return c, err
}
func (b *osEngineBackend) config(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := osLoadConfig(ctx, r.Storage)
	if err != nil {
		return nil, err
	}
	if r.Operation == logical.ReadOperation {
		return &logical.Response{Data: map[string]interface{}{"max_versions": c.MaxVersions, "ssh_host_key_trust_on_first_use": c.Trust}}, nil
	}
	if v, ok := d.GetOk("max_versions"); ok {
		c.MaxVersions = v.(int)
	}
	if c.MaxVersions < 1 {
		return logical.ErrorResponse("max_versions must be positive"), nil
	}
	if v, ok := d.GetOk("ssh_host_key_trust_on_first_use"); ok {
		c.Trust = v.(bool)
	}
	return nil, authOSSave(ctx, r.Storage, "config", c)
}
func osOfflineValidation(m map[string]interface{}) string {
	// Never silently accept a request for remote scheduling or execution.
	d := &framework.FieldData{Raw: m, Schema: map[string]*framework.FieldSchema{"rotation_period": {Type: framework.TypeDurationSecond}, "rotation_window": {Type: framework.TypeDurationSecond}, "rotation_schedule": {Type: framework.TypeString}}}
	if d.Get("rotation_period").(int) != 0 || d.Get("rotation_window").(int) != 0 || d.Get("rotation_schedule").(string) != "" {
		return "remote rotation and scheduling are not implemented; use rotation_period=0"
	}
	return ""
}
func (b *osEngineBackend) host(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Operation == logical.ListOperation {
		keys, err := r.Storage.List(ctx, "hosts/")
		return logical.ListResponse(keys), err
	}
	name := d.Get("name").(string)
	key := "hosts/" + name
	m := map[string]interface{}{}
	ok, err := authOSLoad(ctx, r.Storage, key, &m)
	if err != nil {
		return nil, err
	}
	switch r.Operation {
	case logical.ReadOperation:
		if !ok {
			return nil, nil
		}
		return &logical.Response{Data: m}, nil
	case logical.DeleteOperation:
		keys, err := r.Storage.List(ctx, "accounts/"+name+"/")
		if err != nil {
			return nil, err
		}
		if len(keys) > 0 {
			return logical.ErrorResponse("delete accounts before deleting their host"), nil
		}
		return nil, r.Storage.Delete(ctx, key)
	}
	authOSDefaults(m, d)
	authOSMerge(m, d)
	if m["address"] == "" {
		return logical.ErrorResponse("address is required"), nil
	}
	fd := &framework.FieldData{Raw: m, Schema: d.Schema}
	port := fd.Get("port").(int)
	if port < 1 || port > 65535 {
		return logical.ErrorResponse("port must be between 1 and 65535"), nil
	}
	if k := m["ssh_host_key"].(string); k != "" {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil {
			return logical.ErrorResponse("invalid ssh_host_key"), nil
		}
	}
	if msg := osOfflineValidation(m); msg != "" {
		return logical.ErrorResponse("%s", msg), nil
	}
	return nil, authOSSave(ctx, r.Storage, key, m)
}
func osAccountKey(d *framework.FieldData) string {
	return "accounts/" + d.Get("host_ref").(string) + "/" + d.Get("name").(string)
}
func (b *osEngineBackend) account(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	host := d.Get("host_ref").(string)
	if r.Operation == logical.ListOperation {
		keys, err := r.Storage.List(ctx, "accounts/"+host+"/")
		return logical.ListResponse(keys), err
	}
	key := osAccountKey(d)
	if r.Operation == logical.DeleteOperation {
		return nil, r.Storage.Delete(ctx, key)
	}
	a := osAccount{Values: map[string]interface{}{}, Versions: map[string]osAccountVersion{}}
	ok, err := authOSLoad(ctx, r.Storage, key, &a)
	if err != nil {
		return nil, err
	}
	if r.Operation == logical.ReadOperation {
		if !ok {
			return nil, nil
		}
		return &logical.Response{Data: a.Values}, nil
	}
	h, err := r.Storage.Get(ctx, "hosts/"+host)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return logical.ErrorResponse("host does not exist"), nil
	}
	authOSDefaults(a.Values, d)
	authOSMerge(a.Values, d)
	password := d.Get("password").(string)
	delete(a.Values, "password")
	if a.Values["username"] == "" || (!ok && password == "") {
		return logical.ErrorResponse("username and initial password are required"), nil
	}
	if ok && password != "" && password != a.Versions[strconv.Itoa(a.CurrentVersion)].Password {
		return logical.ErrorResponse("password cannot be changed here; use reset"), nil
	}
	if a.Values["verify_connection"] == true {
		return logical.ErrorResponse("remote connection verification is not implemented; use verify_connection=false"), nil
	}
	if msg := osOfflineValidation(a.Values); msg != "" {
		return logical.ErrorResponse("%s", msg), nil
	}
	if !ok {
		if err := osNewVersion(ctx, r.Storage, &a, password); err != nil {
			return nil, err
		}
	}
	if err := authOSSave(ctx, r.Storage, key, a); err != nil {
		return nil, err
	}
	return &logical.Response{Warnings: []string{"Offline storage only: no remote host connection or password rotation is performed."}}, nil
}
func osNewVersion(ctx context.Context, s logical.Storage, a *osAccount, password string) error {
	c, err := osLoadConfig(ctx, s)
	if err != nil {
		return err
	}
	a.CurrentVersion++
	a.Versions[strconv.Itoa(a.CurrentVersion)] = osAccountVersion{Password: password, CreatedTime: time.Now().UTC().Format(time.RFC3339Nano)}
	for k := range a.Versions {
		v, err := strconv.Atoi(k)
		if err == nil && v <= a.CurrentVersion-c.MaxVersions {
			delete(a.Versions, k)
		}
	}
	return nil
}
func (b *osEngineBackend) credentials(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := osAccountKey(d)
	var a osAccount
	ok, err := authOSLoad(ctx, r.Storage, key, &a)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if r.Operation == logical.ReadOperation {
		if strings.HasSuffix(r.Path, "/versions") {
			versions := map[string]interface{}{}
			for k, v := range a.Versions {
				versions[k] = map[string]interface{}{"created_time": v.CreatedTime}
			}
			return &logical.Response{Data: map[string]interface{}{"current_version": a.CurrentVersion, "versions": versions}}, nil
		}
		return &logical.Response{Data: map[string]interface{}{"username": a.Values["username"], "password": a.Versions[strconv.Itoa(a.CurrentVersion)].Password, "version": a.CurrentVersion}}, nil
	}
	var password string
	if strings.HasSuffix(r.Path, "/restore") {
		v, ok := a.Versions[d.Get("version_id").(string)]
		if !ok {
			return logical.ErrorResponse("credential version does not exist"), nil
		}
		password = v.Password
	} else {
		password = d.Get("password").(string)
		if password == "" {
			return logical.ErrorResponse("password is required"), nil
		}
	}
	if err := osNewVersion(ctx, r.Storage, &a, password); err != nil {
		return nil, err
	}
	return nil, authOSSave(ctx, r.Storage, key, a)
}
