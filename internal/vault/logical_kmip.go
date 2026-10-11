// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// KMIPBackendFactory implements the HTTP control plane and native KMIP subset.
func KMIPBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	if conf == nil {
		return nil, errors.New("nil KMIP backend configuration")
	}
	b := &kmipBackend{Backend: &framework.Backend{BackendType: logical.TypeLogical, Help: "KMIP control plane and native KMIP 1.4 subset.", PathsSpecial: &logical.Paths{SealWrapStorage: []string{"ca/", "scope/"}}}}
	b.Clean = b.kmipCleanup
	b.InitializeFunc = func(ctx context.Context, req *logical.InitializationRequest) error {
		return b.kmipReconcile(ctx, req.Storage)
	}
	fields := map[string]*framework.FieldSchema{}
	for _, k := range strings.Fields("scope role name action ca key_type ca_pem scope_name scope_field role_name role_field address tls_min_version tls_max_version tls_cipher_suites tls_client_key_type serial_number certificate csr format") {
		fields[k] = &framework.FieldSchema{Type: framework.TypeString}
	}
	for _, k := range strings.Fields("key_bits tls_client_key_bits") {
		fields[k] = &framework.FieldSchema{Type: framework.TypeInt}
	}
	for _, k := range strings.Fields("ttl tls_client_ttl") {
		fields[k] = &framework.FieldSchema{Type: framework.TypeDurationSecond}
	}
	for _, k := range strings.Fields("force also_use_legacy_ca") {
		fields[k] = &framework.FieldSchema{Type: framework.TypeBool}
	}
	for _, k := range strings.Fields("server_hostnames server_ips additional_client_cas") {
		fields[k] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
	}
	for _, k := range kmipOperations {
		fields["operation_"+k] = &framework.FieldSchema{Type: framework.TypeBool}
	}
	add := func(pattern string, fn framework.OperationFunc, ops ...logical.Operation) {
		callbacks := map[logical.Operation]framework.OperationFunc{}
		for _, op := range ops {
			callbacks[op] = fn
		}
		b.Paths = append(b.Paths, &framework.Path{Pattern: pattern, Fields: fields, Callbacks: callbacks})
	}
	const scope = "scope/(?P<scope>[A-Za-z0-9_-]+)"
	const role = scope + "/role/(?P<role>[A-Za-z0-9_-]+)"
	add("scope/?", b.resource, logical.ListOperation)
	add(scope, b.resource, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	add(scope+"/role/?", b.resource, logical.ListOperation)
	add(role, b.resource, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	add(role+"/credential/?", b.credential, logical.ListOperation)
	add(role+"/credential/(?P<action>generate|sign|revoke)", b.credential, logical.UpdateOperation)
	add(role+"/credential/(?P<action>lookup)", b.credential, logical.ReadOperation)
	add("ca/?", b.resource, logical.ReadOperation, logical.ListOperation)
	add("ca/(?P<name>[A-Za-z0-9_-]+)/(?P<action>generate|import)", b.caWrite, logical.UpdateOperation)
	add("ca/(?P<name>[A-Za-z0-9_-]+)", b.resource, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	add("listener/?", b.resource, logical.ListOperation)
	add("listener/(?P<name>[A-Za-z0-9_-]+)", b.resource, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	return b, b.Setup(ctx, conf)
}

type kmipBackend struct {
	*framework.Backend
	mu        sync.RWMutex
	listeners kmipListeners
}

var kmipOperations = strings.Fields("all none activate add_attribute create decrypt destroy discover_versions encrypt get get_attribute_list get_attributes import locate query register rekey revoke create_keypair delete_attribute mac mac_verify modify_attribute rekey_keypair sign signature_verify rng_seed rng_retrieve")

func kmipLoad(ctx context.Context, s logical.Storage, key string) (map[string]interface{}, error) {
	e, err := s.Get(ctx, key+"/info")
	if err != nil || e == nil {
		return nil, err
	}
	var data map[string]interface{}
	err = e.DecodeJSON(&data)
	return data, err
}
func kmipSave(ctx context.Context, s logical.Storage, key string, data map[string]interface{}) error {
	e, err := logical.StorageEntryJSON(key+"/info", data)
	if err != nil {
		return err
	}
	return s.Put(ctx, e)
}
func kmipRemove(ctx context.Context, s logical.Storage, prefix string) error {
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			err = kmipRemove(ctx, s, prefix+k)
		} else {
			err = s.Delete(ctx, prefix+k)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func kmipList(ctx context.Context, s logical.Storage, prefix string) (*logical.Response, error) {
	keys, err := s.List(ctx, prefix+"/")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			out = append(out, strings.TrimSuffix(k, "/"))
		}
	}
	sort.Strings(out)
	return logical.ListResponse(out), nil
}
func kmipString(m map[string]interface{}, k string) string { v, _ := m[k].(string); return v }
func kmipInt(m map[string]interface{}, k string, def int) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case json.Number:
		n, err := v.Int64()
		if err == nil {
			return int(n)
		}
	}
	return def
}
func kmipKeyValid(t string, bits int) bool {
	switch t {
	case "rsa":
		return bits == 2048 || bits == 3072 || bits == 4096
	case "ec":
		return bits == 224 || bits == 256 || bits == 384 || bits == 521
	}
	return false
}
func kmipFields(d *framework.FieldData, names string) map[string]interface{} {
	m := map[string]interface{}{}
	for _, k := range strings.Fields(names) {
		if _, ok := d.Raw[k]; ok {
			m[k] = d.Get(k)
		}
	}
	return m
}
func (b *kmipBackend) resource(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	path := strings.TrimSuffix(req.Path, "/")
	if req.Operation == logical.ListOperation {
		return kmipList(ctx, req.Storage, path)
	}
	if path == "ca" {
		return logical.ErrorResponse("legacy CA is not configured"), nil
	}
	data, err := kmipLoad(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if req.Operation == logical.ReadOperation {
		if data == nil {
			return nil, nil
		}
		return &logical.Response{Data: kmipPublic(data)}, nil
	}
	if req.Operation == logical.DeleteOperation {
		if strings.HasPrefix(path, "ca/") {
			used, err := kmipCAInUse(ctx, req.Storage, "", d.Get("name").(string))
			if err != nil {
				return nil, err
			}
			if used {
				return logical.ErrorResponse("CA is in use"), nil
			}
		}
		return nil, kmipRemove(ctx, req.Storage, path+"/")
	}
	if strings.Contains(path, "/role/") {
		scope, err := kmipLoad(ctx, req.Storage, "scope/"+d.Get("scope").(string))
		if err != nil {
			return nil, err
		}
		if scope == nil {
			return logical.ErrorResponse("scope does not exist"), nil
		}
		if data == nil {
			data = map[string]interface{}{}
			for _, k := range kmipOperations {
				data["operation_"+k] = false
			}
		}
		count := 0
		pseudo := false
		for _, k := range kmipOperations {
			key := "operation_" + k
			if _, ok := d.Raw[key]; ok && d.Get(key).(bool) {
				count++
				pseudo = pseudo || k == "all" || k == "none"
			}
		}
		if pseudo && count > 1 {
			return logical.ErrorResponse("operation_all and operation_none are mutually exclusive with other operations"), nil
		}
		if count > 0 {
			if pseudo {
				for _, k := range kmipOperations {
					data["operation_"+k] = false
				}
			} else {
				data["operation_all"] = false
				data["operation_none"] = false
			}
		}
		for _, k := range kmipOperations {
			key := "operation_" + k
			if _, ok := d.Raw[key]; ok {
				data[key] = d.Get(key)
			}
		}
		for k, v := range kmipFields(d, "ca tls_client_key_type tls_client_key_bits tls_client_ttl") {
			data[k] = v
		}
		typ := kmipString(data, "tls_client_key_type")
		if typ == "" {
			typ = "ec"
		}
		bits := kmipInt(data, "tls_client_key_bits", 0)
		if bits == 0 {
			if typ == "rsa" {
				bits = 2048
			} else {
				bits = 521
			}
		}
		if !kmipKeyValid(typ, bits) || kmipInt(data, "tls_client_ttl", 86400) <= 0 {
			return logical.ErrorResponse("invalid client key type, size, or TTL"), nil
		}
		if ca := kmipString(data, "ca"); ca != "" {
			c, err := kmipLoad(ctx, req.Storage, "ca/"+ca)
			if err != nil {
				return nil, err
			}
			if c == nil {
				return logical.ErrorResponse("CA does not exist"), nil
			}
		}
	} else if strings.HasPrefix(path, "scope/") {
		data = map[string]interface{}{"name": d.Get("scope")}
	} else if strings.HasPrefix(path, "ca/") {
		if data == nil || data["imported"] != true {
			return logical.ErrorResponse("only imported CAs can be updated"), nil
		}
		for k, v := range kmipFields(d, "scope_name scope_field role_name role_field") {
			data[k] = v
		}
		if err := kmipSelectors(data); err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
	} else if strings.HasPrefix(path, "listener/") {
		if data == nil {
			data = map[string]interface{}{"server_hostnames": []string{}, "server_ips": []string{"127.0.0.1", "::1"}, "additional_client_cas": []string{}, "also_use_legacy_ca": false, "tls_min_version": "tls12", "tls_max_version": "", "tls_cipher_suites": ""}
		}
		for k, v := range kmipFields(d, "ca address server_hostnames server_ips additional_client_cas also_use_legacy_ca tls_min_version tls_max_version tls_cipher_suites") {
			data[k] = v
		}
		ca := kmipString(data, "ca")
		addr := kmipString(data, "address")
		if ca == "" || addr == "" {
			return logical.ErrorResponse("ca and address are required"), nil
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return logical.ErrorResponse("address must be host:port"), nil
		}
		c, err := kmipLoad(ctx, req.Storage, "ca/"+ca)
		if err != nil {
			return nil, err
		}
		if c == nil || c["imported"] == true {
			return logical.ErrorResponse("listener requires a generated CA"), nil
		}
		for _, k := range []string{"tls_min_version", "tls_max_version"} {
			v := kmipString(data, k)
			if v != "tls12" && v != "tls13" && !(k == "tls_max_version" && v == "") {
				return logical.ErrorResponse("invalid TLS version"), nil
			}
		}
		if kmipString(data, "tls_min_version") == "tls13" && kmipString(data, "tls_max_version") == "tls12" {
			return logical.ErrorResponse("TLS maximum is below minimum"), nil
		}
		if err := kmipSave(ctx, req.Storage, path, data); err != nil {
			return nil, err
		}
		return &logical.Response{Data: data}, nil
	}
	return nil, kmipSave(ctx, req.Storage, path, data)
}
func kmipPublic(m map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range m {
		if k != "private_key" {
			out[k] = v
		}
	}
	return out
}
func kmipSelectors(m map[string]interface{}) error {
	for _, p := range []string{"scope", "role"} {
		name, field := kmipString(m, p+"_name"), kmipString(m, p+"_field")
		if (name == "") == (field == "") {
			return fmt.Errorf("exactly one %s selector is required", p)
		}
		if field != "" && field != "CN" && field != "O" && field != "OU" && field != "UID" {
			return fmt.Errorf("invalid %s field", p)
		}
	}
	return nil
}

// Scan mount-local metadata, including role and listener trust references.
func kmipCAInUse(ctx context.Context, s logical.Storage, prefix, name string) (bool, error) {
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			used, err := kmipCAInUse(ctx, s, prefix+k, name)
			if used || err != nil {
				return used, err
			}
		} else if k == "info" {
			m, err := kmipLoad(ctx, s, strings.TrimSuffix(prefix, "/"))
			if err != nil {
				return false, err
			}
			if kmipString(m, "ca") == name {
				return true, nil
			}
			if a, ok := m["additional_client_cas"].([]interface{}); ok {
				for _, v := range a {
					if v == name {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}
