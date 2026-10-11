// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func configRequest(t *testing.T, b logical.Backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}, invalid bool) *logical.Response {
	t.Helper()
	r, e := b.HandleRequest(t.Context(), &logical.Request{Operation: op, Path: path, Storage: s, Data: data})
	if e != nil {
		t.Fatal(e)
	}
	if (r != nil && r.IsError()) != invalid {
		t.Fatalf("%s %s: %#v", op, path, r)
	}
	return r
}

func TestIssuanceConfiguration(t *testing.T) {
	b, s := CreateBackendWithStorage(t)
	request := func(op logical.Operation, path string, d map[string]interface{}, invalid bool) *logical.Response {
		return configRequest(t, b, s, op, path, d, invalid)
	}
	for _, protocol := range []string{"est", "cmp"} {
		path := "config/" + protocol
		request(logical.UpdateOperation, path, map[string]interface{}{"enabled": true}, true)
		request(logical.UpdateOperation, path, map[string]interface{}{"audit_fields": []string{"bogus"}}, true)
		request(logical.UpdateOperation, path, map[string]interface{}{"default_path_policy": "bogus"}, true)
		r := request(logical.UpdateOperation, path, map[string]interface{}{"enabled": false, "default_path_policy": "sign-verbatim", "enable_sentinel_parsing": true, "audit_fields": []string{"common_name"}}, false)
		if r.Data["last_updated"] == "" {
			t.Fatal(r)
		}
		request(logical.UpdateOperation, path, map[string]interface{}{"enable_sentinel_parsing": false}, false)
		r = request(logical.ReadOperation, path, nil, false)
		if r.Data["enable_sentinel_parsing"] != false || r.Data["default_path_policy"] != "sign-verbatim" {
			t.Fatal(r)
		}
	}
	request(logical.UpdateOperation, "config/cmp", map[string]interface{}{"disabled_validations": []string{"bogus"}}, true)
	for _, level := range []string{"WARN", ""} {
		request(logical.UpdateOperation, "config/scep", map[string]interface{}{"log_level": level}, false)
		r := request(logical.ReadOperation, "config/scep", nil, false)
		if r.Data["log_level"] != level {
			t.Fatal(r)
		}
	}
	r := request(logical.ReadOperation, "config/external-policy", nil, false)
	if r.Data["enabled"] != false || r.Data["external_service_validated"] != false {
		t.Fatal(r)
	}
	for _, url := range []string{"http://127.0.0.1:1", "https://127.0.0.1:1"} {
		request(logical.UpdateOperation, "config/external-policy", map[string]interface{}{"enabled": true, "external_service_url": url}, true)
	}
	for _, value := range []bool{false, true} {
		request(logical.UpdateOperation, "roles/metadata", map[string]interface{}{"no_store": true, "no_store_metadata": value}, false)
		r := request(logical.ReadOperation, "roles/metadata", nil, false)
		if r.Data["no_store"] != true || r.Data["no_store_metadata"] != value {
			t.Fatal(r)
		}
	}
	request(logical.PatchOperation, "roles/metadata", map[string]interface{}{"ttl": "1h"}, false)
	r = request(logical.ReadOperation, "roles/metadata", nil, false)
	if r.Data["no_store_metadata"] != true {
		t.Fatal(r)
	}
}

func TestExportKeyManagement(t *testing.T) {
	b, s := CreateBackendWithStorage(t)
	request := func(op logical.Operation, path string, d map[string]interface{}, invalid bool) *logical.Response {
		return configRequest(t, b, s, op, path, d, invalid)
	}
	request(logical.UpdateOperation, "export", map[string]interface{}{"key_type": "bad"}, true)
	r := request(logical.UpdateOperation, "export", map[string]interface{}{"key_type": "ec-p256", "name": "key"}, false)
	block, _ := pem.Decode([]byte(r.Data["public_key"].(string)))
	if block == nil {
		t.Fatal(r)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatal(pub)
	}
	uuid := r.Data["export_key_uuid"].(string)
	entry, err := s.Get(t.Context(), "config/export-keys/"+uuid)
	if err != nil {
		t.Fatal(err)
	}
	var rec exportKeyRecord
	if err = json.Unmarshal(entry.Value, &rec); err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(rec.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.(*ecdsa.PrivateKey).PublicKey.Equal(pub) {
		t.Fatal("public/private mismatch")
	}
	request(logical.UpdateOperation, "export", map[string]interface{}{"key_type": "ec-p256", "name": "key"}, true)
	request(logical.ListOperation, "export", nil, false)
	r = request(logical.ReadOperation, "export/"+uuid, nil, false)
	if _, ok := r.Data["private"]; ok {
		t.Fatal("private key leaked")
	}
	request(logical.DeleteOperation, "export/"+uuid, nil, false)
	if request(logical.ReadOperation, "export/"+uuid, nil, false) != nil {
		t.Fatal("key survived delete")
	}
}
