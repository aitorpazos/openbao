// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func managedKeyRequest(t *testing.T, b logical.Backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}, bad bool) *logical.Response {
	t.Helper()
	r, err := b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Data: data, Storage: s})
	if err != nil {
		t.Fatal(err)
	}
	if (r != nil && r.IsError()) != bad {
		t.Fatalf("%s %s: %#v", op, path, r)
	}
	return r
}
func TestManagedKeyRegistry(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}
	b := &framework.Backend{Paths: (&SystemBackend{}).managedKeyPaths()}
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s}); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"pkcs11", "awskms", "azurekeyvault", "gcpckms", "invalid"} {
		t.Run(typ, func(t *testing.T) {
			managedKeyRequest(t, b, s, logical.UpdateOperation, "managed-keys/"+typ+"/missing", nil, true)
		})
	}
	configs := map[string]map[string]interface{}{
		"pkcs11":        {"library": "fixture", "pin": "secret", "slot": "1", "key_label": "key", "mechanism": "0x0001"},
		"awskms":        {"kms_key": "existing-key", "key_type": "RSA", "key_bits": "2048"},
		"azurekeyvault": {"tenant_id": "tenant", "vault_name": "vault", "key_name": "key", "key_type": "RSA-HSM"},
		"gcpckms":       {"crypto_key": "key", "key_ring": "ring", "project": "project", "region": "region", "algorithm": "EC_SIGN_P256_SHA256"},
	}
	for typ, config := range configs {
		t.Run(typ+"CRUD", func(t *testing.T) {
			path := "managed-keys/" + typ + "/test-" + typ
			if r := managedKeyRequest(t, b, s, logical.ReadOperation, path, nil, false); r != nil {
				t.Fatal(r)
			}
			managedKeyRequest(t, b, s, logical.UpdateOperation, path, config, false)
			r := managedKeyRequest(t, b, s, logical.ReadOperation, path, nil, false)
			if r.Data["UUID"] == nil || r.Data["name"] != "test-"+typ {
				t.Fatal(r)
			}
			if typ == "pkcs11" && r.Data["pin"] != "redacted" {
				t.Fatal(r)
			}
			managedKeyRequest(t, b, s, logical.UpdateOperation, path, map[string]interface{}{"any_mount": true}, false)
			managedKeyRequest(t, b, s, logical.UpdateOperation, path, map[string]interface{}{"any_mount": false}, false)
			r = managedKeyRequest(t, b, s, logical.ReadOperation, path, nil, false)
			if r.Data["any_mount"] != false {
				t.Fatal(r)
			}
			managedKeyRequest(t, b, s, logical.UpdateOperation, path, map[string]interface{}{"usages": "invalid"}, true)
			r = managedKeyRequest(t, b, s, logical.ListOperation, "managed-keys/"+typ, nil, false)
			if len(r.Data["keys"].([]string)) != 1 {
				t.Fatal(r)
			}
			managedKeyRequest(t, b, s, logical.DeleteOperation, path, nil, false)
			if r = managedKeyRequest(t, b, s, logical.ReadOperation, path, nil, false); r != nil {
				t.Fatal(r)
			}
		})
	}
}
func TestKeyMgmtLifecycle(t *testing.T) {
	s := &logical.InmemStorage{}
	b, err := KeyMgmtBackendFactory(context.Background(), &logical.BackendConfig{StorageView: s})
	if err != nil {
		t.Fatal(err)
	}
	req := func(op logical.Operation, path string, data map[string]interface{}, bad bool) *logical.Response {
		return managedKeyRequest(t, b, s, op, path, data, bad)
	}
	req(logical.UpdateOperation, "key/bad", map[string]interface{}{"type": "invalid"}, true)
	req(logical.UpdateOperation, "key/local", nil, false)
	r := req(logical.ReadOperation, "key/local", nil, false)
	if r.Data["latest_version"] != 1 || r.Data["type"] != "rsa-2048" {
		t.Fatal(r)
	}
	versions := r.Data["keys"].(map[string]interface{})
	v := versions["1"].(map[string]interface{})
	if _, ok := v["private_key"]; ok {
		t.Fatal("private key exposed")
	}
	block, _ := pem.Decode([]byte(v["public_key"].(string)))
	if block == nil {
		t.Fatal("invalid PEM")
	}
	if _, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	req(logical.DeleteOperation, "key/local", nil, true)
	req(logical.UpdateOperation, "key/local/rotate", nil, false)
	req(logical.UpdateOperation, "key/local", map[string]interface{}{"min_enabled_version": 3}, true)
	req(logical.UpdateOperation, "key/local", map[string]interface{}{"min_enabled_version": 2, "deletion_allowed": true}, false)
	req(logical.UpdateOperation, "key/local", map[string]interface{}{"deletion_allowed": false}, false)
	req(logical.DeleteOperation, "key/local", nil, true)
	// Recreate backend to verify persisted versions survive backend recreation.
	b, err = KeyMgmtBackendFactory(context.Background(), &logical.BackendConfig{StorageView: s})
	if err != nil {
		t.Fatal(err)
	}
	r = req(logical.ReadOperation, "key/local", nil, false)
	if r.Data["latest_version"] != 2 || r.Data["min_enabled_version"] != 2 {
		t.Fatal(r)
	}
	if r.Data["keys"].(map[string]interface{})["2"].(map[string]interface{})["public_key"] == v["public_key"] {
		t.Fatal("rotation reused key")
	}
	req(logical.UpdateOperation, "key/local", map[string]interface{}{"deletion_allowed": true}, false)
	req(logical.DeleteOperation, "key/local", nil, false)
	if r = req(logical.ReadOperation, "key/local", nil, false); r != nil {
		t.Fatal(r)
	}
	for _, typ := range []string{"aes256-gcm96", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"} {
		req(logical.UpdateOperation, "key/"+typ, map[string]interface{}{"type": typ}, false)
	}
}
func TestKeyManagementProviders(t *testing.T) {
	s := &logical.InmemStorage{}
	b, err := KeyMgmtBackendFactory(context.Background(), &logical.BackendConfig{StorageView: s})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []map[string]interface{}{{}, {"key_collection": "x"}, {"provider": "invalid", "key_collection": "x"}, {"provider": "awskms"}, {"provider": "azurekeyvault"}, {"provider": "gcpckms"}} {
		managedKeyRequest(t, b, s, logical.UpdateOperation, "kms/provider", data, true)
	}
	managedKeyRequest(t, b, s, logical.UpdateOperation, "kms/provider", map[string]interface{}{"provider": "awskms", "key_collection": "collection", "credentials": map[string]interface{}{"secret_key": "secret"}}, false)
	r := managedKeyRequest(t, b, s, logical.ReadOperation, "kms/provider", nil, false)
	if _, ok := r.Data["credentials"]; ok {
		t.Fatal("credentials exposed")
	}
	managedKeyRequest(t, b, s, logical.UpdateOperation, "kms/provider", map[string]interface{}{"provider": "gcpckms"}, true)
	managedKeyRequest(t, b, s, logical.DeleteOperation, "kms/provider", nil, false)
}
