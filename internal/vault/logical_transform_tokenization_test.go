// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/openbao/openbao/sdk/v2/logical"
	"testing"
	"time"
)

func TestTransformTokenization(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, err := TransformBackendFactory(ctx, conf)
	if err != nil {
		t.Fatal(err)
	}
	call := func(op logical.Operation, path string, data map[string]interface{}, bad bool) *logical.Response {
		t.Helper()
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, Storage: storage})
		if err != nil {
			t.Fatal(err)
		}
		if (resp != nil && resp.IsError()) != bad {
			t.Fatalf("%s: %#v", path, resp)
		}
		return resp
	}
	for _, data := range []map[string]interface{}{{}, {"type": "sql"}, {"type": "sql", "driver": "postgres"}, {"type": "sql", "driver": "invalid", "connection_string": "x", "username": "u", "password": "p"}, {"type": "sql", "driver": "mysql", "connection_string": "postgresql://x", "username": "u", "password": "p"}} {
		call(logical.UpdateOperation, "stores/test", data, true)
	}
	if r := call(logical.ReadOperation, "stores/test", nil, false); r != nil {
		t.Fatal("invalid store persisted")
	}
	call(logical.UpdateOperation, "stores/test", map[string]interface{}{"type": "sql", "driver": "postgres", "connection_string": "postgresql://{{username}}:{{password}}@localhost/db", "username": "u", "password": "secret"}, false)
	read := call(logical.ReadOperation, "stores/test", nil, false)
	if read.Data["password"] != nil || read.Data["driver"] != "postgres" {
		t.Fatal(read)
	}
	call(logical.UpdateOperation, "stores/test", map[string]interface{}{"username": "updated"}, false)
	if call(logical.ReadOperation, "stores/test", nil, false).Data["username"] != "updated" {
		t.Fatal("store update lost")
	}
	if len(call(logical.ListOperation, "stores", nil, false).Data["keys"].([]string)) != 1 {
		t.Fatal("store missing from list")
	}
	call(logical.DeleteOperation, "stores/test", nil, false)
	call(logical.DeleteOperation, "stores/test", nil, false)
	if call(logical.ReadOperation, "stores/test", nil, false) != nil {
		t.Fatal("store not deleted")
	}
	call(logical.UpdateOperation, "transformations/tokenization/test", map[string]interface{}{"max_ttl": "1h", "allowed_roles": []string{"before"}, "deletion_allowed": true}, false)
	call(logical.UpdateOperation, "transformations/tokenization/test", map[string]interface{}{"max_ttl": "2h", "allowed_roles": []string{"test"}}, false)
	read = call(logical.ReadOperation, "transformation/test", nil, false)
	if read.Data["type"] != "tokenization" || read.Data["max_ttl"] != 7200 || read.Data["allowed_roles"].([]string)[0] != "test" || read.Data["id"] != nil {
		t.Fatal(read)
	}
	if len(call(logical.ListOperation, "transformation", map[string]interface{}{"filter": "te"}, false).Data["keys"].([]string)) != 1 {
		t.Fatal("transformation list")
	}
	call(logical.UpdateOperation, "role/test", map[string]interface{}{"transformations": []string{"test"}}, false)
	for _, op := range []string{"encode", "decode", "validate", "metadata"} {
		for _, data := range []map[string]interface{}{{"transformation": "test"}, {"value": ""}} {
			call(logical.UpdateOperation, op+"/test", data, true)
		}
	}
	encoded := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"value": "secret", "metadata": map[string]interface{}{"owner": "test"}}, false).Data["encoded_value"].(string)
	encoded2 := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"value": "secret"}, false).Data["encoded_value"].(string)
	if encoded == encoded2 {
		t.Fatal("nonconvergent token repeated")
	}
	b, err = TransformBackendFactory(ctx, conf)
	if err != nil {
		t.Fatal(err)
	}
	if call(logical.UpdateOperation, "decode/test", map[string]interface{}{"value": encoded}, false).Data["decoded_value"] != "secret" {
		t.Fatal("roundtrip")
	}
	if call(logical.UpdateOperation, "validate/test", map[string]interface{}{"value": encoded}, false).Data["valid"] != true {
		t.Fatal("valid token rejected")
	}
	if call(logical.UpdateOperation, "validate/test", map[string]interface{}{"value": "unknown"}, false).Data["valid"] != false {
		t.Fatal("unknown token accepted")
	}
	if call(logical.UpdateOperation, "metadata/test", map[string]interface{}{"value": encoded}, false).Data["metadata"].(map[string]string)["owner"] != "test" {
		t.Fatal("metadata lost")
	}
	call(logical.UpdateOperation, "decode/test", map[string]interface{}{"value": encoded, "source_id": "other"}, true)
	encodeTTLResp := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"value": "secret", "ttl": "3h"}, false)
	if encodeTTLResp == nil || encodeTTLResp.Data["encoded_value"] == nil || encodeTTLResp.Data["encoded_value"] == "" {
		t.Fatal("ttl-capped encode failed: ttl is capped at the transformation max_ttl, not rejected")
	}
	call(logical.UpdateOperation, "transformations/tokenization/test", map[string]interface{}{"convergent": true}, true)
	var config transformTokenConfig
	if _, err := transformLoad(ctx, storage, "transformation/test", &config); err != nil {
		t.Fatal(err)
	}
	var record transformTokenRecord
	key := "tokenization/" + config.ID + "/" + encoded
	if _, err := transformLoad(ctx, storage, key, &record); err != nil {
		t.Fatal(err)
	}
	record.Expires = time.Now().Add(-time.Second)
	if err := transformSave(ctx, storage, key, record); err != nil {
		t.Fatal(err)
	}
	call(logical.UpdateOperation, "decode/test", map[string]interface{}{"value": encoded}, true)
	call(logical.DeleteOperation, "transformation/test", nil, true)
	call(logical.DeleteOperation, "role/test", nil, false)
	call(logical.DeleteOperation, "transformation/test", nil, false)
	if call(logical.ReadOperation, "transformation/test", nil, false) != nil {
		t.Fatal("transformation not deleted")
	}
	call(logical.UpdateOperation, "transformations/tokenization/test", map[string]interface{}{"convergent": true, "allowed_roles": []string{"test"}}, false)
	call(logical.UpdateOperation, "role/test", map[string]interface{}{"transformations": []string{"test"}}, false)
	call(logical.UpdateOperation, "decode/test", map[string]interface{}{"value": encoded2}, true)
	first := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"value": "same"}, false).Data["encoded_value"]
	second := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"value": "same"}, false).Data["encoded_value"]
	if first != second {
		t.Fatal("convergence")
	}
	call(logical.UpdateOperation, "role/other", map[string]interface{}{"transformations": []string{"test"}}, false)
	call(logical.UpdateOperation, "encode/other", map[string]interface{}{"value": "secret"}, true)
	call(logical.DeleteOperation, "role/test", nil, false)
	call(logical.DeleteOperation, "role/other", nil, false)
	call(logical.DeleteOperation, "transformation/test", nil, true)
}
