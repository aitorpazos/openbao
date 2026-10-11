// SPDX-License-Identifier: MPL-2.0
package gcp

import (
	"context"
	"encoding/json"
	"github.com/openbao/openbao/sdk/v2/logical"
	"strings"
	"testing"
)

func TestConfigurationOnly(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	b, err := Factory(ctx, &logical.BackendConfig{StorageView: storage, System: &logical.StaticSystemView{}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(op logical.Operation, path string, data map[string]interface{}, bad bool) *logical.Response {
		t.Helper()
		r, e := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: storage, Data: data})
		if e != nil {
			t.Fatalf("%s %s: %v", op, path, e)
		}
		if bad {
			if r == nil || !r.IsError() {
				t.Fatalf("expected error: %#v", r)
			}
		} else if r != nil && r.IsError() {
			t.Fatalf("%s: %#v", path, r)
		}
		return r
	}
	config := map[string]interface{}{"tenant_id": "tenant", "resource": "https://management.azure.com/", "credentials": "", "rotation_schedule": "0 0 * * SAT", "rotation_window": 3600, "disable_automated_rotation": true}
	r := call(logical.UpdateOperation, "config", config, false)
	if len(r.Warnings) == 0 {
		t.Fatal("missing config-only warning")
	}
	r = call(logical.ReadOperation, "config", nil, false)
	if r.Data["rotation_schedule"] != "0 0 * * SAT" || toJSON(r.Data["rotation_window"]) != "3600" {
		t.Fatalf("bad read: %#v", r)
	}
	for _, k := range []string{"access_key", "secret_key", "token", "client_secret", "credentials", "subscription_id", "resource_group_name"} {
		if _, ok := r.Data[k]; ok {
			t.Fatalf("leaked %s", k)
		}
	}
	before, _ := json.Marshal(r.Data)
	for _, negative := range []map[string]interface{}{
		{"rotation_period": 86400, "rotation_schedule": "0 0 * * SAT", "rotation_window": 0},
		{"rotation_period": 86400, "rotation_schedule": "", "rotation_window": 3600},
		{"rotation_period": 9, "rotation_schedule": "", "rotation_window": 0},
		{"rotation_period": 0, "rotation_schedule": "0 0 * * SAT", "rotation_window": 3599},
		{"rotation_schedule": "not cron"}, {"identity_token_ttl": -1}, {"verify_connection": true},
	} {
		call(logical.UpdateOperation, "config", negative, true)
	}
	r = call(logical.ReadOperation, "config", nil, false)
	after, _ := json.Marshal(r.Data)
	if string(before) != string(after) {
		t.Fatal("failed validation changed storage")
	}
	call(logical.DeleteOperation, "config", nil, false)
	if call(logical.ReadOperation, "config", nil, false) != nil {
		t.Fatal("delete failed")
	}
	wif := map[string]interface{}{"tenant_id": "tenant", "resource": "https://management.azure.com/", "service_account_email": "svc@example.com", "identity_token_audience": "aud", "identity_token_ttl": 600}
	call(logical.UpdateOperation, "config", wif, false)
	r = call(logical.ReadOperation, "config", nil, false)
	if r.Data["identity_token_audience"] != "aud" || toJSON(r.Data["identity_token_ttl"]) != "600" {
		t.Fatal(r)
	}
	conflict := map[string]interface{}{"credentials": `{"type":"service_account"}`}
	call(logical.UpdateOperation, "config", conflict, true)
	call(logical.UpdateOperation, "roleset/demo", map[string]interface{}{"project": "test-project", "bindings": `resource "project/test" { roles = ["roles/viewer"] }`}, false)
	r = call(logical.ReadOperation, "roleset/demo", nil, false)
	if r == nil || len(r.Data) == 0 {
		t.Fatal("missing role")
	}
	r = call(logical.ListOperation, "rolesets", nil, false)
	if !strings.Contains(strings.TrimSpace(toJSON(r.Data)), "demo") {
		t.Fatal(r)
	}
	call(logical.UpdateOperation, "roleset/invalid", map[string]interface{}{"auth_type": "invalid", "type": "invalid", "credential_type": "invalid", "secret_type": "invalid"}, true)
	call(logical.DeleteOperation, "roleset/demo", nil, false)
	if call(logical.ReadOperation, "roleset/demo", nil, false) != nil {
		t.Fatal("role delete failed")
	}
	r = call(logical.UpdateOperation, "config/rotate-root", nil, true)
	if len(r.Warnings) == 0 {
		t.Fatal("missing rejection warning")
	}
}
func toJSON(v interface{}) string { b, _ := json.Marshal(v); return string(b) }
