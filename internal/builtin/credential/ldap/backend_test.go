// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func harness(t *testing.T, secret bool) func(logical.Operation, string, map[string]interface{}) *logical.Response {
	t.Helper()
	ctx := context.Background()
	s := &logical.InmemStorage{}
	b := newBackend(secret)
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s, System: &logical.StaticSystemView{}}); err != nil {
		t.Fatal(err)
	}
	return func(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
		t.Helper()
		r, e := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, Storage: s})
		if e != nil {
			t.Fatalf("%s %s: %v", op, path, e)
		}
		return r
	}
}
func good(t *testing.T, r *logical.Response) {
	t.Helper()
	if r != nil && r.IsError() {
		t.Fatalf("unexpected error: %#v", r)
	}
}
func bad(t *testing.T, r *logical.Response) {
	t.Helper()
	if r == nil || !r.IsError() {
		t.Fatalf("expected rejection: %#v", r)
	}
}
func TestConfig(t *testing.T) {
	call := harness(t, false)
	if r := call(logical.ReadOperation, "config", nil); r != nil {
		t.Fatal(r)
	}
	good(t, call(logical.UpdateOperation, "config", map[string]interface{}{"url": "ldap://127.0.0.1:1", "bindpass": "secret", "rotation_url": "ldap://127.0.0.1:2", "rotation_schedule": "0 0 * * SAT", "rotation_window": 3600, "disable_automated_rotation": true, "token_ttl": "1h"}))
	r := call(logical.ReadOperation, "config", nil)
	if _, ok := r.Data["bindpass"]; ok {
		t.Fatal("password disclosed")
	}
	if _, ok := r.Data["client_tls_key"]; ok {
		t.Fatal("key disclosed")
	}
	if r.Data["rotation_url"] != "ldap://127.0.0.1:2" || r.Data["rotation_schedule"] != "0 0 * * SAT" || r.Data["disable_automated_rotation"] != true {
		t.Fatal(r)
	}
	good(t, call(logical.UpdateOperation, "config", map[string]interface{}{"userdn": "ou=People"}))
	r = call(logical.ReadOperation, "config", nil)
	if r.Data["userdn"] != "ou=People" || r.Data["rotation_schedule"] != "0 0 * * SAT" {
		t.Fatal(r)
	}
	for _, m := range []map[string]interface{}{{"rotation_period": 86400}, {"rotation_window": 3599}, {"rotation_schedule": "invalid"}, {"url": "https://example.com"}, {"certificate": "garbage"}, {"client_tls_key": "secret"}, {"verify_connection": true}, {"token_ttl": -1}, {"tls_min_version": "tls13", "tls_max_version": "tls12"}} {
		bad(t, call(logical.UpdateOperation, "config", m))
	}
	r = call(logical.ReadOperation, "config", nil)
	if r.Data["url"] != "ldap://127.0.0.1:1" {
		t.Fatal("failed write persisted")
	}
	bad(t, call(logical.UpdateOperation, "login/bob", map[string]interface{}{"password": "secret"}))
	bad(t, call(logical.UpdateOperation, "config/rotate-root", nil))
}
func TestMappings(t *testing.T) {
	call := harness(t, false)
	for _, kind := range []string{"users", "groups"} {
		good(t, call(logical.UpdateOperation, kind+"/Alice", map[string]interface{}{"policies": "admin,default"}))
		r := call(logical.ReadOperation, kind+"/alice", nil)
		if r == nil || r.Data["policies"] == nil {
			t.Fatal(r)
		}
		good(t, call(logical.ListOperation, kind, nil))
		good(t, call(logical.DeleteOperation, kind+"/ALICE", nil))
		if r := call(logical.ReadOperation, kind+"/alice", nil); r != nil {
			t.Fatal(r)
		}
	}
	good(t, call(logical.UpdateOperation, "config", map[string]interface{}{"case_sensitive_names": true}))
	good(t, call(logical.UpdateOperation, "users/Alice", map[string]interface{}{"groups": "engineering", "policies": "admin"}))
	if r := call(logical.ReadOperation, "users/alice", nil); r != nil {
		t.Fatal(r)
	}
	if r := call(logical.ReadOperation, "users/Alice", nil); r == nil {
		t.Fatal("missing case-sensitive user")
	}
}
func TestStaticRoles(t *testing.T) {
	call := harness(t, true)
	good(t, call(logical.UpdateOperation, "config", map[string]interface{}{"self_managed": true, "skip_static_role_import_rotation": true}))
	bad(t, call(logical.UpdateOperation, "config", map[string]interface{}{"self_managed": false}))
	bad(t, call(logical.UpdateOperation, "config", map[string]interface{}{"bindpass": "secret"}))
	base := func() map[string]interface{} {
		return map[string]interface{}{"username": "bob", "dn": "cn=bob", "password": "secret", "rotation_period": 86400, "rotation_policy": "compat-policy", "disable_automated_rotation": true}
	}
	for _, field := range []string{"password", "dn", "username"} {
		m := base()
		delete(m, field)
		bad(t, call(logical.UpdateOperation, "static-role/missing-"+field, m))
	}
	good(t, call(logical.UpdateOperation, "static-role/bob", base()))
	r := call(logical.ReadOperation, "static-role/bob", nil)
	if r.Data["rotation_policy"] != "compat-policy" || r.Data["dn"] != "cn=bob" {
		t.Fatal(r)
	}
	if _, ok := r.Data["password"]; ok {
		t.Fatal("password disclosed")
	}
	bad(t, call(logical.UpdateOperation, "static-role/bob", map[string]interface{}{"dn": "cn=other"}))
	m := base()
	m["skip_import_rotation"] = false
	bad(t, call(logical.UpdateOperation, "static-role/remote", m))
	m = base()
	m["rotation_schedule"] = "0 0 * * SAT"
	bad(t, call(logical.UpdateOperation, "static-role/invalid", m))
	good(t, call(logical.ListOperation, "static-role", nil))
	bad(t, call(logical.UpdateOperation, "rotate-role/bob", nil))
	bad(t, call(logical.UpdateOperation, "static-migration", nil))
	good(t, call(logical.DeleteOperation, "static-role/bob", nil))
	if r := call(logical.ReadOperation, "static-role/bob", nil); r != nil {
		t.Fatal(r)
	}
}
func TestEmptyMigration(t *testing.T) {
	call := harness(t, true)
	bad(t, call(logical.ReadOperation, "static-migration", nil))
	good(t, call(logical.ReadOperation, "static-migration", map[string]interface{}{"include_role_names": false}))
	good(t, call(logical.UpdateOperation, "static-migration", nil))
	good(t, call(logical.UpdateOperation, "static-migration/stop", nil))
}
func TestSchedule(t *testing.T) {
	for _, s := range []string{"0 0 * * SAT", "*/5 0-12 * JAN,MAR MON-FRI"} {
		if e := validateSchedule(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"bad", "60 0 * * *", "0 24 * * *", "0 0 0 * *", "0 0 * 13 *", "*/0 * * * *", "0 0 * * FOO"} {
		if e := validateSchedule(s); e == nil {
			t.Fatal(s)
		}
	}
}
