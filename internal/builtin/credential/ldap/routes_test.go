// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestFactoryRouteSeparation(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		secret bool
		kind   logical.BackendType
		absent []string
	}{{false, logical.TypeCredential, []string{"role/example", "static-role/example", "static-migration"}}, {true, logical.TypeLogical, []string{"users/example", "login/example"}}} {
		conf := &logical.BackendConfig{StorageView: &logical.InmemStorage{}, System: &logical.StaticSystemView{}}
		factory := Factory
		if tc.secret {
			factory = SecretsFactory
		}
		b, e := factory(ctx, conf)
		if e != nil {
			t.Fatal(e)
		}
		if b.Type() != tc.kind {
			t.Fatal("incorrect backend type")
		}
		for _, path := range tc.absent {
			_, e := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: conf.StorageView})
			if !errors.Is(e, logical.ErrUnsupportedPath) {
				t.Fatalf("%s: %v", path, e)
			}
		}
	}
}
func TestOfflineConfigAndDeprecatedPolicies(t *testing.T) {
	call := harness(t, false)
	good(t, call(logical.UpdateOperation, "config", map[string]interface{}{"verify_connection": false, "policies": "legacy", "connection_timeout": "30s"}))
	r := call(logical.ReadOperation, "config", nil)
	p := r.Data["token_policies"].([]interface{})
	if len(p) != 1 || p[0] != "legacy" {
		t.Fatal(r)
	}
	for _, m := range []map[string]interface{}{{"max_page_size": -1}, {"token_explicit_max_ttl": -1}, {"dereference_aliases": "invalid"}, {"rotation_period": 9}, {"rotation_period": 86400, "rotation_window": 3600}} {
		bad(t, call(logical.UpdateOperation, "config", m))
	}
}
