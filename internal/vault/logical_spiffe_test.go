// SPDX-License-Identifier: MPL-2.0
package vault

import (
	"context"
	"encoding/json"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"testing"
	"time"
)

func spiffeTestBackend(t *testing.T, a bool) (logical.Backend, *logical.InmemStorage) {
	t.Helper()
	s := &logical.InmemStorage{}
	b, e := spiffeFactory(a, "http://localhost:8200")(context.Background(), &logical.BackendConfig{StorageView: s, System: &logical.StaticSystemView{DefaultLeaseTTLVal: time.Hour, MaxLeaseTTLVal: 24 * time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	return b, s
}
func spiffeTestCall(t *testing.T, b logical.Backend, s logical.Storage, op logical.Operation, p string, d map[string]interface{}, bad bool) *logical.Response {
	t.Helper()
	r, e := b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: p, Storage: s, Data: d, MountPoint: "spiffe/"})
	if e != nil {
		t.Fatal(e)
	}
	if bad {
		if r == nil || !r.IsError() {
			t.Fatalf("%s expected error: %#v", p, r)
		}
	} else if r != nil && r.IsError() {
		t.Fatalf("%s: %v", p, r)
	}
	return r
}
func TestSpiffeMountLifecycle(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	call := func(op logical.Operation, path, token string, data map[string]interface{}, denied bool) {
		t.Helper()
		r, e := c.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, ClientToken: token, Data: data})
		if denied {
			if e == nil && (r == nil || !r.IsError()) {
				t.Fatalf("unauthenticated %s allowed", path)
			}
			return
		}
		if e != nil || r != nil && r.IsError() {
			t.Fatalf("%s: %v %v", path, r, e)
		}
	}
	for _, p := range []string{"sys/auth/spiffe-test", "sys/mounts/spiffe-test"} {
		call(logical.UpdateOperation, p, root, map[string]interface{}{"type": "spiffe"}, false)
	}
	call(logical.UpdateOperation, "spiffe-test/config", root, map[string]interface{}{"trust_domain": "example.org", "jwt_signing_algorithm": "ES256"}, false)
	call(logical.ReadOperation, "spiffe-test/.well-known/keys", "", nil, false)
	call(logical.ReadOperation, "spiffe-test/.well-known/openid-configuration", "", nil, false)
	call(logical.ReadOperation, "spiffe-test/config", "", nil, true)
	call(logical.UpdateOperation, "spiffe-test/role/r/mintjwt", "", map[string]interface{}{"audience": "vault"}, true)
	for _, p := range []string{"sys/auth/spiffe-test", "sys/mounts/spiffe-test"} {
		call(logical.DeleteOperation, p, root, nil, false)
	}
}

func TestSpiffeCRUD(t *testing.T) {
	for _, a := range []bool{false, true} {
		b, s := spiffeTestBackend(t, a)
		call := func(op logical.Operation, p string, d map[string]interface{}, bad bool) *logical.Response {
			return spiffeTestCall(t, b, s, op, p, d, bad)
		}
		call(logical.UpdateOperation, "config", map[string]interface{}{}, true)
		call(logical.ListOperation, "role", nil, false)
		call(logical.UpdateOperation, "role/r", map[string]interface{}{}, true)
		if a {
			for _, d := range []map[string]interface{}{{"trust_domain": "example.org"}, {"trust_domain": "example.org", "profile": "bad"}, {"trust_domain": "example.org", "profile": "static", "bundle": "bad"}, {"trust_domain": "example.org", "profile": "https_web_bundle"}} {
				call(logical.UpdateOperation, "config", d, true)
			}
			call(logical.UpdateOperation, "config", map[string]interface{}{"trust_domain": "example.org", "profile": "https_web_bundle", "endpoint_url": "https://127.0.0.1:1", "defer_bundle_fetch": true}, false)
			call(logical.UpdateOperation, "role/r", map[string]interface{}{"workload_id_patterns": []string{"team/+/service", "other/*"}}, false)
			call(logical.UpdateOperation, "role/duplicate", map[string]interface{}{"workload_id_patterns": []string{"other/*"}}, true)
			call(logical.UpdateOperation, "role/invalid", map[string]interface{}{"workload_id_patterns": []string{"bad/*/path"}}, true)
			call(logical.UpdateOperation, "role/r", map[string]interface{}{"display_name": "updated"}, false)
		} else {
			call(logical.UpdateOperation, "config", map[string]interface{}{"trust_domain": "example.org", "jwt_signing_algorithm": "none"}, true)
			call(logical.UpdateOperation, "config", map[string]interface{}{"trust_domain": "example.org", "key_lifetime": "1h", "bundle_refresh_hint": "1h"}, true)
			call(logical.UpdateOperation, "config", map[string]interface{}{"trust_domain": "example.org", "jwt_signing_algorithm": "ES256"}, false)
			call(logical.UpdateOperation, "role/r", map[string]interface{}{"template": "{}"}, true)
			call(logical.UpdateOperation, "role/r", map[string]interface{}{"template": `{"sub":"/service"}`}, false)
			call(logical.UpdateOperation, "role/r", map[string]interface{}{"ttl": "10m"}, false)
		}
		if call(logical.ReadOperation, "config", nil, false).Data["trust_domain"] != "example.org" {
			t.Fatal("config read")
		}
		if call(logical.ReadOperation, "role/r", nil, false) == nil {
			t.Fatal("missing role")
		}
		call(logical.ListOperation, "role", nil, false)
		call(logical.DeleteOperation, "role/r", nil, false)
		if call(logical.ReadOperation, "role/r", nil, false) != nil {
			t.Fatal("deleted role present")
		}
	}
}
func TestSpiffeRoundTrip(t *testing.T) {
	for _, alg := range spiffeAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			b, s := spiffeTestBackend(t, false)
			spiffeTestCall(t, b, s, logical.UpdateOperation, "config", map[string]interface{}{"trust_domain": "example.org", "jwt_signing_algorithm": string(alg)}, false)
			spiffeTestCall(t, b, s, logical.UpdateOperation, "role/r", map[string]interface{}{"template": `{"sub":"/team/workload","exp":1}`, "use_jti_claim": true}, false)
			raw := spiffeTestCall(t, b, s, logical.UpdateOperation, "role/r/mintjwt", map[string]interface{}{"audience": "vault"}, false).Data["token"].(string)
			bundle := spiffeTestCall(t, b, s, logical.ReadOperation, ".well-known/keys", nil, false).Data[logical.HTTPRawBody].([]byte)
			var keys jose.JSONWebKeySet
			if e := json.Unmarshal(bundle, &keys); e != nil || len(keys.Keys) != 1 {
				t.Fatal(string(bundle), e)
			}
			if !keys.Keys[0].IsPublic() {
				t.Fatal("private key disclosed")
			}
			token, e := jwt.ParseSigned(raw, spiffeAlgorithms)
			if e != nil {
				t.Fatal(e)
			}
			var c jwt.Claims
			if e = token.Claims(keys.Keys[0].Key, &c); e != nil {
				t.Fatal(e)
			}
			if e = c.Validate(jwt.Expected{Subject: "spiffe://example.org/team/workload", AnyAudience: jwt.Audience{"vault"}, Time: time.Now()}); e != nil {
				t.Fatal(e)
			}
			if c.ID == "" || c.Expiry.Time().Sub(c.IssuedAt.Time()) != 5*time.Minute {
				t.Fatal(c)
			}
			spiffeTestCall(t, b, s, logical.ReadOperation, ".well-known/openid-configuration", nil, false)
			if len(b.SpecialPaths().Unauthenticated) != 2 {
				t.Fatal("public paths")
			}
			a, as := spiffeTestBackend(t, true)
			spiffeTestCall(t, a, as, logical.UpdateOperation, "config", map[string]interface{}{"trust_domain": "example.org", "profile": "static", "bundle": string(bundle), "audience": []string{"vault"}}, false)
			spiffeTestCall(t, a, as, logical.UpdateOperation, "role/r", map[string]interface{}{"workload_id_patterns": []string{"team/+"}}, false)
			login := func(token string) *logical.Response {
				r, e := a.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "login", Storage: as, Headers: map[string][]string{"Authorization": {"Bearer " + token}}})
				if e != nil {
					t.Fatal(e)
				}
				return r
			}
			if r := login(raw); r == nil || r.Auth == nil || r.Auth.Alias.Name != c.Subject {
				t.Fatalf("login %#v", r)
			}
			if r := login(raw + "bad"); r == nil || !r.IsError() {
				t.Fatal("tampering accepted")
			}
			spiffeTestCall(t, a, as, logical.UpdateOperation, "config", map[string]interface{}{"audience": []string{}}, false)
			if r := login(raw); r == nil || !r.IsError() {
				t.Fatal("empty audience accepted")
			}
		})
	}
}
