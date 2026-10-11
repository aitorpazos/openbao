// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/logical/pki"
)

type authOSTestBackend struct {
	b logical.Backend
	s logical.Storage
	t *testing.T
}

func newAuthOSTestBackend(t *testing.T, f logical.Factory) *authOSTestBackend {
	t.Helper()
	s := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = s
	b, err := f(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Cleanup(context.Background()) })
	return &authOSTestBackend{b, s, t}
}
func (b *authOSTestBackend) req(op logical.Operation, path string, data map[string]interface{}, invalid bool) *logical.Response {
	b.t.Helper()
	r, err := b.b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Data: data, Storage: b.s})
	if invalid {
		if r == nil || !r.IsError() {
			b.t.Fatalf("%s %s: wanted invalid, got %#v %v", op, path, r, err)
		}
	} else if err != nil || (r != nil && r.IsError()) {
		b.t.Fatalf("%s %s: %#v %v", op, path, r, err)
	}
	return r
}
func authOSAssert(t *testing.T, r *logical.Response, k string, v interface{}) {
	t.Helper()
	if r == nil {
		t.Fatalf("nil response for %s", k)
	}
	a, _ := json.Marshal(r.Data[k])
	b, _ := json.Marshal(v)
	if string(a) != string(b) {
		t.Fatalf("%s: got %s want %s", k, a, b)
	}
}
func samlTestConfig(t *testing.T) map[string]interface{} {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{"entity_id": "https://sp.invalid", "acs_urls": []string{"https://sp.invalid/callback"}, "idp_sso_url": "https://idp.invalid/sso", "idp_entity_id": "idp", "idp_cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "validate_response_signature": true}
}
func TestSamlConfiguration(t *testing.T) {
	b := newAuthOSTestBackend(t, SamlBackendFactory)
	if r := b.req(logical.ReadOperation, "config", nil, false); r != nil {
		t.Fatal(r)
	}
	b.req(logical.UpdateOperation, "config", nil, true)
	config := samlTestConfig(t)
	b.req(logical.UpdateOperation, "config", config, false)
	authOSAssert(t, b.req(logical.ReadOperation, "config", nil, false), "entity_id", config["entity_id"])
	b.req(logical.UpdateOperation, "config", map[string]interface{}{"default_role": "r"}, false)
	authOSAssert(t, b.req(logical.ReadOperation, "config", nil, false), "default_role", "r")
	for _, bad := range []map[string]interface{}{{"entity_id": ""}, {"acs_urls": []string{}}, {"acs_urls": []string{"invalid"}}, {"idp_sso_url": "invalid"}, {"idp_cert": "bad"}, {"idp_entity_id": ""}, {"idp_metadata_url": "https://idp.invalid/metadata"}} {
		b.req(logical.UpdateOperation, "config", bad, true)
	}
	authOSAssert(t, b.req(logical.ReadOperation, "config", nil, false), "idp_cert", config["idp_cert"])
	b.req(logical.UpdateOperation, "config", map[string]interface{}{"idp_metadata_url": "https://idp.invalid/metadata", "idp_cert": "", "idp_sso_url": "", "idp_entity_id": ""}, false)
	b.req(logical.UpdateOperation, "config", map[string]interface{}{"idp_metadata_url": "invalid"}, true)
	for _, p := range []string{"sso_service_url", "token"} {
		b.req(logical.UpdateOperation, p, nil, true)
	}
}
func TestSamlRoleCRUD(t *testing.T) {
	b := newAuthOSTestBackend(t, SamlBackendFactory)
	for _, bad := range []map[string]interface{}{{"bound_subjects_type": "bad"}, {"bound_attributes_type": "bad"}, {"bound_attributes": map[string]interface{}{"x": 123}}, {"token_ttl": -1}, {"token_type": "invalid"}} {
		b.req(logical.UpdateOperation, "role/bad", bad, true)
	}
	b.req(logical.UpdateOperation, "role/r", map[string]interface{}{"bound_subjects": "*@example.invalid", "bound_subjects_type": "glob", "bound_attributes": map[string]interface{}{"group": "g"}, "token_type": "batch", "token_ttl": 300, "token_policies": []string{"a"}}, false)
	r := b.req(logical.ReadOperation, "role/r", nil, false)
	authOSAssert(t, r, "bound_subjects", []string{"*@example.invalid"})
	authOSAssert(t, r, "bound_attributes", map[string]interface{}{"group": []string{"g"}})
	authOSAssert(t, r, "token_ttl", 300)
	b.req(logical.UpdateOperation, "role/r", map[string]interface{}{"token_ttl": "10m", "token_policies": []string{"b"}, "bound_attributes": map[string]interface{}{"group": "g, h"}, "alias_metadata": map[string]interface{}{"source": "test"}}, false)
	r = b.req(logical.ReadOperation, "role/r", nil, false)
	authOSAssert(t, r, "token_ttl", 600)
	authOSAssert(t, r, "bound_attributes", map[string]interface{}{"group": []string{"g", "h"}})
	authOSAssert(t, r, "alias_metadata", map[string]string{"source": "test"})
	authOSAssert(t, b.req(logical.ListOperation, "role", nil, false), "keys", []string{"r"})
	b.req(logical.DeleteOperation, "role/r", nil, false)
	if r := b.req(logical.ReadOperation, "role/r", nil, false); r != nil {
		t.Fatal(r)
	}
}
func TestScepRoleCRUD(t *testing.T) {
	b := newAuthOSTestBackend(t, ScepBackendFactory)
	for _, bad := range []map[string]interface{}{{}, {"auth_type": "bad"}, {"auth_type": "static-challenge"}, {"auth_type": "intune", "token_type": "bad"}, {"auth_type": "intune", "token_ttl": -1}} {
		b.req(logical.UpdateOperation, "role/bad", bad, true)
	}
	b.req(logical.UpdateOperation, "role/static", map[string]interface{}{"auth_type": "static-challenge", "challenge": "secret", "token_type": "batch", "token_ttl": 300}, false)
	r := b.req(logical.ReadOperation, "role/static", nil, false)
	authOSAssert(t, r, "name", "static")
	authOSAssert(t, r, "display_name", "static")
	if _, ok := r.Data["challenge"]; ok {
		t.Fatal("challenge exposed")
	}
	b.req(logical.UpdateOperation, "role/static", map[string]interface{}{"challenge": "new", "display_name": "updated", "token_ttl": "10m"}, false)
	authOSAssert(t, b.req(logical.ReadOperation, "role/static", nil, false), "token_ttl", 600)
	b.req(logical.UpdateOperation, "role/intune", map[string]interface{}{"auth_type": "intune", "token_type": "batch"}, false)
	authOSAssert(t, b.req(logical.ListOperation, "role", nil, false), "keys", []string{"intune", "static"})
	for _, name := range []string{"static", "intune"} {
		b.req(logical.DeleteOperation, "role/"+name, nil, false)
		if r := b.req(logical.ReadOperation, "role/"+name, nil, false); r != nil {
			t.Fatal(r)
		}
	}
	r = b.req(logical.ListOperation, "role", nil, false)
	if len(r.Data) != 0 {
		t.Fatal(r)
	}
}
func TestScepPKIConfiguration(t *testing.T) {
	b := newAuthOSTestBackend(t, pki.Factory)
	authOSAssert(t, b.req(logical.ReadOperation, "config/scep", nil, false), "enabled", false)
	for _, bad := range []map[string]interface{}{{"allowed_digest_algorithms": []string{"invalid"}}, {"allowed_encryption_algorithms": []string{"invalid"}}, {"enabled": true}, {"default_path_policy": "invalid"}, {"log_level": "invalid"}, {"authenticators": map[string]interface{}{"invalid": map[string]interface{}{"accessor": "x"}}}, {"authenticators": map[string]interface{}{"scep": map[string]interface{}{}}}, {"external_validation": map[string]interface{}{}}} {
		b.req(logical.UpdateOperation, "config/scep", bad, true)
	}
	config := map[string]interface{}{"enabled": false, "default_path_policy": "sign-verbatim", "allowed_digest_algorithms": []string{"sha-256"}, "allowed_encryption_algorithms": []string{"aes256-cbc"}, "restrict_ca_chain_to_issuer": true}
	b.req(logical.UpdateOperation, "config/scep", config, false)
	r := b.req(logical.ReadOperation, "config/scep", nil, false)
	for k, v := range config {
		authOSAssert(t, r, k, v)
	}
	b.req(logical.UpdateOperation, "config/scep", map[string]interface{}{"restrict_ca_chain_to_issuer": false}, false)
	authOSAssert(t, b.req(logical.ReadOperation, "config/scep", nil, false), "restrict_ca_chain_to_issuer", false)
}
func TestOsEngineConfiguration(t *testing.T) {
	b := newAuthOSTestBackend(t, OsEngineBackendFactory)
	authOSAssert(t, b.req(logical.ReadOperation, "config", nil, false), "max_versions", 10)
	for _, n := range []int{-1, 0} {
		b.req(logical.UpdateOperation, "config", map[string]interface{}{"max_versions": n}, true)
	}
	b.req(logical.UpdateOperation, "config", map[string]interface{}{"max_versions": 5, "ssh_host_key_trust_on_first_use": false}, false)
	authOSAssert(t, b.req(logical.ReadOperation, "config", nil, false), "max_versions", 5)
	b.req(logical.UpdateOperation, "config", map[string]interface{}{"max_versions": 2}, false)
	authOSAssert(t, b.req(logical.ReadOperation, "config", nil, false), "max_versions", 2)
}
func TestOsHostAccountLifecycle(t *testing.T) {
	b := newAuthOSTestBackend(t, OsEngineBackendFactory)
	for _, bad := range []map[string]interface{}{{}, {"address": "localhost", "port": 0}, {"address": "localhost", "port": 65536}, {"address": "localhost", "ssh_host_key": "bad"}, {"address": "localhost", "rotation_period": 10}} {
		b.req(logical.UpdateOperation, "hosts/bad", bad, true)
	}
	b.req(logical.UpdateOperation, "hosts/h", map[string]interface{}{"address": "127.0.0.1", "port": 1, "disable_automated_rotation": true, "custom_metadata": map[string]interface{}{"old": "v"}}, false)
	b.req(logical.UpdateOperation, "hosts/h", map[string]interface{}{"custom_metadata": map[string]interface{}{"new": "v"}}, false)
	authOSAssert(t, b.req(logical.ReadOperation, "hosts/h", nil, false), "custom_metadata", map[string]string{"new": "v"})
	authOSAssert(t, b.req(logical.ListOperation, "hosts", nil, false), "keys", []string{"h"})
	path := "hosts/h/accounts/a"
	for _, bad := range []map[string]interface{}{{"username": "u", "verify_connection": false}, {"password": "p", "verify_connection": false}, {"username": "u", "password": "p"}, {"username": "u", "password": "p", "verify_connection": false, "rotation_schedule": "* * * * *"}} {
		b.req(logical.UpdateOperation, path, bad, true)
	}
	b.req(logical.UpdateOperation, "hosts/missing/accounts/a", map[string]interface{}{"username": "u", "password": "p", "verify_connection": false}, true)
	b.req(logical.UpdateOperation, path, map[string]interface{}{"username": "u", "password": "p", "verify_connection": false, "disable_automated_rotation": true, "custom_metadata": map[string]interface{}{"old": "v"}}, false)
	b.req(logical.DeleteOperation, "hosts/h", nil, true)
	b.req(logical.UpdateOperation, path, map[string]interface{}{"custom_metadata": map[string]interface{}{"new": "v"}}, false)
	r := b.req(logical.ReadOperation, path, nil, false)
	authOSAssert(t, r, "custom_metadata", map[string]string{"new": "v"})
	if _, ok := r.Data["password"]; ok {
		t.Fatal("password leaked")
	}
	b.req(logical.UpdateOperation, path, map[string]interface{}{"password": "different"}, true)
	authOSAssert(t, b.req(logical.ReadOperation, path+"/creds", nil, false), "password", "p")
	authOSAssert(t, b.req(logical.ListOperation, "hosts/h/accounts/", nil, false), "keys", []string{"a"})
	b.req(logical.UpdateOperation, path+"/reset", nil, true)
	b.req(logical.UpdateOperation, path+"/versions/999/restore", nil, true)
	before := b.req(logical.ReadOperation, path+"/versions", nil, false)
	v := before.Data["current_version"].(int)
	b.req(logical.UpdateOperation, path+"/reset", map[string]interface{}{"password": "p2"}, false)
	authOSAssert(t, b.req(logical.ReadOperation, path+"/creds", nil, false), "password", "p2")
	b.req(logical.UpdateOperation, path+"/versions/"+strconv.Itoa(v)+"/restore", nil, false)
	authOSAssert(t, b.req(logical.ReadOperation, path+"/creds", nil, false), "password", "p")
	b.req(logical.UpdateOperation, "config", map[string]interface{}{"max_versions": 2}, false)
	b.req(logical.UpdateOperation, path+"/reset", map[string]interface{}{"password": "p3"}, false)
	versions := b.req(logical.ReadOperation, path+"/versions", nil, false)
	if reflect.ValueOf(versions.Data["versions"]).Len() != 2 {
		t.Fatal(versions)
	}
	encoded, _ := json.Marshal(versions)
	if strings.Contains(string(encoded), "password") {
		t.Fatal("version metadata exposed secret")
	}
	b.req(logical.UpdateOperation, path+"/versions/"+strconv.Itoa(v)+"/restore", nil, true)
	b.req(logical.DeleteOperation, path, nil, false)
	if r := b.req(logical.ReadOperation, path+"/creds", nil, false); r != nil {
		t.Fatal(r)
	}
	if r := b.req(logical.ListOperation, "hosts/h/accounts/", nil, false); len(r.Data) != 0 {
		t.Fatal(r)
	}
	b.req(logical.DeleteOperation, "hosts/h", nil, false)
	if r := b.req(logical.ReadOperation, "hosts/h", nil, false); r != nil {
		t.Fatal(r)
	}
	if r := b.req(logical.ListOperation, "hosts", nil, false); len(r.Data) != 0 {
		t.Fatal(r)
	}
}
