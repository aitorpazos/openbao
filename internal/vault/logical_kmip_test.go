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
	"encoding/pem"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestKMIPHTTP(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	b, err := KMIPBackendFactory(ctx, logical.TestBackendConfig())
	if err != nil {
		t.Fatal(err)
	}
	call := func(op logical.Operation, path string, data map[string]interface{}, invalid bool) *logical.Response {
		t.Helper()
		r, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, Storage: storage})
		if err != nil {
			t.Fatalf("%s %s: %v", op, path, err)
		}
		if invalid {
			if r == nil || !r.IsError() {
				t.Fatalf("%s: expected error, got %#v", path, r)
			}
		} else if r != nil && r.IsError() {
			t.Fatalf("%s: %v", path, r.Error())
		}
		return r
	}
	write := logical.UpdateOperation
	read := logical.ReadOperation
	del := logical.DeleteOperation
	list := logical.ListOperation
	call(write, "scope/s", nil, false)
	r := call(list, "scope", nil, false)
	if len(r.Data["keys"].([]string)) != 1 {
		t.Fatal(r)
	}
	if call(read, "scope/s", nil, false).Data["name"] != "s" {
		t.Fatal("missing scope")
	}
	path := "scope/s/role/r"
	cred := path + "/credential"
	call(write, "scope/absent/role/r", nil, true)
	for _, pair := range [][2]string{{"all", "none"}, {"all", "get"}, {"none", "create"}, {"all", "encrypt"}, {"none", "revoke"}} {
		call(write, path, map[string]interface{}{"operation_" + pair[0]: true, "operation_" + pair[1]: true}, true)
	}
	call(write, path, map[string]interface{}{"operation_get": true}, false)
	if call(read, path, nil, false).Data["operation_get"] != true {
		t.Fatal("missing permission")
	}
	call(write, path, map[string]interface{}{"operation_all": true}, false)
	call(write, path, map[string]interface{}{"operation_get": true}, false)
	r = call(read, path, nil, false)
	if r.Data["operation_all"] != false || r.Data["operation_get"] != true {
		t.Fatal(r)
	}
	if len(call(list, "scope/s/role", nil, false).Data["keys"].([]string)) != 1 {
		t.Fatal("role list")
	}
	for _, m := range []map[string]interface{}{{"key_bits": 2048}, {"key_type": "rsa"}, {"key_type": "unsupported", "key_bits": 2048}, {"key_type": "rsa", "key_bits": 123}, {"key_type": "ec", "key_bits": 123}} {
		call(write, "ca/invalid/generate", m, true)
	}
	call(write, "ca/invalid/import", map[string]interface{}{"scope_name": "s", "role_name": "r"}, true)
	call(write, "ca/invalid/import", map[string]interface{}{"scope_name": "s", "role_name": "r", "ca_pem": "bad"}, true)
	for _, m := range []map[string]interface{}{nil, {"address": "127.0.0.1:5696"}, {"ca": "absent"}} {
		call(write, "listener/invalid", m, true)
	}
	call(read, "ca", nil, true)
	call(read, cred+"/lookup", nil, true)
	call(write, cred+"/revoke", nil, true)
	call(write, cred+"/revoke", map[string]interface{}{"serial_number": "1", "certificate": "bad"}, true)
	call(write, cred+"/sign", nil, true)
	call(write, cred+"/generate", map[string]interface{}{"format": "unsupported"}, true)
	r = call(write, cred+"/generate", map[string]interface{}{"format": "pem"}, false)
	c, err := kmipParseCert(r.Data["certificate"].(string))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(r.Data["private_key"].(string)))
	if block == nil {
		t.Fatal("missing key")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "r" || c.Subject.OrganizationalUnit[0] != "s" {
		t.Fatal(c.Subject)
	}
	serial := r.Data["serial_number"]
	r = call(read, cred+"/lookup", map[string]interface{}{"serial_number": serial, "format": "pem"}, false)
	if _, ok := r.Data["private_key"]; ok {
		t.Fatal("private key persisted")
	}
	call(write, cred+"/revoke", map[string]interface{}{"serial_number": serial}, false)
	if call(read, cred+"/lookup", map[string]interface{}{"serial_number": serial}, false) != nil {
		t.Fatal("revoked credential still exists")
	}
	ca := call(write, "ca/root/generate", map[string]interface{}{"key_type": "ec", "key_bits": 256}, false)
	if _, ok := ca.Data["private_key"]; ok {
		t.Fatal("CA key exposed")
	}
	caCert, err := kmipParseCert(ca.Data["certificate"].(string))
	if err != nil {
		t.Fatal(err)
	}
	call(write, path, map[string]interface{}{"ca": "root", "tls_client_key_type": "ec", "tls_client_key_bits": 256}, false)
	call(del, "ca/root", nil, true)
	r = call(write, cred+"/generate", map[string]interface{}{"format": "pem"}, false)
	c, err = kmipParseCert(r.Data["certificate"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.CheckSignatureFrom(caCert); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	r = call(write, cred+"/sign", map[string]interface{}{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "format": "pem"}, false)
	c, err = kmipParseCert(r.Data["certificate"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "r" {
		t.Fatal("CSR changed authorization identity")
	}
	if err = c.CheckSignatureFrom(caCert); err != nil {
		t.Fatal(err)
	}
	call(write, cred+"/revoke", map[string]interface{}{"certificate": r.Data["certificate"]}, false)
	t.Cleanup(func() { b.Cleanup(ctx) })
	r = call(write, "listener/l", map[string]interface{}{"ca": "root", "address": "127.0.0.1:0"}, false)
	if len(r.Warnings) != 0 {
		t.Fatal("native listener unexpectedly warned", r.Warnings)
	}
	call(write, "ca/imported/import", map[string]interface{}{"ca_pem": ca.Data["certificate"], "scope_name": "s", "role_field": "CN"}, false)
	call(write, "ca/imported", map[string]interface{}{"scope_field": "OU"}, true)
	call(write, "listener/bad", map[string]interface{}{"ca": "imported", "address": "127.0.0.1:5696"}, true)
	call(del, path, nil, false)
	if call(read, path, nil, false) != nil {
		t.Fatal("role not deleted")
	}
	call(del, "ca/root", nil, true)
	call(del, "listener/l", nil, false)
	call(del, "ca/root", nil, false)
	call(del, "scope/s", map[string]interface{}{"force": true}, false)
	keys, _ := call(list, "scope", nil, false).Data["keys"].([]string)
	if len(keys) != 0 {
		t.Fatal("scope not deleted")
	}
}
