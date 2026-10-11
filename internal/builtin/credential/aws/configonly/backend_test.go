// SPDX-License-Identifier: MPL-2.0

package configonly

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestAdditionalCRUD(t *testing.T) {
	for _, tc := range []struct {
		provider, path, list string
		secret               bool
		body                 map[string]interface{}
	}{
		{"aws", "config/certificate/test", "config/certificates", false, map[string]interface{}{"aws_public_cert": testCertificate(t)}},
		{"aws", "config/sts/123456789012", "config/sts", false, map[string]interface{}{"sts_role": "arn:aws:iam::123456789012:role/test", "external_id": "test"}},
		{"gcp", "static-account/test", "static-accounts", true, map[string]interface{}{"service_account_email": "test@example.com", "secret_type": "access_token", "token_scopes": []string{"scope"}}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			ctx := context.Background()
			b := New(tc.provider, tc.secret)
			s := &logical.InmemStorage{}
			if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s, System: &logical.StaticSystemView{}}); err != nil {
				t.Fatal(err)
			}
			call := func(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
				t.Helper()
				r, e := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: s, Data: data})
				if e != nil || r != nil && r.IsError() {
					t.Fatalf("%s: %#v %v", path, r, e)
				}
				return r
			}
			call(logical.UpdateOperation, tc.path, tc.body)
			if r := call(logical.ReadOperation, tc.path, nil); r == nil {
				t.Fatal("not persisted")
			}
			if r := call(logical.ListOperation, tc.list, nil); len(r.Data["keys"].([]string)) != 1 {
				t.Fatal(r)
			}
			if tc.provider == "gcp" {
				r, e := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: tc.path, Storage: s, Data: map[string]interface{}{"service_account_email": "changed@example.com"}})
				if e != nil || r == nil || !r.IsError() {
					t.Fatalf("immutable selector accepted: %#v %v", r, e)
				}
			}
			call(logical.DeleteOperation, tc.path, nil)
			if call(logical.ReadOperation, tc.path, nil) != nil {
				t.Fatal("delete failed")
			}
		})
	}
}
func testCertificate(t *testing.T) string {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestCloudOperationsRejected(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			b := New(provider, true)
			s := &logical.InmemStorage{}
			ctx := context.Background()
			if e := b.Setup(ctx, &logical.BackendConfig{StorageView: s}); e != nil {
				t.Fatal(e)
			}
			paths := []string{"config/rotate-root", "creds/test"}
			if provider == "gcp" {
				paths = append(paths, "roleset/test/token", "roleset/test/key", "static-account/test/rotate-key")
			}
			for _, p := range paths {
				r, e := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: p, Storage: s})
				if e != nil || r == nil || !r.IsError() || len(r.Warnings) == 0 {
					t.Fatalf("%s: %#v %v", p, r, e)
				}
			}
		})
	}
}
