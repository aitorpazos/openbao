// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// NIST's public-domain FF1 samples 1–3:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
func TestTransformFF1NIST(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	alphabet := "0123456789abcdefghijklmnopqrstuvwxyz"
	for _, tc := range []struct {
		radix                int
		plain, tweak, cipher string
	}{{10, "0123456789", "", "2433477484"}, {10, "0123456789", "9876543210", "6124200773"}, {36, "0123456789abcdefghi", "7777pqrs777", "a9tv40mll9kdu509eum"}} {
		for _, decrypt := range []bool{false, true} {
			input, want := tc.plain, tc.cipher
			if decrypt {
				input, want = want, input
			}
			digits := []int{}
			for _, ch := range input {
				digits = append(digits, strings.IndexRune(alphabet, ch))
			}
			got, err := transformFF1(key, []byte(tc.tweak), tc.radix, digits, decrypt)
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			for _, v := range got {
				out.WriteByte(alphabet[v])
			}
			if out.String() != want {
				t.Fatalf("decrypt=%v got %s want %s", decrypt, out.String(), want)
			}
		}
	}
	if _, err := transformFF1(key, nil, 10, []int{1, 2, 3}, false); err == nil {
		t.Fatal("small domain accepted")
	}
}
func TestTransformFPELifecycle(t *testing.T) {
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
	for _, alphabet := range []string{"numeric", "alphanumericlower"} {
		call(logical.UpdateOperation, "template/test", map[string]interface{}{"type": "regex", "pattern": "([0-9a-z]+)", "alphabet": "builtin/" + alphabet}, false)
		call(logical.UpdateOperation, "transformations/fpe/test", map[string]interface{}{"template": "test", "tweak_source": "internal", "allowed_roles": []string{"test"}}, false)
		read := call(logical.ReadOperation, "transformation/test", nil, false)
		if read.Data["type"] != "fpe" || read.Data["key"] != nil {
			t.Fatal(read)
		}
		call(logical.ListOperation, "transformation", nil, false)
		call(logical.DeleteOperation, "transformation/test", nil, true)
		call(logical.UpdateOperation, "role/test", map[string]interface{}{"transformations": []string{"test"}}, false)
		plain := "0123456789"
		if alphabet != "numeric" {
			plain = "0123abcdefghi"
		}
		encoded := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"value": plain}, false).Data["encoded_value"].(string)
		// Recreate the backend: key and internal tweak must survive restart.
		b, err = TransformBackendFactory(ctx, conf)
		if err != nil {
			t.Fatal(err)
		}
		decoded := call(logical.UpdateOperation, "decode/test", map[string]interface{}{"value": encoded}, false).Data["decoded_value"]
		if decoded != plain {
			t.Fatalf("got %v want %s", decoded, plain)
		}
		call(logical.UpdateOperation, "encode/test", nil, true)
		batch := call(logical.UpdateOperation, "encode/test", map[string]interface{}{"batch_input": []interface{}{map[string]interface{}{"value": plain, "reference": "a"}, map[string]interface{}{"value": "?", "reference": "b"}}}, false)
		results := batch.Data["batch_results"].([]interface{})
		if results[0].(map[string]interface{})["reference"] != "a" || results[1].(map[string]interface{})["error"] == nil {
			t.Fatal(batch)
		}
		call(logical.UpdateOperation, "transformation/test", map[string]interface{}{"deletion_allowed": true}, false)
		call(logical.DeleteOperation, "transformation/test", nil, true)
		call(logical.DeleteOperation, "role/test", nil, false)
		call(logical.DeleteOperation, "transformation/test", nil, false)
		if call(logical.ReadOperation, "transformation/test", nil, false) != nil {
			t.Fatal("not deleted")
		}
	}
}
