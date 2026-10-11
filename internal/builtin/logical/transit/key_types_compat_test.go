// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/base64"
	"fmt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDocumentedTransitKeyTypes(t *testing.T) {
	b, storage := createBackendWithSysView(t)
	call := func(op logical.Operation, path string, data map[string]any) *logical.Response {
		t.Helper()
		resp, err := b.HandleRequest(t.Context(), &logical.Request{Storage: storage, Operation: op, Path: path, Data: data})
		require.NoError(t, err)
		require.False(t, resp.IsError(), "%v", resp)
		return resp
	}
	write := func(path string, data map[string]any) *logical.Response {
		t.Helper()
		return call(logical.UpdateOperation, path, data)
	}
	for _, typ := range []string{"aes128-cbc", "aes256-cbc"} {
		for _, derived := range []bool{false, true} {
			name := fmt.Sprintf("%s-%t", typ, derived)
			write("keys/"+name, map[string]any{"type": typ, "derived": derived})
			require.Equal(t, typ, call(logical.ReadOperation, "keys/"+name, nil).Data["type"])
			for _, plain := range []string{"", "aGVsbG8=", base64.StdEncoding.EncodeToString(make([]byte, 32))} {
				data := map[string]any{"plaintext": plain, "context": "Y3R4"}
				ct := write("encrypt/"+name, data).Data["ciphertext"]
				require.Equal(t, plain, write("decrypt/"+name, map[string]any{"ciphertext": ct, "context": "Y3R4"}).Data["plaintext"])
			}
			iv := base64.StdEncoding.EncodeToString(make([]byte, 16))
			batch := write("encrypt/"+name, map[string]any{"batch_input": []any{map[string]any{"plaintext": "aGVsbG8=", "context": "Y3R4", "iv": iv, "reference": "one"}, map[string]any{"plaintext": "aGVsbG8=", "context": "Y3R4", "iv": iv}}})
			results := batch.Data["batch_results"].([]EncryptBatchResponseItem)
			require.Equal(t, results[0].Ciphertext, results[1].Ciphertext)
			require.Equal(t, "one", results[0].Reference)
			require.Equal(t, "aGVsbG8=", write("decrypt/"+name, map[string]any{"ciphertext": results[0].Ciphertext, "context": "Y3R4"}).Data["plaintext"])
		}
	}
	for _, typ := range []string{"aes128-cmac", "aes192-cmac", "aes256-cmac"} {
		for _, derived := range []bool{false, true} {
			name := fmt.Sprintf("%s-%t", typ, derived)
			write("keys/"+name, map[string]any{"type": typ, "derived": derived, "exportable": true})
			data := map[string]any{"input": "aGVsbG8=", "context": "Y3R4"}
			tag := write("cmac/"+name, data).Data["cmac"]
			require.Equal(t, tag, write("cmac/"+name, data).Data["cmac"])
			require.NotEqual(t, tag, write("cmac/"+name, map[string]any{"input": "", "context": "Y3R4"}).Data["cmac"])
			data["mac_length"] = 1000
			require.NotEmpty(t, write("cmac/"+name+"/8", data).Data["cmac"])
			require.NotEmpty(t, call(logical.ReadOperation, "export/cmac-key/"+name+"/1", nil).Data["keys"])
		}
	}
	for _, set := range []string{"44", "65", "87"} {
		name := "ml" + set
		write("keys/"+name, map[string]any{"type": "ml-dsa", "parameter_set": set})
		read := call(logical.ReadOperation, "keys/"+name, nil)
		require.Equal(t, "ml-dsa", read.Data["type"])
		require.Equal(t, set, read.Data["parameter_set"])
		sig := write("sign/"+name, map[string]any{"input": "aGVsbG8="}).Data["signature"]
		require.Equal(t, true, write("verify/"+name, map[string]any{"input": "aGVsbG8=", "signature": sig}).Data["valid"])
		require.Equal(t, false, write("verify/"+name, map[string]any{"input": "d3Jvbmc=", "signature": sig}).Data["valid"])
	}
	write("keys/hybrid", map[string]any{"type": "hybrid", "parameter_set": "44", "hybrid_key_type_pqc": "ml-dsa", "hybrid_key_type_ec": "ecdsa-p256"})
	read := call(logical.ReadOperation, "keys/hybrid", nil)
	require.Equal(t, "hybrid", read.Data["type"])
	require.Equal(t, "44", read.Data["parameter_set"])
	require.Equal(t, "ml-dsa", read.Data["hybrid_key_type_pqc"])
	require.Equal(t, "ecdsa-p256", read.Data["hybrid_key_type_ec"])
	require.Equal(t, true, read.Data["supports_signing"])
	require.NotEmpty(t, read.Warnings)
	resp, err := b.HandleRequest(t.Context(), &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: "sign/hybrid", Data: map[string]any{"input": "aGVsbG8="}})
	require.True(t, err != nil || resp.IsError(), "structural hybrid must not emit a fake signature")
}
