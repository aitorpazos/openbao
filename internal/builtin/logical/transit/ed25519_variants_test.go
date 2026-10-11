// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestEd25519Variants(t *testing.T) {
	b, storage := createBackendWithSysView(t)
	call := func(path string, data map[string]any) *logical.Response {
		t.Helper()
		resp, err := b.HandleRequest(t.Context(), &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: path, Data: data})
		require.NoError(t, err)
		require.False(t, resp.IsError(), "%v", resp)
		return resp
	}
	call("keys/variants", map[string]any{"type": "ed25519"})
	for _, ctx := range []string{"!!!", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 256)))} {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: "sign/variants", Data: map[string]any{"input": "aGVsbG8=", "signature_context": ctx}})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
		require.True(t, resp.IsError())
	}
	for _, derived := range []bool{false, true} {
		name := "variants"
		if derived {
			name = "derived"
			call("keys/"+name, map[string]any{"type": "ed25519", "derived": true})
		}
		for _, ph := range []bool{false, true} {
			input, suffix := "aGVsbG8=", ""
			if ph {
				input = "jpbazUleztsz7s/FeDuSw2cLkKICV0wq8ms3RcQIQqTf9RvV0Ked95r1sEbfTKHyJ15LuiLc7rn/rboY1I/IRA=="
				suffix = "/sha2-512"
			}
			data := map[string]any{"input": input, "prehashed": ph, "signature_context": "Y29udGV4dA==", "context": "ZGVyaXZhdGlvbg=="}
			signed := call("sign/"+name+suffix, data)
			data["signature"] = signed.Data["signature"]
			require.Equal(t, true, call("verify/"+name+suffix, data).Data["valid"])
			data["signature_context"] = "d3Jvbmc="
			require.Equal(t, false, call("verify/"+name+suffix, data).Data["valid"])
		}
	}
	call("keys/fixture/import", map[string]any{"type": "ed25519", "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----"})
	batch := call("sign/variants", map[string]any{"batch_input": []map[string]any{
		{"input": "aGVsbG8=", "signature_context": "Y29udGV4dA==", "reference": "good"},
		{"input": "aGVsbG8=", "signature_context": "!!!", "reference": "bad"},
	}})
	results := batch.Data["batch_results"].([]batchResponseSignItem)
	require.NotEmpty(t, results[0].Signature)
	require.Equal(t, "good", results[0].Reference)
	require.NotEmpty(t, results[1].Error)
	require.Equal(t, "bad", results[1].Reference)
	data := map[string]any{
		"input":     "jpbazUleztsz7s/FeDuSw2cLkKICV0wq8ms3RcQIQqTf9RvV0Ked95r1sEbfTKHyJ15LuiLc7rn/rboY1I/IRA==",
		"prehashed": true,
		"signature": "vault:v1:OWxzUzD4BSk7HHtmN9qHvgmuxpglqAJi5XONCUzfEyPWOz06pFH8H98tZASZgn+nxTnuFZGZtd6NY7dbvNedBQ==",
	}
	require.Equal(t, true, call("verify/fixture/sha2-512", data).Data["valid"])
	data["signature_context"] = "d3Jvbmc="
	require.Equal(t, false, call("verify/fixture/sha2-512", data).Data["valid"])
}
