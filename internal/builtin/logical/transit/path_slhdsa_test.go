// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// documentedSLHDSAParameterSets mirrors the documented SLH-DSA parameter-set
// list from the transit API docs page, including the documented
// "slh-dsa-shake-128" spelling at the SHAKE-128f list position.
var documentedSLHDSAParameterSets = []string{
	"slh-dsa-sha2-128s",
	"slh-dsa-shake-128s",
	"slh-dsa-sha2-128f",
	"slh-dsa-shake-128",
	"slh-dsa-sha2-192s",
	"slh-dsa-shake-192s",
	"slh-dsa-sha2-192f",
	"slh-dsa-shake-192f",
	"slh-dsa-shake-256s",
	"slh-dsa-sha2-256s",
	"slh-dsa-shake-256f",
	"slh-dsa-sha2-256f",
}

func TestTransit_SLHDSA_CreateAndReadAllParameterSets(t *testing.T) {
	ctx := t.Context()
	b, storage := createBackendWithSysView(t)

	for i, parameterSet := range documentedSLHDSAParameterSets {
		name := fmt.Sprintf("slhdsa-%d", i)
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "keys/" + name,
			Data: map[string]any{
				"type":          "slh-dsa",
				"parameter_set": parameterSet,
			},
		})
		require.NoError(t, err, "creating %s", parameterSet)
		require.NoError(t, resp.Error(), "creating %s", parameterSet)

		resp, err = b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "keys/" + name,
		})
		require.NoError(t, err)
		require.NoError(t, resp.Error())

		require.Equal(t, name, resp.Data["name"])
		require.Equal(t, "slh-dsa", resp.Data["type"])
		require.Equal(t, parameterSet, resp.Data["parameter_set"])
		require.Equal(t, true, resp.Data["supports_signing"])
		require.Equal(t, false, resp.Data["supports_encryption"])
		require.Equal(t, false, resp.Data["supports_derivation"])
		// In-process the keys map has the concrete type
		// map[string]map[string]any; after an HTTP round-trip it would be
		// map[string]any. Accept both.
		var keys map[string]any
		switch v := resp.Data["keys"].(type) {
		case map[string]any:
			keys = v
		case map[string]map[string]any:
			keys = map[string]any{}
			for k, vv := range v {
				keys[k] = vv
			}
		}
		require.NotNil(t, keys)
		require.Len(t, keys, 1)
		for _, entry := range keys {
			entryMap, ok := entry.(map[string]any)
			require.True(t, ok)
			publicKey, ok := entryMap["public_key"].(string)
			require.True(t, ok)
			require.NotEmpty(t, publicKey)
			decoded, err := base64.StdEncoding.DecodeString(publicKey)
			require.NoError(t, err)
			// FIPS 205 public keys are 2n bytes: 32, 48 or 64 bytes.
			require.Contains(t, []int{32, 48, 64}, len(decoded))
		}
	}
}

func TestTransit_SLHDSA_MissingParameterSetRejected(t *testing.T) {
	ctx := t.Context()
	b, storage := createBackendWithSysView(t)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]any{
			"type": "slh-dsa",
		},
	})
	require.Error(t, resp.Error())
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
}

func TestTransit_SLHDSA_UnknownParameterSetRejected(t *testing.T) {
	ctx := t.Context()
	b, storage := createBackendWithSysView(t)

	// "slh-dsa-shake-128f" is the consistent spelling of the SHAKE-128f
	// parameter set, but the documented list spells it "slh-dsa-shake-128";
	// the consistent spelling is not on the documented list and must be
	// rejected rather than silently corrected.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]any{
			"type":          "slh-dsa",
			"parameter_set": "slh-dsa-shake-128f",
		},
	})
	require.Error(t, resp.Error())
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
}

func TestTransit_SignVerify_SLHDSA(t *testing.T) {
	// Sign and verify the fastest parameter sets, including the documented
	// "slh-dsa-shake-128" oddity mapping.
	for _, parameterSet := range []string{"slh-dsa-sha2-128s", "slh-dsa-shake-128s", "slh-dsa-shake-128", "slh-dsa-sha2-128f"} {
		t.Run(parameterSet, func(t *testing.T) {
			testTransit_SignVerify_SLHDSA(t, parameterSet)
		})
	}
}

func testTransit_SignVerify_SLHDSA(t *testing.T, parameterSet string) {
	ctx := t.Context()
	b, storage := createBackendWithSysView(t)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]any{
			"type":          "slh-dsa",
			"parameter_set": parameterSet,
		},
	})
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	// Reload through a second backend sharing the same storage to exercise
	// the persisted-policy load path (ParameterSet round-trip and lazy
	// private-key parsing).
	b2 := createBackendWithSysViewWithStorage(t, storage)

	input := base64.StdEncoding.EncodeToString([]byte("Hello, World!"))

	resp, err = b2.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data: map[string]any{
			"input": input,
		},
	})
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	signature := resp.Data["signature"].(string)
	require.NotEmpty(t, signature)

	resp, err = b2.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data: map[string]any{
			"input":     input,
			"signature": signature,
		},
	})
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	valid := resp.Data["valid"].(bool)
	require.True(t, valid)

	// Verify a bad signature:
	resp, err = b2.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data: map[string]any{
			"input":     input,
			"signature": "vault:v1:" + input,
		},
	})
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	valid = resp.Data["valid"].(bool)
	require.False(t, valid)
}

func TestTransit_SLHDSA_ParameterSetMapComplete(t *testing.T) {
	// Every documented parameter-set name must resolve to a valid FIPS 205
	// parameter-set identifier.
	for _, parameterSet := range documentedSLHDSAParameterSets {
		_, ok := keysutil.DocumentedSLHDSAParameterSets[parameterSet]
		require.True(t, ok, "documented parameter set %q not resolvable", parameterSet)
	}

	// Nothing undocumented may resolve.
	for _, parameterSet := range []string{"slh-dsa-shake-128f", "slh-dsa", "slh-dsa-sha2-128", ""} {
		_, ok := keysutil.DocumentedSLHDSAParameterSets[parameterSet]
		require.False(t, ok, "unexpected resolvable parameter set %q", parameterSet)
	}
}
