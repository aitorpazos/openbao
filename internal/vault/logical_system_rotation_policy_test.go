// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestRotationPolicy(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	storage := &logical.InmemStorage{}
	newBackend := func() *framework.Backend { return &framework.Backend{Paths: (&SystemBackend{}).rotationPolicyPaths()} }
	backend := newBackend()
	call := func(op logical.Operation, data map[string]interface{}) (*logical.Response, error) {
		return backend.HandleRequest(ctx, &logical.Request{Operation: op, Path: "policies/rotation/test", Storage: storage, Data: data})
	}
	read := func() *logical.Response {
		t.Helper()
		resp, err := call(logical.ReadOperation, nil)
		require.NoError(t, err)
		return resp
	}
	require.Nil(t, read())
	config := map[string]interface{}{"max_retries_per_cycle": 3, "max_retry_cycles": 3}
	resp, err := call(logical.UpdateOperation, config)
	require.NoError(t, err)
	require.Nil(t, resp)
	backend = newBackend() // Read from persisted storage, not backend memory.
	require.Equal(t, config, read().Data)
	for _, field := range []string{"max_retries_per_cycle", "max_retry_cycles"} {
		for i, value := range []interface{}{nil, "3", "invalid", true, 1.5, json.Number("2.5"), map[string]interface{}{"invalid": true}, []int{3}} {
			t.Run(fmt.Sprintf("%s/invalid-%d", field, i), func(t *testing.T) {
				invalid := map[string]interface{}{"max_retries_per_cycle": 9, "max_retry_cycles": 9}
				invalid[field] = value
				resp, err := call(logical.UpdateOperation, invalid)
				require.True(t, err != nil || (resp != nil && resp.IsError()))
				require.Equal(t, config, read().Data)
			})
		}
		missing := map[string]interface{}{"max_retries_per_cycle": 9, "max_retry_cycles": 9}
		delete(missing, field)
		resp, err := call(logical.UpdateOperation, missing)
		require.NoError(t, err)
		require.True(t, resp.IsError())
	}
	resp, err = call(logical.UpdateOperation, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	resp, err = call(logical.UpdateOperation, map[string]interface{}{"max_retries_per_cycle": json.Number("5"), "max_retry_cycles": 4})
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Equal(t, map[string]interface{}{"max_retries_per_cycle": 5, "max_retry_cycles": 4}, read().Data)
	childCtx := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation} {
		resp, err := backend.HandleRequest(childCtx, &logical.Request{Operation: op, Path: "policies/rotation/test", Storage: storage, Data: config})
		require.ErrorIs(t, err, logical.ErrPermissionDenied)
		require.True(t, resp.IsError())
	}
	for range 2 {
		resp, err = call(logical.DeleteOperation, nil)
		require.NoError(t, err)
		require.Nil(t, resp)
		require.Nil(t, read())
	}
}

func TestRotationPolicyCore(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	for _, op := range []logical.Operation{logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation, logical.ReadOperation} {
		resp, err := core.HandleRequest(ctx, &logical.Request{
			Operation: op, Path: "sys/policies/rotation/test", ClientToken: token,
			Data: map[string]interface{}{"max_retries_per_cycle": 3, "max_retry_cycles": 3},
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
	}
}
