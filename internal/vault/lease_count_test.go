// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0
package vault

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestLeaseCountAPIAndRevocation(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	call := func(op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
		return c.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, ClientToken: root})
	}
	quota := "sys/quotas/lease-count/test"
	resp, err := call(logical.UpdateOperation, quota, map[string]any{})
	require.True(t, err != nil || resp.IsError())
	resp, err = call(logical.UpdateOperation, quota, map[string]any{"path": "auth/token/create", "max_leases": 1})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	resp, err = call(logical.ReadOperation, quota, nil)
	require.NoError(t, err)
	require.Equal(t, 1, resp.Data["max_leases"])
	payload := map[string]any{"policies": []string{"default"}, "ttl": "10m"}
	resp, err = call(logical.UpdateOperation, "auth/token/create", payload)
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	first := resp.Auth.ClientToken
	_, err = call(logical.UpdateOperation, "auth/token/create", payload)
	require.ErrorContains(t, err, "lease count quota exceeded")
	// A full quota must not block emergency root-token creation.
	resp, err = call(logical.UpdateOperation, "auth/token/create", map[string]any{"policies": []string{"root"}, "ttl": "10m"})
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	_, err = call(logical.UpdateOperation, "auth/token/revoke", map[string]any{"token": resp.Auth.ClientToken})
	require.NoError(t, err)
	_, err = call(logical.UpdateOperation, "auth/token/revoke", map[string]any{"token": first})
	require.NoError(t, err)
	resp, err = call(logical.UpdateOperation, "auth/token/create", payload)
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	_, err = call(logical.UpdateOperation, quota, map[string]any{"path": "auth/token/create", "max_leases": 2})
	require.NoError(t, err)
	resp, err = call(logical.ListOperation, "sys/quotas/lease-count", nil)
	require.NoError(t, err)
	require.Contains(t, resp.Data["keys"], "test")
	_, err = call(logical.DeleteOperation, quota, nil)
	require.NoError(t, err)
	resp, err = call(logical.ReadOperation, quota, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
}
