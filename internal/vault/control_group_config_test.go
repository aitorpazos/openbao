// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestControlGroupConfig(t *testing.T) {
	c, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	request := func(op logical.Operation, data map[string]interface{}) (*logical.Response, error) {
		return c.HandleRequest(ctx, &logical.Request{Operation: op, Path: "sys/" + controlGroupConfigPath, ClientToken: token, Data: data})
	}
	read := func(expected string) {
		resp, err := request(logical.ReadOperation, nil)
		require.NoError(t, err)
		require.Equal(t, expected, resp.Data["max_ttl"])
	}
	read("0s")
	for _, tc := range []struct {
		value    interface{}
		expected string
		ttl      time.Duration
	}{
		{"5m", "5m0s", 5 * time.Minute},
		{7200, "2h0m0s", 2 * time.Hour},
	} {
		resp, err := request(logical.UpdateOperation, map[string]interface{}{"max_ttl": tc.value})
		require.NoError(t, err)
		require.Nil(t, resp)
		read(tc.expected)
		for _, wrapping := range []struct {
			ttl  time.Duration
			meta map[string]string
			want time.Duration
		}{
			{4 * time.Hour, map[string]string{"control_group": "{}"}, tc.ttl},
			{time.Minute, map[string]string{"control_group": "{}"}, time.Minute},
			{4 * time.Hour, nil, 4 * time.Hour},
		} {
			got, err := c.controlGroupWrappingTTL(ctx, wrapping.ttl, wrapping.meta)
			require.NoError(t, err)
			require.Equal(t, wrapping.want, got)
		}
	}
	for _, invalid := range []interface{}{map[string]interface{}{"invalid": true}, true, "not-a-duration", -1} {
		req := &logical.Request{Operation: logical.UpdateOperation, Path: "sys/" + controlGroupConfigPath, ClientToken: token, Data: map[string]interface{}{"max_ttl": invalid}}
		resp, err := c.HandleRequest(ctx, req)
		code, _ := logical.RespondErrorCommon(req, resp, err)
		require.Equal(t, http.StatusBadRequest, code)
		read("2h0m0s")
	}
	resp, err := request(logical.DeleteOperation, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	read("0s")
	storage := c.router.MatchingStorageByAPIPath(ctx, "sys/")
	entry, err := storage.Get(ctx, controlGroupConfigPath)
	require.NoError(t, err)
	require.Nil(t, entry)
	ttl, err := c.controlGroupWrappingTTL(ctx, 4*time.Hour, map[string]string{"control_group": "{}"})
	require.NoError(t, err)
	require.Equal(t, 4*time.Hour, ttl)
}
