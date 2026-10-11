// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestSystemBackend_SealRewrap(t *testing.T) {
	b := testSystemBackend(t)
	ctx := namespace.RootContext(t.Context())
	expected := map[string]any{"is_running": false, "entries": map[string]any{"failed": 0, "processed": 0, "succeeded": 0}}
	for i := 0; i < 2; i++ {
		resp, err := b.HandleRequest(ctx, logical.TestRequest(t, logical.ReadOperation, "sealwrap/rewrap"))
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, expected, resp.Data)
		resp, err = b.HandleRequest(ctx, logical.TestRequest(t, logical.UpdateOperation, "sealwrap/rewrap"))
		require.NoError(t, err)
		require.False(t, resp.IsError())
		require.Equal(t, http.StatusAccepted, resp.Data[logical.HTTPStatusCode])
	}
	require.Contains(t, b.SpecialPaths().Unauthenticated, "seal-backend-status")
	require.NotContains(t, b.SpecialPaths().Unauthenticated, "sealwrap/rewrap")
	resp, err := b.HandleRequest(ctx, logical.TestRequest(t, logical.ReadOperation, "seal-backend-status"))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Data[logical.HTTPStatusCode])
	var body map[string]any
	require.NoError(t, json.Unmarshal(resp.Data[logical.HTTPRawBody].([]byte), &body))
	require.NotContains(t, body, "data")
	require.Equal(t, true, body["healthy"])
	require.Equal(t, true, body["fully_wrapped"])
	backends := body["backends"].([]any)
	require.Len(t, backends, 1)
	backend := backends[0].(map[string]any)
	require.Equal(t, "shamir", backend["name"])
	require.Equal(t, true, backend["configured"])
	require.Equal(t, false, backend["disabled"])
	require.Equal(t, true, backend["healthy"])
	require.NotContains(t, backend, "unhealthy_since")
}

func TestSystemBackend_SealBackendCachedHealth(t *testing.T) {
	s := &autoSeal{barrierType: "test"}
	b := &SystemBackend{Core: &Core{seal: s}}
	since := time.Now().UTC()
	s.backendUnhealthySince.Store(&since)
	for _, healthy := range []bool{false, true} {
		if healthy {
			s.backendUnhealthySince.Store(nil)
		}
		resp, err := b.handleSealBackendStatus(t.Context(), nil, nil)
		require.NoError(t, err)
		var body map[string]any
		require.NoError(t, json.Unmarshal(resp.Data[logical.HTTPRawBody].([]byte), &body))
		require.Equal(t, healthy, body["healthy"])
		require.Equal(t, false, body["fully_wrapped"])
		if !healthy {
			require.Equal(t, since.Format(time.RFC3339Nano), body["unhealthy_since"])
		} else {
			require.NotContains(t, body, "unhealthy_since")
		}
	}
	resp, err := b.handleSealRewrapStart(t.Context(), nil, nil)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.True(t, resp.IsError())
}

func TestSystemBackend_SealRewrapRequiresAuthentication(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
		_, err := c.HandleRequest(ctx, &logical.Request{Operation: op, Path: "sys/sealwrap/rewrap"})
		require.Error(t, err)
	}
	resp, err := c.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "sys/seal-backend-status"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
}
