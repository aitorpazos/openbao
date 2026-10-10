// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestNamedMFAMethods(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	storage := &logical.InmemStorage{}
	newBackend := func() *framework.Backend {
		b := &SystemBackend{}
		return &framework.Backend{Paths: b.namedMFAMethodPaths()}
	}
	backend := newBackend()
	call := func(kind string, op logical.Operation, data map[string]interface{}) *logical.Response {
		t.Helper()
		resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: op, Path: "mfa/method/" + kind + "/test", Storage: storage, Data: data})
		require.NoError(t, err)
		return resp
	}
	for _, kind := range []string{"totp", "duo", "okta", "pingid"} {
		t.Run(kind, func(t *testing.T) {
			require.True(t, call(kind, logical.UpdateOperation, nil).IsError())
			config := map[string]interface{}{"mount_accessor": "auth_test", "username_format": "{{alias.name}}"}
			if kind == "totp" {
				config = map[string]interface{}{"issuer": "test"}
			}
			require.Nil(t, call(kind, logical.UpdateOperation, config))
			// A fresh backend must recover the configuration from storage, not a cache.
			backend = newBackend()
			resp := call(kind, logical.ReadOperation, nil)
			require.Equal(t, kind, resp.Data["type"])
			require.Equal(t, "test", resp.Data["name"])
			id, ok := resp.Data["id"].(string)
			require.True(t, ok)
			require.NotEmpty(t, id)
			if kind == "totp" {
				for field, value := range map[string]interface{}{"algorithm": "SHA1", "digits": json.Number("6"), "key_size": json.Number("20"), "period": json.Number("30"), "qr_size": json.Number("200"), "skew": json.Number("1"), "max_validation_attempts": json.Number("5")} {
					require.Equal(t, value, resp.Data[field], field)
				}
				config["period"] = "60s"
				config["algorithm"] = "SHA256"
				config["digits"] = 8
				config["skew"] = 0
			}
			require.Nil(t, call(kind, logical.UpdateOperation, config))
			resp = call(kind, logical.ReadOperation, nil)
			require.Equal(t, id, resp.Data["id"])
			if kind == "totp" {
				require.Equal(t, json.Number("60"), resp.Data["period"])
				require.Equal(t, json.Number("0"), resp.Data["skew"])
				require.Nil(t, call(kind, logical.UpdateOperation, map[string]interface{}{"issuer": "reset"}))
				require.Equal(t, json.Number("30"), call(kind, logical.ReadOperation, nil).Data["period"])
			}
			require.Nil(t, call(kind, logical.DeleteOperation, nil))
			require.Nil(t, call(kind, logical.ReadOperation, nil))
			require.Nil(t, call(kind, logical.DeleteOperation, nil))
		})
	}
	for field, value := range map[string]interface{}{"algorithm": "MD5", "digits": 7, "skew": 2, "period": 0, "key_size": -1, "qr_size": -1, "max_validation_attempts": 0} {
		resp := call("totp", logical.UpdateOperation, map[string]interface{}{"issuer": "invalid", field: value})
		require.True(t, resp.IsError(), field)
		require.Nil(t, call("totp", logical.ReadOperation, nil))
	}
	childCtx := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation} {
		resp, err := backend.HandleRequest(childCtx, &logical.Request{Operation: op, Path: "mfa/method/totp/test", Storage: storage, Data: map[string]interface{}{"issuer": "denied"}})
		require.ErrorIs(t, err, logical.ErrPermissionDenied)
		require.True(t, resp.IsError())
	}
}
