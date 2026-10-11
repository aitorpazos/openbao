// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	mfaconfig "github.com/openbao/openbao/v2/internal/helper/identity/mfa"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestIdentityMFATOTPSelfEnroll(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	ctx := namespace.RootContext(t.Context())
	call := func(op logical.Operation, path, entity string, data map[string]any) *logical.Response {
		t.Helper()
		resp, err := c.identityStore.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, EntityID: entity, Data: data})
		require.NoError(t, err)
		return resp
	}
	write := func(path string, data map[string]any) *logical.Response {
		t.Helper()
		resp := call(logical.UpdateOperation, path, "", data)
		require.False(t, resp.IsError(), "%v", resp)
		return resp
	}
	entity := write("entity", map[string]any{"name": "self-enroll"}).Data["id"].(string)
	other := write("entity", map[string]any{"name": "other"}).Data["id"].(string)
	method := write("mfa/method/totp", map[string]any{"issuer": "test"}).Data["method_id"].(string)
	read := func() *logical.Response { return call(logical.ReadOperation, "mfa/method/totp/"+method, "", nil) }
	require.Equal(t, false, read().Data["enable_self_enrollment"])
	write("mfa/login-enforcement/self-enroll", map[string]any{"mfa_method_ids": []string{method}, "identity_entity_ids": []string{entity}})
	pending := &MFACachedAuthResponse{RequestID: "pending", RequestNSID: namespace.RootNamespaceID, RequestPath: "auth/token/create", CachedAuth: &logical.Auth{EntityID: entity}, TimeOfStorage: time.Now()}
	require.NoError(t, c.SaveMFAResponseAuth(pending))
	path := "mfa/method/totp/self-enroll"
	data := map[string]any{"mfa_request_id": "pending", "mfa_method_id": method}
	for _, missing := range []map[string]any{nil, {"mfa_request_id": "pending"}, {"mfa_method_id": method}} {
		require.True(t, call(logical.UpdateOperation, path, entity, missing).IsError())
	}
	require.True(t, call(logical.UpdateOperation, path, entity, data).IsError(), "disabled by default")
	write("mfa/method/totp/"+method, map[string]any{"issuer": "test", "enable_self_enrollment": true})
	require.Equal(t, true, read().Data["enable_self_enrollment"])
	// The new flag must survive protobuf persistence, not merely exist in MemDB.
	cfg, err := c.loginMFABackend.MemDBMFAConfigByID(method)
	require.NoError(t, err)
	encoded, err := proto.Marshal(cfg)
	require.NoError(t, err)
	var decoded mfaconfig.Config
	require.NoError(t, proto.Unmarshal(encoded, &decoded))
	require.True(t, decoded.GetTOTPConfig().GetEnableSelfEnrollment())
	require.True(t, call(logical.UpdateOperation, path, "", data).IsError(), "non-entity token")
	require.True(t, call(logical.UpdateOperation, path, other, data).IsError(), "another entity's pending request")
	require.True(t, call(logical.UpdateOperation, path, entity, map[string]any{"mfa_request_id": "unknown", "mfa_method_id": method}).IsError())
	resp := call(logical.UpdateOperation, path, entity, data)
	require.False(t, resp.IsError(), "%v", resp)
	barcode, err := base64.StdEncoding.DecodeString(resp.Data["barcode"].(string))
	require.NoError(t, err)
	require.NotEmpty(t, barcode)
	otpURL, err := url.Parse(resp.Data["url"].(string))
	require.NoError(t, err)
	require.Equal(t, "otpauth", otpURL.Scheme)
	key, err := c.fetchTOTPKey(ctx, method, entity)
	require.NoError(t, err)
	require.Equal(t, key, otpURL.Query().Get("secret"))
	// Re-enrollment must not disclose or overwrite an existing secret.
	repeat := call(logical.UpdateOperation, path, entity, data)
	require.Empty(t, repeat.Data)
	require.NotEmpty(t, repeat.Warnings)
	cached, err := c.PopMFAResponseAuthByID("pending")
	require.NoError(t, err)
	require.NotNil(t, cached, "self-enrollment must preserve pending login")
	cached.TimeOfStorage = time.Now().Add(-2 * defaultMFAAuthResponseTTL)
	require.NoError(t, c.SaveMFAResponseAuth(cached))
	require.True(t, call(logical.UpdateOperation, path, entity, data).IsError(), "expired request")
	write("mfa/method/totp/"+method, map[string]any{"issuer": "test", "enable_self_enrollment": false})
	require.Equal(t, false, read().Data["enable_self_enrollment"])
}
