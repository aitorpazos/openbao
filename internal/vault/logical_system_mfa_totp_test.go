// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"image/png"
	"net/url"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestNamedMFATOTPEnrollment(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	b := &SystemBackend{Core: c}
	backend := &framework.Backend{Paths: b.namedMFAMethodPaths()}
	storage := &logical.InmemStorage{}
	call := func(action, caller string, data map[string]interface{}) *logical.Response {
		t.Helper()
		op := logical.UpdateOperation
		path := "mfa/method/totp/test"
		if action != "" {
			path += "/" + action
		}
		if action == "generate" {
			op = logical.ReadOperation
		}
		resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: storage, EntityID: caller, Data: data})
		require.NoError(t, err)
		return resp
	}
	require.True(t, call("admin-generate", "", nil).IsError())
	require.True(t, call("admin-destroy", "", nil).IsError())
	require.True(t, call("generate", "", nil).IsError())
	require.Nil(t, call("", "", map[string]interface{}{"issuer": "Bao Test", "key_size": 32, "digits": 8, "algorithm": "SHA256", "period": 60}))
	entry, err := storage.Get(ctx, namedMFAMethodPrefix+"totp/test")
	require.NoError(t, err)
	var cfg namedTOTPEnrollmentConfig
	require.NoError(t, entry.DecodeJSON(&cfg))
	newEntity := func(name string) string {
		t.Helper()
		resp, err := c.identityStore.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "entity", Data: map[string]interface{}{"name": name}})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		return resp.Data["id"].(string)
	}
	first, second := newEntity("first"), newEntity("second")
	require.True(t, call("admin-generate", "", map[string]interface{}{"entity_id": "missing"}).IsError())
	require.True(t, call("admin-destroy", "", map[string]interface{}{"entity_id": "missing"}).IsError())
	check := func(resp *logical.Response, id string, size int, algorithm, digits, period string) string {
		t.Helper()
		require.NotNil(t, resp)
		require.False(t, resp.IsError())
		u, err := url.Parse(resp.Data["url"].(string))
		require.NoError(t, err)
		require.Equal(t, "otpauth", u.Scheme)
		require.Equal(t, "totp", u.Host)
		require.Contains(t, u.Path, id)
		require.Equal(t, "Bao Test", u.Query().Get("issuer"))
		require.Equal(t, algorithm, u.Query().Get("algorithm"))
		require.Equal(t, digits, u.Query().Get("digits"))
		require.Equal(t, period, u.Query().Get("period"))
		secret := u.Query().Get("secret")
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		require.Len(t, raw, size)
		barcode, err := base64.StdEncoding.DecodeString(resp.Data["barcode"].(string))
		require.NoError(t, err)
		image, err := png.Decode(bytes.NewReader(barcode))
		require.NoError(t, err)
		require.Equal(t, 200, image.Bounds().Dx())
		for range 2 {
			stored, err := c.fetchTOTPKey(ctx, cfg.ID, id)
			require.NoError(t, err)
			require.Equal(t, secret, stored)
		}
		entity, err := c.identityStore.MemDBEntityByID(ctx, id, true)
		require.NoError(t, err)
		require.NotNil(t, entity.MFASecrets[cfg.ID])
		return secret
	}
	s1 := check(call("generate", first, map[string]interface{}{"entity_id": second}), first, 32, "SHA256", "8", "60")
	absent, err := c.fetchTOTPKey(ctx, cfg.ID, second)
	require.NoError(t, err)
	require.Empty(t, absent)
	s2 := check(call("admin-generate", "", map[string]interface{}{"entity_id": second}), second, 32, "SHA256", "8", "60")
	require.NotEqual(t, s1, s2)
	require.NotEqual(t, s1, check(call("generate", first, nil), first, 32, "SHA256", "8", "60"))
	for range 2 {
		require.Nil(t, call("admin-destroy", "", map[string]interface{}{"entity_id": first}))
		key, err := c.fetchTOTPKey(ctx, cfg.ID, first)
		require.NoError(t, err)
		require.Empty(t, key)
		entity, err := c.identityStore.MemDBEntityByID(ctx, first, true)
		require.NoError(t, err)
		require.NotContains(t, entity.MFASecrets, cfg.ID)
	}
	key, err := c.fetchTOTPKey(ctx, cfg.ID, second)
	require.NoError(t, err)
	require.Equal(t, s2, key)
	require.Nil(t, call("", "", map[string]interface{}{"issuer": "Bao Test"}))
	check(call("generate", first, nil), first, 20, "SHA1", "6", "30")
}
