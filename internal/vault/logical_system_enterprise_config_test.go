// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func enterpriseConfigTestBackend(t *testing.T) (*framework.Backend, logical.Storage) {
	t.Helper()
	b := &framework.Backend{Paths: (&SystemBackend{}).enterpriseConfigPaths(), BackendType: logical.TypeLogical}
	s := &logical.InmemStorage{}
	require.NoError(t, b.Setup(namespace.RootContext(context.Background()), &logical.BackendConfig{StorageView: s, System: logical.StaticSystemView{}}))
	return b, s
}

func enterpriseConfigRequest(t *testing.T, b *framework.Backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}, invalid bool) *logical.Response {
	t.Helper()
	req := &logical.Request{Operation: op, Path: path, Data: data, Storage: s}
	resp, err := b.HandleRequest(namespace.RootContext(context.Background()), req)
	if invalid {
		status, _ := logical.RespondErrorCommon(req, resp, err)
		require.Equal(t, http.StatusBadRequest, status, "response=%#v err=%v", resp, err)
	} else {
		require.NoError(t, err)
		if resp != nil {
			require.False(t, resp.IsError(), "%#v", resp)
		}
	}
	return resp
}

func TestGroupPolicyApplication(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	read := func() string {
		return enterpriseConfigRequest(t, b, s, logical.ReadOperation, groupPolicyApplicationPath, nil, false).Data["group_policy_application_mode"].(string)
	}
	require.Equal(t, "within_namespace_hierarchy", read())
	for _, mode := range []interface{}{"invalid", map[string]interface{}{"bad": true}, 42, true} {
		enterpriseConfigRequest(t, b, s, logical.UpdateOperation, groupPolicyApplicationPath, map[string]interface{}{"group_policy_application_mode": mode}, true)
		require.Equal(t, "within_namespace_hierarchy", read())
	}
	for _, mode := range []string{"any", "within_namespace_hierarchy"} {
		enterpriseConfigRequest(t, b, s, logical.UpdateOperation, groupPolicyApplicationPath, map[string]interface{}{"group_policy_application_mode": mode}, false)
		require.Equal(t, mode, read())
	}
	_, err := b.HandleRequest(namespace.RootContext(context.Background()), &logical.Request{Operation: logical.DeleteOperation, Path: groupPolicyApplicationPath, Storage: s})
	require.ErrorIs(t, err, logical.ErrUnsupportedOperation)
}

func messageInput() map[string]interface{} {
	return map[string]interface{}{"title": "test", "message": "aGVsbG8=", "start_time": "2024-01-01T00:00:00Z"}
}

func TestUICustomMessageCRUD(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	created := enterpriseConfigRequest(t, b, s, logical.UpdateOperation, uiCustomMessagePath, messageInput(), false)
	id := created.Data["id"].(string)
	require.NotEmpty(t, id)
	require.Equal(t, "banner", created.Data["type"])
	require.Equal(t, true, created.Data["authenticated"])
	require.Nil(t, created.Data["end_time"])
	path := uiCustomMessagePath + "/" + id
	read := enterpriseConfigRequest(t, b, s, logical.ReadOperation, path, nil, false)
	require.Equal(t, created.Data, read.Data)
	input := messageInput()
	input["title"], input["authenticated"], input["type"] = "updated", false, "modal"
	input["link"] = map[string]interface{}{"docs": "https://example.com"}
	input["options"] = map[string]interface{}{"dismissible": false}
	input["end_time"] = "2025-01-01T00:00:00Z"
	updated := enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, input, false)
	read = enterpriseConfigRequest(t, b, s, logical.ReadOperation, path, nil, false)
	require.Equal(t, updated.Data, read.Data)
	require.Equal(t, "updated", read.Data["title"])
	require.Equal(t, input["options"], read.Data["options"])
	require.Equal(t, map[string]string{"docs": "https://example.com"}, read.Data["link"])
	for _, filter := range []map[string]interface{}{nil, {"type": "modal"}, {"authenticated": "false"}, {"active": "false"}} {
		listed := enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, filter, false)
		require.Equal(t, []string{id}, listed.Data["keys"])
		require.Equal(t, "updated", listed.Data["key_info"].(map[string]interface{})[id].(map[string]interface{})["title"])
	}
	for _, filter := range []map[string]interface{}{{"type": "banner"}, {"authenticated": "true"}, {"active": "true"}} {
		listed := enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, filter, false)
		require.Empty(t, listed.Data["keys"])
		require.Empty(t, listed.Data["key_info"])
	}
	enterpriseConfigRequest(t, b, s, logical.DeleteOperation, path, nil, false)
	require.Nil(t, enterpriseConfigRequest(t, b, s, logical.ReadOperation, path, nil, false))
	require.Empty(t, enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, nil, false).Data["keys"])
}

func TestUICustomMessageInvalid(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	id := enterpriseConfigRequest(t, b, s, logical.UpdateOperation, uiCustomMessagePath, messageInput(), false).Data["id"].(string)
	for _, path := range []string{uiCustomMessagePath, uiCustomMessagePath + "/" + id} {
		for _, field := range []string{"title", "message", "start_time"} {
			data := messageInput()
			delete(data, field)
			enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, data, true)
		}
		for field, value := range map[string]interface{}{"type": "other", "message": "%%%", "start_time": "yesterday", "end_time": "tomorrow", "authenticated": map[string]interface{}{}, "link": map[string]interface{}{}, "options": 12, "title": 12} {
			t.Run(field+path, func(t *testing.T) {
				data := messageInput()
				data[field] = value
				enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, data, true)
			})
		}
	}
	enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, map[string]interface{}{"type": "other"}, true)
	enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, map[string]interface{}{"active": "bad"}, true)
	require.Equal(t, []string{id}, enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, nil, false).Data["keys"])
	require.Equal(t, "test", enterpriseConfigRequest(t, b, s, logical.ReadOperation, uiCustomMessagePath+"/"+id, nil, false).Data["title"])
}

func TestUICustomMessageCapacityAndIsolation(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	ctx := namespace.RootContext(context.Background())
	// Concurrent requests cannot race the per-namespace capacity check.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enterpriseConfigRequest(t, b, s, logical.UpdateOperation, uiCustomMessagePath, messageInput(), false)
		}()
	}
	wg.Wait()
	require.Len(t, enterpriseConfigRequest(t, b, s, logical.ListOperation, uiCustomMessagePath, nil, false).Data["keys"], 100)
	enterpriseConfigRequest(t, b, s, logical.UpdateOperation, uiCustomMessagePath, messageInput(), true)
	other := &logical.InmemStorage{}
	child := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	resp, err := b.HandleRequest(child, &logical.Request{Operation: logical.UpdateOperation, Path: uiCustomMessagePath, Data: messageInput(), Storage: other})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Len(t, enterpriseConfigRequest(t, b, other, logical.ListOperation, uiCustomMessagePath, nil, false).Data["keys"], 1)
}

func TestUICustomMessageActive(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	m := uiCustomMessage{StartTime: start, EndTime: &end}
	for _, tc := range []struct {
		at     time.Time
		active bool
	}{{start.Add(-time.Second), false}, {start, true}, {start.Add(time.Second), true}, {end, false}} {
		require.Equal(t, tc.active, m.data("id", tc.at)["active"])
	}
	m.EndTime = nil
	require.Equal(t, true, m.data("id", end)["active"])
}

func TestUIDefaultAuthCRUD(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	path := uiDefaultAuthPath + "/test_login-1"
	enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, map[string]interface{}{"default_auth_type": "token"}, false)
	read := enterpriseConfigRequest(t, b, s, logical.ReadOperation, path, nil, false)
	require.Equal(t, map[string]interface{}{"namespace_path": "", "default_auth_type": "token", "backup_auth_types": []interface{}{}, "disable_inheritance": false}, read.Data)
	enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, map[string]interface{}{"namespace_path": "root", "default_auth_type": "token", "disable_inheritance": true}, false)
	listed := enterpriseConfigRequest(t, b, s, logical.ListOperation, uiDefaultAuthPath, nil, false)
	require.Equal(t, []string{"test_login-1"}, listed.Data["keys"])
	require.Equal(t, map[string]interface{}{"name": "test_login-1", "namespace_path": "root", "disable_inheritance": true}, listed.Data["key_info"].(map[string]interface{})["test_login-1"])
	enterpriseConfigRequest(t, b, s, logical.UpdateOperation, uiDefaultAuthPath+"/duplicate", map[string]interface{}{"namespace_path": "root", "default_auth_type": "token"}, true)
	enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, map[string]interface{}{"namespace_path": "root", "backup_auth_types": []string{"token", "oidc"}}, false)
	read = enterpriseConfigRequest(t, b, s, logical.ReadOperation, path, nil, false)
	require.Equal(t, []interface{}{"token", "oidc"}, read.Data["backup_auth_types"])
	require.Equal(t, "", read.Data["default_auth_type"])
	require.Equal(t, false, read.Data["disable_inheritance"])
	enterpriseConfigRequest(t, b, s, logical.DeleteOperation, path, nil, false)
	require.Nil(t, enterpriseConfigRequest(t, b, s, logical.ReadOperation, path, nil, false))
	require.Empty(t, enterpriseConfigRequest(t, b, s, logical.ListOperation, uiDefaultAuthPath, nil, false).Data["keys"])
}

func TestUIDefaultAuthInvalid(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	path := uiDefaultAuthPath + "/test"
	for i, data := range []map[string]interface{}{{}, {"default_auth_type": "other"}, {"backup_auth_types": []string{"other"}}, {"default_auth_type": "token", "disable_inheritance": map[string]interface{}{}}, {"default_auth_type": "token", "namespace_path": 4}, {"backup_auth_types": "token"}, {"default_auth_type": 4}, {"default_auth_type": "token", "disable_inheritance": "true"}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) { enterpriseConfigRequest(t, b, s, logical.UpdateOperation, path, data, true) })
	}
	require.Empty(t, enterpriseConfigRequest(t, b, s, logical.ListOperation, uiDefaultAuthPath, nil, false).Data["keys"])
}

func TestEnterpriseConfigNamespaceRestrictions(t *testing.T) {
	b, s := enterpriseConfigTestBackend(t)
	ctx := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", Path: "child/"})
	for _, path := range []string{groupPolicyApplicationPath, uiDefaultAuthPath + "/test"} {
		for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
			_, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: s})
			require.ErrorIs(t, err, logical.ErrPermissionDenied)
		}
	}
	for _, tc := range []struct {
		path string
		op   logical.Operation
	}{{uiDefaultAuthPath, logical.ListOperation}, {uiDefaultAuthPath + "/test", logical.DeleteOperation}} {
		_, err := b.HandleRequest(ctx, &logical.Request{Operation: tc.op, Path: tc.path, Storage: s})
		require.ErrorIs(t, err, logical.ErrPermissionDenied)
	}
}
