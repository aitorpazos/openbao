// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	kv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestSyncAssociationSetExistingSecret(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	core, _, root := TestCoreUnsealedWithConfig(t, &CoreConfig{LogicalBackends: map[string]logical.Factory{"kv": kv.Factory}})
	call := func(path string, op logical.Operation, data map[string]any) *logical.Response {
		t.Helper()
		resp, err := core.HandleRequest(ctx, &logical.Request{Path: path, Operation: op, Data: data, ClientToken: root})
		require.NoError(t, err)
		return resp
	}
	require.False(t, call("sys/mounts/sync-kv", logical.UpdateOperation, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}).IsError())
	require.False(t, call("sys/sync/destinations/aws-sm/test", logical.UpdateOperation, nil).IsError())
	association := map[string]any{"mount": "sync-kv", "secret_name": "a/b"}
	require.True(t, call("sys/sync/destinations/aws-sm/test/associations/set", logical.UpdateOperation, association).IsError())
	require.False(t, call("sync-kv/data/a/b", logical.UpdateOperation, map[string]any{"data": map[string]any{"password": "test"}}).IsError())
	for i := 0; i < 2; i++ {
		resp := call("sys/sync/destinations/aws-sm/test/associations/set", logical.UpdateOperation, association)
		require.False(t, resp.IsError())
		require.Len(t, resp.Data["associated_secrets"], 1)
		for _, a := range resp.Data["associated_secrets"].(map[string]any) {
			require.Equal(t, "PENDING", a.(map[string]any)["sync_status"])
		}
	}
	policy := `path "sys/sync/*" { capabilities = ["read", "update", "list"] }`
	require.False(t, call("sys/policies/acl/sync-only", logical.UpdateOperation, map[string]any{"policy": policy}).IsError())
	token := call("auth/token/create", logical.UpdateOperation, map[string]any{"policies": []string{"sync-only"}, "no_default_policy": true}).Auth.ClientToken
	_, err := core.HandleRequest(ctx, &logical.Request{Path: "sys/sync/destinations/aws-sm/test/associations/set", Operation: logical.UpdateOperation, Data: association, ClientToken: token})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
	require.Equal(t, 1, call("sys/sync/associations", logical.ListOperation, nil).Data["total_associations"])
	require.Empty(t, call("sys/sync/destinations/aws-sm/test/associations/remove", logical.UpdateOperation, association).Data["associated_secrets"])
}

func TestSyncDestinationCRUD(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	storage := &logical.InmemStorage{}
	newBackend := func() *framework.Backend { b := &SystemBackend{}; return &framework.Backend{Paths: b.syncPaths()} }
	backend := newBackend()
	call := func(path string, op logical.Operation, data map[string]any) *logical.Response {
		t.Helper()
		resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: storage, Data: data})
		require.NoError(t, err)
		return resp
	}
	fixtures := map[string]map[string]any{
		"aws-sm":         {"region": "us-east-1", "access_key_id": "test", "secret_access_key": "secret"},
		"azure-kv":       {"key_vault_uri": "https://example.invalid", "client_id": "client", "tenant_id": "tenant", "client_secret": "secret"},
		"gcp-sm":         {"credentials": "{}", "project_id": "test"},
		"gh":             {"access_token": "secret", "repository_name": "test"},
		"vercel-project": {"access_token": "secret", "project_id": "test", "deployment_environments": []string{"development"}},
	}
	for _, typ := range syncDestinationTypes {
		t.Run(typ, func(t *testing.T) {
			path := "sync/destinations/" + typ + "/test"
			require.Nil(t, call(path, logical.ReadOperation, nil))
			resp := call(path, logical.UpdateOperation, fixtures[typ])
			require.False(t, resp.IsError())
			require.Equal(t, typ, resp.Data["type"])
			encoded, err := json.Marshal(resp.Data)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), `:"secret"`)
			backend = newBackend()
			readJSON, err := json.Marshal(call(path, logical.ReadOperation, nil).Data)
			require.NoError(t, err)
			require.JSONEq(t, string(encoded), string(readJSON))
			updated := call(path, logical.UpdateOperation, map[string]any{"secret_name_template": "test-{{ .SecretPath }}"})
			require.False(t, updated.IsError())
			beforeJSON, err := json.Marshal(resp.Data["connection_details"])
			require.NoError(t, err)
			afterJSON, err := json.Marshal(updated.Data["connection_details"])
			require.NoError(t, err)
			require.JSONEq(t, string(beforeJSON), string(afterJSON))
			require.True(t, call(path, logical.UpdateOperation, map[string]any{"granularity": "invalid"}).IsError())
			require.Equal(t, updated.Data, call(path, logical.ReadOperation, nil).Data)
			require.Equal(t, []string{"test"}, call("sync/destinations/"+typ, logical.ListOperation, nil).Data["keys"])
		})
	}
	unified := call("sync/destinations", logical.ListOperation, nil)
	require.Equal(t, 5, unified.Data["total_destinations"])
	require.Equal(t, []string{"test"}, unified.Data["key_info"].(map[string]any)["aws-sm/"])
	for _, typ := range syncDestinationTypes {
		path := "sync/destinations/" + typ + "/test"
		require.Nil(t, call(path, logical.DeleteOperation, nil))
		require.Nil(t, call(path, logical.DeleteOperation, nil))
		require.Nil(t, call(path, logical.ReadOperation, nil))
	}
	require.Equal(t, 0, call("sync/destinations", logical.ListOperation, nil).Data["total_destinations"])
}

func TestSyncValidationAndConfig(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	storage := &logical.InmemStorage{}
	b := &SystemBackend{}
	backend := &framework.Backend{Paths: b.syncPaths()}
	for _, tc := range []struct {
		typ  string
		data map[string]any
	}{
		{"aws-sm", map[string]any{"access_key_id": "x", "identity_token_audience": "x", "role_arn": "x"}},
		{"aws-sm", map[string]any{"identity_token_audience": "x"}},
		{"aws-sm", map[string]any{"allowed_ipv4_addresses": []string{"::1/128"}}},
		{"azure-kv", map[string]any{}}, {"gcp-sm", map[string]any{"credentials": "bad"}},
		{"gcp-sm", map[string]any{"identity_token_ttl": "-1h"}},
		{"gh", map[string]any{"secrets_location": "environment"}},
		{"gh", map[string]any{"organization_visibility": "public"}},
		{"gh", map[string]any{"app_name": "app"}}, {"vercel-project", map[string]any{}},
	} {
		resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "sync/destinations/" + tc.typ + "/invalid", Storage: storage, Data: tc.data})
		require.True(t, err != nil || resp.IsError(), "%s: %#v", tc.typ, tc.data)
	}
	for _, data := range []map[string]any{{}, {"disabled": true, "queue_capacity": 42}, {"disabled": false}} {
		resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: logical.PatchOperation, Path: "sync/config", Storage: storage, Data: data})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		require.Contains(t, resp.Data, "disabled")
		require.Contains(t, resp.Data, "queue_capacity")
	}
	for _, field := range []string{"disabled", "queue_capacity"} {
		for _, invalid := range []any{"not-a-value", map[string]any{"invalid": true}} {
			resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: logical.PatchOperation, Path: "sync/config", Storage: storage, Data: map[string]any{field: invalid}})
			require.True(t, err != nil || resp.IsError())
		}
	}
	child := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	_, err := backend.HandleRequest(child, &logical.Request{Operation: logical.PatchOperation, Path: "sync/config", Storage: storage})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
}

func TestSyncAssociationShapesAndRemove(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	storage := &logical.InmemStorage{}
	b := &SystemBackend{}
	backend := &framework.Backend{Paths: b.syncPaths()}
	call := func(path string, op logical.Operation, data map[string]any) *logical.Response {
		t.Helper()
		r, e := backend.HandleRequest(ctx, &logical.Request{Path: path, Operation: op, Data: data, Storage: storage})
		require.NoError(t, e)
		return r
	}
	require.False(t, call("sync/destinations/aws-sm/test", logical.UpdateOperation, nil).IsError())
	require.True(t, call("sync/destinations/aws-sm/test/associations/set", logical.UpdateOperation, nil).IsError())
	require.True(t, call("sync/associations/destinations", logical.ReadOperation, nil).IsError())
	// Seed local state only; this is not a fabricated provider delivery result.
	tuple, _ := json.Marshal([]string{"aws-sm", "test", "secret", "a/b"})
	a := syncAssociation{Type: "aws-sm", Name: "test", Mount: "secret", Accessor: "kv_test", Secret: "a/b", Status: "PENDING", Updated: "2026-01-01T00:00:00Z"}
	require.NoError(t, syncSave(ctx, storage, "associations", map[string]syncAssociation{string(tuple): a}))
	r := call("sync/destinations/aws-sm/test/associations", logical.ReadOperation, nil)
	require.Equal(t, "PENDING", r.Data["associated_secrets"].(map[string]any)["kv_test/a/b"].(map[string]any)["sync_status"])
	r = call("sync/associations", logical.ListOperation, nil)
	require.Equal(t, 1, r.Data["total_associations"])
	require.Equal(t, 1, r.Data["total_secrets"])
	r = call("sync/associations/destinations", logical.ReadOperation, map[string]any{"mount": "secret", "secret_name": "a/b"})
	require.Contains(t, r.Data["associated_destinations"], "aws-sm/test")
	require.True(t, call("sync/destinations/aws-sm/test", logical.DeleteOperation, nil).IsError())
	for i := 0; i < 2; i++ {
		r = call("sync/destinations/aws-sm/test/associations/remove", logical.UpdateOperation, map[string]any{"mount": "secret", "secret_name": "a/b"})
		require.Empty(t, r.Data["associated_secrets"])
	}
	require.Equal(t, 0, call("sync/associations", logical.ListOperation, nil).Data["total_secrets"])
}
