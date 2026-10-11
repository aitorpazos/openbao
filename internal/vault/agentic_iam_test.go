// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/routing"
	"github.com/stretchr/testify/require"
)

func agenticTestCall(t *testing.T, b logical.Backend, s logical.Storage, ctx context.Context, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: s, Data: data})
	require.NoError(t, err)
	return resp
}
func agenticTestKeys(t *testing.T) []any {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return []any{map[string]any{"key_id": "test", "pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}
}

func TestOAuthResourceProfiles(t *testing.T) {
	b := &framework.Backend{Paths: (&SystemBackend{}).oauthResourceServerPaths()}
	s := &logical.InmemStorage{}
	ctx := namespace.RootContext(t.Context())
	const base = "config/oauth-resource-server/"
	call := func(op logical.Operation, path string, data map[string]any) *logical.Response {
		return agenticTestCall(t, b, s, ctx, op, base+path, data)
	}
	keys := agenticTestKeys(t)
	for _, data := range []map[string]any{
		{}, {"issuer_id": "issuer", "use_jwks": false}, {"issuer_id": "issuer", "use_jwks": true},
		{"issuer_id": "issuer", "use_jwks": false, "public_keys": []any{map[string]any{"key_id": "x", "pem": "bad"}}},
		{"issuer_id": "issuer", "use_jwks": false, "public_keys": keys, "jwks_uri": "https://example.com/keys"},
		{"issuer_id": "issuer", "use_jwks": true, "public_keys": keys, "jwks_uri": "https://example.com/keys"},
		{"issuer_id": "issuer", "use_jwks": false, "public_keys": keys, "jwt_type": "id_token"},
		{"issuer_id": "issuer", "use_jwks": false, "public_keys": []any{keys[0], keys[0]}},
	} {
		require.True(t, call(logical.UpdateOperation, "invalid", data).IsError())
		require.Nil(t, call(logical.ReadOperation, "invalid", nil))
	}
	require.Nil(t, call(logical.UpdateOperation, "first", map[string]any{"issuer_id": "HTTPS://ISSUER.EXAMPLE///", "use_jwks": false, "public_keys": keys}))
	first := call(logical.ReadOperation, "first", nil)
	require.Equal(t, "https://issuer.example", first.Data["issuer_id"])
	require.Equal(t, "sub", first.Data["user_claim"])
	require.Equal(t, "jti", first.Data["unique_id_claim"])
	require.Equal(t, true, first.Data["enabled"])
	id := first.Data["config_id"].(string)
	require.Equal(t, first.Data, call(logical.ReadOperation, "id/"+id, nil).Data)
	require.True(t, call(logical.UpdateOperation, "duplicate", map[string]any{"issuer_id": "https://ISSUER.EXAMPLE/", "use_jwks": false, "public_keys": keys}).IsError())
	for _, data := range []map[string]any{{"issuer_id": "changed"}, {"unique_id_claim": "changed"}} {
		require.True(t, call(logical.UpdateOperation, "first", data).IsError())
	}
	require.Nil(t, call(logical.UpdateOperation, "first", map[string]any{"issuer_id": "https://issuer.example/", "unique_id_claim": "jti", "audiences": []string{"updated"}, "enabled": false, "clock_skew_leeway": 60}))
	updated := call(logical.ReadOperation, "first", nil)
	require.Equal(t, first.Data["public_keys"], updated.Data["public_keys"])
	require.Equal(t, id, updated.Data["config_id"])
	require.Equal(t, false, updated.Data["enabled"])
	require.Equal(t, float64(60), updated.Data["clock_skew_leeway"])
	require.Nil(t, call(logical.UpdateOperation, "first", map[string]any{"use_jwks": true, "jwks_uri": "https://example.com/keys"}))
	require.NotContains(t, call(logical.ReadOperation, "first", nil).Data, "public_keys")
	require.Nil(t, call(logical.UpdateOperation, "first", map[string]any{"use_jwks": false, "public_keys": keys}))
	require.NotContains(t, call(logical.ReadOperation, "first", nil).Data, "jwks_uri")
	// Identical issuer and profile name are independent in another namespace, even on shared storage.
	child := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	require.Nil(t, agenticTestCall(t, b, s, child, logical.ReadOperation, base+"first", nil))
	require.Nil(t, agenticTestCall(t, b, s, child, logical.UpdateOperation, base+"first", map[string]any{"issuer_id": "https://issuer.example", "use_jwks": false, "public_keys": keys}))
	childProfile := agenticTestCall(t, b, s, child, logical.ReadOperation, base+"first", nil)
	require.NotEqual(t, id, childProfile.Data["config_id"])
	require.Nil(t, agenticTestCall(t, b, s, child, logical.ReadOperation, base+"id/"+id, nil))
	for range 2 {
		require.Nil(t, call(logical.DeleteOperation, "first", nil))
	}
	require.Nil(t, call(logical.ReadOperation, "first", nil))
	require.Nil(t, call(logical.ReadOperation, "id/"+id, nil))
	require.NotNil(t, agenticTestCall(t, b, s, child, logical.ReadOperation, base+"first", nil))
}

func TestAgentRegistryMountBackfill(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	child := testCreateNamespace(t, ctx, c.systemBackend, "agentic-upgrade", nil)
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()
	original := c.mounts
	defer func() { c.mounts = original }()
	c.mounts = &routing.MountTable{Type: routing.MountTableType}
	// Simulate an upgrade with an existing root registry but no child registry.
	for _, entry := range original.Entries {
		if entry.Type != "agent-registry" || entry.NamespaceID != child.ID {
			c.mounts.Entries = append(c.mounts.Entries, entry)
		}
	}
	added, err := c.ensureAgentRegistryMounts(ctx)
	require.NoError(t, err)
	require.True(t, added)
	require.Len(t, c.mounts.Entries, len(original.Entries))
	added, err = c.ensureAgentRegistryMounts(ctx)
	require.NoError(t, err)
	require.False(t, added)
}

func TestAgentRegistryCRUD(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	s := &logical.InmemStorage{}
	b, err := c.agentRegistryFactory(ctx, &logical.BackendConfig{StorageView: s})
	require.NoError(t, err)
	call := func(op logical.Operation, path string, data map[string]any) *logical.Response {
		return agenticTestCall(t, b, s, ctx, op, path, data)
	}
	entity := func(name string) string {
		resp, err := c.identityStore.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "entity", Data: map[string]any{"name": name}})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		return resp.Data["id"].(string)
	}
	one, two := entity("agent-one"), entity("agent-two")
	for _, data := range []map[string]any{{}, {"display_name": "agent"}, {"entity_id": one}, {"entity_id": "00000000-0000-0000-0000-000000000000", "display_name": "agent"}, {"entity_id": one, "display_name": "agent", "ceiling_policies": []string{"root"}}} {
		require.True(t, call(logical.UpdateOperation, "register", data).IsError())
	}
	created := call(logical.UpdateOperation, "register", map[string]any{"display_name": "agent", "entity_id": one, "ceiling_policies": []string{"limited"}})
	require.False(t, created.IsError())
	id := created.Data["id"].(string)
	first := call(logical.ReadOperation, "registration/id/"+id, nil)
	require.Equal(t, []any{"limited", "default", "default-ceiling"}, first.Data["ceiling_policies"])
	require.Equal(t, first.Data, call(logical.ReadOperation, "registration/display-name/agent", nil).Data)
	require.Equal(t, first.Data, call(logical.ReadOperation, "registration/entity-id/"+one, nil).Data)
	for _, data := range []map[string]any{{"display_name": "agent", "entity_id": two}, {"display_name": "other", "entity_id": one}} {
		require.True(t, call(logical.UpdateOperation, "register", data).IsError())
	}
	for _, path := range []string{"registration/id", "registration/display-name"} {
		require.Len(t, call(logical.ListOperation, path, nil).Data["keys"], 1)
	}
	require.False(t, call(logical.UpdateOperation, "registration/id/"+id, map[string]any{"display_name": "renamed", "entity_id": one, "no_default_ceiling_policy": true, "owner": "team", "optional_authorization_details": true}).IsError())
	renamed := call(logical.ReadOperation, "registration/display-name/renamed", nil)
	require.Empty(t, renamed.Data["ceiling_policies"])
	require.Equal(t, "team", renamed.Data["owner"])
	require.Equal(t, true, renamed.Data["optional_authorization_details"])
	require.Equal(t, first.Data["creation_time"], renamed.Data["creation_time"])
	require.Nil(t, call(logical.ReadOperation, "registration/display-name/agent", nil))
	require.False(t, call(logical.UpdateOperation, "registration/display-name/renamed", map[string]any{"entity_id": two, "description": "updated"}).IsError())
	require.Nil(t, call(logical.ReadOperation, "registration/entity-id/"+one, nil))
	require.Equal(t, id, call(logical.ReadOperation, "registration/entity-id/"+two, nil).Data["id"])
	require.False(t, call(logical.UpdateOperation, "register", map[string]any{"id": id, "display_name": "final", "entity_id": one}).IsError())
	child := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	require.Nil(t, agenticTestCall(t, b, s, child, logical.ReadOperation, "registration/id/"+id, nil))
	require.True(t, agenticTestCall(t, b, s, child, logical.UpdateOperation, "register", map[string]any{"display_name": "cross-namespace", "entity_id": one}).IsError())
	require.Nil(t, call(logical.DeleteOperation, "registration/display-name/final", nil))
	require.Nil(t, call(logical.ReadOperation, "registration/id/"+id, nil))
	require.True(t, call(logical.UpdateOperation, "register", map[string]any{"id": id, "display_name": "absent", "entity_id": one}).IsError())
	require.False(t, call(logical.UpdateOperation, "register", map[string]any{"display_name": "reused", "entity_id": one}).IsError())
}
