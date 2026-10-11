// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestActivationFlagSCIM(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	b := NewSystemBackend(c, nil)
	call := func(op logical.Operation, path string) *logical.Response {
		t.Helper()
		r, e := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path})
		require.NoError(t, e)
		return r
	}
	r := call(logical.ReadOperation, "activation-flags")
	require.Equal(t, []string{}, r.Data["activated"])
	require.Equal(t, []string{"enable-scim"}, r.Data["unactivated"])
	for range 2 {
		call(logical.UpdateOperation, "activation-flags/enable-scim/activate")
	}
	r = call(logical.ReadOperation, "activation-flags")
	require.Equal(t, []string{"enable-scim"}, r.Data["activated"])
	require.Equal(t, []string{}, r.Data["unactivated"])
	_, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "activation-flags/enable-scim/activate"})
	require.ErrorIs(t, err, logical.ErrUnsupportedOperation)
}

func TestSCIMAliasAndNamespace(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	i := c.identityStore
	require.NoError(t, i.ActivateSCIM(ctx))
	mounts, err := c.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "sys/auth", ClientToken: root})
	require.NoError(t, err)
	accessor := mounts.Data["token/"].(map[string]any)["accessor"].(string)
	invoke := func(path string, data map[string]any) *logical.Response {
		t.Helper()
		r, e := i.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: path, Data: data})
		require.NoError(t, e)
		return r
	}
	actor := invoke("entity", map[string]any{"name": "alias-actor"}).Data["id"].(string)
	require.Nil(t, invoke("scim/client/actor", map[string]any{"access_grant_principal": actor, "alias_mount_accessor": accessor}))
	require.True(t, invoke("scim/client/actor", map[string]any{"access_grant_principal": actor, "alias_mount_accessor": ""}).IsError())
	protocol := func(path, name string) string {
		t.Helper()
		r, e := i.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: path, EntityID: actor, Data: map[string]any{"userName": name, "externalId": "alias-external"}})
		require.NoError(t, e)
		require.Contains(t, []int{200, 201}, r.Data[logical.HTTPStatusCode])
		var body map[string]any
		require.NoError(t, json.Unmarshal(r.Data[logical.HTTPRawBody].([]byte), &body))
		return body["id"].(string)
	}
	uid := protocol("scim/v2/Users", "alias-user")
	alias, err := i.MemDBAliasByFactors(ctx, accessor, "alias-user", false, false)
	require.NoError(t, err)
	require.NotNil(t, alias)
	require.Equal(t, uid, alias.CanonicalID)
	protocol("scim/v2/Users/"+uid, "alias-renamed")
	alias, err = i.MemDBAliasByFactors(ctx, accessor, "alias-renamed", false, false)
	require.NoError(t, err)
	require.NotNil(t, alias)
	require.Equal(t, uid, alias.CanonicalID)
	child := &namespace.Namespace{ID: "scim-child", UUID: "11111111-1111-1111-1111-111111111111", Path: "scim-child/"}
	require.NoError(t, i.AddNamespaceView(c, child, &logical.InmemStorage{}))
	childCtx := namespace.ContextWithNamespace(ctx, child)
	require.ErrorIs(t, i.ActivateSCIM(childCtx), logical.ErrPermissionDenied)
	active, err := i.SCIMActivated(childCtx)
	require.NoError(t, err)
	require.True(t, active)
	r, err := i.HandleRequest(childCtx, &logical.Request{Operation: logical.UpdateOperation, Path: "scim/client/actor", Data: map[string]any{"access_grant_principal": actor}})
	require.NoError(t, err)
	require.True(t, r.IsError())
	r, err = i.HandleRequest(childCtx, &logical.Request{Operation: logical.ReadOperation, Path: "scim/client/actor"})
	require.NoError(t, err)
	require.Nil(t, r)
}

func TestSCIMLifecycle(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	i := c.identityStore
	call := func(op logical.Operation, path, actor string, data map[string]any) *logical.Response {
		t.Helper()
		r, e := i.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, EntityID: actor, Data: data})
		require.NoError(t, e)
		return r
	}
	protocol := func(op logical.Operation, path, actor string, data map[string]any, status int) map[string]any {
		t.Helper()
		r := call(op, "scim/v2/"+path, actor, data)
		require.NotNil(t, r)
		require.Equal(t, status, r.Data[logical.HTTPStatusCode], r)
		require.Equal(t, "application/scim+json", r.Data[logical.HTTPContentType])
		var body map[string]any
		require.NoError(t, json.Unmarshal(r.Data[logical.HTTPRawBody].([]byte), &body))
		return body
	}
	protocol(logical.ReadOperation, "ServiceProviderConfig", "", nil, 403)
	require.NoError(t, i.ActivateSCIM(ctx))
	protocol(logical.ReadOperation, "ServiceProviderConfig", "", nil, 200)
	protocol(logical.ReadOperation, "Users", "", nil, 403)
	actor := call(logical.UpdateOperation, "entity", "", map[string]any{"name": "scim-actor"}).Data["id"].(string)
	other := call(logical.UpdateOperation, "entity", "", map[string]any{"name": "scim-other"}).Data["id"].(string)
	for _, data := range []map[string]any{{}, {"access_grant_principal": map[string]any{"bad": true}}, {"access_grant_principal": "00000000-0000-0000-0000-000000000000"}, {"access_grant_principal": actor, "alias_mount_accessor": "missing"}} {
		r := call(logical.UpdateOperation, "scim/client/invalid", "", data)
		require.True(t, r.IsError(), r)
	}
	call(logical.UpdateOperation, "scim/client/actor", "", map[string]any{"access_grant_principal": actor})
	call(logical.UpdateOperation, "scim/client/other", "", map[string]any{"access_grant_principal": other})
	r := call(logical.ReadOperation, "scim/client/actor", "", nil)
	require.Equal(t, actor, r.Data["access_grant_principal"])
	r = call(logical.ListOperation, "scim/client/", "", nil)
	require.Len(t, r.Data["keys"], 2)
	for _, path := range []string{"Schemas", "ResourceTypes"} {
		protocol(logical.ReadOperation, path, actor, nil, 200)
	}
	protocol(logical.ReadOperation, "Me", actor, nil, 501)
	for _, data := range []map[string]any{{"userName": "missing-external"}, {"externalId": "missing-name"}} {
		protocol(logical.UpdateOperation, "Users", actor, data, 400)
	}
	user := protocol(logical.UpdateOperation, "Users", actor, map[string]any{"userName": "scim-user", "externalId": "scim-external", "active": true}, 201)
	uid := user["id"].(string)
	entity, err := i.MemDBEntityByID(ctx, uid, false)
	require.NoError(t, err)
	require.Equal(t, "scim-user", entity.Name)
	require.False(t, entity.Disabled)
	protocol(logical.ReadOperation, "Users/"+uid, other, nil, 404)
	list := protocol(logical.ReadOperation, "Users", other, nil, 200)
	require.Equal(t, float64(0), list["totalResults"])
	for _, filter := range []string{`userName eq "scim-user"`, `externalId eq "scim-external"`, `active eq true`, `meta.lastModified gt "2000-01-01T00:00:00Z"`} {
		list := protocol(logical.ReadOperation, "Users", actor, map[string]any{"filter": filter}, 200)
		require.Equal(t, float64(1), list["totalResults"])
	}
	for _, filter := range []string{`userName ne "x"`, `other eq "x"`, `active eq "true"`, `meta.lastModified eq "2000-01-01T00:00:00Z"`} {
		protocol(logical.ReadOperation, "Users", actor, map[string]any{"filter": filter}, 400)
	}
	protocol(logical.UpdateOperation, "Users/"+uid, actor, map[string]any{"userName": "scim-user", "externalId": "changed"}, 400)
	protocol(logical.UpdateOperation, "Users/"+uid, actor, map[string]any{"userName": "renamed-user", "externalId": "scim-external", "active": true}, 200)
	patch := map[string]any{"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}}}
	protocol(logical.PatchOperation, "Users/"+uid, actor, patch, 200)
	entity, err = i.MemDBEntityByID(ctx, uid, false)
	require.NoError(t, err)
	require.True(t, entity.Disabled)
	_, err = i.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "entity/id/" + uid, Data: map[string]any{"disabled": false}})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
	call(logical.UpdateOperation, "entity/id/"+uid, "", map[string]any{"policies": []string{"test"}})
	group := protocol(logical.UpdateOperation, "Groups", actor, map[string]any{"displayName": "scim-group", "members": []any{map[string]any{"value": uid}}}, 201)
	gid := group["id"].(string)
	protocol(logical.UpdateOperation, "Groups", other, map[string]any{"displayName": "bad-group", "members": []any{map[string]any{"value": uid}}}, 400)
	protocol(logical.ReadOperation, "Groups/"+gid, other, nil, 404)
	user = protocol(logical.ReadOperation, "Users/"+uid, actor, nil, 200)
	require.Len(t, user["groups"], 1)
	for _, tc := range []struct {
		filter string
		status int
	}{{`displayName eq "scim-group"`, 200}, {`displayName ne "scim-group"`, 400}, {`externalId eq "x"`, 400}} {
		protocol(logical.ReadOperation, "Groups", actor, map[string]any{"filter": tc.filter}, tc.status)
	}
	protocol(logical.UpdateOperation, "Groups/"+gid, actor, map[string]any{"displayName": "renamed-group", "members": []any{}}, 200)
	for _, op := range []string{"add", "remove"} {
		result := protocol(logical.PatchOperation, "Groups/"+gid, actor, map[string]any{"Operations": []any{map[string]any{"op": op, "path": "members", "value": []any{map[string]any{"value": uid}}}}}, 200)
		if op == "add" {
			require.Len(t, result["members"], 1)
		} else {
			require.Len(t, result["members"], 0)
		}
	}
	protocol(logical.DeleteOperation, "Groups/"+gid, actor, nil, 204)
	protocol(logical.DeleteOperation, "Users/"+uid, actor, nil, 204)
	protocol(logical.ReadOperation, "Users/"+uid, actor, nil, 404)
	// Client deletion persists a marker and removes all owned identity objects.
	user = protocol(logical.UpdateOperation, "Users", actor, map[string]any{"userName": "cleanup-user", "externalId": "cleanup"}, 201)
	uid = user["id"].(string)
	call(logical.DeleteOperation, "scim/client/actor", "", nil)
	require.Eventually(t, func() bool {
		r, e := i.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "scim/client/actor"})
		return e == nil && r == nil
	}, 5*time.Second, 10*time.Millisecond)
	entity, err = i.MemDBEntityByID(ctx, uid, false)
	require.NoError(t, err)
	require.Nil(t, entity)
	protocol(logical.ReadOperation, "Users", actor, nil, 403)
}
