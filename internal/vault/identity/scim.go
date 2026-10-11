// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// Serialize configuration and resource mutations, including asynchronous cleanup.
// Identity's existing locks continue to protect the underlying entity/group DB.
var scimLock sync.Mutex

const scimPrefix = "scim/"
const scimCore = "urn:ietf:params:scim:schemas:core:2.0:"

type scimClient struct {
	Principal string `json:"access_grant_principal"`
	Accessor  string `json:"alias_mount_accessor"`
	Deleting  bool   `json:"deleting"`
}

func (i *IdentityStore) SCIMActivated(ctx context.Context) (bool, error) {
	s := i.View(namespace.ContextWithNamespace(ctx, namespace.RootNamespace))
	if s == nil {
		return false, fmt.Errorf("root identity storage unavailable")
	}
	entry, err := s.Get(ctx, scimPrefix+"activated")
	return entry != nil, err
}

// ActivateSCIM is intentionally one-way. There is no deactivation operation.
func (i *IdentityStore) ActivateSCIM(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrPermissionDenied
	}
	return i.View(ctx).Put(ctx, &logical.StorageEntry{Key: scimPrefix + "activated", Value: []byte("true")})
}

func scimPaths(i *IdentityStore) []*framework.Path {
	fields := map[string]*framework.FieldSchema{}
	for _, name := range []string{"client_name", "kind", "id", "filter"} {
		fields[name] = &framework.FieldSchema{Type: framework.TypeString}
	}
	client := &framework.Path{Pattern: "scim/client/(?P<client_name>[^/]+)$", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{}}
	for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation} {
		client.Callbacks[op] = i.handleSCIMClient
	}
	protocol := &framework.Path{Pattern: "scim/v2/(?P<kind>Users|Groups|Schemas|ResourceTypes|ServiceProviderConfig|Me)(/(?P<id>[^/]+))?$", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{}}
	for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation, logical.PatchOperation, logical.DeleteOperation} {
		protocol.Callbacks[op] = i.handleSCIMProtocol
	}
	return []*framework.Path{client, {Pattern: "scim/client/?$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: i.handleSCIMClient}}, protocol}
}

func scimLoad(ctx context.Context, s logical.Storage, key string, value any) (bool, error) {
	entry, err := s.Get(ctx, scimPrefix+key)
	if err != nil || entry == nil {
		return false, err
	}
	return true, entry.DecodeJSON(value)
}
func scimSave(ctx context.Context, s logical.Storage, key string, value any) error {
	entry, err := logical.StorageEntryJSON(scimPrefix+key, value)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
func (i *IdentityStore) handleSCIMClient(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	scimLock.Lock()
	defer scimLock.Unlock()
	active, err := i.SCIMActivated(ctx)
	if err != nil {
		return nil, err
	}
	if !active {
		return logical.ErrorResponse("SCIM is not activated"), nil
	}
	s := i.View(ctx)
	if req.Operation == logical.ListOperation {
		keys, err := s.List(ctx, scimPrefix+"clients/")
		return logical.ListResponse(keys), err
	}
	name := d.Get("client_name").(string)
	var c scimClient
	exists, err := scimLoad(ctx, s, "clients/"+name, &c)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case logical.ReadOperation:
		if !exists {
			return nil, nil
		}
		return &logical.Response{Data: map[string]any{"access_grant_principal": c.Principal, "alias_mount_accessor": c.Accessor, "deleting": c.Deleting}}, nil
	case logical.DeleteOperation:
		if !exists {
			return nil, nil
		}
		c.Deleting = true
		if err := scimSave(ctx, s, "clients/"+name, c); err != nil {
			return nil, err
		}
		// Periodic cleanup retries persisted deletion markers after restart/failure.
		go func() {
			cleanupCtx := context.WithoutCancel(ctx)
			if err := i.SCIMCleanup(cleanupCtx); err != nil {
				i.logger.Error("SCIM cleanup failed", "error", err)
			}
		}()
		return nil, nil
	}
	if c.Deleting {
		return logical.ErrorResponse("client is deleting"), nil
	}
	principal, ok := req.Data["access_grant_principal"].(string)
	if !ok || principal == "" {
		return logical.ErrorResponse("access_grant_principal must be an entity ID string"), nil
	}
	entity, err := i.MemDBEntityByID(ctx, principal, false)
	if err != nil {
		return logical.ErrorResponse("invalid access_grant_principal"), nil
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if entity == nil || entity.NamespaceID != ns.ID {
		return logical.ErrorResponse("access_grant_principal must be an existing entity in this namespace"), nil
	}
	accessor := c.Accessor
	if value, present := req.Data["alias_mount_accessor"]; present {
		var valid bool
		accessor, valid = value.(string)
		if !valid {
			return logical.ErrorResponse("alias_mount_accessor must be a string"), nil
		}
		if exists && accessor != c.Accessor {
			return logical.ErrorResponse("alias_mount_accessor is immutable"), nil
		}
	}
	if accessor != "" {
		mount := i.router.MatchingMountByAccessor(accessor)
		if mount == nil || mount.NamespaceID != ns.ID || mount.Local || mount.Table != "auth" {
			return logical.ErrorResponse("alias_mount_accessor must identify a non-local auth mount in this namespace"), nil
		}
	}
	c.Principal, c.Accessor = principal, accessor
	return nil, scimSave(ctx, s, "clients/"+name, c)
}

func scimResponse(status int, body any) (*logical.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{logical.HTTPStatusCode: status, logical.HTTPContentType: "application/scim+json", logical.HTTPRawBody: raw}}, nil
}
func scimError(status int, detail string) (*logical.Response, error) {
	return scimResponse(status, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprint(status), "detail": detail})
}
func scimList(resources []any) map[string]any {
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources}
}
func (i *IdentityStore) handleSCIMProtocol(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	scimLock.Lock()
	defer scimLock.Unlock()
	active, err := i.SCIMActivated(ctx)
	if err != nil {
		return nil, err
	}
	if !active {
		return scimError(403, "SCIM is not activated")
	}
	kind, id := d.Get("kind").(string), d.Get("id").(string)
	if kind == "ServiceProviderConfig" && req.Operation == logical.ReadOperation && id == "" {
		return scimResponse(200, map[string]any{"schemas": []string{scimCore + "ServiceProviderConfig"}, "patch": map[string]any{"supported": true}, "filter": map[string]any{"supported": true}, "bulk": map[string]any{"supported": false}, "sort": map[string]any{"supported": false}, "etag": map[string]any{"supported": false}, "changePassword": map[string]any{"supported": false}, "authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "Bearer token", "description": "Entity-bound OpenBao token"}}})
	}
	s := i.View(ctx)
	names, err := s.List(ctx, scimPrefix+"clients/")
	if err != nil {
		return nil, err
	}
	owner := ""
	var client scimClient
	for _, name := range names {
		var c scimClient
		if _, err := scimLoad(ctx, s, "clients/"+name, &c); err != nil {
			return nil, err
		}
		if req.EntityID != "" && c.Principal == req.EntityID && !c.Deleting {
			if owner != "" {
				return scimError(403, "ambiguous client principal")
			}
			owner, client = name, c
		}
	}
	if owner == "" {
		return scimError(403, "token must belong to an active SCIM client principal")
	}
	if kind == "Me" {
		return scimError(501, "Me is not implemented")
	}
	if kind == "Schemas" || kind == "ResourceTypes" {
		if req.Operation != logical.ReadOperation {
			return scimError(405, "discovery is read-only")
		}
		resources := []any{}
		for _, typ := range []string{"User", "Group"} {
			resource := map[string]any{"id": scimCore + typ, "name": typ, "schemas": []string{scimCore + "Schema"}, "attributes": []any{}}
			if kind == "ResourceTypes" {
				resource = map[string]any{"id": typ, "name": typ, "endpoint": "/" + typ + "s", "schema": scimCore + typ, "schemas": []string{scimCore + "ResourceType"}}
			}
			if id != "" && (id == resource["id"] || id == typ) {
				return scimResponse(200, resource)
			}
			resources = append(resources, resource)
		}
		if id != "" {
			return scimError(404, "resource not found")
		}
		return scimResponse(200, scimList(resources))
	}
	if kind != "Users" && kind != "Groups" {
		return scimError(405, "unsupported operation")
	}
	return i.scimResource(ctx, req, d, owner, client, kind, id)
}

func (i *IdentityStore) SCIMCleanup(ctx context.Context) error {
	scimLock.Lock()
	defer scimLock.Unlock()
	s := i.View(ctx)
	names, err := s.List(ctx, scimPrefix+"clients/")
	if err != nil {
		return err
	}
	for _, name := range names {
		var c scimClient
		if _, err := scimLoad(ctx, s, "clients/"+name, &c); err != nil {
			return err
		}
		if !c.Deleting {
			continue
		}
		for _, kind := range []string{"Groups", "Users"} {
			ids, err := s.List(ctx, scimPrefix+"resources/"+kind+"/")
			if err != nil {
				return err
			}
			for _, id := range ids {
				var r scimResourceRecord
				if _, err := scimLoad(ctx, s, "resources/"+kind+"/"+id, &r); err != nil {
					return err
				}
				if r.Owner != name {
					continue
				}
				if err := i.scimDeleteResource(ctx, kind, id); err != nil {
					return err
				}
			}
		}
		if err := s.Delete(ctx, scimPrefix+"clients/"+name); err != nil {
			return err
		}
	}
	return nil
}

func scimString(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return strings.TrimSpace(value)
}
