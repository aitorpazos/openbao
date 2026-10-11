// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// HandleRequest protects managed identity fields on the ordinary identity API.
// SCIM uses the internal identity primitives after authenticating its owner.
func (i *IdentityStore) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	mutation := req.Operation == logical.UpdateOperation || req.Operation == logical.CreateOperation || req.Operation == logical.DeleteOperation || req.Operation == logical.PatchOperation
	if !mutation || !(strings.HasPrefix(req.Path, "entity") || strings.HasPrefix(req.Path, "group")) {
		return i.Backend.HandleRequest(ctx, req)
	}
	scimLock.Lock()
	defer scimLock.Unlock()
	denied, err := i.scimManagedMutation(ctx, req)
	if err != nil {
		return nil, err
	}
	if denied {
		return logical.ErrorResponse("SCIM-managed fields can only be changed through the owning SCIM client"), logical.ErrPermissionDenied
	}
	return i.Backend.HandleRequest(ctx, req)
}

func (i *IdentityStore) scimManagedMutation(ctx context.Context, req *logical.Request) (bool, error) {
	s := i.View(ctx)
	isManaged := func(kind, id string) (bool, error) {
		if id == "" {
			return false, nil
		}
		var r scimResourceRecord
		return scimLoad(ctx, s, "resources/"+kind+"/"+id, &r)
	}
	path := strings.Split(strings.TrimSuffix(req.Path, "/"), "/")
	id, name := scimString(req.Data, "id"), scimString(req.Data, "name")
	if len(path) > 2 {
		if path[1] == "id" {
			id = path[2]
		}
		if path[1] == "name" {
			name = path[2]
		}
	}
	switch path[0] {
	case "entity":
		// Merges and batch deletes may reference more than one managed entity.
		if len(path) > 1 && (path[1] == "merge" || path[1] == "batch-delete") {
			ids := []string{scimString(req.Data, "to_entity_id")}
			for _, key := range []string{"from_entity_ids", "entity_ids"} {
				switch values := req.Data[key].(type) {
				case []string:
					ids = append(ids, values...)
				case []any:
					for _, v := range values {
						if text, ok := v.(string); ok {
							ids = append(ids, text)
						}
					}
				case string:
					ids = append(ids, strings.Split(values, ",")...)
				}
			}
			for _, id := range ids {
				managed, err := isManaged("Users", id)
				if managed || err != nil {
					return managed, err
				}
			}
			return false, nil
		}
		if id == "" && name != "" {
			e, err := i.MemDBEntityByName(ctx, name, false)
			if err != nil {
				return false, err
			}
			if e != nil {
				id = e.ID
			}
		}
		managed, err := isManaged("Users", id)
		if err != nil || !managed {
			return false, err
		}
		if req.Operation == logical.DeleteOperation {
			return true, nil
		}
		for _, key := range []string{"name", "disabled"} {
			if _, present := req.Data[key]; present {
				return true, nil
			}
		}
	case "group":
		if id == "" && name != "" {
			g, err := i.MemDBGroupByName(ctx, name, false)
			if err != nil {
				return false, err
			}
			if g != nil {
				id = g.ID
			}
		}
		managed, err := isManaged("Groups", id)
		if err != nil || !managed {
			return false, err
		}
		if req.Operation == logical.DeleteOperation {
			return true, nil
		}
		for _, key := range []string{"name", "type", "member_entity_ids", "member_group_ids"} {
			if _, present := req.Data[key]; present {
				return true, nil
			}
		}
	case "entity-alias":
		entityID := scimString(req.Data, "canonical_id")
		if id != "" {
			a, err := i.MemDBAliasByID(ctx, id, false, false)
			if err != nil {
				return false, err
			}
			if a != nil {
				managed, err := isManaged("Users", a.CanonicalID)
				if managed || err != nil {
					return managed, err
				}
			}
		}
		if accessor := scimString(req.Data, "mount_accessor"); accessor != "" && name != "" {
			a, err := i.MemDBAliasByFactors(ctx, accessor, name, false, false)
			if err != nil {
				return false, err
			}
			if a != nil {
				managed, err := isManaged("Users", a.CanonicalID)
				if managed || err != nil {
					return managed, err
				}
			}
		}
		return isManaged("Users", entityID)
	}
	return false, nil
}
