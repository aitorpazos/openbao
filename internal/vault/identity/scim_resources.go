// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	identitymodel "github.com/openbao/openbao/v2/internal/helper/identity"
)

type scimResourceRecord struct {
	Owner string         `json:"owner"`
	Body  map[string]any `json:"body"`
}

var scimFilterRE = regexp.MustCompile(`^\s*([A-Za-z.]+)\s+(eq|gt|ge|lt|le)\s+("(?:[^"\\]|\\.)*"|true|false)\s*$`)

func scimFilter(kind, filter string) (func(map[string]any) bool, error) {
	if filter == "" {
		return func(map[string]any) bool { return true }, nil
	}
	match := scimFilterRE.FindStringSubmatch(filter)
	if match == nil {
		return nil, fmt.Errorf("unsupported filter")
	}
	attr, op := match[1], match[2]
	var value any
	if err := json.Unmarshal([]byte(match[3]), &value); err != nil {
		return nil, err
	}
	if attr == "meta.lastModified" {
		text, ok := value.(string)
		if !ok || op == "eq" {
			return nil, fmt.Errorf("unsupported lastModified filter")
		}
		target, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return nil, fmt.Errorf("invalid lastModified timestamp")
		}
		return func(body map[string]any) bool {
			meta, _ := body["meta"].(map[string]any)
			t, err := time.Parse(time.RFC3339Nano, scimString(meta, "lastModified"))
			if err != nil {
				return false
			}
			switch op {
			case "gt":
				return t.After(target)
			case "ge":
				return !t.Before(target)
			case "lt":
				return t.Before(target)
			case "le":
				return !t.After(target)
			}
			return false
		}, nil
	}
	allowed := kind == "Users" && (attr == "userName" || attr == "externalId" || attr == "active") || kind == "Groups" && attr == "displayName"
	if !allowed || op != "eq" {
		return nil, fmt.Errorf("unsupported filter attribute or operator")
	}
	if attr == "active" {
		if _, ok := value.(bool); !ok {
			return nil, fmt.Errorf("active filter requires boolean")
		}
	} else if _, ok := value.(string); !ok {
		return nil, fmt.Errorf("filter requires string")
	}
	return func(body map[string]any) bool { return body[attr] == value }, nil
}

func (i *IdentityStore) scimResource(ctx context.Context, req *logical.Request, d *framework.FieldData, owner string, client scimClient, kind, id string) (*logical.Response, error) {
	s := i.View(ctx)
	prefix := "resources/" + kind + "/"
	var old scimResourceRecord
	if id != "" {
		exists, err := scimLoad(ctx, s, prefix+id, &old)
		if err != nil {
			return nil, err
		}
		if !exists || old.Owner != owner {
			return scimError(404, "resource not found")
		}
	}
	switch req.Operation {
	case logical.ReadOperation:
		if id != "" {
			if kind == "Users" {
				if err := i.scimUserGroups(ctx, owner, old.Body); err != nil {
					return nil, err
				}
			}
			return scimResponse(200, old.Body)
		}
		match, err := scimFilter(kind, d.Get("filter").(string))
		if err != nil {
			return scimError(400, err.Error())
		}
		ids, err := s.List(ctx, scimPrefix+prefix)
		if err != nil {
			return nil, err
		}
		resources := []any{}
		for _, rid := range ids {
			var r scimResourceRecord
			if _, err := scimLoad(ctx, s, prefix+rid, &r); err != nil {
				return nil, err
			}
			if r.Owner == owner && match(r.Body) {
				if kind == "Users" {
					if err := i.scimUserGroups(ctx, owner, r.Body); err != nil {
						return nil, err
					}
				}
				resources = append(resources, r.Body)
			}
		}
		return scimResponse(200, scimList(resources))
	case logical.DeleteOperation:
		if id == "" {
			return scimError(405, "resource ID required")
		}
		if err := i.scimDeleteResource(ctx, kind, id); err != nil {
			return nil, err
		}
		return scimResponse(204, nil)
	}
	body := make(map[string]any)
	for key, value := range req.Data {
		body[key] = value
	}
	if req.Operation == logical.PatchOperation {
		if id == "" {
			return scimError(405, "resource ID required")
		}
		var err error
		body, err = scimPatch(kind, old.Body, req.Data)
		if err != nil {
			return scimError(400, err.Error())
		}
	}
	nameField, typ := "userName", "User"
	if kind == "Groups" {
		nameField, typ = "displayName", "Group"
	}
	name := scimString(body, nameField)
	if name == "" {
		return scimError(400, nameField+" is required")
	}
	body[nameField] = name
	if kind == "Users" {
		external := scimString(body, "externalId")
		if external == "" {
			return scimError(400, "externalId is required")
		}
		if id != "" && old.Body["externalId"] != external {
			return scimError(400, "externalId is immutable")
		}
		body["externalId"] = external
		if value, present := body["active"]; present {
			if _, ok := value.(bool); !ok {
				return scimError(400, "active must be boolean")
			}
		} else {
			body["active"] = true
		}
		// A client cannot adopt an existing entity, including one with the same name.
		e, err := i.MemDBEntityByName(ctx, name, false)
		if err != nil {
			return nil, err
		}
		if e != nil && e.ID != id {
			return scimError(409, "userName is already in use")
		}
		ids, err := s.List(ctx, scimPrefix+prefix)
		if err != nil {
			return nil, err
		}
		for _, rid := range ids {
			var r scimResourceRecord
			if _, err := scimLoad(ctx, s, prefix+rid, &r); err != nil {
				return nil, err
			}
			if rid != id && r.Owner == owner && r.Body["externalId"] == external {
				return scimError(409, "externalId is already in use")
			}
		}
	} else {
		members, err := scimMembers(body["members"])
		if err != nil {
			return scimError(400, err.Error())
		}
		for _, member := range members {
			var user scimResourceRecord
			exists, err := scimLoad(ctx, s, "resources/Users/"+member, &user)
			if err != nil {
				return nil, err
			}
			if !exists || user.Owner != owner {
				return scimError(400, "members must be users owned by this client")
			}
		}
		g, err := i.MemDBGroupByName(ctx, name, false)
		if err != nil {
			return nil, err
		}
		if g != nil && g.ID != id {
			return scimError(409, "displayName is already in use")
		}
		body["members"] = scimMemberObjects(members)
	}
	created := id == ""
	var err error
	if kind == "Users" {
		id, err = i.scimUpsertUser(ctx, id, name, !body["active"].(bool), client)
	} else {
		members, _ := scimMembers(body["members"])
		id, err = i.scimUpsertGroup(ctx, id, name, members)
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	createdAt := now
	if !created {
		meta, _ := old.Body["meta"].(map[string]any)
		if t := scimString(meta, "created"); t != "" {
			createdAt = t
		}
	}
	// Construct the managed response explicitly; do not persist arbitrary request keys.
	out := map[string]any{"id": id, "schemas": []string{scimCore + typ}, nameField: name, "meta": map[string]any{"resourceType": typ, "created": createdAt, "lastModified": now}}
	if kind == "Users" {
		out["externalId"], out["active"], out["groups"] = body["externalId"], body["active"], []any{}
	} else {
		out["members"] = body["members"]
	}
	if err := scimSave(ctx, s, prefix+id, scimResourceRecord{Owner: owner, Body: out}); err != nil {
		return nil, err
	}
	status := 200
	if created {
		status = 201
	}
	return scimResponse(status, out)
}

func scimMembers(raw any) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	if raw == nil {
		return out, nil
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("members must be an array")
	}
	for _, entry := range entries {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid member")
		}
		id := scimString(m, "value")
		if id == "" {
			return nil, fmt.Errorf("member value is required")
		}
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out, nil
}
func scimMemberObjects(ids []string) []any {
	out := []any{}
	for _, id := range ids {
		out = append(out, map[string]any{"value": id})
	}
	return out
}

var scimMemberPath = regexp.MustCompile(`^members\[value eq "([^"/]+)"\]$`)

func scimPatch(kind string, old, patch map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range old {
		out[k] = v
	}
	ops, ok := patch["Operations"].([]any)
	if !ok || len(ops) == 0 {
		return nil, fmt.Errorf("Operations is required")
	}
	if kind == "Users" && len(ops) != 1 {
		return nil, fmt.Errorf("only one active replacement is supported")
	}
	for _, raw := range ops {
		op, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid operation")
		}
		action, path := strings.ToLower(scimString(op, "op")), scimString(op, "path")
		if kind == "Users" {
			active, ok := op["value"].(bool)
			if action != "replace" || path != "active" || !ok {
				return nil, fmt.Errorf("only replace active with a boolean is supported")
			}
			out["active"] = active
			continue
		}
		if action != "add" && action != "remove" {
			return nil, fmt.Errorf("only member add/remove is supported")
		}
		members, err := scimMembers(out["members"])
		if err != nil {
			return nil, err
		}
		var values []string
		if path == "members" {
			values, err = scimMembers(op["value"])
			if err != nil {
				return nil, err
			}
			if action == "remove" && op["value"] == nil {
				members = nil
			}
		} else if match := scimMemberPath.FindStringSubmatch(path); match != nil && action == "remove" {
			values = []string{match[1]}
		} else {
			return nil, fmt.Errorf("only members paths are supported")
		}
		for _, id := range values {
			next := []string{}
			found := false
			for _, current := range members {
				if current == id {
					found = true
					if action == "remove" {
						continue
					}
				}
				next = append(next, current)
			}
			if action == "add" && !found {
				next = append(next, id)
			}
			members = next
		}
		out["members"] = scimMemberObjects(members)
	}
	return out, nil
}

func (i *IdentityStore) scimUpsertUser(ctx context.Context, id, name string, disabled bool, client scimClient) (string, error) {
	i.Lock()
	defer i.Unlock()
	e := new(identitymodel.Entity)
	if id != "" {
		var err error
		e, err = i.MemDBEntityByID(ctx, id, true)
		if err != nil {
			return "", err
		}
		if e == nil {
			return "", fmt.Errorf("managed entity missing")
		}
	}
	oldName := e.Name
	e.Name, e.Disabled = name, disabled
	if err := i.SanitizeEntity(ctx, e); err != nil {
		return "", err
	}
	if err := i.UpsertEntity(ctx, e, nil, true); err != nil {
		return "", err
	}
	if client.Accessor != "" {
		if id == "" {
			resp, err := i.handleAliasCreate(ctx, e.ID, name, client.Accessor, false, nil)
			if err != nil {
				return "", err
			}
			if resp != nil && resp.IsError() {
				return "", fmt.Errorf("alias creation failed: %v", resp.Data)
			}
		} else if oldName != name {
			alias, err := i.MemDBAliasByFactors(ctx, client.Accessor, oldName, true, false)
			if err != nil {
				return "", err
			}
			if alias != nil {
				resp, err := i.handleAliasUpdate(ctx, e.ID, name, client.Accessor, alias, nil)
				if err != nil {
					return "", err
				}
				if resp != nil && resp.IsError() {
					return "", fmt.Errorf("alias update failed: %v", resp.Data)
				}
			}
		}
	}
	return e.ID, nil
}
func (i *IdentityStore) scimUpsertGroup(ctx context.Context, id, name string, members []string) (string, error) {
	i.groupLock.Lock()
	defer i.groupLock.Unlock()
	g := new(identitymodel.Group)
	if id != "" {
		var err error
		g, err = i.MemDBGroupByID(ctx, id, true)
		if err != nil {
			return "", err
		}
		if g == nil {
			return "", fmt.Errorf("managed group missing")
		}
	}
	g.Name, g.Type, g.MemberEntityIDs = name, groupTypeInternal, members
	if err := i.SanitizeAndUpsertGroup(ctx, g, nil, nil); err != nil {
		return "", err
	}
	return g.ID, nil
}
func (i *IdentityStore) scimUserGroups(ctx context.Context, owner string, body map[string]any) error {
	s := i.View(ctx)
	ids, err := s.List(ctx, scimPrefix+"resources/Groups/")
	if err != nil {
		return err
	}
	groups := []any{}
	for _, id := range ids {
		var r scimResourceRecord
		if _, err := scimLoad(ctx, s, "resources/Groups/"+id, &r); err != nil {
			return err
		}
		if r.Owner != owner {
			continue
		}
		members, err := scimMembers(r.Body["members"])
		if err != nil {
			return err
		}
		for _, member := range members {
			if member == body["id"] {
				groups = append(groups, map[string]any{"value": id, "display": r.Body["displayName"], "type": "direct"})
			}
		}
	}
	body["groups"] = groups
	return nil
}

func (i *IdentityStore) scimDeleteResource(ctx context.Context, kind, id string) error {
	var resp *logical.Response
	var err error
	if kind == "Users" {
		resp, err = i.pathEntityIDDelete()(ctx, &logical.Request{}, &framework.FieldData{Raw: map[string]any{"id": id}, Schema: map[string]*framework.FieldSchema{"id": {Type: framework.TypeString}}})
	} else {
		resp, err = i.handleGroupDeleteCommon(ctx, id, true)
	}
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return fmt.Errorf("identity deletion failed: %v", resp.Data)
	}
	return i.View(ctx).Delete(ctx, scimPrefix+"resources/"+kind+"/"+id)
}
