// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/versions"
	"github.com/openbao/openbao/v2/internal/vault/routing"
)

type agentRegistration struct {
	ID                           string   `json:"id"`
	DisplayName                  string   `json:"display_name"`
	EntityID                     string   `json:"entity_id"`
	Description                  string   `json:"description"`
	Owner                        string   `json:"owner"`
	CeilingPolicies              []string `json:"ceiling_policies"`
	NoDefaultCeilingPolicy       bool     `json:"no_default_ceiling_policy"`
	OptionalAuthorizationDetails bool     `json:"optional_authorization_details"`
	CreationTime                 string   `json:"creation_time"`
	LastUpdatedTime              string   `json:"last_updated_time"`
}

// Public documentation places the registry at /agent-registry, not /sys.
// A required singleton mount keeps normal routing, ACL and namespace semantics.
func (c *Core) agentRegistryMount(ns *namespace.Namespace) (*routing.MountEntry, error) {
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	backendID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	accessor, err := c.generateMountAccessor("agent-registry")
	if err != nil {
		return nil, err
	}
	return &routing.MountEntry{Table: routing.MountTableType, Path: "agent-registry/", Type: "agent-registry", Description: "agent identity registrations", UUID: id, BackendAwareUUID: backendID, Accessor: accessor, RunningVersion: versions.DefaultBuiltinVersion, NamespaceID: ns.ID, Namespace: ns}, nil
}

// ensureAgentRegistryMounts runs under the mount-table lock during mount loading.
func (c *Core) ensureAgentRegistryMounts(ctx context.Context) (bool, error) {
	namespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return false, err
	}
	added := false
	for _, ns := range namespaces {
		found := false
		for _, entry := range c.mounts.Entries {
			if entry.Type == "agent-registry" && entry.NamespaceID == ns.ID {
				found = true
				break
			}
		}
		if found {
			continue
		}
		entry, err := c.agentRegistryMount(ns)
		if err != nil {
			return false, err
		}
		c.mounts.Entries = append(c.mounts.Entries, entry)
		added = true
	}
	return added, nil
}

func (c *Core) agentRegistryFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &framework.Backend{BackendType: logical.TypeLogical}
	fields := agenticFields([]string{"id", "display_name", "entity_id", "description", "owner", "lookup"}, []string{"no_default_ceiling_policy", "optional_authorization_details"}, []string{"ceiling_policies"})
	var mu sync.Mutex
	handler := func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		prefix, err := agenticPrefix(ctx, "registrations")
		if err != nil {
			return nil, err
		}
		ids, err := req.Storage.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		records := make([]agentRegistration, 0, len(ids))
		for _, id := range ids {
			var record agentRegistration
			ok, err := agenticLoad(ctx, req.Storage, prefix+id, &record)
			if err != nil {
				return nil, err
			}
			if ok {
				records = append(records, record)
			}
		}
		byName := strings.HasPrefix(req.Path, "registration/display-name")
		byEntity := strings.HasPrefix(req.Path, "registration/entity-id/")
		if req.Operation == logical.ListOperation {
			keys := []string{}
			info := map[string]any{}
			for _, r := range records {
				key := r.ID
				detail := map[string]any{"display_name": r.DisplayName, "entity_id": r.EntityID}
				if byName {
					key = r.DisplayName
					detail = map[string]any{"id": r.ID, "entity_id": r.EntityID}
				}
				keys = append(keys, key)
				info[key] = detail
			}
			sort.Strings(keys)
			resp := logical.ListResponse(keys)
			resp.Data["key_info"] = info
			return resp, nil
		}
		lookup := d.Get("lookup").(string)
		register := req.Path == "register"
		if register {
			lookup = d.Get("id").(string)
		}
		var existing *agentRegistration
		for idx := range records {
			r := &records[idx]
			value := r.ID
			if byName {
				value = r.DisplayName
			}
			if byEntity {
				value = r.EntityID
			}
			if value == lookup {
				existing = r
				break
			}
		}
		switch req.Operation {
		case logical.ReadOperation:
			if existing == nil {
				return nil, nil
			}
			return agenticResponse(existing)
		case logical.DeleteOperation:
			if existing == nil {
				return nil, nil
			}
			return nil, req.Storage.Delete(ctx, prefix+existing.ID)
		}
		if existing == nil && (!register || lookup != "") {
			return logical.ErrorResponse("registration does not exist"), nil
		}
		var record agentRegistration
		if err := agenticDecode(d, &record); err != nil {
			return logical.ErrorResponse("invalid registration: %s", err), nil
		}
		if byName {
			record.DisplayName = lookup
		}
		if record.DisplayName == "" || record.EntityID == "" {
			return logical.ErrorResponse("display_name and entity_id are required"), nil
		}
		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, err
		}
		entity, err := c.identityStore.MemDBEntityByID(ctx, record.EntityID, false)
		if err != nil || entity == nil || entity.NamespaceID != ns.ID {
			return logical.ErrorResponse("entity_id must identify an existing entity in this namespace"), nil
		}
		policies := []string{}
		seen := map[string]bool{}
		for _, policy := range record.CeilingPolicies {
			policy = strings.ToLower(strings.TrimSpace(policy))
			if policy == "root" {
				return logical.ErrorResponse("root cannot be a ceiling policy"), nil
			}
			if policy != "" && !seen[policy] {
				seen[policy] = true
				policies = append(policies, policy)
			}
		}
		if !record.NoDefaultCeilingPolicy {
			for _, policy := range []string{"default", "default-ceiling"} {
				if !seen[policy] {
					policies = append(policies, policy)
				}
			}
		}
		record.CeilingPolicies = policies
		record.LastUpdatedTime = time.Now().UTC().Format(time.RFC3339Nano)
		if existing != nil {
			record.ID = existing.ID
			record.CreationTime = existing.CreationTime
		} else {
			record.ID, err = uuid.GenerateUUID()
			if err != nil {
				return nil, err
			}
			record.CreationTime = record.LastUpdatedTime
		}
		for _, other := range records {
			if other.ID != record.ID && (other.EntityID == record.EntityID || other.DisplayName == record.DisplayName) {
				return logical.ErrorResponse("entity_id and display_name must be unique within the namespace"), nil
			}
		}
		if err := agenticSave(ctx, req.Storage, prefix+record.ID, &record); err != nil {
			return nil, err
		}
		return &logical.Response{Data: map[string]any{"id": record.ID, "display_name": record.DisplayName}}, nil
	}
	for _, pattern := range []string{"register$", "registration/id/(?P<lookup>[^/]+)$", "registration/display-name/(?P<lookup>[^/]+)$", "registration/entity-id/(?P<lookup>[^/]+)$", "registration/id/?$", "registration/display-name/?$"} {
		callbacks := map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handler, logical.UpdateOperation: handler, logical.DeleteOperation: handler}
		if pattern == "register$" {
			callbacks = map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: handler}
		} else if strings.Contains(pattern, "entity-id") {
			callbacks = map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handler}
		} else if strings.HasSuffix(pattern, "/?$") {
			callbacks = map[logical.Operation]framework.OperationFunc{logical.ListOperation: handler}
		}
		b.Paths = append(b.Paths, &framework.Path{Pattern: pattern, Fields: fields, Callbacks: callbacks, HelpSynopsis: "Manage namespace-local agent registrations."})
	}
	return b, b.Setup(ctx, conf)
}
