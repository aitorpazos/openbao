// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/quotas"
)

func (b *SystemBackend) leaseCountPaths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":        {Type: framework.TypeString},
		"path":        {Type: framework.TypeString},
		"role":        {Type: framework.TypeString},
		"max_leases":  {Type: framework.TypeInt},
		"inheritable": {Type: framework.TypeBool},
	}
	return []*framework.Path{
		{Pattern: "quotas/lease-count/?$", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.handleLeaseCountQuota}},
		{Pattern: "quotas/lease-count/" + framework.GenericNameRegex("name"), Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleLeaseCountQuota, logical.ReadOperation: b.handleLeaseCountQuota, logical.DeleteOperation: b.handleLeaseCountQuota,
		}},
	}
}

func (b *SystemBackend) handleLeaseCountQuota(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	caller, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	// OpenBao has no administrative namespace configuration; this restricted
	// endpoint is available at root, as documented for non-admin deployments.
	if caller.ID != namespace.RootNamespaceID {
		return nil, logical.ErrPermissionDenied
	}
	manager := b.Core.quotaManager
	kind := quotas.TypeLeaseCount.String()
	if req.Operation == logical.ListOperation {
		names, err := manager.QuotaNames(quotas.TypeLeaseCount)
		return logical.ListResponse(names), err
	}
	name := d.Get("name").(string)
	existing, err := manager.QuotaByName(kind, name)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case logical.ReadOperation:
		if existing == nil {
			return nil, nil
		}
		q := existing.(*quotas.LeaseCountQuota)
		ns := q.NamespacePath
		if ns == "root" {
			ns = ""
		}
		return &logical.Response{Data: map[string]any{"name": q.Name, "type": kind, "path": ns + q.MountPath + q.PathSuffix, "role": q.Role, "max_leases": q.MaxLeases, "inheritable": q.Inheritable}}, nil
	case logical.DeleteOperation:
		if err := req.Storage.Delete(ctx, quotas.QuotaStoragePath(kind, name)); err != nil {
			return nil, err
		}
		return nil, manager.DeleteQuota(ctx, kind, name)
	}
	max := d.Get("max_leases")
	if _, ok := d.Raw["max_leases"]; !ok {
		return logical.ErrorResponse("max_leases is required"), nil
	}
	if max.(int) < 0 {
		return logical.ErrorResponse("max_leases must not be negative"), nil
	}
	ns, mount := b.Core.namespaceStore.GetNamespaceByLongestPrefix(ctx, sanitizePath(d.Get("path").(string)))
	suffix := ""
	if mount != "" {
		me := b.Core.router.MatchingMountEntry(namespace.ContextWithNamespace(ctx, ns), mount)
		if me == nil {
			return logical.ErrorResponse("invalid mount path %q", mount), nil
		}
		apiPath := me.APIPathNoNamespace()
		suffix = strings.TrimSuffix(strings.TrimPrefix(mount, apiPath), "/")
		mount = apiPath
	}
	inherit := d.Get("inheritable").(bool)
	if _, supplied := d.Raw["inheritable"]; !supplied && ns.Path == "" && mount == "" {
		inherit = true
	}
	if inherit && mount != "" {
		return logical.ErrorResponse("inheritable requires a namespace path"), nil
	}
	role := d.Get("role").(string)
	if role != "" {
		backend := b.Core.router.MatchingBackend(namespace.ContextWithNamespace(ctx, ns), mount)
		if suffix != "" || backend == nil || backend.Type() != logical.TypeCredential {
			return logical.ErrorResponse("role requires a role-aware auth mount"), nil
		}
		_, err := backend.HandleRequest(ctx, &logical.Request{Path: "login", Operation: logical.ResolveRoleOperation})
		if err == logical.ErrUnsupportedOperation || err == logical.ErrUnsupportedPath {
			return logical.ErrorResponse("auth mount does not support roles"), nil
		}
	}
	same, err := manager.QuotaByFactors(ctx, kind, ns.Path, mount, suffix, role)
	if err != nil {
		return nil, err
	}
	if same != nil && same.QuotaName() != name {
		return logical.ErrorResponse("quota rule with similar properties exists under the name %q", same.QuotaName()), nil
	}
	q := &quotas.LeaseCountQuota{ID: name, Name: name, Type: quotas.TypeLeaseCount, NamespacePath: ns.Path, MountPath: mount, PathSuffix: suffix, Role: role, MaxLeases: max.(int), Inheritable: inherit}
	entry, err := logical.StorageEntryJSON(quotas.QuotaStoragePath(kind, name), q)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, manager.SetQuota(ctx, kind, q)
}
