// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

func (b *SystemBackend) rotationOrphanPaths() []*framework.Path {
	return []*framework.Path{{
		Pattern: "rotation/orphans/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.handleRotationOrphans,
		},
		HelpSynopsis: "Read orphaned LDAP and OS-account rotations.",
	}}
}

func (b *SystemBackend) handleRotationOrphans(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrorResponse("rotation orphans are only available in the root namespace"), logical.ErrPermissionDenied
	}
	// Rotation policies currently have no LDAP/OS-account scheduler integration,
	// so there are no managed rotations that can produce orphan records. Do not
	// confuse expired leases or database static-role queues with these orphans.
	return &logical.Response{Data: map[string]interface{}{"orphans": []interface{}{}}}, nil
}
