// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

func (b *SystemBackend) activationFlagPaths() []*framework.Path {
	return []*framework.Path{
		{Pattern: "activation-flags$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.handleActivationFlags}},
		{Pattern: "activation-flags/enable-scim/activate$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.handleActivationFlags}},
	}
}

func (b *SystemBackend) handleActivationFlags(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrorResponse("activation flags are only available in the root namespace"), logical.ErrPermissionDenied
	}
	if req.Operation == logical.UpdateOperation {
		if err := b.Core.identityStore.ActivateSCIM(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	active, err := b.Core.identityStore.SCIMActivated(ctx)
	if err != nil {
		return nil, err
	}
	activated, unactivated := []string{}, []string{}
	if active {
		activated = append(activated, "enable-scim")
	} else {
		unactivated = append(unactivated, "enable-scim")
	}
	return &logical.Response{Data: map[string]any{"activated": activated, "unactivated": unactivated}}, nil
}
