// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// activationFlagSecretsImport is the feature key for the secrets import
// one-time activation flag (Vault docs: Secrets import — Beta; activated
// with PUT /sys/activation-flags/secrets-import/activate).
const activationFlagSecretsImport = "secrets-import"

func (b *SystemBackend) activationFlagPaths() []*framework.Path {
	return []*framework.Path{
		{Pattern: "activation-flags$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.handleActivationFlags}},
		{Pattern: "activation-flags/enable-scim/activate$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.handleActivationFlags}},
		// The secrets import feature is activated with the same one-time
		// activation-flag endpoint (Vault docs: Secrets import / Activate
		// secrets import; the API reference documents
		// PUT /sys/activation-flags/:feature/activate).
		{Pattern: "activation-flags/secrets-import/activate$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.handleActivationFlags}},
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
		// Match the update operation against the mount-relative request
		// path: enable-scim activates SCIM, secrets-import activates the
		// secrets import feature. Unknown features fall through to the
		// normal 404 routing.
		switch {
		case strings.HasSuffix(strings.TrimSuffix(req.Path, "activate"), "enable-scim/"):
			if err := b.Core.identityStore.ActivateSCIM(ctx); err != nil {
				return nil, err
			}
			return nil, nil
		case strings.HasSuffix(strings.TrimSuffix(req.Path, "activate"), "secrets-import/"):
			if err := b.Core.ActivateActivationFlag(ctx, activationFlagSecretsImport); err != nil {
				return nil, err
			}
			return nil, nil
		}
		return nil, nil
	}
	activated, unactivated := []string{}, []string{}
	if active, err := b.Core.identityStore.SCIMActivated(ctx); err != nil {
		return nil, err
	} else if active {
		activated = append(activated, "enable-scim")
	} else {
		unactivated = append(unactivated, "enable-scim")
	}
	if active, err := b.Core.ActivationFlagActive(ctx, activationFlagSecretsImport); err != nil {
		return nil, err
	} else if active {
		activated = append(activated, "secrets-import")
	} else {
		unactivated = append(unactivated, "secrets-import")
	}
	return &logical.Response{Data: map[string]any{"activated": activated, "unactivated": unactivated}}, nil
}
