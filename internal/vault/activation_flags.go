// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// coreActivationFlagPath is the barrier prefix for one-time feature
// activation flags (see the Vault Enterprise activation-flags API).
const coreActivationFlagPath = "core/activation-flags/"

// ActivationFlagActive reports whether the given one-time feature flag has
// been activated. Activation is one-way; there is no deactivation.
func (c *Core) ActivationFlagActive(ctx context.Context, flag string) (bool, error) {
	se, err := c.barrier.Get(ctx, coreActivationFlagPath+flag)
	if err != nil {
		return false, err
	}
	return se != nil, nil
}

// ActivateActivationFlag stores the one-way activation record for the given
// feature flag. Idempotent: re-activation is a no-op.
func (c *Core) ActivateActivationFlag(ctx context.Context, flag string) error {
	return c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreActivationFlagPath + flag,
		Value: []byte("true"),
	})
}
