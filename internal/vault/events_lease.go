// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

type leaseExpiryEventKey struct{}

func (m *ExpirationManager) emitLeaseEvent(ctx context.Context, le *leaseEntry, operation string) {
	if m.core == nil || le == nil || le.namespace == nil {
		return
	}
	ctx = namespace.ContextWithNamespace(ctx, le.namespace)
	_ = logical.SendEvent(ctx, EventBusFor(m.core), "lease/"+operation, "lease_id", le.LeaseID, "path", le.Path, "modified", "true", "operation", operation)
}
