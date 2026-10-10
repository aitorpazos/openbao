// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"slices"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/quotas"
)

func isLeaseCountQuotaError(err error) bool { return errors.Is(err, quotas.ErrLeaseCountQuotaExceeded) }

func quotaLeaseRequest(le *leaseEntry) quotas.Request {
	return quotas.Request{NamespacePath: le.namespace.Path, Path: le.Path, Role: le.LoginRole}
}
func (m *ExpirationManager) trackQuotaLease(le *leaseEntry) {
	if le.Auth != nil && slices.Contains(le.Auth.Policies, "root") {
		return
	}
	if m.core != nil && m.core.quotaManager != nil && le.namespace != nil {
		m.core.quotaManager.TrackLease(le.LeaseID, quotaLeaseRequest(le))
	}
}
func (m *ExpirationManager) persistQuotaLease(ctx context.Context, le *leaseEntry, entry *logical.StorageEntry) error {
	persist := func() error { return m.leaseView(le.namespace).Put(ctx, entry) }
	if m.core == nil || m.core.quotaManager == nil || (le.Auth != nil && slices.Contains(le.Auth.Policies, "root")) {
		return persist()
	}
	// A lease may be renewed before the asynchronous restore has seen it.
	existing, err := m.leaseView(le.namespace).Get(ctx, le.LeaseID)
	if err != nil {
		return err
	}
	if existing != nil {
		m.trackQuotaLease(le)
	}
	return m.core.quotaManager.PersistLease(le.LeaseID, quotaLeaseRequest(le), persist)
}

func (c *Core) checkBatchLeaseQuota(ctx context.Context, path, role string) error {
	if c.quotaManager == nil {
		return nil
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	if err := c.quotaManager.PersistLease("", quotas.Request{NamespacePath: ns.Path, Path: path, Role: role}, nil); err != nil {
		if isLeaseCountQuotaError(err) {
			return logical.ErrLeaseCountQuotaExceeded
		}
		return err
	}
	return nil
}
