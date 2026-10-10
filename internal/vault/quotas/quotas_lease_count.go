// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package quotas

import (
	"context"
	"fmt"
	"strings"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
)

const TypeLeaseCount Type = "lease-count"

// LeaseCountQuota shares the manager's persistent configuration and indexes.
// Counters are derived from registered leases, not from request attempts.
type LeaseCountQuota struct {
	ID            string `json:"id"`
	Type          Type   `json:"type"`
	Name          string `json:"name"`
	NamespacePath string `json:"namespace_path"`
	MountPath     string `json:"mount_path"`
	PathSuffix    string `json:"path_suffix"`
	Role          string `json:"role"`
	Inheritable   bool   `json:"inheritable"`
	MaxLeases     int    `json:"max_leases"`
}

func (q *LeaseCountQuota) quotaID() string                { return q.ID }
func (q *LeaseCountQuota) QuotaName() string              { return q.Name }
func (q *LeaseCountQuota) IsInheritable() bool            { return q.Inheritable }
func (q *LeaseCountQuota) Clone() Quota                   { c := *q; return &c }
func (q *LeaseCountQuota) close(context.Context) error    { return nil }
func (q *LeaseCountQuota) handleRemount(ns, mount string) { q.NamespacePath, q.MountPath = ns, mount }
func (q *LeaseCountQuota) initialize(log.Logger, *metricsutil.ClusterMetricSink) error {
	if q.MaxLeases < 0 {
		return fmt.Errorf("max_leases must not be negative")
	}
	if q.ID == "" {
		q.ID = q.Name
	}
	if q.NamespacePath == "" {
		q.NamespacePath = "root"
	}
	q.Type = TypeLeaseCount
	return nil
}
func (q *LeaseCountQuota) allow(context.Context, *Request) (Response, error) {
	// Actual admission must be atomic with lease persistence: see PersistLease.
	return Response{}, fmt.Errorf("lease count admission requires PersistLease")
}
func (q *LeaseCountQuota) Matches(r Request) bool {
	ns := q.NamespacePath
	if ns == "root" {
		ns = ""
	}
	if r.NamespacePath != ns && !(q.MountPath == "" && q.Inheritable && strings.HasPrefix(r.NamespacePath, ns)) {
		return false
	}
	if q.Role != "" && q.Role != r.Role {
		return false
	}
	if q.MountPath == "" {
		return true
	}
	if !strings.HasPrefix(r.Path, q.MountPath) {
		return false
	}
	suffix := strings.TrimPrefix(r.Path, q.MountPath)
	if q.PathSuffix == "" {
		return true
	}
	if strings.HasSuffix(q.PathSuffix, "*") {
		return strings.HasPrefix(suffix, strings.TrimSuffix(q.PathSuffix, "*"))
	}
	return suffix == q.PathSuffix
}

// selectLeaseQuota follows role > exact suffix > longest glob > mount >
// closest namespace precedence. Inherited namespace usage is cumulative.
func selectLeaseQuota(rules []*LeaseCountQuota, r Request) *LeaseCountQuota {
	var best *LeaseCountQuota
	rank := func(q *LeaseCountQuota) int {
		switch {
		case q.Role != "":
			return 5
		case q.PathSuffix != "" && !strings.HasSuffix(q.PathSuffix, "*"):
			return 4
		case q.PathSuffix != "":
			return 3
		case q.MountPath != "":
			return 2
		default:
			return 1
		}
	}
	for _, q := range rules {
		if !q.Matches(r) {
			continue
		}
		if best == nil || rank(q) > rank(best) || (rank(q) == rank(best) && (len(strings.TrimPrefix(q.NamespacePath, "root")) > len(strings.TrimPrefix(best.NamespacePath, "root")) || len(q.PathSuffix) > len(best.PathSuffix))) {
			best = q
		}
	}
	return best
}

// PersistLease serializes admission with persistence, preventing concurrent
// issuances from exceeding a quota. Existing IDs are renewals, not new leases.
func (m *Manager) PersistLease(id string, r Request, persist func() error) error {
	m.quotaLock.Lock()
	defer m.quotaLock.Unlock()
	m.dbAndCacheLock.RLock()
	defer m.dbAndCacheLock.RUnlock()
	if _, exists := m.leaseRecords[id]; !exists {
		txn := m.db.Txn(false)
		defer txn.Abort()
		it, err := txn.Get(TypeLeaseCount.String(), indexID)
		if err != nil {
			return err
		}
		var rules []*LeaseCountQuota
		for raw := it.Next(); raw != nil; raw = it.Next() {
			rules = append(rules, raw.(*LeaseCountQuota))
		}
		if q := selectLeaseQuota(rules, r); q != nil {
			count := 0
			for _, lease := range m.leaseRecords {
				if selectLeaseQuota(rules, lease) == q {
					count++
				}
			}
			if count >= q.MaxLeases {
				return ErrLeaseCountQuotaExceeded
			}
		}
	}
	// Batch tokens check pressure but have no registered lease.
	if persist == nil {
		return nil
	}
	if err := persist(); err != nil {
		return err
	}
	if m.leaseRecords == nil {
		m.leaseRecords = make(map[string]Request)
	}
	m.leaseRecords[id] = r
	return nil
}

// TrackLease is also used during expiration restoration, including leases
// created before a quota was configured. Loading never rejects existing leases.
func (m *Manager) TrackLease(id string, r Request) {
	m.quotaLock.Lock()
	defer m.quotaLock.Unlock()
	if m.leaseRecords == nil {
		m.leaseRecords = make(map[string]Request)
	}
	m.leaseRecords[id] = r
}
func (m *Manager) ForgetLease(id string) {
	m.quotaLock.Lock()
	defer m.quotaLock.Unlock()
	delete(m.leaseRecords, id)
}
