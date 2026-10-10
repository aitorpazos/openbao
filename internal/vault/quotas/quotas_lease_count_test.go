// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0
package quotas

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestLeaseCountCRUDAndAdmission(t *testing.T) {
	ctx := context.Background()
	m, err := NewManager(log.NewNullLogger(), nil, false)
	require.NoError(t, err)
	r := Request{Path: "auth/token/create"}
	// Existing leases populate newly created quotas, even beyond the limit.
	m.TrackLease("old", r)
	q := &LeaseCountQuota{Name: "test", MaxLeases: 1, MountPath: "auth/token/"}
	require.NoError(t, m.SetQuota(ctx, TypeLeaseCount.String(), q))
	got, err := m.QuotaByName(TypeLeaseCount.String(), "test")
	require.NoError(t, err)
	require.Equal(t, q, got)
	names, err := m.QuotaNames(TypeLeaseCount)
	require.NoError(t, err)
	require.Equal(t, []string{"test"}, names)
	persist := func() error { return nil }
	require.ErrorIs(t, m.PersistLease("next", r, persist), ErrLeaseCountQuotaExceeded)
	require.NoError(t, m.PersistLease("old", r, persist)) // renewal
	m.ForgetLease("old")
	require.NoError(t, m.PersistLease("next", r, persist))
	q2 := q.Clone().(*LeaseCountQuota)
	q2.MaxLeases = 2
	require.NoError(t, m.SetQuota(ctx, TypeLeaseCount.String(), q2))
	failure := errors.New("storage failed")
	require.ErrorIs(t, m.PersistLease("failed", r, func() error { return failure }), failure)
	require.NoError(t, m.PersistLease("last", r, persist))
	require.ErrorIs(t, m.PersistLease("over", r, persist), ErrLeaseCountQuotaExceeded)
	require.NoError(t, m.DeleteQuota(ctx, TypeLeaseCount.String(), "test"))
	require.NoError(t, m.PersistLease("over", r, persist))
}

func TestLeaseCountPrecedenceAndBatch(t *testing.T) {
	m, err := NewManager(log.NewNullLogger(), nil, false)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, m.SetQuota(ctx, TypeLeaseCount.String(), &LeaseCountQuota{Name: "global", MaxLeases: 0, Inheritable: true}))
	require.NoError(t, m.SetQuota(ctx, TypeLeaseCount.String(), &LeaseCountQuota{Name: "mount", MountPath: "auth/token/", MaxLeases: 1}))
	r := Request{Path: "auth/token/create"}
	require.NoError(t, m.PersistLease("", r, nil))
	require.NoError(t, m.PersistLease("", r, nil)) // batch tokens do not consume capacity
	require.NoError(t, m.PersistLease("service", r, func() error { return nil }))
	require.ErrorIs(t, m.PersistLease("", r, nil), ErrLeaseCountQuotaExceeded)
	require.ErrorIs(t, m.PersistLease("other", Request{Path: "database/creds/app"}, func() error { return nil }), ErrLeaseCountQuotaExceeded)
}

func TestLeaseCountMatching(t *testing.T) {
	q := &LeaseCountQuota{NamespacePath: "team/", MountPath: "auth/approle/", Role: "app"}
	require.True(t, q.Matches(Request{NamespacePath: "team/", Path: "auth/approle/login", Role: "app"}))
	require.False(t, q.Matches(Request{NamespacePath: "team/", Path: "auth/approle/login", Role: "other"}))
	q.Role = ""
	q.PathSuffix = "login/*"
	require.True(t, q.Matches(Request{NamespacePath: "team/", Path: "auth/approle/login/foo"}))
	require.False(t, q.Matches(Request{NamespacePath: "team/", Path: "auth/approle/login"}))
	q.PathSuffix = "login"
	require.True(t, q.Matches(Request{NamespacePath: "team/", Path: "auth/approle/login"}))
	require.False(t, q.Matches(Request{NamespacePath: "team/", Path: "auth/approle/login/foo"}))
	q.MountPath = ""
	q.PathSuffix = ""
	require.False(t, q.Matches(Request{NamespacePath: "team/child/"}))
	q.Inheritable = true
	require.True(t, q.Matches(Request{NamespacePath: "team/child/"}))
	require.False(t, q.Matches(Request{NamespacePath: "team-other/"}))
}

func TestLeaseCountConcurrentCumulative(t *testing.T) {
	m, err := NewManager(log.NewNullLogger(), nil, false)
	require.NoError(t, err)
	require.NoError(t, m.SetQuota(context.Background(), TypeLeaseCount.String(), &LeaseCountQuota{Name: "parent", NamespacePath: "team/", Inheritable: true, MaxLeases: 1}))
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := m.PersistLease(fmt.Sprint(i), Request{NamespacePath: fmt.Sprintf("team/child%d/", i)}, func() error { return nil })
			if err == nil {
				allowed.Add(1)
			} else {
				require.ErrorIs(t, err, ErrLeaseCountQuotaExceeded)
			}
		}(i)
	}
	wg.Wait()
	require.EqualValues(t, 1, allowed.Load())
}
