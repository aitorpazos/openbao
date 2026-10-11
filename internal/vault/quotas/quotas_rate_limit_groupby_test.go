// SPDX-License-Identifier: MPL-2.0

package quotas

import (
	"testing"
	"testing/synctest"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	"github.com/stretchr/testify/require"
)

// TestRateLimitQuota_Allow_GroupBy verifies the documented group_by bucket
// selection: entity buckets take `rate`, and requests without an entity
// (IP for entity_then_ip, the shared "none" bucket for entity_then_none)
// take `secondary_rate`.
func TestRateLimitQuota_Allow_GroupBy(t *testing.T) {
	t.Parallel()

	// 1 request per second for entity buckets, 3 per second for the
	// secondary (non-entity) buckets.
	rlq := &RateLimitQuota{
		Name:          "test-identity-rate-limiter",
		Type:          TypeRateLimit,
		NamespacePath: "qa",
		Rate:          1,
		Interval:      time.Minute,
		GroupBy:       "entity_then_none",
		SecondaryRate: 3,

		purgeInterval: 10 * time.Second,
		staleAge:      10 * time.Second,
	}
	require.NoError(t, rlq.initialize(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink()))
	defer func() {
		_ = rlq.close(t.Context())
	}()

	synctest.Test(t, func(t *testing.T) {
		// Three requests from the same (empty) entity fall into the shared
		// "none" bucket under the secondary rate of 3.
		for range 3 {
			resp, err := rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.1"})
			require.NoError(t, err)
			require.True(t, resp.Allowed, "expected secondary bucket to allow 3 requests")
		}
		resp, err := rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.1"})
		require.NoError(t, err)
		require.False(t, resp.Allowed, "expected secondary bucket to be exhausted")

		// An entity-carrying request uses its own bucket under the primary
		// rate of 1, unaffected by the exhausted secondary bucket.
		for range 1 {
			resp, err := rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.2", EntityID: "ent-1"})
			require.NoError(t, err)
			require.True(t, resp.Allowed, "expected entity bucket to allow the first request")
		}
		resp, err = rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.2", EntityID: "ent-1"})
		require.NoError(t, err)
		require.False(t, resp.Allowed, "expected entity bucket to be exhausted at rate 1")

		// A different entity gets its own bucket.
		resp, err = rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.2", EntityID: "ent-2"})
		require.NoError(t, err)
		require.True(t, resp.Allowed, "expected a different entity to have its own bucket")
	})
}

// TestRateLimitQuota_Allow_GroupByNone verifies that group_by none puts all
// requests in one shared bucket at the primary rate.
func TestRateLimitQuota_Allow_GroupByNone(t *testing.T) {
	t.Parallel()

	rlq := &RateLimitQuota{
		Name:          "test-none-rate-limiter",
		Type:          TypeRateLimit,
		NamespacePath: "qa",
		Rate:          2,
		Interval:      time.Minute,
		GroupBy:       "none",

		purgeInterval: 10 * time.Second,
		staleAge:      10 * time.Second,
	}
	require.NoError(t, rlq.initialize(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink()))
	defer func() {
		_ = rlq.close(t.Context())
	}()

	synctest.Test(t, func(t *testing.T) {
		for range 2 {
			resp, err := rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.1"})
			require.NoError(t, err)
			require.True(t, resp.Allowed)
		}
		resp, err := rlq.allow(t.Context(), &Request{ClientAddress: "127.0.0.2", EntityID: "ent-1"})
		require.NoError(t, err)
		require.False(t, resp.Allowed, "expected the shared none bucket to be exhausted regardless of source address or entity")
	})
}
