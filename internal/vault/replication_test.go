// Copyright (c) 2026 OpenBao a.s. / OpenBao community
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for the clean-room replication surface. These exercise the
// documented configuration/state machine: enable, secondary tokens,
// paths-filter management, demote/promote, activation via response-wrapped
// tokens, and status shapes.

package vault

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

func replicationSysBackend(t *testing.T) (*SystemBackend, *Core) {
	t.Helper()
	c, _, _ := TestCoreUnsealed(t)
	if err := c.setupCluster(t.Context()); err != nil {
		t.Fatal(err)
	}
	return c.systemBackend, c
}

func replicationUpdate(ctx context.Context, b *SystemBackend, path string, body map[string]any) (*logical.Response, error) {
	return b.HandleRequest(namespace.RootContext(ctx), &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data:      body,
	})
}

func replicationRead(ctx context.Context, b *SystemBackend, path string) (*logical.Response, error) {
	return b.HandleRequest(namespace.RootContext(ctx), &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	})
}

// issueTestSecondaryToken invokes the secondary-token handler and then
// wraps the response in cubbyhole exactly like the core request pipeline
// does, yielding a real, unwrappable activation token.
func issueTestSecondaryToken(t *testing.T, b *SystemBackend, c *Core, id string) string {
	t.Helper()
	resp, err := replicationUpdate(t.Context(), b, "replication/performance/primary/secondary-token", map[string]any{
		"id": id,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.WrapInfo, "expected a response-wrapped secondary token")
	require.Equal(t, 30*60, int(resp.WrapInfo.TTL/time.Second))

	req := &logical.Request{Path: "replication/performance/primary/secondary-token"}
	// wrapInCubbyhole returns (nil, nil) on success and mutates resp to
	// carry the wrapping token; the core pipeline then replaces the
	// response with a Data-less wrapper (data: null in the API output).
	_, err = c.wrapInCubbyhole(namespace.RootContext(t.Context()), req, resp, nil, nil)
	require.NoError(t, err)
	require.NotEmpty(t, resp.WrapInfo.Token, "expected a wrapping token")
	return resp.WrapInfo.Token
}

func TestReplicationStatusEmpty(t *testing.T) {
	b, _ := replicationSysBackend(t)

	resp, err := replicationRead(t.Context(), b, "replication/status")
	require.NoError(t, err)
	require.NotNil(t, resp)
	// Nothing configured: both stanzas are omitted.
	require.Empty(t, resp.Data)
}

func TestReplicationPerformancePrimaryLifecycle(t *testing.T) {
	b, c := replicationSysBackend(t)

	// secondary-token before enable must fail
	resp, err := replicationUpdate(t.Context(), b, "replication/performance/primary/secondary-token", map[string]any{
		"id": "us-east-1",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "expected error, got %v", resp)

	resp, err = replicationUpdate(t.Context(), b, "replication/performance/primary/enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Status reflects the primary mode.
	resp, err = replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, "primary", resp.Data["mode"])
	require.Equal(t, "running", resp.Data["state"])
	require.Equal(t, c.ClusterID(), resp.Data["cluster_id"])
	require.Contains(t, resp.Data, "merkle_root")
	require.Contains(t, resp.Data, "last_wal")
	require.Contains(t, resp.Data, "last_performance_wal")
	require.Equal(t, []map[string]any{}, resp.Data["secondaries"])
	require.Empty(t, resp.Data["known_secondaries"])

	// The combined status reports the performance stanza and omits DR.
	resp, err = replicationRead(t.Context(), b, "replication/status")
	require.NoError(t, err)
	require.Contains(t, resp.Data, "performance")
	require.NotContains(t, resp.Data, "dr")
	require.Equal(t, "primary", resp.Data["performance"].(map[string]any)["mode"])

	// Core replication state now reports performance primary.
	require.NotZero(t, uint32(c.ReplicationState()) & uint32(consts.ReplicationPerformancePrimary))
}

func TestReplicationSecondaryTokenLifecycle(t *testing.T) {
	b, c := replicationSysBackend(t)

	_, err := replicationUpdate(t.Context(), b, "replication/performance/primary/enable", map[string]any{})
	require.NoError(t, err)

	token := issueTestSecondaryToken(t, b, c, "us-east")
	require.NotEmpty(t, token)

	// The secondary is now known.
	status, err := replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, []string{"us-east"}, status.Data["known_secondaries"])

	// A duplicate id is rejected.
	resp, err := replicationUpdate(t.Context(), b, "replication/performance/primary/secondary-token", map[string]any{
		"id": "us-east",
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// Revoke the secondary.
	resp, err = replicationUpdate(t.Context(), b, "replication/performance/primary/revoke-secondary", map[string]any{
		"id": "us-east",
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	status, err = replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, []string{}, status.Data["known_secondaries"])

	// Revoking an unknown id errors.
	resp, err = replicationUpdate(t.Context(), b, "replication/performance/primary/revoke-secondary", map[string]any{
		"id": "us-west",
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestReplicationPathsFilterLifecycle(t *testing.T) {
	b, _ := replicationSysBackend(t)

	resp, err := replicationUpdate(t.Context(), b, "replication/performance/primary/paths-filter/us-east", map[string]any{})
	require.NoError(t, err)
	require.True(t, resp.IsError(), "expected error before enabling replication")

	_, err = replicationUpdate(t.Context(), b, "replication/performance/primary/enable", map[string]any{})
	require.NoError(t, err)

	// Write a filter.
	resp, err = replicationUpdate(t.Context(), b, "replication/performance/primary/paths-filter/us-east", map[string]any{
		"mode":  "deny",
		"paths": []string{"secret/teams/", "auth/approle/*"},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Invalid mode rejected.
	resp, err = replicationUpdate(t.Context(), b, "replication/performance/primary/paths-filter/us-east", map[string]any{
		"mode": "bogus",
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// Read it back.
	resp, err = replicationRead(t.Context(), b, "replication/performance/primary/paths-filter/us-east")
	require.NoError(t, err)
	require.Equal(t, "deny", resp.Data["mode"])
	require.Equal(t, []string{"secret/teams/", "auth/approle/*"}, resp.Data["paths"])

	// Unknown id → empty (204).
	resp, err = replicationRead(t.Context(), b, "replication/performance/primary/paths-filter/unknown")
	require.NoError(t, err)
	require.Nil(t, resp)

	// Delete it.
	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Path:      "replication/performance/primary/paths-filter/us-east",
		Operation: logical.DeleteOperation,
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = replicationRead(t.Context(), b, "replication/performance/primary/paths-filter/us-east")
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestReplicationSecondaryActivationAndPromotion(t *testing.T) {
	b, c := replicationSysBackend(t)

	_, err := replicationUpdate(t.Context(), b, "replication/performance/primary/enable", map[string]any{})
	require.NoError(t, err)

	token := issueTestSecondaryToken(t, b, c, "us-east")

	// Enable secondary on the same core: first demote so the mode gate
	// allows activation (on real deployments this runs on a second cluster).
	resp, err := replicationUpdate(t.Context(), b, "replication/performance/primary/demote", nil)
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = replicationUpdate(t.Context(), b, "replication/performance/secondary/enable", map[string]any{
		"token": token,
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	status, err := replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, "secondary", status.Data["mode"])
	require.NotEqual(t, "", status.Data["cluster_id"])
	require.Equal(t, "us-east", status.Data["secondary_id"])
	require.Equal(t, []map[string]any{}, status.Data["primaries"])
	require.Contains(t, status.Data, "last_remote_wal")

	// The core replication state reflects secondary.
	require.NotZero(t, uint32(c.ReplicationState()) & uint32(consts.ReplicationPerformanceSecondary))

	// Update-primary with a new address list.
	resp, err = replicationUpdate(t.Context(), b, "replication/performance/secondary/update-primary", map[string]any{
		"update_primary_addrs": []string{"https://127.0.0.1:8999"},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	status, err = replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, []string{"https://127.0.0.1:8999"}, status.Data["known_primary_cluster_addrs"])

	// Promote back to primary (performance promote needs no operation token).
	resp, err = replicationUpdate(t.Context(), b, "replication/performance/secondary/promote", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, resp)

	status, err = replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, "primary", status.Data["mode"])

	// Demote again, then disable.
	_, err = replicationUpdate(t.Context(), b, "replication/performance/primary/demote", nil)
	require.NoError(t, err)
	status, err = replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Equal(t, "secondary", status.Data["mode"])

	resp, err = replicationUpdate(t.Context(), b, "replication/performance/secondary/disable", nil)
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = replicationRead(t.Context(), b, "replication/performance/status")
	require.NoError(t, err)
	require.Empty(t, resp.Data)
}

func TestReplicationDRLifecycle(t *testing.T) {
	b, _ := replicationSysBackend(t)

	_, err := replicationUpdate(t.Context(), b, "replication/dr/primary/enable", map[string]any{})
	require.NoError(t, err)

	resp, err := replicationRead(t.Context(), b, "replication/dr/status")
	require.NoError(t, err)
	require.Equal(t, "primary", resp.Data["mode"])

	// DR has no paths-filter surface (the route is unregistered).
	_, err = replicationRead(t.Context(), b, "replication/dr/primary/paths-filter/someid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported path")

	// DR secondary disable requires an operation token.
	resp, err = replicationUpdate(t.Context(), b, "replication/dr/secondary/disable", nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "dr_operation_token")

	resp, err = replicationUpdate(t.Context(), b, "replication/dr/secondary/disable", map[string]any{
		"dr_operation_token": "dummy",
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = replicationRead(t.Context(), b, "replication/dr/status")
	require.NoError(t, err)
	require.Empty(t, resp.Data)
}

func TestReplicationReindexMerkleCheckRecover(t *testing.T) {
	b, _ := replicationSysBackend(t)

	resp, err := replicationUpdate(t.Context(), b, "replication/merkle-check", nil)
	require.NoError(t, err)
	report := resp.Data["merkle_corruption_report"].(map[string]any)
	require.False(t, report["corrupted_root"].(bool))

	resp, err = replicationUpdate(t.Context(), b, "replication/reindex", map[string]any{"force": true})
	require.NoError(t, err)
	require.NotNil(t, resp)

	resp, err = replicationUpdate(t.Context(), b, "replication/recover", nil)
	require.NoError(t, err)
	warnings := resp.Data["warnings"].([]string)
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "replication is not enabled")

	// With performance replication enabled, recover reports no adverse state.
	_, err = replicationUpdate(t.Context(), b, "replication/performance/primary/enable", nil)
	require.NoError(t, err)
	resp, err = replicationUpdate(t.Context(), b, "replication/recover", nil)
	require.NoError(t, err)
	warnings = resp.Data["warnings"].([]string)
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "no replication adverse state")
}

func TestReplicationGeneratePublicKey(t *testing.T) {
	b, _ := replicationSysBackend(t)

	resp, err := replicationUpdate(t.Context(), b, "replication/performance/secondary/generate-public-key", nil)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Data["public_key"])

	// Stable across calls.
	resp2, err := replicationUpdate(t.Context(), b, "replication/dr/secondary/generate-public-key", nil)
	require.NoError(t, err)
	require.NotEqual(t, resp.Data["public_key"], resp2.Data["public_key"])
}
