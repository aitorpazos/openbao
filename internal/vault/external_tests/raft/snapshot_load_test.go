// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package rafttests

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

// End-to-end coverage for the documented non-destructive snapshot-load
// surface: POST /v1/sys/storage/raft/snapshot-load accepts a raw binary
// snapshot upload and creates an isolated recovery view without overwriting
// live cluster data. Mirrors TestRaft_SnapshotAPI's cluster conventions.
func TestRaft_SnapshotLoad(t *testing.T) {
	cluster, _ := raftCluster(t, nil)
	defer cluster.Cleanup()

	leaderClient := cluster.Cores[0].Client

	// Marker policy whose value changes after the snapshot so the isolated
	// recovery view can be distinguished from live data.
	require.NoError(t, leaderClient.Sys().PutPolicy("load-marker", beforePolicy))
	buf := new(bytes.Buffer)
	require.NoError(t, leaderClient.Sys().RaftSnapshot(buf))
	snapshot := buf.Bytes()
	require.NotEmpty(t, snapshot)
	require.NoError(t, leaderClient.Sys().PutPolicy("load-marker", afterPolicy))

	// Load the snapshot non-destructively.
	first, err := snapshotLoadRequest(leaderClient, snapshot)
	require.NoError(t, err)
	require.Equal(t, cluster.Cores[0].Core.ClusterID(), first["cluster_id"])
	require.NotEmpty(t, first["snapshot_id"])
	require.Equal(t, "loading", first["status"])
	created, err := time.Parse(time.RFC3339Nano, first["created_at"].(string))
	require.NoError(t, err)
	expires, err := time.Parse(time.RFC3339Nano, first["expires_at"].(string))
	require.NoError(t, err)
	require.Equal(t, 72*time.Hour, expires.Sub(created))

	// GET by ID reports the terminal ready state immediately.
	ready, err := snapshotReadRequest(leaderClient, first["snapshot_id"].(string))
	require.NoError(t, err)
	require.Equal(t, "ready", ready["status"])

	// Live data is untouched: the post-snapshot value is still served.
	policy, err := leaderClient.Sys().GetPolicy("load-marker")
	require.NoError(t, err)
	require.Equal(t, afterPolicy, policy)

	// A second load is rejected until the first is unloaded.
	_, err = snapshotLoadRequest(leaderClient, snapshot)
	require.Error(t, err)
	require.Contains(t, err.Error(), "only one snapshot")

	// Unload, then loading again succeeds.
	unloadSnapshot(leaderClient, first["snapshot_id"].(string))
	again, err := snapshotLoadRequest(leaderClient, snapshot)
	require.NoError(t, err)
	// snapshot_id is a fresh random identifier per load.
	require.NotEmpty(t, again["snapshot_id"])
	require.NotEqual(t, first["snapshot_id"], again["snapshot_id"])
	unloadSnapshot(leaderClient, again["snapshot_id"].(string))

	// Damaged snapshots are rejected once the slot is free.
	damaged := append([]byte(nil), snapshot...)
	damaged[len(damaged)/2] ^= 1
	_, err = snapshotLoadRequest(leaderClient, damaged)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")

	truncated := snapshot[:len(snapshot)-8]
	_, err = snapshotLoadRequest(leaderClient, truncated)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

// Cross-cluster snapshots are rejected even when structurally valid and
// unsealable with a foreign cluster's seal.
func TestRaft_SnapshotLoad_CrossCluster(t *testing.T) {
	clusterA, _ := raftCluster(t, nil)
	defer clusterA.Cleanup()
	clusterB, _ := raftCluster(t, nil)
	defer clusterB.Cleanup()

	buf := new(bytes.Buffer)
	require.NoError(t, clusterB.Cores[0].Client.Sys().RaftSnapshot(buf))

	_, err := snapshotLoadRequest(clusterA.Cores[0].Client, buf.Bytes())
	require.Error(t, err)
	// A foreign cluster's seal cannot decrypt the snapshot, so the seal
	// mismatch surfaces first; the explicit cluster-ID check guards the
	// same-seal case.
	require.Contains(t, err.Error(), "different unseal keys")
}

const beforePolicy = `path "load-marker" {
  capabilities = ["read"]
}
`
const afterPolicy = `path "load-marker" {
  capabilities = ["read"]
}
# changed after snapshot
`

func snapshotLoadRequest(client *api.Client, data []byte) (map[string]any, error) {
	req := client.NewRequest("POST", "/v1/sys/storage/raft/snapshot-load")
	req.Body = bytes.NewBuffer(data)
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if data, ok := out["data"].(map[string]any); ok {
		return data, nil
	}
	return out, nil
}

func snapshotReadRequest(client *api.Client, snapshotID string) (map[string]any, error) {
	req := client.NewRequest("GET", "/v1/sys/storage/raft/snapshot-load/"+snapshotID)
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if data, ok := out["data"].(map[string]any); ok {
		return data, nil
	}
	return out, nil
}

func unloadSnapshot(client *api.Client, snapshotID string) {
	req := client.NewRequest("DELETE", "/v1/sys/storage/raft/snapshot-load/"+snapshotID)
	_, _ = client.RawRequest(req)
}

var _ = vault.TestCluster{}
