// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	raftphys "github.com/openbao/openbao/v2/internal/physical/raft"
	"github.com/openbao/openbao/v2/internal/vault/forwarding"
	"github.com/stretchr/testify/require"
	"zgo.at/zcache/v2"
)

// Redundancy-zone reporting for /sys/ha-status is clean-roomed from public
// documentation; see compat/specs/redundancy/notes.md.

func raftBackendWithZone(t *testing.T, zone string) *raftphys.RaftBackend {
	t.Helper()
	conf := map[string]string{
		"path":    t.TempDir(),
		"node_id": "zones-test-1",
	}
	if zone != "" {
		conf["autopilot_redundancy_zone"] = zone
	}
	logger := hclog.NewNullLogger()
	rb, err := raftphys.NewRaftBackend(conf, logger)
	require.NoError(t, err)
	typed, ok := rb.(*raftphys.RaftBackend)
	require.True(t, ok)
	return typed
}

func forwardingNodeHAConnectionInfoForTest(apiAddr, zone string) forwarding.NodeHAConnectionInfo {
	return forwarding.NodeHAConnectionInfo{
		NodeInfo: &forwarding.NodeInformation{
			ClusterAddr: "",
			ApiAddr:     apiAddr,
		},
		LastHeartbeat:  time.Now(),
		RedundancyZone: zone,
	}
}

func TestGetRedundancyZones(t *testing.T) {
	rb := raftBackendWithZone(t, "zone-a")

	c := &Core{
		redirectAddr:                 "http://127.0.0.1:8210",
		ha:                           rb,
		clusterPeerClusterAddrsCache: zcacheNewHAForTest(t),
	}
	c.clusterPeerClusterAddrsCache.Set(
		"https://127.0.0.1:8221",
		forwardingNodeHAConnectionInfoForTest("http://127.0.0.1:8220", "zone-b"),
	)
	// A peer with no zone label must keep the empty default, not a fabricated one.
	c.clusterPeerClusterAddrsCache.Set(
		"https://127.0.0.1:8231",
		forwardingNodeHAConnectionInfoForTest("http://127.0.0.1:8230", ""),
	)

	zones := c.getRedundancyZones()
	require.Equal(t, map[string]string{
		// Self, keyed by redirect (API) address.
		"http://127.0.0.1:8210": "zone-a",
		// Peers, keyed by API address, labeled from echo updates.
		"http://127.0.0.1:8220": "zone-b",
		"http://127.0.0.1:8230": "",
	}, zones)
}

func TestGetRedundancyZonesWithoutRaft(t *testing.T) {
	// Non-raft cluster: no self label, but peers heard over echo still report.
	c := &Core{
		redirectAddr:                 "http://127.0.0.1:8210",
		clusterPeerClusterAddrsCache: zcacheNewHAForTest(t),
	}
	c.clusterPeerClusterAddrsCache.Set(
		"https://127.0.0.1:8221",
		forwardingNodeHAConnectionInfoForTest("http://127.0.0.1:8220", "zone-b"),
	)

	zones := c.getRedundancyZones()
	require.Equal(t, map[string]string{
		"http://127.0.0.1:8220": "zone-b",
	}, zones)
}

func TestGetRedundancyZonesEmpty(t *testing.T) {
	c := &Core{
		clusterPeerClusterAddrsCache: zcacheNewHAForTest(t),
	}
	require.Empty(t, c.getRedundancyZones())
}

func zcacheNewHAForTest(t *testing.T) *zcache.Cache[string, forwarding.NodeHAConnectionInfo] {
	t.Helper()
	return zcache.New[string, forwarding.NodeHAConnectionInfo](3*time.Second, time.Second)
}
