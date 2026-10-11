// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"testing"

	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
	"github.com/stretchr/testify/require"
)

func testZoneState(servers map[string]autopilot.RaftState, voters []string, leader string) *autopilot.State {
	s := &autopilot.State{
		Servers: make(map[raft.ServerID]*autopilot.ServerState, len(servers)),
		Leader:  raft.ServerID(leader),
	}
	for id, state := range servers {
		s.Servers[raft.ServerID(id)] = &autopilot.ServerState{
			Server: autopilot.Server{ID: raft.ServerID(id)},
			State:  state,
		}
	}
	for _, id := range voters {
		s.Voters = append(s.Voters, raft.ServerID(id))
	}
	return s
}

func zoneFunc(zones map[string]string) func(raft.ServerID) string {
	return func(id raft.ServerID) string {
		return zones[string(id)]
	}
}

// TestZonesFromAutopilotState covers the documented Enterprise shape for
// /sys/storage/raft/autopilot/state: the redundancy_zones map keyed by zone
// with servers/voters/failure_tolerance, the cluster-wide optimistic failure
// tolerance (sum over zones of promotable backups), and the zone-aware node
// types. The documented example has zone a with 3 servers/1 voter and zone b
// with 2 servers/1 voter, giving optimistic_failure_tolerance 3.
func TestZonesFromAutopilotState(t *testing.T) {
	t.Run("documented example", func(t *testing.T) {
		state := testZoneState(map[string]autopilot.RaftState{
			"vault_1": autopilot.RaftVoter,
			"vault_2": autopilot.RaftNonVoter,
			"vault_5": autopilot.RaftNonVoter,
			"vault_3": autopilot.RaftVoter,
			"vault_4": autopilot.RaftNonVoter,
		}, []string{"vault_1", "vault_3"}, "vault_1")

		zones, oft, nodeTypes := zonesFromAutopilotState(state, zoneFunc(map[string]string{
			"vault_1": "a", "vault_2": "a", "vault_5": "a",
			"vault_3": "b", "vault_4": "b",
		}))

		require.Equal(t, 3, oft)
		require.Equal(t, map[string]*AutopilotZone{
			"a": {Servers: []string{"vault_1", "vault_2", "vault_5"}, Voters: []string{"vault_1"}, FailureTolerance: 2},
			"b": {Servers: []string{"vault_3", "vault_4"}, Voters: []string{"vault_3"}, FailureTolerance: 1},
		}, zones)
		require.Equal(t, map[raft.ServerID]string{
			"vault_1": "zone-voter",
			"vault_2": "zone-standby",
			"vault_5": "zone-standby",
			"vault_3": "zone-voter",
			"vault_4": "zone-standby",
		}, nodeTypes)
	})

	t.Run("extra voters demoted in node types", func(t *testing.T) {
		state := testZoneState(map[string]autopilot.RaftState{
			"a1": autopilot.RaftVoter,
			"a2": autopilot.RaftVoter,
			"a3": autopilot.RaftNonVoter,
		}, []string{"a1", "a2"}, "a1")

		zones, oft, nodeTypes := zonesFromAutopilotState(state, zoneFunc(map[string]string{
			"a1": "a", "a2": "a", "a3": "a",
		}))

		// Two voters, one non-voter: per-zone tolerance 1, optimistic 1.
		require.Equal(t, 1, oft)
		require.Equal(t, 1, zones["a"].FailureTolerance)
		require.Equal(t, "zone-voter", nodeTypes["a1"])
		require.Equal(t, "zone-extra-voter", nodeTypes["a2"])
		require.Equal(t, "zone-standby", nodeTypes["a3"])
	})

	t.Run("unzoned servers are excluded", func(t *testing.T) {
		state := testZoneState(map[string]autopilot.RaftState{
			"z1": autopilot.RaftVoter,
			"z2": autopilot.RaftNonVoter,
			"u1": autopilot.RaftVoter,
		}, []string{"z1", "u1"}, "z1")

		zones, oft, nodeTypes := zonesFromAutopilotState(state, zoneFunc(map[string]string{
			"z1": "a", "z2": "a",
			// u1 unzoned
		}))

		require.Equal(t, 1, oft)
		require.Equal(t, map[string]*AutopilotZone{
			"a": {Servers: []string{"z1", "z2"}, Voters: []string{"z1"}, FailureTolerance: 1},
		}, zones)
		require.NotContains(t, nodeTypes, "u1")
	})

	t.Run("no zones configured", func(t *testing.T) {
		state := testZoneState(map[string]autopilot.RaftState{
			"n1": autopilot.RaftVoter,
		}, []string{"n1"}, "n1")

		zones, oft, nodeTypes := zonesFromAutopilotState(state, zoneFunc(map[string]string{"n1": ""}))

		require.Empty(t, zones)
		require.Equal(t, 0, oft)
		require.Empty(t, nodeTypes)
	})

	t.Run("nil state and resolver", func(t *testing.T) {
		zones, oft, nodeTypes := zonesFromAutopilotState(nil, nil)
		require.Empty(t, zones)
		require.Equal(t, 0, oft)
		require.Empty(t, nodeTypes)
	})
}

func TestZoneResolver(t *testing.T) {
	b := &RaftBackend{localID: "self", redundancyZone: "a", followerStates: NewFollowerStates()}
	b.followerStates.Update(&EchoRequestUpdate{NodeID: "peer1", RedundancyZone: "b"})

	resolver := b.zoneResolver()
	require.Equal(t, "a", resolver("self"))
	require.Equal(t, "b", resolver("peer1"))
	require.Equal(t, "", resolver("unknown"))

	// The locked variant (used while the backend lock is already held) must
	// agree with the public one.
	locked := b.zoneResolverLocked()
	require.Equal(t, "a", locked("self"))
	require.Equal(t, "b", locked("peer1"))
	require.Equal(t, "", locked("unknown"))
}
