// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"testing"
	"time"

	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
	"github.com/stretchr/testify/require"
)

func zoneTestState(servers map[string]autopilot.RaftState, leader string) *autopilot.State {
	now := time.Now()
	s := &autopilot.State{
		Servers: make(map[raft.ServerID]*autopilot.ServerState, len(servers)),
		Leader:  raft.ServerID(leader),
	}
	for id, state := range servers {
		s.Servers[raft.ServerID(id)] = &autopilot.ServerState{
			Server: autopilot.Server{ID: raft.ServerID(id)},
			State:  state,
			Health: autopilot.ServerHealth{Healthy: true, StableSince: now},
		}
	}
	for id := range servers {
		if servers[id] == autopilot.RaftVoter {
			s.Voters = append(s.Voters, raft.ServerID(id))
		}
	}
	return s
}

func zoneTestConfig(minQuorum uint) *autopilot.Config {
	return &autopilot.Config{
		Ext:       map[raft.ServerID]bool{},
		MinQuorum: minQuorum,
	}
}

// TestCustomPromoter_GetNodeTypes_ZoneAware covers the desired-suffrage view:
// exactly one voter per labeled zone (the keeper), other zone members desired
// as non-voters, unzoned servers unchanged.
func TestCustomPromoter_GetNodeTypes_ZoneAware(t *testing.T) {
	zones := map[string]string{"a1": "a", "a2": "a", "b1": "b", "u1": ""}
	state := zoneTestState(map[string]autopilot.RaftState{
		"a1": autopilot.RaftVoter,
		"a2": autopilot.RaftNonVoter,
		"b1": autopilot.RaftVoter,
		"u1": autopilot.RaftVoter,
	}, "a1")

	p := &CustomPromoter{zoneOf: zoneFunc(zones)}
	types := p.GetNodeTypes(zoneTestConfig(0), state)

	require.Equal(t, autopilot.NodeVoter, types["a1"])
	require.Equal(t, NodeNonVoter, types["a2"])
	require.Equal(t, autopilot.NodeVoter, types["b1"])
	// Unzoned servers keep the existing behavior (voter).
	require.Equal(t, autopilot.NodeVoter, types["u1"])
}

// TestCustomPromoter_CalculatePromotionsAndDemotions_ZoneAware covers the
// documented flows: a zone whose voter disappeared promotes its stable
// non-voter; extra voters in a zone are demoted; the leader is never demoted;
// unzoned servers keep the existing behavior.
func TestCustomPromoter_CalculatePromotionsAndDemotions_ZoneAware(t *testing.T) {
	zones := map[string]string{"a1": "a", "a2": "a", "b1": "b", "u1": ""}

	t.Run("balanced zones need no changes", func(t *testing.T) {
		state := zoneTestState(map[string]autopilot.RaftState{
			"a1": autopilot.RaftVoter,
			"a2": autopilot.RaftNonVoter,
			"b1": autopilot.RaftVoter,
		}, "a1")

		p := &CustomPromoter{zoneOf: zoneFunc(zones)}
		changes := p.CalculatePromotionsAndDemotions(zoneTestConfig(0), state)

		require.Empty(t, changes.Promotions)
		require.Empty(t, changes.Demotions)
	})

	t.Run("zone without voter promotes its stable standby", func(t *testing.T) {
		// Zone a lost its voter: only a non-voter remains there. Zone b still
		// has its voter. The standby is healthy and stable.
		zones := map[string]string{"a2": "a", "b1": "b"}
		state := zoneTestState(map[string]autopilot.RaftState{
			"a2": autopilot.RaftNonVoter,
			"b1": autopilot.RaftVoter,
		}, "b1")

		p := &CustomPromoter{zoneOf: zoneFunc(zones)}
		changes := p.CalculatePromotionsAndDemotions(zoneTestConfig(0), state)

		require.Contains(t, changes.Promotions, raft.ServerID("a2"))
		require.Empty(t, changes.Demotions)
	})

	t.Run("extra zone voter is demoted unless it is the leader", func(t *testing.T) {
		zones := map[string]string{"a1": "a", "a2": "a", "b1": "b"}
		state := zoneTestState(map[string]autopilot.RaftState{
			"a1": autopilot.RaftVoter,
			"a2": autopilot.RaftVoter,
			"b1": autopilot.RaftVoter,
		}, "b1")

		p := &CustomPromoter{zoneOf: zoneFunc(zones)}
		changes := p.CalculatePromotionsAndDemotions(zoneTestConfig(0), state)

		// Zone a keeps its lexicographically lowest current voter (a1) and
		// demotes the extra (a2). b1 is balanced.
		require.Contains(t, changes.Demotions, raft.ServerID("a2"))
		require.NotContains(t, changes.Demotions, raft.ServerID("a1"))
		require.Empty(t, changes.Promotions)

		// Same shape, but the leader is the extra: the leader is never demoted.
		state.Leader = raft.ServerID("a2")
		changes = p.CalculatePromotionsAndDemotions(zoneTestConfig(0), state)
		require.NotContains(t, changes.Demotions, raft.ServerID("a2"))
	})

	t.Run("MinQuorum guards extra-voter demotions", func(t *testing.T) {
		zones := map[string]string{"a1": "a", "a2": "a"}
		state := zoneTestState(map[string]autopilot.RaftState{
			"a1": autopilot.RaftVoter,
			"a2": autopilot.RaftVoter,
		}, "a1")

		p := &CustomPromoter{zoneOf: zoneFunc(zones)}
		// Requiring two voters blocks demoting either extra down to one.
		changes := p.CalculatePromotionsAndDemotions(zoneTestConfig(2), state)

		require.Empty(t, changes.Demotions)
	})

	t.Run("unzoned servers keep existing behavior", func(t *testing.T) {
		zones := map[string]string{"u1": "", "u2": ""}
		state := zoneTestState(map[string]autopilot.RaftState{
			"u1": autopilot.RaftVoter,
			"u2": autopilot.RaftNonVoter,
		}, "u1")

		p := &CustomPromoter{zoneOf: zoneFunc(zones)}
		changes := p.CalculatePromotionsAndDemotions(zoneTestConfig(0), state)

		// The healthy stable unzoned non-voter is promoted, as before zones.
		require.Contains(t, changes.Promotions, raft.ServerID("u2"))
		require.Empty(t, changes.Demotions)
	})
}

// TestCustomPromoter_NilZoneOf verifies the pre-zones behavior is intact when
// no zone resolver is configured.
func TestCustomPromoter_NilZoneOf(t *testing.T) {
	state := zoneTestState(map[string]autopilot.RaftState{
		"v1": autopilot.RaftVoter,
		"v2": autopilot.RaftNonVoter,
	}, "v1")

	p := &CustomPromoter{}
	types := p.GetNodeTypes(zoneTestConfig(0), state)
	require.Equal(t, autopilot.NodeVoter, types["v1"])
	require.Equal(t, autopilot.NodeVoter, types["v2"])

	changes := p.CalculatePromotionsAndDemotions(zoneTestConfig(0), state)
	require.Contains(t, changes.Promotions, raft.ServerID("v2"))
	require.Empty(t, changes.Demotions)
}
