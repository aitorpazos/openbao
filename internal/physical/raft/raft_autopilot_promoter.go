// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"sort"
	"time"

	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
)

// Ensure that the CustomPromoter implements the autopilot.Promoter interface
var _ autopilot.Promoter = (*CustomPromoter)(nil)

type CustomPromoter struct {
	autopilot.StablePromoter

	// zoneOf resolves a server's autopilot redundancy-zone label ("" when the
	// server is unzoned). Nil disables zone-aware suffrage and keeps the
	// pre-zones behavior below.
	zoneOf func(raft.ServerID) string
}

// zoneKeeper picks the server a zone should keep as its single voter
// (documented semantics: exactly one voting node per zone). Preference order:
// the current leader if it is a zone voter, else the lexicographically lowest
// current voter, else the lowest member ID.
func zoneKeeper(s *autopilot.State, members []raft.ServerID, voterStates map[raft.ServerID]autopilot.RaftState) raft.ServerID {
	leader := s.Leader
	for _, id := range members {
		if id == leader && voterStates[id] == autopilot.RaftVoter {
			return id
		}
	}
	for _, id := range members {
		if voterStates[id] == autopilot.RaftVoter {
			return id
		}
	}
	if len(members) > 0 {
		return members[0]
	}
	return ""
}

// GetNodeTypes will return a map of node types for each server in the cluster.
// Without zone information this marks all servers as voters except those
// marked as non-voters in the configuration. With redundancy zones configured,
// each labeled zone keeps exactly one voter (its keeper) and its other members
// are desired non-voters; unlabeled servers keep the existing behavior.
func (p *CustomPromoter) GetNodeTypes(c *autopilot.Config, s *autopilot.State) map[raft.ServerID]autopilot.NodeType {
	types := make(map[raft.ServerID]autopilot.NodeType)
	nonVoters := c.Ext.(map[raft.ServerID]bool)
	for id := range s.Servers {
		// If the server is a non-voter, mark it as such
		if _, ok := nonVoters[id]; ok {
			types[id] = NodeNonVoter
		} else {
			types[id] = autopilot.NodeVoter
		}
	}

	if p == nil || p.zoneOf == nil {
		return types
	}

	voterStates := make(map[raft.ServerID]autopilot.RaftState, len(s.Servers))
	for id, server := range s.Servers {
		voterStates[id] = server.State
	}

	zones := make(map[string][]raft.ServerID)
	for id := range types {
		if zone := p.zoneOf(id); zone != "" {
			zones[zone] = append(zones[zone], id)
		}
	}

	for _, members := range zones {
		sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
		keeper := zoneKeeper(s, members, voterStates)
		for _, id := range members {
			if _, isPerm := nonVoters[id]; isPerm {
				continue
			}
			if id != keeper {
				types[id] = NodeNonVoter
			}
		}
	}

	return types
}

// CalculatePromotionsAndDemotions will return a list of all promotions and demotions to be done as well as the server id of
// the desired leader. Without zone information this implementation maintains a stable leader and will promote healthy servers
// to voting status if they are not marked as permanent non-voters. It will never change the leader ID nor will it perform demotions.
//
// With redundancy zones configured, each labeled zone keeps exactly one voter:
// when a zone lost its voter its healthiest stable non-voter is promoted, and
// extra voters in a zone are demoted, subject to MinQuorum. The leader is
// never demoted. Unlabeled servers keep the existing behavior.
func (p *CustomPromoter) CalculatePromotionsAndDemotions(c *autopilot.Config, s *autopilot.State) autopilot.RaftChanges {
	var changes autopilot.RaftChanges

	now := time.Now()
	minStableDuration := s.ServerStabilizationTime(c)
	nonVoters := c.Ext.(map[raft.ServerID]bool)

	demoted := make(map[raft.ServerID]bool)
	promoted := make(map[raft.ServerID]bool)
	addDemotion := func(id raft.ServerID) {
		if !demoted[id] {
			demoted[id] = true
			changes.Demotions = append(changes.Demotions, id)
		}
	}
	addPromotion := func(id raft.ServerID) {
		if !promoted[id] {
			promoted[id] = true
			changes.Promotions = append(changes.Promotions, id)
		}
	}

	if p != nil && p.zoneOf != nil {
		zones := make(map[string][]raft.ServerID)
		for id := range s.Servers {
			if zone := p.zoneOf(id); zone != "" {
				zones[zone] = append(zones[zone], id)
			}
		}

		voterStates := make(map[raft.ServerID]autopilot.RaftState, len(s.Servers))
		voterCount := 0
		for id, server := range s.Servers {
			voterStates[id] = server.State
			if server.State == autopilot.RaftVoter {
				voterCount++
			}
		}

		var pendingDemotions []raft.ServerID
		for _, members := range zones {
			sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
			keeper := zoneKeeper(s, members, voterStates)

			for _, id := range members {
				if _, isPerm := nonVoters[id]; isPerm {
					// Configured permanent non-voters are handled below.
					continue
				}
				switch {
				case id == keeper:
					if voterStates[id] == autopilot.RaftNonVoter && s.Servers[id].Health.IsStable(now, minStableDuration) {
						addPromotion(id)
					}
				case voterStates[id] == autopilot.RaftVoter:
					pendingDemotions = append(pendingDemotions, id)
				}
			}
		}

		// Quorum guard: apply extra-voter demotions only while the projected
		// voter count stays at or above MinQuorum (when configured).
		minQuorum := int(c.MinQuorum)
		remaining := voterCount - len(pendingDemotions) + len(promoted)
		for _, id := range pendingDemotions {
			if id == s.Leader {
				continue
			}
			if minQuorum > 0 && remaining < minQuorum {
				break
			}
			addDemotion(id)
			remaining--
		}
	}

	for id, server := range s.Servers {
		if _, ok := nonVoters[id]; ok {
			// If the server is marked as a non-voter, demote it
			if server.State == autopilot.RaftVoter {
				addDemotion(id)
			}
			continue
		}

		// With zones configured, zoned non-keepers stay non-voters (the zone
		// pass decides their promotions); unlabeled servers keep the existing
		// promotion behavior.
		if p != nil && p.zoneOf != nil && p.zoneOf(id) != "" {
			continue
		}

		// If the server is healthy and stable, promote it to a voter
		if server.State == autopilot.RaftNonVoter && server.Health.IsStable(now, minStableDuration) {
			addPromotion(id)
		}
	}

	return changes
}
