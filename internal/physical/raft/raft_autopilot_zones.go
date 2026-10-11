// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"sort"

	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
)

// Redundancy-zone surface, clean-roomed from public documentation:
//
//   - /sys/storage/raft/autopilot/state exposes a redundancy_zones object
//     keyed by zone label, each holding servers, voters, and a per-zone
//     failure_tolerance, plus a cluster-wide optimistic_failure_tolerance
//     integer. The documented example (zones a: 3 servers/1 voter -> 2,
//     b: 2 servers/1 voter -> 1) yields optimistic_failure_tolerance 3,
//     i.e. the sum over zones of promotable backups (servers minus voters).
//   - Documented per-server node types for zoned servers are zone-voter,
//     zone-extra-voter, and zone-standby (a promotable non-voter).
//   - Autopilot maintains exactly one voting node per zone; extras are
//     demoted and a failed zone voter is replaced by promoting that zone's
//     standby, subject to continued quorum.
//
// See compat/specs/redundancy/notes.md for the citation table. Unlabeled
// servers (empty zone) keep the pre-zones behavior: the docs define no
// default zone group for this endpoint.

// zonesFromAutopilotState computes the redundancy_zones map, the cluster-wide
// optimistic failure tolerance, and zone-aware node types from an autopilot
// state plus a node-ID-to-zone resolver.
func zonesFromAutopilotState(state *autopilot.State, zoneOf func(raft.ServerID) string) (map[string]*AutopilotZone, int, map[raft.ServerID]string) {
	zones := make(map[string]*AutopilotZone)
	nodeTypes := make(map[raft.ServerID]string)
	oft := 0

	if state == nil || zoneOf == nil {
		return zones, oft, nodeTypes
	}

	voterSet := make(map[raft.ServerID]bool, len(state.Voters))
	for _, id := range state.Voters {
		voterSet[id] = true
	}

	for id := range state.Servers {
		zone := zoneOf(id)
		if zone == "" {
			continue
		}
		z, ok := zones[zone]
		if !ok {
			z = &AutopilotZone{}
			zones[zone] = z
		}
		z.Servers = append(z.Servers, string(id))
		if voterSet[id] {
			z.Voters = append(z.Voters, string(id))
		}
	}

	for _, z := range zones {
		// Deterministic output: the harness and operators diff these arrays.
		sort.Strings(z.Servers)
		sort.Strings(z.Voters)
		z.FailureTolerance = len(z.Servers) - len(z.Voters)
		oft += z.FailureTolerance

		zoneVoter := ""
		if len(z.Voters) > 0 {
			zoneVoter = z.Voters[0]
		}
		for _, id := range z.Servers {
			switch {
			case zoneVoter != "" && id == zoneVoter:
				nodeTypes[raft.ServerID(id)] = "zone-voter"
			case voterSet[raft.ServerID(id)]:
				nodeTypes[raft.ServerID(id)] = "zone-extra-voter"
			default:
				nodeTypes[raft.ServerID(id)] = "zone-standby"
			}
		}
	}

	return zones, oft, nodeTypes
}

// zoneResolverLocked returns a zone resolver for use while the backend's
// read lock is already held (direct field access, no re-lock).
func (b *RaftBackend) zoneResolverLocked() func(raft.ServerID) string {
	return func(id raft.ServerID) string {
		if string(id) == b.localID {
			return b.redundancyZone
		}
		if b.followerStates != nil {
			return b.followerStates.Zone(string(id))
		}
		return ""
	}
}

// zoneResolver returns a zone resolver that takes the backend read lock for
// the duration of the lookup. Use this from goroutines that do not already
// hold b.l (e.g. the autopilot promoter).
func (b *RaftBackend) zoneResolver() func(raft.ServerID) string {
	return func(id raft.ServerID) string {
		b.l.RLock()
		defer b.l.RUnlock()
		return b.zoneResolverLocked()(id)
	}
}
