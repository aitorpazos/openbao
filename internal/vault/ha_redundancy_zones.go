// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

// Redundancy-zone reporting for /sys/ha-status, clean-roomed from public
// documentation (see compat/specs/redundancy/notes.md): the documented
// Enterprise /sys/ha-status shape exposes Nodes[].redundancy_zone per node.
// Each node's zone is its own autopilot_redundancy_zone configuration value;
// the active node learns peers' labels over the echo channel, exactly like
// peer versions. Unconfigured or non-raft nodes report an empty label.

// getRedundancyZones returns a map of node API address to redundancy-zone
// label, covering this node (from its raft storage configuration) and the
// peers heard from recently (from echo updates). Callers on the active node
// can therefore resolve a zone for every member listed by getHAMembers.
// Keyed by API address because that is the identifier HAStatusNode entries
// carry; API addresses are unique per node.
func (c *Core) getRedundancyZones() map[string]string {
	zones := make(map[string]string)

	if rb := c.GetRaftBackend(); rb != nil {
		if c.redirectAddr != "" {
			zones[c.redirectAddr] = rb.RedundancyZone()
		}
	}

	for _, peer := range c.GetHAPeerNodesCached() {
		if peer.APIAddress != "" {
			zones[peer.APIAddress] = peer.RedundancyZone
		}
	}

	return zones
}
