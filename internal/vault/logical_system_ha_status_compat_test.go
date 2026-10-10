// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSystemBackend_HAStatusCompatibility(t *testing.T) {
	b := testSystemBackend(t)
	resp, err := b.(*SystemBackend).handleHAStatus(context.Background(), nil, nil)
	require.NoError(t, err)

	encoded, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var data map[string][]map[string]any
	require.NoError(t, json.Unmarshal(encoded, &data))
	require.Len(t, data, 2)
	require.Len(t, data["nodes"], 1)
	require.Len(t, data["Nodes"], 1)
	legacy := data["nodes"][0]
	require.Len(t, legacy, 6)
	for _, key := range []string{"hostname", "api_address", "cluster_address", "active_node", "last_echo", "version"} {
		require.Contains(t, legacy, key)
	}
	require.NotContains(t, legacy, "redundancy_zone")
	compat := data["Nodes"][0]
	require.Contains(t, compat, "redundancy_zone")
	require.Equal(t, "", compat["redundancy_zone"])
	delete(compat, "redundancy_zone")
	require.Equal(t, legacy, compat)
}

func TestHAStatusCompatNode_PreservesFields(t *testing.T) {
	lastEcho := time.Now().UTC()
	for _, node := range []HAStatusNode{
		{Hostname: "active", APIAddress: "https://active:8200", ClusterAddress: "https://active:8201", ActiveNode: true, Version: "2.7.1"},
		{Hostname: "standby", APIAddress: "https://standby:8200", ClusterAddress: "https://standby:8201", LastEcho: &lastEcho, Version: "2.7.1", UpgradeVersion: "2.7.0"},
	} {
		t.Run(node.Hostname, func(t *testing.T) {
			legacyJSON, err := json.Marshal(node)
			require.NoError(t, err)
			compatJSON, err := json.Marshal(haStatusCompatNode{HAStatusNode: node})
			require.NoError(t, err)
			var legacy, compat map[string]any
			require.NoError(t, json.Unmarshal(legacyJSON, &legacy))
			require.NoError(t, json.Unmarshal(compatJSON, &compat))
			require.NotContains(t, legacy, "redundancy_zone")
			require.Contains(t, compat, "redundancy_zone")
			require.Equal(t, "", compat["redundancy_zone"])
			delete(compat, "redundancy_zone")
			require.Equal(t, legacy, compat)
		})
	}
}
