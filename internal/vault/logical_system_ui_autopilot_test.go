// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/physical/raft"
	"github.com/stretchr/testify/require"
)

func TestInternalUINamespaceRecursive(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	defer core.Shutdown()
	parent := &namespace.Namespace{Path: "ui-parent/"}
	child := &namespace.Namespace{Path: "ui-parent/nested/"}
	other := &namespace.Namespace{Path: "ui-other/"}
	TestCoreCreateNamespaces(t, core, parent, child, other)
	b := &SystemBackend{Core: core}
	ctx := namespace.RootContext(context.Background())
	for i := 0; i < 3; i++ {
		resp, err := b.pathInternalUINamespacesRead(ctx, &logical.Request{ClientToken: token}, nil)
		require.NoError(t, err)
		require.Equal(t, []string{"ui-other/", "ui-parent/", "ui-parent/nested/"}, resp.Data["keys"])
	}
	resp, err := b.pathInternalUINamespacesRead(namespace.ContextWithNamespace(ctx, parent), &logical.Request{ClientToken: token}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"nested/"}, resp.Data["keys"])
	_, err = b.pathInternalUINamespacesRead(ctx, &logical.Request{}, nil)
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
}

func TestAutopilotDisableUpgradeMigrationConfiguration(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	defer core.Shutdown()
	rb := raftBackendWithZone(t, "")
	rb.SetAutopilotConfig(&raft.AutopilotConfig{MaxTrailingLogs: 100})
	// Exercise the real handlers against Raft's configuration state without a
	// running Raft cluster. The unsealed core supplies real barrier persistence.
	b := &SystemBackend{Core: &Core{ha: rb, barrier: core.barrier}}
	ctx := namespace.RootContext(context.Background())
	var schema map[string]*framework.FieldSchema
	for _, path := range b.raftStoragePaths() {
		if path.Pattern == "storage/raft/autopilot/configuration" {
			schema = path.Fields
		}
	}
	require.NotNil(t, schema)
	read := func(want bool) {
		t.Helper()
		resp, err := b.handleStorageRaftAutopilotConfigRead()(ctx, &logical.Request{}, nil)
		require.NoError(t, err)
		require.Equal(t, want, resp.Data["disable_upgrade_migration"])
	}
	read(false)
	for _, value := range []bool{true, false} {
		data := &framework.FieldData{Raw: map[string]any{"disable_upgrade_migration": value}, Schema: schema}
		require.NoError(t, data.Validate())
		resp, err := b.handleStorageRaftAutopilotConfigUpdate()(ctx, &logical.Request{}, data)
		require.NoError(t, err)
		require.Nil(t, resp)
		read(value)
		stored, err := b.Core.loadAutopilotAPIConfiguration(ctx)
		require.NoError(t, err)
		require.Equal(t, value, stored.DisableUpgradeMigration)
		// An unrelated write must not reset the setting.
		_, err = b.handleStorageRaftAutopilotConfigUpdate()(ctx, &logical.Request{}, &framework.FieldData{Raw: map[string]any{"max_trailing_logs": 101}, Schema: schema})
		require.NoError(t, err)
		require.Equal(t, uint64(101), rb.AutopilotConfig().MaxTrailingLogs)
		read(value)
		// The original Raft loader must still understand the same storage entry.
		legacy, err := b.Core.loadAutopilotConfiguration(ctx)
		require.NoError(t, err)
		require.Equal(t, uint64(101), legacy.MaxTrailingLogs)
	}
	invalid := &framework.FieldData{Raw: map[string]any{"disable_upgrade_migration": "not-a-boolean"}, Schema: schema}
	require.Error(t, invalid.Validate())
	read(false)
}
