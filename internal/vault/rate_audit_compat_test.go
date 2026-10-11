// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/v2/internal/vault/quotas"
	"github.com/openbao/openbao/v2/internal/vault/routing"
	"github.com/stretchr/testify/require"
)

func TestIdentityQuotaRoundTrip(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	call := func(op logical.Operation, data map[string]interface{}) *logical.Response {
		t.Helper()
		resp, err := core.HandleRequest(ctx, &logical.Request{Operation: op, Path: "sys/quotas/rate-limit/identity-test", ClientToken: token, Data: data})
		require.NoError(t, err)
		return resp
	}
	for _, group := range []string{"entity_then_ip", "entity_then_none", "ip", "none"} {
		config := map[string]interface{}{"rate": 100000.0, "group_by": group}
		if group == "entity_then_ip" || group == "entity_then_none" {
			config["secondary_rate"] = 50000.0
		}
		require.False(t, call(logical.UpdateOperation, config).IsError())
		resp := call(logical.ReadOperation, nil)
		require.Equal(t, group, resp.Data["group_by"])
		if rate, ok := config["secondary_rate"]; ok {
			require.Equal(t, rate, resp.Data["secondary_rate"])
		}
		stored, err := core.quotaManager.QuotaByName("rate-limit", "identity-test")
		require.NoError(t, err)
		cloned := stored.Clone().(*quotas.RateLimitQuota)
		require.Equal(t, group, cloned.GroupBy)
		encoded, err := json.Marshal(cloned)
		require.NoError(t, err)
		var decoded quotas.RateLimitQuota
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, cloned.GroupBy, decoded.GroupBy)
		require.Equal(t, cloned.SecondaryRate, decoded.SecondaryRate)
	}
	for _, config := range []map[string]interface{}{
		{"rate": 100000.0, "group_by": "unknown"},
		{"rate": 100000.0, "group_by": "ip", "secondary_rate": 1.0},
		{"rate": 100000.0, "group_by": "none", "secondary_rate": 1.0},
		{"rate": 100000.0, "group_by": "entity_then_ip", "secondary_rate": -1.0},
	} {
		require.True(t, call(logical.UpdateOperation, config).IsError())
		require.Equal(t, "none", call(logical.ReadOperation, nil).Data["group_by"])
	}
	require.False(t, call(logical.DeleteOperation, nil).IsError())
	require.False(t, call(logical.UpdateOperation, map[string]interface{}{"rate": 100000.0, "group_by": "entity_then_ip"}).IsError())
	require.Equal(t, 100000.0, call(logical.ReadOperation, nil).Data["secondary_rate"])
	require.False(t, call(logical.DeleteOperation, nil).IsError())
}

func TestSecondaryRateValidation(t *testing.T) {
	for _, group := range []string{"entity_then_ip", "entity_then_none"} {
		got, rate, err := quotas.ValidateIdentityRateConfig(group, 100, 0, false)
		require.NoError(t, err)
		require.Equal(t, group, got)
		require.Equal(t, 100.0, rate)
	}
	group, rate, err := quotas.ValidateIdentityRateConfig("", 100, 0, false)
	require.NoError(t, err)
	require.Equal(t, "ip", group)
	require.Zero(t, rate)
}

func TestRotationOrphans(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	for _, path := range []string{"sys/rotation/orphans", "sys/rotation/orphans/"} {
		resp, err := core.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: path, ClientToken: token})
		require.NoError(t, err)
		require.Equal(t, []interface{}{}, resp.Data["orphans"])
	}
	backend := &framework.Backend{Paths: (&SystemBackend{}).rotationOrphanPaths()}
	child := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "child", Path: "child/"})
	_, err := backend.HandleRequest(child, &logical.Request{Operation: logical.ReadOperation, Path: "rotation/orphans"})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
}

func TestAuditFilterOptionsValidation(t *testing.T) {
	for _, options := range []map[string]string{
		{"filter": `operation == "read"`},
		{"filter": `(mount_type == "kv" and namespace != "") or path matches "secret/.+"`},
		{"fallback": "true"},
		{"exclude": `[{"fields":["/response/data"]}]`},
		{"exclude": `[{"condition":"\"/request/mount_type\" == transit","fields":["/request/data","/response/data"]},{"condition":"\"/auth/client_token\" matches \"hmac.+\"","fields":["/auth/entity_id"]}]`},
	} {
		require.NoError(t, validateAuditFilterOptions(&routing.MountEntry{Type: "file", Options: options}, nil))
	}
	for _, options := range []map[string]string{
		{"filter": `unknown == "read"`}, {"filter": `operation ==`},
		{"filter": `(operation == "read"`}, {"filter": `path matches "["`},
		{"fallback": "bad"}, {"exclude": "not-json"}, {"exclude": "null"},
		{"exclude": `[{"fields":[]}]`}, {"exclude": `[{"fields":["data"]}]`},
		{"exclude": `[{"fields":["/bad~2"]}]`},
	} {
		require.Error(t, validateAuditFilterOptions(&routing.MountEntry{Type: "file", Options: options}, nil), "%v", options)
	}
	fallback := &routing.MountEntry{Type: "file", Options: map[string]string{"fallback": "true"}}
	require.Error(t, validateAuditFilterOptions(fallback, []*routing.MountEntry{fallback}))
}

func TestAuditFilterCRUDReadback(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	// The live harness uses the real file backend; this unit test isolates mount
	// storage/list behavior from OS log I/O.
	core.auditBackends["file"] = corehelpers.NoopAuditFactory(nil)
	ctx := namespace.RootContext(context.Background())
	options := map[string]string{"filter": `operation == "read"`, "exclude": `[{"fields":["/response/data"]}]`}
	entry := &routing.MountEntry{Table: auditTableType, Type: "file", Path: "filtered", Options: options}
	require.NoError(t, core.enableAudit(ctx, entry, true))
	b := &SystemBackend{Core: core}
	resp, err := b.handleAuditTable(ctx, nil, nil)
	require.NoError(t, err)
	require.Equal(t, options, resp.Data["filtered/"].(map[string]interface{})["options"])
	// Reload the persisted table, proving options are not just held in memory.
	require.NoError(t, core.loadAudits(ctx, false))
	resp, err = b.handleAuditTable(ctx, nil, nil)
	require.NoError(t, err)
	require.Equal(t, options, resp.Data["filtered/"].(map[string]interface{})["options"])
	fallback := &routing.MountEntry{Table: auditTableType, Type: "file", Path: "fallback", Options: map[string]string{"fallback": "true"}}
	require.NoError(t, core.enableAudit(ctx, fallback, true))
	duplicate := &routing.MountEntry{Table: auditTableType, Type: "file", Path: "duplicate", Options: map[string]string{"fallback": "true"}}
	require.Error(t, core.enableAudit(ctx, duplicate, true))
	_, err = core.disableAudit(ctx, "fallback/", true)
	require.NoError(t, err)
	require.NoError(t, core.enableAudit(ctx, duplicate, true))
	for _, path := range []string{"filtered/", "duplicate/"} {
		_, err := core.disableAudit(ctx, path, true)
		require.NoError(t, err)
	}
	resp, err = b.handleAuditTable(ctx, nil, nil)
	require.NoError(t, err)
	require.Empty(t, resp.Data)
}
