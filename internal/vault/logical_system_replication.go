// Copyright (c) 2026 OpenBao a.s. / OpenBao community
// SPDX-License-Identifier: MPL-2.0
//
// Clean-room implementation of the documented Vault Enterprise replication
// API surface (developer.hashicorp.com/vault/api-docs/system/replication*,
// v2.x latest). Phase 1 implements the documented configuration/status
// surface as a persistent, in-cluster state machine; WAL streaming between
// clusters is not part of this phase. Deviations are documented in
// compat/specs/replication/notes.md.

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	replicationModePerformance = "performance"
	replicationModeDR          = "dr"
)

func (b *SystemBackend) replicationModePath(mode string) string {
	switch mode {
	case replicationModePerformance:
		return replicationPerformanceConfigPath
	case replicationModeDR:
		return replicationDRConfigPath
	}
	return ""
}

func (b *SystemBackend) replicationWALLabel(mode string) string {
	switch mode {
	case replicationModePerformance:
		return "last_performance_wal"
	case replicationModeDR:
		return "last_dr_wal"
	}
	return "last_wal"
}

// replicationPaths registers the documented /sys/replication surface.
func (b *SystemBackend) replicationPaths() []*framework.Path {
	perfPrefix := "replication/performance"
	drPrefix := "replication/dr"

	primaryLifecycle := func(prefix, mode string) []*framework.Path {
		p := prefix + "/primary/"
		return []*framework.Path{
			{
				Pattern: p + "enable$",
				Fields: map[string]*framework.FieldSchema{
					"primary_cluster_addr": {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationPrimaryEnable(ctx, mode, d)
						},
					},
				},
			},
			{
				Pattern: p + "demote$",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationPrimaryDemote(ctx, mode)
						},
					},
				},
			},
			{
				Pattern: p + "disable$",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationPrimaryDisable(ctx, mode)
						},
					},
				},
			},
			{
				Pattern: p + "secondary-token$",
				Fields: map[string]*framework.FieldSchema{
					"id":                  {Type: framework.TypeString},
					"ttl":                 {Type: framework.TypeString},
					"secondary_public_key": {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationSecondaryToken(ctx, mode, d)
						},
					},
				},
			},
			{
				Pattern: p + "revoke-secondary$",
				Fields: map[string]*framework.FieldSchema{
					"id": {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationRevokeSecondary(ctx, mode, d)
						},
					},
				},
			},
		}
	}

	secondaryLifecycle := func(prefix, mode string) []*framework.Path {
		p := prefix + "/secondary/"
		paths := []*framework.Path{
			{
				Pattern: p + "enable$",
				Fields: map[string]*framework.FieldSchema{
					"token":            {Type: framework.TypeString},
					"primary_api_addr": {Type: framework.TypeString},
					"ca_file":          {Type: framework.TypeString},
					"ca_path":          {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationSecondaryEnable(ctx, mode, d)
						},
					},
				},
			},
			{
				Pattern: p + "disable$",
				Fields: map[string]*framework.FieldSchema{
					"dr_operation_token": {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationSecondaryDisable(ctx, mode, d)
						},
					},
				},
			},
			{
				Pattern: p + "promote$",
				Fields: map[string]*framework.FieldSchema{
					"dr_operation_token":   {Type: framework.TypeString},
					"primary_cluster_addr": {Type: framework.TypeString},
					"force":                {Type: framework.TypeBool},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationSecondaryPromote(ctx, mode, d)
						},
					},
				},
			},
			{
				Pattern: p + "update-primary$",
				Fields: map[string]*framework.FieldSchema{
					"dr_operation_token":   {Type: framework.TypeString},
					"token":                {Type: framework.TypeString},
					"primary_api_addr":     {Type: framework.TypeString},
					"ca_file":              {Type: framework.TypeString},
					"ca_path":              {Type: framework.TypeString},
					"update_primary_addrs": {Type: framework.TypeCommaStringSlice},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationUpdatePrimary(ctx, mode, d)
						},
					},
				},
			},
			{
				Pattern: p + "generate-public-key$",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationGeneratePublicKey(ctx, mode)
						},
					},
				},
			},
			{
				Pattern: p + "dynamic-filter/(?P<id>.+)$",
				Fields: map[string]*framework.FieldSchema{
					"id": {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
							return b.handleReplicationDynamicFilter(ctx, mode, d)
						},
					},
				},
			},
		}
		return paths
	}

	paths := []*framework.Path{
		{
			Pattern: "replication/status$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleReplicationStatus,
				},
			},
		},
		{
			Pattern: "replication/performance/status$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleReplicationStatus,
				},
			},
		},
		{
			Pattern: "replication/dr/status$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleReplicationStatus,
				},
			},
		},
		{
			Pattern: "replication/recover$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleReplicationRecover,
				},
			},
		},
		{
			Pattern: "replication/reindex$",
			Fields: map[string]*framework.FieldSchema{
				"diff":       {Type: framework.TypeBool},
				"force":      {Type: framework.TypeBool},
				"skip_flush": {Type: framework.TypeBool},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleReplicationReindex,
				},
			},
		},
		{
			Pattern: "replication/merkle-check$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleReplicationMerkleCheck,
				},
			},
		},
	}

	paths = append(paths, primaryLifecycle(perfPrefix, replicationModePerformance)...)
	paths = append(paths, primaryLifecycle(drPrefix, replicationModeDR)...)
	paths = append(paths, secondaryLifecycle(perfPrefix, replicationModePerformance)...)
	paths = append(paths, secondaryLifecycle(drPrefix, replicationModeDR)...)
	paths = append(paths, b.drOperationTokenPaths()...)

	// paths-filter is performance-only per the documented surface.
	paths = append(paths, &framework.Path{
		Pattern: perfPrefix + "/primary/paths-filter/(?P<id>.+)$",
		Fields: map[string]*framework.FieldSchema{
			"id":    {Type: framework.TypeString},
			"mode":  {Type: framework.TypeString},
			"paths": {Type: framework.TypeCommaStringSlice},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleReplicationReadPathsFilter,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleReplicationWritePathsFilter,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleReplicationDeletePathsFilter,
			},
		},
	})

	return paths
}

// handleReplicationStatus implements the documented (unauthenticated)
// status endpoints. /sys/replication/status reports both streams;
// the typed endpoints report their single stream.
func (b *SystemBackend) handleReplicationStatus(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	path := req.Path
	trimmed := path
	if i := len("sys/"); strings.HasPrefix(path, "sys/") {
		trimmed = path[i:]
	}
	trimmed = strings.TrimPrefix(trimmed, "v1/")

	// route the request path (strip prefix) to the right stanza selection
	var wantPerf, wantDR, combined bool
	switch {
	case strings.HasSuffix(trimmed, "replication/status"):
		combined = true
	case strings.HasSuffix(trimmed, "replication/performance/status"):
		wantPerf = true
	case strings.HasSuffix(trimmed, "replication/dr/status"):
		wantDR = true
	default:
		// The router matches the pattern with the sys/ prefix stripped;
		// fall back on the raw path.
		switch {
		case strings.HasSuffix(path, "replication/status"):
			combined = true
		case strings.HasSuffix(path, "replication/performance/status"):
			wantPerf = true
		case strings.HasSuffix(path, "replication/dr/status"):
			wantDR = true
		}
	}

	c := b.Core
	perf, err := c.loadReplicationModeState(ctx, replicationPerformanceConfigPath)
	if err != nil {
		return nil, err
	}
	dr, err := c.loadReplicationModeState(ctx, replicationDRConfigPath)
	if err != nil {
		return nil, err
	}

	data := map[string]any{}
	if wantPerf || combined {
		st, err := c.replicationStatus(ctx, perf, b.replicationWALLabel(replicationModePerformance))
		if err != nil {
			return nil, err
		}
		if combined {
			if st != nil && len(st) > 0 {
				data["performance"] = st
			}
		} else {
			data = st
		}
	}
	if wantDR || combined {
		st, err := c.replicationStatus(ctx, dr, b.replicationWALLabel(replicationModeDR))
		if err != nil {
			return nil, err
		}
		if combined {
			if st != nil && len(st) > 0 {
				data["dr"] = st
			}
		} else {
			data = st
		}
	}

	return &logical.Response{Data: data}, nil
}

func (b *SystemBackend) handleReplicationPrimaryEnable(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st != nil && st.Mode == "secondary" {
		return logical.ErrorResponse("cluster is a secondary; it must be promoted before enabling primary replication"), nil
	}

	clusterID := c.ClusterID()
	if clusterID == "" {
		return logical.ErrorResponse("cluster ID is not present; cannot enable replication"), nil
	}

	primaryClusterAddr := d.Get("primary_cluster_addr").(string)
	if primaryClusterAddr == "" {
		primaryClusterAddr = c.ClusterAddr()
	}

	st = &replicationModeState{
		Mode:               "primary",
		State:              "running",
		ClusterID:          clusterID,
		PrimaryClusterAddr: primaryClusterAddr,
		KnownSecondaries:   map[string]string{},
		LastStart:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationPrimaryDemote(ctx context.Context, mode string) (*logical.Response, error) {
	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "primary" {
		return logical.ErrorResponse("replication is not enabled in primary mode"), nil
	}

	// The documented demote semantics: keep the cluster ID so the cluster
	// can be reconnected to the same replication set without wiping local
	// storage; do not attempt to connect to a primary.
	st.Mode = "secondary"
	st.State = "running"
	st.PrimaryClusterAddr = ""
	st.KnownSecondaries = map[string]string{}
	st.SecondaryID = ""
	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationPrimaryDisable(ctx context.Context, mode string) (*logical.Response, error) {
	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, nil
	}

	if err := c.saveReplicationModeState(ctx, path, nil); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationSecondaryToken(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	pubKey := d.Get("secondary_public_key").(string)
	ttl := 30 * time.Minute
	if raw := d.Get("ttl").(string); raw != "" {
		dur, err := parseDuration(raw)
		if err != nil {
			return logical.ErrorResponse("invalid ttl: %v", err), nil
		}
		ttl = dur
	}

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "primary" {
		return logical.ErrorResponse("replication is not enabled in primary mode"), nil
	}
	if id == "" {
		return logical.ErrorResponse("id is required"), nil
	}
	if _, ok := st.KnownSecondaries[id]; ok {
		return logical.ErrorResponse("secondary id already exists: %s", id), nil
	}

	st.KnownSecondaries[id] = pubKey
	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]any{
			"cluster_id":   st.ClusterID,
			"cluster_addr": st.PrimaryClusterAddr,
			"id":           id,
			"mode":         mode,
		},
	}
	resp.WrapInfo = &wrapping.ResponseWrapInfo{
		TTL:    ttl,
		Format: "jwt",
	}
	return resp, nil
}

func (b *SystemBackend) handleReplicationRevokeSecondary(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id is required"), nil
	}

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "primary" {
		return logical.ErrorResponse("replication is not enabled in primary mode"), nil
	}
	if _, ok := st.KnownSecondaries[id]; !ok {
		return logical.ErrorResponse("unknown secondary id: %s", id), nil
	}
	delete(st.KnownSecondaries, id)
	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationSecondaryEnable(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("token").(string)
	primaryAPIAddr := d.Get("primary_api_addr").(string)

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st != nil && st.Mode == "primary" {
		return logical.ErrorResponse("cluster is already a primary; demote or disable first"), nil
	}

	// The wrapping write happens under the state lock; the unwrap performs
	// storage IO on the cubbyhole. This is acceptable for an activation
	// flow which is a rare, operator-driven event.
	if b.Core.tokenStore == nil {
		return nil, errors.New("token store not initialized")
	}

	// Release the state lock for the unwrap network of IO, then re-acquire
	// for the state write.
	c.replicationStateMut.Unlock()
	act, actErr := c.activateSecondary(ctx, token, primaryAPIAddr)
	c.replicationStateMut.Lock()
	if actErr != nil {
		return nil, actErr
	}
	if act.Mode != mode {
		return logical.ErrorResponse("activation token is for the wrong replication mode (%s)", act.Mode), nil
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	primaryAddr := act.ClusterAddr
	st = &replicationModeState{
		Mode:                     "secondary",
		State:                    "running",
		ClusterID:                act.ClusterID,
		PrimaryClusterAddr:       primaryAddr,
		SecondaryID:              act.ID,
		KnownSecondaries:         map[string]string{},
		KnownPrimaryClusterAddrs: []string{primaryAddr},
		LastStart:                now,
	}
	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationSecondaryDisable(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)

	// The documented DR surface requires a DR operation token for
	// secondary disable/promote; performance secondary disable does not.
	if mode == replicationModeDR {
		if d.Get("dr_operation_token").(string) == "" {
			return logical.ErrorResponse("dr_operation_token is required"), nil
		}
	}

	if err := c.saveReplicationModeState(ctx, path, nil); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationSecondaryPromote(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "secondary" {
		return logical.ErrorResponse("replication is not enabled in secondary mode"), nil
	}

	if mode == replicationModeDR {
		if d.Get("dr_operation_token").(string) == "" {
			return logical.ErrorResponse("dr_operation_token is required"), nil
		}
	}

	primaryClusterAddr := d.Get("primary_cluster_addr").(string)
	if primaryClusterAddr == "" {
		primaryClusterAddr = c.ClusterAddr()
	}

	st.Mode = "primary"
	st.State = "running"
	st.PrimaryClusterAddr = primaryClusterAddr
	st.KnownSecondaries = map[string]string{}
	st.SecondaryID = ""
	st.KnownPrimaryClusterAddrs = nil
	st.LastStart = time.Now().UTC().Format(time.RFC3339Nano)
	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationUpdatePrimary(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("token").(string)
	addrs := d.Get("update_primary_addrs").([]string)
	primaryAPIAddr := d.Get("primary_api_addr").(string)

	if token != "" && len(addrs) > 0 {
		return logical.ErrorResponse("token and update_primary_addrs are mutually exclusive"), nil
	}

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	path := b.replicationModePath(mode)
	st, err := c.loadReplicationModeState(ctx, path)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "secondary" {
		return logical.ErrorResponse("replication is not enabled in secondary mode"), nil
	}

	if mode == replicationModeDR && token == "" && len(addrs) == 0 {
		return logical.ErrorResponse("either token or update_primary_addrs must be provided"), nil
	}

	if token != "" {
		// release the state lock for the unwrap IO
		c.replicationStateMut.Unlock()
		var act *replicationActivationData
		var actErr error
		if mode == replicationModeDR {
			if d.Get("dr_operation_token").(string) == "" {
				actErr = errors.New("dr_operation_token is required")
			} else {
				act, actErr = c.activateSecondary(ctx, token, primaryAPIAddr)
			}
		} else {
			act, actErr = c.activateSecondary(ctx, token, primaryAPIAddr)
		}
		c.replicationStateMut.Lock()
		if actErr != nil {
			return nil, actErr
		}
		st.ClusterID = act.ClusterID
		st.PrimaryClusterAddr = act.ClusterAddr
		st.KnownPrimaryClusterAddrs = []string{act.ClusterAddr}
	} else if len(addrs) > 0 {
		st.KnownPrimaryClusterAddrs = addrs
		st.PrimaryClusterAddr = addrs[0]
	} else {
		// blank token: stay a secondary but clear knowledge of any past
		// primary (documented semantics).
		st.PrimaryClusterAddr = ""
		st.KnownPrimaryClusterAddrs = nil
	}

	if err := c.saveReplicationModeState(ctx, path, st); err != nil {
		return nil, err
	}
	if err := c.refreshReplicationStateLocked(mode); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationGeneratePublicKey(ctx context.Context, mode string) (*logical.Response, error) {
	path := b.replicationModePath(mode)
	pub, err := b.Core.replicationSecondaryKeyPair(ctx, path)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"public_key": pub}}, nil
}

func (b *SystemBackend) handleReplicationWritePathsFilter(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	mode := d.Get("mode").(string)
	if id == "" {
		return logical.ErrorResponse("id is required"), nil
	}
	if mode != "allow" && mode != "deny" {
		return logical.ErrorResponse("mode must be one of allow or deny"), nil
	}
	paths := d.Get("paths").([]string)

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	st, err := c.loadReplicationModeState(ctx, replicationPerformanceConfigPath)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "primary" {
		return logical.ErrorResponse("performance replication is not enabled in primary mode"), nil
	}
	if st.PathsFilters == nil {
		st.PathsFilters = map[string]replicationPathsFilter{}
	}
	st.PathsFilters[id] = replicationPathsFilter{Mode: mode, Paths: paths}
	if err := c.saveReplicationModeState(ctx, replicationPerformanceConfigPath, st); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationReadPathsFilter(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id is required"), nil
	}

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	st, err := c.loadReplicationModeState(ctx, replicationPerformanceConfigPath)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "primary" {
		return logical.ErrorResponse("performance replication is not enabled in primary mode"), nil
	}

	f, ok := st.PathsFilters[id]
	if !ok {
		return nil, nil
	}
	return &logical.Response{Data: map[string]any{"mode": f.Mode, "paths": f.Paths}}, nil
}

func (b *SystemBackend) handleReplicationDeletePathsFilter(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id is required"), nil
	}

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	st, err := c.loadReplicationModeState(ctx, replicationPerformanceConfigPath)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Mode != "primary" {
		return logical.ErrorResponse("performance replication is not enabled in primary mode"), nil
	}

	delete(st.PathsFilters, id)
	if err := c.saveReplicationModeState(ctx, replicationPerformanceConfigPath, st); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *SystemBackend) handleReplicationDynamicFilter(ctx context.Context, mode string, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id is required"), nil
	}

	c := b.Core
	c.replicationStateMut.Lock()
	defer c.replicationStateMut.Unlock()

	st, err := c.loadReplicationModeState(ctx, b.replicationModePath(mode))
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, nil
	}

	// Phase 1: no dynamic filter computation exists (that is part of WAL
	// streaming / filtered replication); report the empty document.
	return &logical.Response{Data: map[string]any{
		"dynamic_filtered_mounts":     []string{},
		"dynamic_filtered_namespaces": []string{},
	}}, nil
}

func (b *SystemBackend) handleReplicationRecover(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c := b.Core
	perf, err := c.loadReplicationModeState(ctx, replicationPerformanceConfigPath)
	if err != nil {
		return nil, err
	}
	dr, err := c.loadReplicationModeState(ctx, replicationDRConfigPath)
	if err != nil {
		return nil, err
	}

	warnings := []string{}
	if perf == nil && dr == nil {
		warnings = append(warnings, "replication is not enabled")
	} else {
		// Phase 1: there is no streaming machinery to recover, so report
		// that no adverse state was found.
		warnings = append(warnings, "no replication adverse state detected")
	}
	return &logical.Response{Data: map[string]any{"warnings": warnings}}, nil
}

func (b *SystemBackend) handleReplicationReindex(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c := b.Core
	// Recompute the merkle root now (that is the meaningful part of a
	// reindex in this implementation) and stamp the epoch on both streams
	// where configured.
	root, err := c.merkleRoot(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	c.replicationStateMut.Lock()
	for _, path := range []string{replicationPerformanceConfigPath, replicationDRConfigPath} {
		st, err := c.loadReplicationModeState(ctx, path)
		if err != nil {
			c.replicationStateMut.Unlock()
			return nil, err
		}
		if st == nil {
			continue
		}
		st.LastReindexEpoch = now
		if err := c.saveReplicationModeState(ctx, path, st); err != nil {
			c.replicationStateMut.Unlock()
			return nil, err
		}
	}
	c.replicationStateMut.Unlock()

	warnings := []string{}
	if d.Get("force").(bool) {
		warnings = append(warnings, fmt.Sprintf("reindex complete (%s)", root[:16]))
	}
	return &logical.Response{Data: map[string]any{"warnings": warnings}}, nil
}

func (b *SystemBackend) handleReplicationMerkleCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c := b.Core
	root, err := c.merkleRoot(ctx)
	if err != nil {
		return nil, err
	}

	// Phase 1: the storage-walk root is treated as the authoritative hash;
	// corruption detection against the Enterprise indexed tree is not
	// implemented (documented deviation).
	return &logical.Response{Data: map[string]any{
		"merkle_corruption_report": map[string]any{
			"corrupted_root": false,
			"corrupted_tree_map": map[string]any{
				"1": map[string]any{
					"corrupted_index_tuples_map": nil,
					"corrupted_subtree_root":     false,
					"root_hash":                  root[:24] + "=",
					"tree_type":                  "local",
				},
			},
		},
		"last_corruption_check_epoch": time.Now().Format(time.RFC3339Nano),
	}}, nil
}
// refreshReplicationStateLocked updates the consts replication state. The
// caller typically holds c.stateLock; the atomic store makes concurrent
// updates benign regardless.
func (c *Core) refreshReplicationStateLocked(_ string) error {
	return c.refreshReplicationStateConsts(context.Background(), !c.standby.Load())
}

// parseDuration parses a duration string accepting both Go duration syntax
// and bare seconds (e.g. "300").
func parseDuration(raw string) (time.Duration, error) {
	return parseutil.ParseDurationSecond(raw)
}
