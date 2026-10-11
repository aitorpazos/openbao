// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

// Validation-path tests for the snapshot-load service that do not require a
// started raft cluster. Snapshot-dependent flows (isolated recovery view,
// cross-cluster rejection, damaged archives, sealed success path) run end to
// end against a raft test cluster in
// internal/vault/external_tests/raft/snapshot_load_test.go: a sealed snapshot
// needs a fully bootstrapped, leader-elected raft backend, which the
// in-package fixtures do not provide.
func TestSnapshotLoadValidation(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	b := &SystemBackend{Core: c, Backend: &framework.Backend{}}
	b.Paths = b.raftStoragePaths()
	s := new(snapshotLoadService)
	defer func() { s.mu.Lock(); defer s.mu.Unlock(); s.unload() }()
	call := func(data []byte) (*logical.Response, error) {
		return s.handle(ctx, b, &logical.Request{Operation: logical.UpdateOperation, HTTPRequest: &http.Request{Body: io.NopCloser(bytes.NewReader(data))}}, nil)
	}

	// Empty body on non-raft storage hits the storage check first.
	resp, err := call(nil)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "raft storage is not in use")

	// Non-raft storage backend is rejected before parsing the body.
	resp, err = call([]byte("not a snapshot"))
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "raft storage is not in use")

	// List with nothing loaded yields no keys.
	resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.ListOperation, Path: "storage/raft/snapshot-load"})
	require.NoError(t, err)
	require.Empty(t, resp.Data["keys"])

	// Non-root namespaces are rejected up front.
	nsCtx := namespace.ContextWithNamespace(ctx, &namespace.Namespace{ID: "ns1", Path: "ns1/"})
	_, err = s.handle(nsCtx, b, &logical.Request{Operation: logical.UpdateOperation, HTTPRequest: &http.Request{Body: io.NopCloser(bytes.NewReader([]byte("x")))}}, nil)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
}

// Documented negative surface of POST /sys/storage/raft/snapshot-auto/snapshot-load/:name:
// unknown configuration and the local-storage prohibition.
func TestSnapshotLoadAutoLoad(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	b := &SystemBackend{Core: c, Backend: &framework.Backend{}}
	s := new(snapshotLoadService)
	defer func() { s.mu.Lock(); defer s.mu.Unlock(); s.unload() }()

	call := func(name string, extra map[string]any) (*logical.Response, error) {
		raw := map[string]any{"name": name}
		for k, v := range extra {
			raw[k] = v
		}
		fields := &framework.FieldData{Raw: raw, Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "url": {Type: framework.TypeString}}}
		return s.handleAutoLoad(ctx, b, &logical.Request{Operation: logical.UpdateOperation, Storage: c.barrier}, fields)
	}

	resp, err := call("compat-nonexistent", map[string]any{"url": "https://example.invalid/raft.snap"})
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.Contains(t, resp.Error().Error(), "unknown automated snapshots configuration")

	// A local-storage configuration is a prohibited load source.
	entry, err := logical.StorageEntryJSON(autoSnapshotStoragePrefix+"compat-snap-load", &autoSnapshotConfig{Interval: 86400, StorageType: "local", PathPrefix: "/tmp/compat-snap-load/", LocalMaxSpace: 10000000})
	require.NoError(t, err)
	require.NoError(t, c.barrier.Put(ctx, entry))
	resp, err = call("compat-snap-load", map[string]any{"url": "file:///tmp/compat-nonexistent.snap"})
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.Contains(t, resp.Error().Error(), "local automated snapshots configuration")

	// Missing url is rejected.
	resp, err = call("compat-snap-load", nil)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.Contains(t, resp.Error().Error(), "url is required")
}
