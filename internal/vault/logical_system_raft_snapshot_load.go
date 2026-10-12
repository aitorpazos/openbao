// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/physical/raft"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
)

// The public API specifies no size limit. Bound both the upload and expanded
// archive to 1 GiB, and individual protobuf entries to 32 MiB. The HTTP listener
// may impose a smaller limit. These are OpenBao resource limits, not Vault claims.
const snapshotLoadLimit int64 = 1 << 30

// snapshotLoadService belongs to a system backend, never to the live Raft FSM.
// The retained barrier and its underlying encrypted store are wholly isolated.
// Recovery request routing is deliberately not implemented by these endpoints.
type snapshotLoadService struct {
	mu     sync.Mutex
	core   *Core
	view   barrier.SecurityBarrier
	data   map[string]interface{}
	cancel context.CancelFunc
}

func (s *snapshotLoadService) unload() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.view != nil {
		_ = s.view.Seal()
		s.view = nil
	}
	s.data = nil
	if s.core != nil {
		s.core.setLoadedSnapshot(nil)
	}
}

func (b *SystemBackend) snapshotLoadPaths() []*framework.Path {
	s := new(snapshotLoadService)
	if b.Core != nil {
		// The recover flow (RECOVER method on secret paths) reads the loaded
		// snapshot through the core registry, not through this service's own
		// paths.
		b.Core.setLoadedSnapshot(s)
	}
	op := func() framework.OperationHandler {
		return &framework.PathOperation{Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
			return s.handle(ctx, b, req, d)
		}, ForwardPerformanceStandby: true}
	}
	return []*framework.Path{
		{Pattern: "storage/raft/snapshot-load/?$", Operations: map[logical.Operation]framework.OperationHandler{logical.UpdateOperation: op(), logical.ListOperation: op()}, HelpSynopsis: "Load an isolated Raft snapshot without replacing live data."},
		{Pattern: "storage/raft/snapshot-load/" + framework.GenericNameRegex("snapshot_id"), Fields: map[string]*framework.FieldSchema{"snapshot_id": {Type: framework.TypeString}, "force": {Type: framework.TypeBool, Default: false}}, Operations: map[logical.Operation]framework.OperationHandler{logical.ReadOperation: op(), logical.DeleteOperation: op()}, HelpSynopsis: "Inspect or unload an isolated snapshot."},
		{Pattern: "storage/raft/snapshot-auto/snapshot-load/" + framework.GenericNameRegex("name"), Fields: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "url": {Type: framework.TypeString}}, Operations: map[logical.Operation]framework.OperationHandler{logical.UpdateOperation: &framework.PathOperation{Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
			return s.handleAutoLoad(ctx, b, req, d)
		}, ForwardPerformanceStandby: true}}, HelpSynopsis: "Load a snapshot from an automated snapshots configuration by URL."},
	}
}

func (s *snapshotLoadService) handle(ctx context.Context, b *SystemBackend, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	invalid := func(message string) (*logical.Response, error) {
		return logical.ErrorResponse(message), logical.ErrInvalidRequest
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return invalid("snapshot loading is restricted to the root namespace")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Operation == logical.ListOperation {
		keys := []string{}
		if s.data != nil {
			keys = append(keys, s.data["snapshot_id"].(string))
		}
		return logical.ListResponse(keys), nil
	}
	if req.Operation != logical.UpdateOperation {
		if s.data == nil || s.data["snapshot_id"] != d.Get("snapshot_id") {
			return nil, nil
		}
		if req.Operation == logical.DeleteOperation {
			s.unload()
			return nil, nil
		}
		return &logical.Response{Data: cloneSnapshotLoadData(s.data)}, nil
	}
	if s.data != nil {
		return invalid("only one snapshot can be loaded at a time; unload it first")
	}
	if req.HTTPRequest == nil || req.HTTPRequest.Body == nil {
		return invalid("a binary snapshot body is required")
	}
	defer req.HTTPRequest.Body.Close()
	r, ok := b.Core.underlyingPhysical.(*raft.RaftBackend)
	if !ok {
		return invalid("raft storage is not in use")
	}
	// Staging also prevents an upload from changing between bounded preflight and
	// the existing archive/seal verifier. Temporary files contain ciphertext only.
	upload, err := os.CreateTemp("", "bao-snapshot-load-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(upload.Name())
	defer upload.Close()
	n, err := io.Copy(upload, io.LimitReader(req.HTTPRequest.Body, snapshotLoadLimit+1))
	if err != nil {
		return invalid("could not read snapshot upload")
	}
	if n == 0 {
		return invalid("a binary snapshot body is required")
	}
	if n > snapshotLoadLimit {
		return invalid("snapshot upload exceeds 1 GiB")
	}
	if _, err := upload.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	// Validate gzip magic, trailer and expanded size before allowing the in-tree
	// extractor to write an unbounded state.bin temporary file.
	data, err := s.loadSnapshotFile(ctx, b, r, upload)
	if err != nil {
		if _, ok := err.(snapshotLoadInvalid); ok {
			return invalid(err.Error())
		}
		return nil, err
	}
	response := cloneSnapshotLoadData(data)
	// Validation is synchronous; retain the documented POST acknowledgement while
	// the documented GET-by-ID reports the terminal ready state immediately.
	response["status"] = "loading"
	return &logical.Response{Data: response}, nil
}

// snapshotLoadInvalid marks user-input problems surfaced as 400s. Other errors
// propagate to the 500 path.
type snapshotLoadInvalid struct{ message string }

func (e snapshotLoadInvalid) Error() string { return e.message }

// loadSnapshotFile performs the shared load pipeline over a staged snapshot
// archive: gzip bounds validation, in-tree extraction with the live seal,
// isolated view construction, same-cluster verification, and registration with
// the 72-hour lifetime watcher. The caller must hold s.mu. Returns the terminal
// data map (status ready).
func (s *snapshotLoadService) loadSnapshotFile(ctx context.Context, b *SystemBackend, r *raft.RaftBackend, upload *os.File) (map[string]interface{}, error) {
	z, err := gzip.NewReader(upload)
	if err != nil {
		return nil, snapshotLoadInvalid{"invalid snapshot archive"}
	}
	expanded, readErr := io.Copy(io.Discard, io.LimitReader(z, snapshotLoadLimit+1))
	_ = z.Close()
	if readErr != nil || expanded > snapshotLoadLimit {
		return nil, snapshotLoadInvalid{"invalid or oversized expanded snapshot archive"}
	}
	if _, err := upload.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	state, cleanup, _, err := r.WriteSnapshotToTemp(upload, b.Core.seal.GetAccess())
	if err != nil {
		return nil, snapshotLoadInvalid{"invalid snapshot or snapshot has different unseal keys"}
	}
	defer cleanup()
	view, clusterID, err := b.snapshotLoadView(ctx, state)
	if err != nil {
		return nil, snapshotLoadInvalid{err.Error()}
	}
	keep := false
	defer func() {
		if !keep {
			_ = view.Seal()
		}
	}()
	if clusterID == "" || b.Core.clusterID.Load() != clusterID {
		return nil, snapshotLoadInvalid{"snapshot belongs to a different cluster"}
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	active := b.Core.activeContext.Load()
	if active == nil || active.Err() != nil {
		return nil, snapshotLoadInvalid{"snapshot loading requires an active cluster"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	// Raft SnapshotMeta has no creation timestamp. These are load-record creation
	// and expiry times (72 hours after loading), not a fabricated backup timestamp.
	s.data = map[string]interface{}{"cluster_id": clusterID, "snapshot_id": id, "created_at": now.Format(time.RFC3339Nano), "expires_at": now.Add(72 * time.Hour).Format(time.RFC3339Nano), "status": "ready"}
	s.view = view
	keep = true
	if s.core == nil {
		s.core = b.Core
	}
	b.Core.setLoadedSnapshot(s)
	lifetime, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() {
		timer := time.NewTimer(72 * time.Hour)
		defer timer.Stop()
		select {
		case <-lifetime.Done():
			return
		case <-timer.C:
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.data != nil && s.data["snapshot_id"] == id {
				s.unload()
			}
		case <-active.Done():
			s.mu.Lock()
			if s.data != nil && s.data["snapshot_id"] == id {
				_ = s.view.Seal()
				s.view = nil
				s.data["status"] = "error"
			}
			s.mu.Unlock()
			// Even invalidated metadata expires, unless explicitly unloaded first.
			select {
			case <-lifetime.Done():
				return
			case <-timer.C:
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.data != nil && s.data["snapshot_id"] == id {
				s.unload()
			}
		}
	}()
	return cloneSnapshotLoadData(s.data), nil
}

// handleAutoLoad implements POST /sys/storage/raft/snapshot-auto/snapshot-load/:name,
// documented as loading the snapshot referenced by an automated-snapshot
// configuration without overwriting the cluster. Local-storage configurations
// are prohibited as a load source; snapshots are fetched over HTTP(S).
func (s *snapshotLoadService) handleAutoLoad(ctx context.Context, b *SystemBackend, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	invalid := func(message string) (*logical.Response, error) {
		return logical.ErrorResponse(message), logical.ErrInvalidRequest
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return invalid("snapshot loading is restricted to the root namespace")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		return invalid("only one snapshot can be loaded at a time; unload it first")
	}
	name := d.Get("name").(string)
	snapshotURL := d.Get("url").(string)
	if snapshotURL == "" {
		return invalid("url is required")
	}
	entry, err := req.Storage.Get(ctx, autoSnapshotStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return invalid("unknown automated snapshots configuration")
	}
	var config autoSnapshotConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return invalid("invalid automated snapshots configuration")
	}
	if config.StorageType == "local" {
		return invalid("cannot load a snapshot from a local automated snapshots configuration; upload the snapshot file to sys/storage/raft/snapshot-load instead")
	}
	r, ok := b.Core.underlyingPhysical.(*raft.RaftBackend)
	if !ok {
		return invalid("raft storage is not in use")
	}
	fetcher := &http.Client{Timeout: 5 * time.Minute}
	fetched, err := fetcher.Get(snapshotURL)
	if err != nil {
		return invalid("could not fetch snapshot URL")
	}
	defer fetched.Body.Close()
	if fetched.StatusCode != http.StatusOK {
		return invalid("could not fetch snapshot URL")
	}
	// Staging bounds and isolates the fetched archive the same way as binary
	// uploads; temporary files contain ciphertext only.
	upload, err := os.CreateTemp("", "bao-snapshot-load-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(upload.Name())
	defer upload.Close()
	if _, err := io.Copy(upload, io.LimitReader(fetched.Body, snapshotLoadLimit+1)); err != nil {
		return invalid("could not read fetched snapshot")
	}
	if _, err := upload.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := s.loadSnapshotFile(ctx, b, r, upload)
	if err != nil {
		if _, ok := err.(snapshotLoadInvalid); ok {
			return invalid(err.Error())
		}
		return nil, err
	}
	data["auto_config_name"] = name
	data["url"] = snapshotURL
	s.data = data
	response := cloneSnapshotLoadData(s.data)
	// The documented sample response omits created_at and reports the terminal
	// ready state.
	delete(response, "created_at")
	return &logical.Response{Data: response}, nil
}

func cloneSnapshotLoadData(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(data))
	for k, v := range data {
		result[k] = v
	}
	return result
}

func (b *SystemBackend) snapshotLoadView(ctx context.Context, state io.Reader) (barrier.SecurityBarrier, string, error) {
	store, err := inmem.NewInmem(nil, b.Logger())
	if err != nil {
		return nil, "", err
	}
	reader := raft.NewDelimitedReader(state, 32<<20)
	previous := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		entry := new(pb.StorageEntry)
		err := reader.ReadMsg(entry)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("invalid snapshot storage entries")
		}
		// The in-tree FSM writes sorted, unique physical keys.
		if entry.Key == "" || entry.Key <= previous {
			return nil, "", fmt.Errorf("invalid snapshot storage key order")
		}
		previous = entry.Key
		if err := store.Put(ctx, &physical.Entry{Key: entry.Key, Value: entry.Value}); err != nil {
			return nil, "", err
		}
	}
	// Unseal uses the snapshot's own keyring, not the live keyring. Precheck its
	// framing because the existing barrier assumes trusted local storage.
	entry, err := store.Get(ctx, barrier.KeyringPath)
	if err != nil || entry == nil || len(entry.Value) < 32 {
		return nil, "", fmt.Errorf("snapshot keyring is missing or invalid")
	}
	keyring, err := b.Core.barrier.Keyring()
	if err != nil {
		return nil, "", err
	}
	view := barrier.NewAESGCMBarrier(store, namespace.RootNamespace)
	if err := view.Unseal(ctx, keyring.RootKey()); err != nil {
		return nil, "", fmt.Errorf("snapshot keyring cannot be unsealed with current keys")
	}
	entryLogical, err := view.Get(ctx, coreLocalClusterInfoPath)
	if err != nil || entryLogical == nil {
		_ = view.Seal()
		return nil, "", fmt.Errorf("snapshot cluster information is missing or invalid")
	}
	var cluster Cluster
	if err := json.Unmarshal(entryLogical.Value, &cluster); err != nil {
		_ = view.Seal()
		return nil, "", fmt.Errorf("invalid snapshot cluster information")
	}
	return view, cluster.ID, nil
}
