// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/physical/raft"
)

const autoSnapshotStoragePrefix = "raft/snapshot-auto/config/"

type autoSnapshotConfig struct {
	Interval      int    `json:"interval"`
	Retain        int    `json:"retain"`
	PathPrefix    string `json:"path_prefix"`
	FilePrefix    string `json:"file_prefix"`
	StorageType   string `json:"storage_type"`
	LocalMaxSpace int64  `json:"local_max_space"`
}

// autoSnapshotService is owned by the system backend and its active lifecycle.
// One worker serializes exports and configuration changes, including overlapping
// directories/prefixes. Status is node-local and resets on activation.
type autoSnapshotService struct {
	lifecycle sync.Mutex
	jobMu     sync.Mutex
	jobName   string
	jobCancel context.CancelFunc
	mu        sync.Mutex
	status    map[string]map[string]interface{}
	next      map[string]time.Time
	cancel    context.CancelFunc
	done      chan struct{}
	export    func(io.Writer) error
	active    func() bool
}

func newAutoSnapshotService() *autoSnapshotService {
	return &autoSnapshotService{status: make(map[string]map[string]interface{}), next: make(map[string]time.Time)}
}

func (b *SystemBackend) setupAutoSnapshots() {
	r, ok := b.Core.underlyingPhysical.(*raft.RaftBackend)
	if !ok {
		return
	} // Raft as ha_storage alone cannot export snapshots.
	s := newAutoSnapshotService()
	s.export = func(w io.Writer) error { return r.Snapshot(w, b.Core.seal.GetAccess()) }
	s.active = func() bool {
		return !b.Core.Sealed() && !b.Core.standby.Load() && !b.Core.ReplicationState().HasState(consts.ReplicationDRSecondary)
	}
	b.Paths = append(b.Paths, s.paths()...)
	b.PathsSpecial.Root = append(b.PathsSpecial.Root, "storage/raft/snapshot-auto/config", "storage/raft/snapshot-auto/config/*")
	b.InitializeFunc = func(ctx context.Context, req *logical.InitializationRequest) error {
		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return err
		}
		if ns.ID != namespace.RootNamespaceID {
			return nil
		}
		// The initialization context may be scoped to mount setup. The core active
		// context is explicitly canceled on leadership loss, seal, and shutdown.
		s.start(b.Core.activeContext.Load(), req.Storage, time.Second)
		return nil
	}
	b.Clean = func(context.Context) { s.stop() }
}

func (s *autoSnapshotService) paths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":             {Type: framework.TypeString},
		"interval":         {Type: framework.TypeDurationSecond},
		"retain":           {Type: framework.TypeInt, Default: 1},
		"file_prefix":      {Type: framework.TypeString, Default: "vault-snapshot"},
		"path_prefix":      {Type: framework.TypeString},
		"storage_type":     {Type: framework.TypeString},
		"local_max_space":  {Type: framework.TypeInt64},
		"autoload_enabled": {Type: framework.TypeBool},
	}
	op := func() *framework.PathOperation {
		return &framework.PathOperation{Callback: s.handle, ForwardPerformanceStandby: true}
	}
	return []*framework.Path{
		{Pattern: "storage/raft/snapshot-auto/config/?$", Operations: map[logical.Operation]framework.OperationHandler{logical.ListOperation: op()}, HelpSynopsis: "List automatic snapshot configurations."},
		{Pattern: "storage/raft/snapshot-auto/config/" + framework.GenericNameRegex("name"), Fields: fields, Operations: map[logical.Operation]framework.OperationHandler{logical.UpdateOperation: op(), logical.ReadOperation: op(), logical.DeleteOperation: op()}, HelpSynopsis: "Configure local automatic Raft snapshots."},
		{Pattern: "storage/raft/snapshot-auto/status/" + framework.GenericNameRegex("name"), Fields: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}}, Operations: map[logical.Operation]framework.OperationHandler{logical.ReadOperation: op()}, HelpSynopsis: "Read automatic snapshot status."},
	}
}

func readAutoSnapshotConfig(ctx context.Context, storage logical.Storage, name string) (*autoSnapshotConfig, error) {
	entry, err := storage.Get(ctx, autoSnapshotStoragePrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}
	var c autoSnapshotConfig
	if err := entry.DecodeJSON(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *autoSnapshotService) handle(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrorResponse("automatic snapshots are restricted to the root namespace"), logical.ErrInvalidRequest
	}
	if req.Operation == logical.UpdateOperation || req.Operation == logical.DeleteOperation {
		s.jobMu.Lock()
		if s.jobName == d.Get("name").(string) && s.jobCancel != nil {
			s.jobCancel()
		}
		s.jobMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Operation == logical.ListOperation {
		keys, err := req.Storage.List(ctx, autoSnapshotStoragePrefix)
		if err != nil {
			return nil, err
		}
		sort.Strings(keys)
		return logical.ListResponse(keys), nil
	}
	name := d.Get("name").(string)
	if req.Operation == logical.DeleteOperation {
		if err := req.Storage.Delete(ctx, autoSnapshotStoragePrefix+name); err != nil {
			return nil, err
		}
		delete(s.next, name)
		delete(s.status, name)
		return nil, nil
	}
	if req.Operation == logical.ReadOperation {
		c, err := readAutoSnapshotConfig(ctx, req.Storage, name)
		if err != nil || c == nil {
			return nil, err
		}
		if strings.HasPrefix(req.Path, "storage/raft/snapshot-auto/status/") {
			data := make(map[string]interface{})
			for k, v := range s.status[name] {
				data[k] = v
			}
			return &logical.Response{Data: data}, nil
		}
		return &logical.Response{Data: map[string]interface{}{"interval": c.Interval, "retain": c.Retain, "path_prefix": c.PathPrefix, "file_prefix": c.FilePrefix, "storage_type": c.StorageType, "local_max_space": c.LocalMaxSpace}}, nil
	}
	for _, field := range []string{"interval", "path_prefix", "storage_type", "local_max_space"} {
		if _, ok := d.Raw[field]; !ok {
			return logical.ErrorResponse("%s is required", field), logical.ErrInvalidRequest
		}
	}
	c := autoSnapshotConfig{Interval: d.Get("interval").(int), Retain: d.Get("retain").(int), PathPrefix: d.Get("path_prefix").(string), FilePrefix: d.Get("file_prefix").(string), StorageType: d.Get("storage_type").(string), LocalMaxSpace: d.Get("local_max_space").(int64)}
	if c.StorageType != "local" {
		return logical.ErrorResponse("only local automatic snapshot storage is supported"), logical.ErrInvalidRequest
	}
	if d.Get("autoload_enabled").(bool) {
		return logical.ErrorResponse("autoload_enabled is not supported for local storage"), logical.ErrInvalidRequest
	}
	if c.Interval <= 0 || int64(c.Interval) > int64((1<<63-1)/time.Second) || c.Retain <= 0 || c.LocalMaxSpace <= 0 || strings.TrimSpace(c.PathPrefix) == "" {
		return logical.ErrorResponse("interval, retain, local_max_space and path_prefix must be positive/nonempty"), logical.ErrInvalidRequest
	}
	if c.FilePrefix == "" || c.FilePrefix == "." || c.FilePrefix == ".." || strings.ContainsAny(c.FilePrefix, "/\\\x00") {
		return logical.ErrorResponse("file_prefix must be a nonempty filename prefix"), logical.ErrInvalidRequest
	}
	entry, err := logical.StorageEntryJSON(autoSnapshotStoragePrefix+name, &c)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	s.next[name] = time.Now().Add(time.Duration(c.Interval) * time.Second)
	s.status[name] = map[string]interface{}{"next_snapshot_start": s.next[name].UTC().Format(time.RFC3339Nano)}
	return nil, nil
}

func (s *autoSnapshotService) start(ctx context.Context, storage logical.Storage, tick time.Duration) {
	s.stop()
	s.lifecycle.Lock()
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	done := s.done
	s.lifecycle.Unlock()
	go func() {
		defer close(done)
		timer := time.NewTicker(tick)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-timer.C:
				s.run(ctx, storage, now)
			}
		}
	}()
}

func (s *autoSnapshotService) stop() {
	s.lifecycle.Lock()
	cancel, done := s.cancel, s.done
	s.lifecycle.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (s *autoSnapshotService) run(ctx context.Context, storage logical.Storage, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !s.active() {
		return
	}
	names, err := storage.List(ctx, autoSnapshotStoragePrefix)
	if err != nil {
		return
	}
	for _, name := range names {
		c, err := readAutoSnapshotConfig(ctx, storage, name)
		if err != nil || c == nil {
			continue
		}
		if _, ok := s.next[name]; !ok {
			s.next[name] = now.Add(time.Duration(c.Interval) * time.Second)
		}
		if now.Before(s.next[name]) {
			continue
		}
		if ctx.Err() != nil || !s.active() {
			return
		}
		start := time.Now()
		jobCtx, cancel := context.WithCancel(ctx)
		s.jobMu.Lock()
		s.jobName, s.jobCancel = name, cancel
		s.jobMu.Unlock()
		path, err := writeLocalAutoSnapshot(jobCtx, c, s.export)
		cancel()
		s.jobMu.Lock()
		s.jobName, s.jobCancel = "", nil
		s.jobMu.Unlock()
		end := time.Now()
		s.next[name] = end.Add(time.Duration(c.Interval) * time.Second)
		message := ""
		if err != nil {
			message = err.Error()
		}
		s.status[name] = map[string]interface{}{"last_snapshot_start": start.UTC().Format(time.RFC3339Nano), "last_snapshot_end": end.UTC().Format(time.RFC3339Nano), "last_snapshot_error": message, "last_snapshot_url": path, "snapshot_start": "", "snapshot_url": "", "next_snapshot_start": s.next[name].UTC().Format(time.RFC3339Nano)}
	}
}

// Snapshot naming is an implementation choice: the supplied contract specifies
// file_prefix but no complete filename format. Restrict eviction to regular
// prefix-*.snap files, never symlinks, subdirectories, or arbitrary prefix matches.
func writeLocalAutoSnapshot(ctx context.Context, c *autoSnapshotConfig, export func(io.Writer) error) (string, error) {
	dir, err := os.OpenRoot(c.PathPrefix)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	entries, err := os.ReadDir(c.PathPrefix)
	if err != nil {
		return "", err
	}
	type snapshot struct {
		name string
		size int64
		mod  time.Time
	}
	var old []snapshot
	var used int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), c.FilePrefix+"-") || !strings.HasSuffix(entry.Name(), ".snap") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > (1<<63-1)-used {
			return "", fmt.Errorf("snapshot directory size exceeds accounting limit")
		}
		used += info.Size()
		old = append(old, snapshot{entry.Name(), info.Size(), info.ModTime()})
	}
	sort.Slice(old, func(i, j int) bool {
		if old[i].mod.Equal(old[j].mod) {
			return old[i].name < old[j].name
		}
		return old[i].mod.Before(old[j].mod)
	})
	// Make room while writing rather than staging an unbounded extra snapshot.
	// A snapshot larger than the entire allowance fails and is never published.
	name := fmt.Sprintf("%s-%s.snap", c.FilePrefix, time.Now().UTC().Format("20060102T150405.000000000Z"))
	tmp := name + ".partial"
	file, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer dir.Remove(tmp)
	defer file.Close()
	w := &autoSnapshotWriter{ctx: ctx, w: file, limit: c.LocalMaxSpace, makeRoom: func(n int64) error {
		for used > c.LocalMaxSpace-n && len(old) > 0 {
			if err := dir.Remove(old[0].name); err != nil {
				return err
			}
			used -= old[0].size
			old = old[1:]
		}
		return nil
	}}
	if err := export(w); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := dir.Rename(tmp, name); err != nil {
		return "", err
	}
	for len(old) >= c.Retain {
		if err := dir.Remove(old[0].name); err != nil {
			return "", err
		}
		old = old[1:]
	}
	return (&url.URL{Scheme: "file", Path: filepath.Join(c.PathPrefix, name)}).String(), nil
}

type autoSnapshotWriter struct {
	ctx            context.Context
	w              io.Writer
	limit, written int64
	makeRoom       func(int64) error
}

func (w *autoSnapshotWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.limit-w.written {
		return 0, fmt.Errorf("snapshot exceeds local_max_space")
	}
	if err := w.makeRoom(w.written + int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	w.written += int64(n)
	return n, err
}
