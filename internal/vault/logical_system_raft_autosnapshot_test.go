// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/physical/raft"
	"github.com/stretchr/testify/require"
)

func TestAutoSnapshotConfig(t *testing.T) {
	s := newAutoSnapshotService()
	b := &framework.Backend{Paths: s.paths()}
	storage := &logical.InmemStorage{}
	ctx := namespace.RootContext(context.Background())
	call := func(op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
		return b.HandleRequest(ctx, &logical.Request{Operation: op, Path: "storage/raft/snapshot-auto/" + path, Data: data, Storage: storage})
	}
	valid := func() map[string]interface{} {
		return map[string]interface{}{"interval": "24h", "storage_type": "local", "path_prefix": t.TempDir(), "local_max_space": 10000000}
	}
	for _, field := range []string{"interval", "storage_type", "path_prefix", "local_max_space"} {
		t.Run("missing-"+field, func(t *testing.T) {
			data := valid()
			delete(data, field)
			resp, err := call(logical.UpdateOperation, "config/test", data)
			require.True(t, err != nil || resp.IsError())
		})
	}
	for _, test := range []struct {
		field string
		value interface{}
	}{
		{"interval", "not-a-duration"}, {"interval", map[string]interface{}{"invalid": true}}, {"interval", 0}, {"interval", -1}, {"retain", 0}, {"local_max_space", -1}, {"autoload_enabled", true}, {"storage_type", "aws-s3"}, {"file_prefix", "../escape"}, {"path_prefix", ""},
	} {
		data := valid()
		data[test.field] = test.value
		resp, err := call(logical.UpdateOperation, "config/test", data)
		require.True(t, err != nil || resp.IsError(), "invalid %s=%v", test.field, test.value)
	}
	resp, err := call(logical.ReadOperation, "config/test", nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	data := valid()
	resp, err = call(logical.UpdateOperation, "config/test", data)
	require.NoError(t, err)
	require.Nil(t, resp)
	resp, err = call(logical.ReadOperation, "config/test", nil)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{"interval": 86400, "retain": 1, "file_prefix": "vault-snapshot", "path_prefix": data["path_prefix"], "storage_type": "local", "local_max_space": int64(10000000)}, resp.Data)
	resp, err = call(logical.ListOperation, "config", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"test"}, resp.Data["keys"])
	resp, err = call(logical.ReadOperation, "status/test", nil)
	require.NoError(t, err)
	require.NotNil(t, resp.Data)
	for _, v := range resp.Data {
		require.IsType(t, "", v)
	}
	data["interval"] = 86400
	data["retain"] = 7
	data["file_prefix"] = "changed"
	_, err = call(logical.UpdateOperation, "config/test", data)
	require.NoError(t, err)
	resp, err = call(logical.ReadOperation, "config/test", nil)
	require.NoError(t, err)
	require.Equal(t, 7, resp.Data["retain"])
	require.Equal(t, "changed", resp.Data["file_prefix"])
	_, err = call(logical.DeleteOperation, "config/test", nil)
	require.NoError(t, err)
	resp, err = call(logical.ReadOperation, "config/test", nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	resp, err = call(logical.ReadOperation, "status/test", nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	_, err = b.HandleRequest(namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", Path: "child/"}), &logical.Request{Operation: logical.ListOperation, Path: "storage/raft/snapshot-auto/config", Storage: storage})
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
}

func TestAutoSnapshotScheduler(t *testing.T) {
	r := raft.GetRaft(t, true, false)
	defer r.TeardownCluster(nil)
	ctx := context.Background()
	require.NoError(t, r.Put(ctx, &physical.Entry{Key: "auto-snapshot-test", Value: []byte("persisted raft data")}))
	s := newAutoSnapshotService()
	var active atomic.Bool
	active.Store(true)
	s.active = active.Load
	s.export = func(w io.Writer) error { return r.Snapshot(w, nil) }
	dir := t.TempDir()
	c := &autoSnapshotConfig{Interval: 1, Retain: 10, PathPrefix: dir, FilePrefix: "backup", StorageType: "local", LocalMaxSpace: 1 << 20}
	// Fill the entire allowance with a matching old snapshot, so any real export
	// must evict it even though the retention count has not been reached.
	old := filepath.Join(dir, "backup-old.snap")
	require.NoError(t, os.WriteFile(old, make([]byte, c.LocalMaxSpace), 0600))
	unrelated := filepath.Join(dir, "unrelated.snap")
	require.NoError(t, os.WriteFile(unrelated, []byte("keep"), 0600))
	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON(autoSnapshotStoragePrefix+"test", c)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))
	s.start(ctx, storage, 10*time.Millisecond)
	defer s.stop()
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.status["test"] != nil
	}, 10*time.Second, 20*time.Millisecond)
	s.stop()
	s.mu.Lock()
	status := s.status["test"]
	s.mu.Unlock()
	require.Equal(t, "", status["last_snapshot_error"])
	for _, v := range status {
		require.IsType(t, "", v)
	}
	_, err = os.Stat(old)
	require.True(t, os.IsNotExist(err))
	require.FileExists(t, unrelated)
	files, err := filepath.Glob(filepath.Join(dir, "backup-*.snap"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	info, err := os.Stat(files[0])
	require.NoError(t, err)
	require.LessOrEqual(t, info.Size(), c.LocalMaxSpace)
	f, err := os.Open(files[0])
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		names = append(names, header.Name)
		_, err = io.Copy(io.Discard, tr)
		require.NoError(t, err)
	}
	require.Contains(t, names, "state.bin")
	// A due job must not run when the active-node predicate rejects it.
	active.Store(false)
	s.next["test"] = time.Time{}
	s.run(ctx, storage, time.Now())
	files, err = filepath.Glob(filepath.Join(dir, "backup-*.snap"))
	require.NoError(t, err)
	require.Len(t, files, 1)
}

func TestAutoSnapshotLocalLimits(t *testing.T) {
	dir := t.TempDir()
	c := &autoSnapshotConfig{PathPrefix: dir, FilePrefix: "test", Retain: 1, LocalMaxSpace: 12}
	export := func(w io.Writer) error { _, err := io.WriteString(w, "snapshot"); return err }
	for i := 0; i < 3; i++ {
		_, err := writeLocalAutoSnapshot(context.Background(), c, export)
		require.NoError(t, err)
	}
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	// Retention also applies when space alone would allow every snapshot.
	c.LocalMaxSpace = 128
	for i := 0; i < 3; i++ {
		_, err := writeLocalAutoSnapshot(context.Background(), c, export)
		require.NoError(t, err)
	}
	files, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	c.LocalMaxSpace = 12
	_, err = writeLocalAutoSnapshot(context.Background(), c, func(w io.Writer) error { _, err := io.WriteString(w, strings.Repeat("x", 13)); return err })
	require.ErrorContains(t, err, "local_max_space")
	files, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.True(t, strings.HasSuffix(files[0].Name(), ".snap"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = writeLocalAutoSnapshot(ctx, c, export)
	require.ErrorIs(t, err, context.Canceled)
}

func TestAutoSnapshotCancelDelete(t *testing.T) {
	s := newAutoSnapshotService()
	s.active = func() bool { return true }
	started := make(chan struct{})
	s.export = func(w io.Writer) error {
		close(started)
		for {
			if _, err := w.Write([]byte("x")); err != nil {
				return err
			}
			time.Sleep(time.Millisecond)
		}
	}
	storage := &logical.InmemStorage{}
	c := &autoSnapshotConfig{Interval: 1, Retain: 1, LocalMaxSpace: 1 << 20, PathPrefix: t.TempDir(), FilePrefix: "cancel", StorageType: "local"}
	entry, err := logical.StorageEntryJSON(autoSnapshotStoragePrefix+"test", c)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))
	s.next["test"] = time.Time{}
	s.start(context.Background(), storage, time.Millisecond)
	defer s.stop()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("export did not start")
	}
	b := &framework.Backend{Paths: s.paths()}
	result := make(chan error, 1)
	go func() {
		_, err := b.HandleRequest(namespace.RootContext(context.Background()), &logical.Request{Operation: logical.DeleteOperation, Path: "storage/raft/snapshot-auto/config/test", Storage: storage})
		result <- err
	}()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("delete failed to cancel export")
	}
	files, err := os.ReadDir(c.PathPrefix)
	require.NoError(t, err)
	require.Empty(t, files)
	stored, err := readAutoSnapshotConfig(context.Background(), storage, "test")
	require.NoError(t, err)
	require.Nil(t, stored)
}
