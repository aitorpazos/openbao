// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"net/textproto"
	"path"
	"strings"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/vault/routing"
)

// Documented snapshot-recovery surface (Vault Enterprise;
// docs/sysadmin/snapshots/recover-a-secret): a RECOVER request (or PUT/POST
// with the X-Vault-Recover-Snapshot-Id header) on a secret path reads the
// secret's data out of the currently loaded isolated Raft snapshot and writes
// it into live cluster storage through the secret's own plugin. The snapshot
// must belong to this cluster (enforced at load time), the mount must still
// exist with its original internal identifier (re-created mounts cannot be
// associated — documented constraint), and the caller needs the "recover"
// policy capability on the target path.

// snapshotRecoverableMountTypes are the secret-entry plugins the recovery
// flow writes back through. The documented supported-plugin table also lists
// ssh /config/ca and databases static-roles/static-creds; those store
// plugin-internal config shapes rather than plain API payloads, so writing
// them back through the public API is not implemented here and is rejected
// with an explicit error rather than risking live config corruption.
var snapshotRecoverableMountTypes = map[string]bool{
	"cubbyhole": true,
	"kv":        true,
	"generic":   true,
}

// mountStoragePrefix returns the barrier key prefix for a root-namespace
// secret mount's storage view (mirrors Core's view construction:
// NamespaceView(ns).SubView(backendBarrierPrefix + uuid)).
func mountStoragePrefix(entry *routing.MountEntry) string {
	return path.Join("logical", entry.UUID)
}

// setLoadedSnapshot / loadedSnapshotService maintain the core-level registry
// of the currently loaded snapshot service.
func (c *Core) setLoadedSnapshot(s *snapshotLoadService) {
	c.loadedSnapshotMu.Lock()
	defer c.loadedSnapshotMu.Unlock()
	c.loadedSnapshot = s
}

func (c *Core) loadedSnapshotService() *snapshotLoadService {
	c.loadedSnapshotMu.Lock()
	defer c.loadedSnapshotMu.Unlock()
	return c.loadedSnapshot
}

// recoverSnapshotSecret implements the core recovery flow for
// logical.RecoverOperation. It is called from handleRequest after the token
// and ACL checks have passed (the "recover" capability gates the target
// path), replacing the normal router dispatch for the request.
func (c *Core) recoverSnapshotSecret(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	// The core does not receive the raw HTTP request context, so the
	// documented recovery headers are read from the logical request's
	// cloned header set (map[string][]string, MIME-canonicalized keys).
	getHeader := func(name string) string {
		if req.Headers == nil {
			return ""
		}
		// The http layer canonicalizes header names; match case-insensitively.
		if vals, ok := req.Headers[textproto.CanonicalMIMEHeaderKey(name)]; ok && len(vals) > 0 {
			return vals[0]
		}
		for k, vals := range req.Headers {
			if strings.EqualFold(k, name) && len(vals) > 0 {
				return vals[0]
			}
		}
		return ""
	}
	snapshotID := getHeader("X-Vault-Recover-Snapshot-Id")
	if snapshotID == "" {
		snapshotID = getHeader("X-Vault-Recover-Snapshot-ID")
	}
	sourcePath := getHeader("X-Vault-Recover-Source-Path")
	if snapshotID == "" {
		return logical.ErrorResponse("X-Vault-Recover-Snapshot-Id header is required to recover from a loaded snapshot"), nil
	}
	if sourcePath == "" {
		sourcePath = req.Path
	}
	// Normalize the documented header form of the source path.
	sourcePath = strings.Trim(sourcePath, "/")

	svc := c.loadedSnapshotService()
	if svc == nil {
		return nil, errors.New("no snapshot is currently loaded; load one with sys/storage/raft/snapshot-load first")
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()

	if svc.data == nil || svc.data["snapshot_id"] != snapshotID {
		return nil, fmt.Errorf("snapshot %q is not the currently loaded snapshot", snapshotID)
	}
	if svc.data["status"] != "ready" {
		return nil, fmt.Errorf("loaded snapshot is in state %v; recovery requires a ready snapshot", svc.data["status"])
	}
	view := svc.view
	if view == nil {
		return nil, errors.New("loaded snapshot view is unavailable")
	}

	// The loaded snapshot's mount table is the root-namespace table; recovery
	// is restricted to the root namespace accordingly.
	ns, err := namespace.FromContext(ctx)
	if err != nil || (ns != nil && ns.ID != namespace.RootNamespaceID) {
		return nil, errors.New("snapshot recovery is restricted to the root namespace")
	}

	snapshotMounts, err := readSnapshotMountTable(ctx, view)
	if err != nil {
		return nil, err
	}
	snapshotMount, relativePath, err := matchSnapshotMount(snapshotMounts, sourcePath)
	if err != nil {
		return nil, err
	}
	if relativePath == "" {
		return nil, fmt.Errorf("cannot recover the mount path %q itself; recover a secret path below it", sourcePath)
	}
	if !snapshotRecoverableMountTypes[snapshotMount.Type] {
		// Distinguish documented-but-unimplemented plugins from wholly
		// unsupported ones.
		switch snapshotMount.Type {
		case "ssh":
			if relativePath != "config/ca" {
				return nil, fmt.Errorf("plugin %q supports snapshot recovery only at config/ca", snapshotMount.Type)
			}
		case "database":
			if !strings.HasPrefix(relativePath, "static-roles/") {
				return nil, fmt.Errorf("plugin %q supports snapshot recovery only at static-roles/:role_name", snapshotMount.Type)
			}
		}
		return nil, fmt.Errorf("snapshot recovery for plugin %q is not implemented in this build", snapshotMount.Type)
	}
	if snapshotMount.Type == "kv" && snapshotMount.Options != nil && snapshotMount.Options["version"] == "2" {
		return nil, errors.New("plugin kv at version 2 does not support snapshot recovery; only kv version 1 is documented")
	}

	// The live cluster must still hold the mount identified by the snapshot's
	// internal UUID. A mount deleted and re-created — even at the same path —
	// has a different UUID and cannot be associated (documented constraint).
	liveMount := c.router.MatchingMountByUUID(snapshotMount.UUID)
	if liveMount == nil {
		return nil, fmt.Errorf("mount %q from the snapshot does not exist in the live cluster; re-created or disabled mounts cannot be associated with snapshot storage", snapshotMount.Path)
	}

	// The documented recovery flow only writes back within the source mount
	// ("so long as both paths are on the same mount").
	targetPath := strings.Trim(req.Path, "/")
	if !strings.HasPrefix(targetPath, strings.Trim(liveMount.Path, "/")+"/") && strings.Trim(liveMount.Path, "/") != targetPath {
		return nil, fmt.Errorf("target path %q is not on the same mount as the snapshot source path %q", req.Path, sourcePath)
	}

	// Read the secret's storage entry out of the isolated snapshot view.
	storagePrefix := mountStoragePrefix(snapshotMount)
	var entry *logical.StorageEntry
	if snapshotMount.Type == "cubbyhole" {
		// Cubbyhole storage is per-token: <prefix>/<token-uuid>/<secret>.
		// The snapshot's owning token is not known, so scan token
		// namespaces for a unique suffix match; the caller's own cubbyhole
		// ID wins when the path is ambiguous. The router salts/aliases the
		// client token into te.CubbyholeID for cubbyhole requests.
		cubbyID := req.ClientToken
		if te := req.TokenEntry(); te != nil && te.CubbyholeID != "" {
			cubbyID = te.CubbyholeID
		}
		entry, err = findUniqueCubbyholeEntry(ctx, view, storagePrefix, relativePath, cubbyID)
		if err != nil {
			return nil, err
		}
	} else {
		entry, err = view.Get(ctx, path.Join(storagePrefix, relativePath))
		if err != nil {
			return nil, err
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("path %q not found in the loaded snapshot", sourcePath)
	}

	var data map[string]interface{}
	if len(entry.Value) != 0 {
		if err := jsonutil.DecodeJSON(entry.Value, &data); err != nil {
			return nil, fmt.Errorf("failed to decode the snapshot entry for %q: %w", sourcePath, err)
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("snapshot entry at %q contains no data to recover", sourcePath)
	}

	// Write the recovered data into live storage through the secret's own
	// plugin. The router dispatches directly (the recover capability on the
	// target path was already checked); the caller's identity is preserved
	// for per-token storage such as cubbyhole.
	writeReq := &logical.Request{
		ID:                  req.ID,
		Operation:           logical.UpdateOperation,
		Path:                req.Path,
		Data:                data,
		Connection:          req.Connection,
		ClientToken:         req.ClientToken,
		ClientTokenAccessor: req.ClientTokenAccessor,
		DisplayName:         req.DisplayName,
		EntityID:            req.EntityID,
	}
	// Per-token storage (cubbyhole) validates the routed request's token
	// entry; carry the caller's entry from the recover request.
	if te := req.TokenEntry(); te != nil {
		writeReq.SetTokenEntry(te)
	}
	return c.router.Route(ctx, writeReq)
}

// readSnapshotMountTable reads the root-namespace mount table out of the
// isolated snapshot view: core/mounts/<uuid> and core/local-mounts/<uuid>
// entries, decoded as routing.MountEntry values.
func readSnapshotMountTable(ctx context.Context, view barrier.SecurityBarrier) ([]*routing.MountEntry, error) {
	var entries []*routing.MountEntry
	for _, tablePath := range []string{"core/mounts/", "core/local-mounts/"} {
		uuids, err := view.List(ctx, tablePath)
		if err != nil {
			return nil, fmt.Errorf("failed to list the snapshot mount table: %w", err)
		}
		for _, id := range uuids {
			if strings.HasSuffix(id, "/") {
				continue
			}
			raw, err := view.Get(ctx, tablePath+id)
			if err != nil {
				return nil, fmt.Errorf("failed to read snapshot mount entry %q: %w", id, err)
			}
			if raw == nil {
				continue
			}
			entry := new(routing.MountEntry)
			if err := jsonutil.DecodeJSON(raw.Value, entry); err != nil {
				return nil, fmt.Errorf("failed to decode snapshot mount entry %q: %w", id, err)
			}
			if entry.UUID == "" {
				entry.UUID = id
			}
			if entry.NamespaceID == "" {
				entry.NamespaceID = namespace.RootNamespaceID
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// matchSnapshotMount finds the snapshot mount with the longest prefix match
// for the source path. All mounts in the table are root-namespace entries.
func matchSnapshotMount(entries []*routing.MountEntry, sourcePath string) (*routing.MountEntry, string, error) {
	if len(entries) == 0 {
		return nil, "", errors.New("the loaded snapshot has no mount table")
	}
	mountPath := strings.Trim(sourcePath, "/")
	var best *routing.MountEntry
	for _, entry := range entries {
		mount := strings.Trim(entry.Path, "/")
		if mount == "" {
			continue
		}
		if mountPath == mount {
			best = entry
			break
		}
		prefix := mount + "/"
		if strings.HasPrefix(mountPath, prefix) && (best == nil || len(mount) > len(strings.Trim(best.Path, "/"))) {
			best = entry
		}
	}
	if best == nil {
		return nil, "", fmt.Errorf("source path %q does not belong to any mount in the loaded snapshot", sourcePath)
	}
	return best, strings.TrimPrefix(mountPath, strings.Trim(best.Path, "/")+"/"), nil
}

// findUniqueCubbyholeEntry locates the snapshot cubbyhole entry for the
// requested secret path across the snapshot's per-token storage namespaces
// (cubbyhole storage is <prefix>/<token-uuid>/<nested path>). The snapshot's
// owning token is not known, so the mount prefix is walked recursively. When
// the path exists under several token namespaces and one of them is the
// caller's own token, that entry is used (recovering into one's own
// cubbyhole is the documented flow); otherwise the match is ambiguous and
// rejected.
func findUniqueCubbyholeEntry(ctx context.Context, view barrier.SecurityBarrier, storagePrefix, relativePath, clientToken string) (*logical.StorageEntry, error) {
	var found *logical.StorageEntry
	foundTokens := 0
	ownTokenFound := false
	var walk func(prefix string) error
	walk = func(prefix string) error {
		keys, err := view.List(ctx, prefix)
		if err != nil {
			return err
		}
		for _, key := range keys {
			full := prefix + key
			if strings.HasSuffix(key, "/") {
				if strings.HasSuffix(full, "/"+relativePath+"/") {
					// A folder matching the requested path is not itself
					// a recoverable secret.
					continue
				}
				if err := walk(full); err != nil {
					return err
				}
				continue
			}
			if !strings.HasSuffix(full, "/"+relativePath) {
				continue
			}
			entry, err := view.Get(ctx, full)
			if err != nil {
				return err
			}
			if entry == nil {
				continue
			}
			// Track the owning token namespace: the segment right after the
			// mount storage prefix.
			owner := strings.TrimPrefix(full, storagePrefix+"/")
			owner = owner[:strings.Index(owner, "/")]
			found, foundTokens = entry, foundTokens+1
			if owner == clientToken {
				ownTokenFound = true
			}
		}
		return nil
	}
	if err := walk(storagePrefix + "/"); err != nil {
		return nil, fmt.Errorf("failed to scan snapshot cubbyhole namespaces: %w", err)
	}
	switch {
	case foundTokens == 0:
		return nil, nil
	case foundTokens > 1 && !ownTokenFound:
		return nil, fmt.Errorf("path %q exists under multiple cubbyhole token namespaces in the snapshot; recovery is ambiguous", relativePath)
	default:
		return found, nil
	}
}
