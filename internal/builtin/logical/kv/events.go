// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"github.com/openbao/openbao/sdk/v2/logical"
	"strings"
)

// emitMutation is called only after storage mutation and transaction commit.
func (b *versionedKVBackend) emitMutation(ctx context.Context, req *logical.Request) {
	prefix, key, _ := strings.Cut(req.Path, "/")
	operation := prefix
	switch prefix {
	case "data", "metadata":
		switch req.Operation {
		case logical.DeleteOperation:
			operation += "-delete"
		case logical.PatchOperation:
			operation += "-patch"
		case logical.CreateOperation, logical.UpdateOperation:
			operation += "-write"
		default:
			return
		}
	case "config":
		operation = "config-write"
	case "delete", "destroy", "undelete":
	default:
		return
	}
	metadata := []string{"path", req.Path, "operation", operation, "modified", "true"}
	if prefix != "config" {
		metadata = append(metadata, "data_path", "data/"+key)
	}
	_ = logical.SendEvent(ctx, b, "kv-v2/"+operation, metadata...)
}
