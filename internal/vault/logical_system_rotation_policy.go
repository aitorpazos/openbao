// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

const rotationPolicyPrefix = "policies/rotation/"

// rotationPolicyPaths exposes policy configuration only. Assignment to LDAP
// static roles and OS accounts, and scheduler integration, are separate concerns.
func (b *SystemBackend) rotationPolicyPaths() []*framework.Path {
	return []*framework.Path{{
		Pattern: rotationPolicyPrefix + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name":                  {Type: framework.TypeString, Description: "Rotation policy name."},
			"max_retries_per_cycle": {Type: framework.TypeInt, Description: "Required maximum backoff applications per cycle."},
			"max_retry_cycles":      {Type: framework.TypeInt, Description: "Required maximum requeues to the next scheduled rotation."},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleRotationPolicy,
			logical.ReadOperation:   b.handleRotationPolicy,
			logical.DeleteOperation: b.handleRotationPolicy,
		},
		HelpSynopsis: "Manage rotation policy configuration in the root namespace.",
	}}
}

func (b *SystemBackend) handleRotationPolicy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrorResponse("rotation policies are only available in the root namespace"), logical.ErrPermissionDenied
	}
	key := rotationPolicyPrefix + d.Get("name").(string)
	switch req.Operation {
	case logical.DeleteOperation:
		return nil, req.Storage.Delete(ctx, key)
	case logical.ReadOperation:
		entry, err := req.Storage.Get(ctx, key)
		if err != nil || entry == nil {
			return nil, err
		}
		var policy map[string]int
		if err := entry.DecodeJSON(&policy); err != nil {
			return nil, err
		}
		return &logical.Response{Data: map[string]interface{}{
			"max_retries_per_cycle": policy["max_retries_per_cycle"],
			"max_retry_cycles":      policy["max_retry_cycles"],
		}}, nil
	default:
		policy := make(map[string]int, 2)
		for _, field := range []string{"max_retries_per_cycle", "max_retry_cycles"} {
			raw, ok := d.Raw[field]
			if !ok || raw == nil {
				return logical.ErrorResponse("%s is required", field), nil
			}
			// TypeInt's weak conversion can truncate fractions or accept strings and
			// booleans. Validate the original JSON value before storing either field.
			encoded, err := json.Marshal(raw)
			var value int
			if err != nil || json.Unmarshal(encoded, &value) != nil {
				return logical.ErrorResponse("%s must be an integer", field), nil
			}
			policy[field] = value
		}
		entry, err := logical.StorageEntryJSON(key, policy)
		if err != nil {
			return nil, err
		}
		return nil, req.Storage.Put(ctx, entry)
	}
}
