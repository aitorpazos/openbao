// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"

	"github.com/openbao/openbao/v2/internal/vault/sentinel"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	vpol "github.com/openbao/openbao/v2/internal/vault/policy"
)

// Sentinel-shaped governing-policy management (sys/policies/egp and
// sys/policies/rgp), clean-roomed from the public Vault Enterprise API
// documentation only (compat/specs/sentinel/notes.md).

func (b *SystemBackend) sentinelPaths() []*framework.Path {
	egpFields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Specifies the name of the policy.",
		},
		"policy": {
			Type:        framework.TypeString,
			Description: "Specifies the policy document; may be base64-encoded.",
		},
		"enforcement_level": {
			Type:        framework.TypeString,
			Description: "One of advisory, soft-mandatory, or hard-mandatory.",
		},
		"paths": {
			Type: framework.TypeCommaStringSlice,
			Description: "Paths on which this EGP applies; a trailing glob performs a prefix match.",
		},
	}

	rgpFields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Specifies the name of the policy.",
		},
		"policy": {
			Type:        framework.TypeString,
			Description: "Specifies the policy document; may be base64-encoded.",
		},
		"enforcement_level": {
			Type:        framework.TypeString,
			Description: "One of advisory, soft-mandatory, or hard-mandatory.",
		},
		"paths": {
			Type: framework.TypeCommaStringSlice,
			Description: "Not valid for RGP policies; provided only to return a clear error.",
		},
	}

	return []*framework.Path{
		{
			Pattern: "policies/egp/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleSentinelList(sentinel.TypeEGP),
				},
			},
			HelpSynopsis:    "List configured EGP policies.",
			HelpDescription: "Returns the names of all configured EGP policies.",
		},
		{
			Pattern: "policies/egp/(?P<name>.+)",
			Fields:  egpFields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleSentinelRead(sentinel.TypeEGP),
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleSentinelSet(sentinel.TypeEGP),
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleSentinelSet(sentinel.TypeEGP),
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleSentinelDelete(sentinel.TypeEGP),
				},
			},
			HelpSynopsis:    "Manage EGP policies.",
			HelpDescription: "Create, update, read, and delete EGP policies. EGP policies act on the configured paths.",
		},
		{
			Pattern: "policies/rgp/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleSentinelList(sentinel.TypeRGP),
				},
			},
			HelpSynopsis:    "List configured RGP policies.",
			HelpDescription: "Returns the names of all configured RGP policies.",
		},
		{
			Pattern: "policies/rgp/(?P<name>.+)",
			Fields:  rgpFields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleSentinelRead(sentinel.TypeRGP),
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleSentinelSet(sentinel.TypeRGP),
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleSentinelSet(sentinel.TypeRGP),
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleSentinelDelete(sentinel.TypeRGP),
				},
			},
			HelpSynopsis:    "Manage RGP policies.",
			HelpDescription: "Create, update, read, and delete RGP policies. RGP policies are tied to tokens.",
		},
	}
}

// handleSentinelList lists the configured policies of the given type. EGP
// responses additionally carry name_path_map (names to paths and glob
// status), per the documented list shape.
func (b *SystemBackend) handleSentinelList(t sentinel.PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		policies, err := b.Core.getSentinelStore().List(ctx, t)
		if err != nil {
			return nil, err
		}
		resp := logical.ListResponse(sentinel.SortedNames(policies))
		if t == sentinel.TypeEGP {
			namePathMap := make(map[string]any, len(policies))
			for name, policy := range policies {
				entry := map[string]any{
					"paths": policy.Paths,
				}
				for _, path := range policy.Paths {
					if strings.HasSuffix(path, "*") {
						entry["glob"] = true
						break
					}
				}
				if _, ok := entry["glob"]; !ok {
					entry["glob"] = false
				}
				namePathMap[name] = entry
			}
			resp.Data["name_path_map"] = namePathMap
		}
		return resp, nil
	}
}

// handleSentinelRead returns one policy with the documented response shape.
func (b *SystemBackend) handleSentinelRead(t sentinel.PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := sentinel.SanitizeName(d.Get("name").(string))
		policy, err := b.Core.getSentinelStore().Get(ctx, t, name)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			// Mirror the ACL policy read convention: unknown policy reads
			// return an empty success rather than an error.
			return nil, nil
		}
		data := map[string]any{
			"name":              policy.Name,
			"policy":            policy.Policy,
			"enforcement_level": policy.EnforcementLevel,
		}
		if t == sentinel.TypeEGP {
			data["paths"] = policy.Paths
		}
		return &logical.Response{Data: data}, nil
	}
}

// handleSentinelSet validates and stores one policy.
func (b *SystemBackend) handleSentinelSet(t sentinel.PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := sentinel.SanitizeName(d.Get("name").(string))
		if name == "" {
			return logical.ErrorResponse("policy name is required"), nil
		}

		policy := &sentinel.Policy{
			Name:             name,
			Policy:           d.Get("policy").(string),
			EnforcementLevel: d.Get("enforcement_level").(string),
		}

		if t == sentinel.TypeEGP {
			if raw, ok := d.GetOk("paths"); ok {
				switch v := raw.(type) {
				case []string:
					policy.Paths = v
				case string:
					policy.Paths = []string{v}
				}
			}
		} else if _, ok := d.GetOk("paths"); ok {
			return logical.ErrorResponse("RGP policies do not take paths; RGPs are tied to tokens"), nil
		}

		if err := policy.Validate(t == sentinel.TypeEGP, func() ([]string, error) {
			return b.Core.policyStore.ListPolicies(ctx, vpol.TypeACL, true)
		}); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		// Store the evaluation-ready document: base64 input is decoded so
		// reads return the document, matching the documented read sample.
		decoded, err := sentinel.DecodePolicyDocument(policy.Policy)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		policy.Policy = decoded

		if err := b.Core.getSentinelStore().Put(ctx, t, policy); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

// handleSentinelDelete removes one policy.
func (b *SystemBackend) handleSentinelDelete(t sentinel.PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := sentinel.SanitizeName(d.Get("name").(string))
		if err := b.Core.getSentinelStore().Delete(ctx, t, name); err != nil {
			return nil, err
		}
		return nil, nil
	}
}
