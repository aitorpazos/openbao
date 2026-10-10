// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// Named step-up configurations are separate from identity login MFA methods.
// Storage uses the system barrier view and configuration access is ACL-controlled.
// Enrollment is handled separately from configuration CRUD and enforcement.
const namedMFAMethodPrefix = "mfa/named-methods/"

type namedMFAMethodLock struct{ sync.Mutex }

func (b *SystemBackend) namedMFAMethodPaths() []*framework.Path {
	var paths []*framework.Path
	for _, kind := range []string{"totp", "duo", "okta", "pingid"} {
		fields := map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString, Description: "Name of the step-up MFA method."},
		}
		if kind == "totp" {
			fields["issuer"] = &framework.FieldSchema{Type: framework.TypeString, Description: "Required TOTP issuer."}
			fields["algorithm"] = &framework.FieldSchema{Type: framework.TypeString, Default: "SHA1", Description: "TOTP hash algorithm: SHA1, SHA256, or SHA512."}
			for name, value := range map[string]int{"period": 30, "key_size": 20, "qr_size": 200, "digits": 6, "skew": 1, "max_validation_attempts": 5} {
				fields[name] = &framework.FieldSchema{Type: framework.TypeInt, Default: value, Description: "TOTP configuration parameter."}
			}
			fields["period"].Type = framework.TypeDurationSecond
		} else {
			fields["mount_accessor"] = &framework.FieldSchema{Type: framework.TypeString, Description: "Required auth mount accessor used for alias mapping."}
			fields["username_format"] = &framework.FieldSchema{Type: framework.TypeString, Description: "Username template; empty uses the alias name."}
			var names []string
			switch kind {
			case "duo":
				names = []string{"secret_key", "integration_key", "api_hostname", "push_info"}
			case "okta":
				names = []string{"org_name", "api_token", "base_url"}
				fields["primary_email"] = &framework.FieldSchema{Type: framework.TypeBool, Default: false, Description: "Match only the primary email."}
			case "pingid":
				names = []string{"settings_file_base64"}
			}
			for _, name := range names {
				fields[name] = &framework.FieldSchema{Type: framework.TypeString, Description: "Provider configuration parameter."}
			}
		}
		handler := func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
			return b.handleNamedMFAMethod(ctx, req, d, kind)
		}
		paths = append(paths, &framework.Path{
			Pattern: "mfa/method/" + kind + "/" + framework.GenericNameRegex("name"),
			Fields:  fields,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: handler, logical.ReadOperation: handler, logical.DeleteOperation: handler,
			},
			HelpSynopsis: "Manage a named step-up MFA method configuration in the root namespace.",
		})
	}
	return append(paths, b.namedMFATOTPEnrollmentPaths()...)
}

func (b *SystemBackend) handleNamedMFAMethod(ctx context.Context, req *logical.Request, d *framework.FieldData, kind string) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrorResponse("named MFA methods are only available in the root namespace"), logical.ErrPermissionDenied
	}
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	key := namedMFAMethodPrefix + kind + "/" + name
	b.namedMFAMethodLock.Lock()
	defer b.namedMFAMethodLock.Unlock()
	if req.Operation == logical.DeleteOperation {
		return nil, req.Storage.Delete(ctx, key)
	}
	entry, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	var previous map[string]interface{}
	if entry != nil {
		if err := entry.DecodeJSON(&previous); err != nil {
			return nil, err
		}
	}
	if req.Operation == logical.ReadOperation {
		if entry == nil {
			return nil, nil
		}
		return &logical.Response{Data: previous}, nil
	}
	required := "mount_accessor"
	if kind == "totp" {
		required = "issuer"
	}
	if d.Get(required).(string) == "" {
		return logical.ErrorResponse("%s is required", required), nil
	}
	if kind == "totp" {
		switch d.Get("algorithm").(string) {
		case "SHA1", "SHA256", "SHA512":
		default:
			return logical.ErrorResponse("algorithm must be SHA1, SHA256, or SHA512"), nil
		}
		digits := d.Get("digits").(int)
		if digits != 6 && digits != 8 {
			return logical.ErrorResponse("digits must be 6 or 8"), nil
		}
		skew := d.Get("skew").(int)
		if skew != 0 && skew != 1 {
			return logical.ErrorResponse("skew must be 0 or 1"), nil
		}
		for _, field := range []string{"period", "key_size", "qr_size", "max_validation_attempts"} {
			if d.Get(field).(int) <= 0 {
				return logical.ErrorResponse("%s must be positive", field), nil
			}
		}
	}
	// POST replaces the configuration with supplied values and documented defaults,
	// while keeping the method identifier stable for subsequent enrollment.
	config := make(map[string]interface{}, len(d.Schema)+2)
	for field := range d.Schema {
		config[field] = d.Get(field)
	}
	config["type"] = kind
	if previous != nil {
		config["id"] = previous["id"]
	} else {
		id, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
		config["id"] = id
	}
	entry, err = logical.StorageEntryJSON(key, config)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}
