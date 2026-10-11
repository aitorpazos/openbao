// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathConfigSCEP is configuration-only. Enrollment is intentionally unavailable.
// The closure lock belongs to this backend instance, not to a global mount.
func pathConfigSCEP() *framework.Path {
	var mu sync.Mutex
	fields := map[string]*framework.FieldSchema{
		"enabled":                       {Type: framework.TypeBool},
		"default_path_policy":           {Type: framework.TypeString},
		"authenticators":                {Type: framework.TypeMap},
		"allowed_digest_algorithms":     {Type: framework.TypeCommaStringSlice},
		"allowed_encryption_algorithms": {Type: framework.TypeCommaStringSlice},
		"restrict_ca_chain_to_issuer":   {Type: framework.TypeBool},
		"log_level":                     {Type: framework.TypeString},
	}
	handler := func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		config := map[string]interface{}{"enabled": false, "default_path_policy": "", "restrict_ca_chain_to_issuer": false, "log_level": "", "authenticators": map[string]interface{}{}, "allowed_digest_algorithms": []string{}, "allowed_encryption_algorithms": []string{}}
		entry, err := r.Storage.Get(ctx, "config/scep")
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&config); err != nil {
				return nil, err
			}
		}
		if r.Operation == logical.ReadOperation {
			return &logical.Response{Data: config}, nil
		}
		if _, ok := r.Data["external_validation"]; ok {
			return logical.ErrorResponse("external SCEP validation is not implemented"), nil
		}
		for k := range fields {
			if v, ok := d.GetOk(k); ok {
				config[k] = v
			}
		}
		if config["enabled"] == true {
			return logical.ErrorResponse("SCEP enrollment is not implemented; configuration must remain disabled"), nil
		}
		policy := config["default_path_policy"].(string)
		if policy != "" && policy != "sign-verbatim" && !(strings.HasPrefix(policy, "role:") && len(policy) > len("role:")) {
			return logical.ErrorResponse("default_path_policy must be sign-verbatim or role:<role_name>"), nil
		}
		fd := &framework.FieldData{Raw: config, Schema: fields}
		for field, allowed := range map[string][]string{"allowed_digest_algorithms": {"sha-1", "sha-256", "sha-384", "sha-512"}, "allowed_encryption_algorithms": {"des-cbc", "3des-cbc", "aes128-cbc", "aes256-cbc", "aes128-gcm", "aes256-gcm"}} {
			for _, v := range fd.Get(field).([]string) {
				if !slices.Contains(allowed, v) {
					return logical.ErrorResponse("invalid %s value %q", field, v), nil
				}
			}
		}
		if !slices.Contains([]string{"", "TRACE", "DEBUG", "INFO", "WARN", "ERROR"}, config["log_level"].(string)) {
			return logical.ErrorResponse("invalid log_level"), nil
		}
		for kind, raw := range fd.Get("authenticators").(map[string]interface{}) {
			if kind != "scep" && kind != "cert" {
				return logical.ErrorResponse("authenticators supports only scep or cert"), nil
			}
			m, ok := raw.(map[string]interface{})
			if !ok {
				return logical.ErrorResponse("authenticator must be a map"), nil
			}
			accessor, ok := m["accessor"].(string)
			if !ok || accessor == "" {
				return logical.ErrorResponse("authenticator accessor is required"), nil
			}
			for k, v := range m {
				if k != "accessor" && k != kind+"_role" {
					return logical.ErrorResponse("unknown authenticator field %s", k), nil
				}
				if _, ok := v.(string); !ok {
					return logical.ErrorResponse("authenticator values must be strings"), nil
				}
			}
		}
		config["last_updated"] = time.Now().UTC().Format(time.RFC3339Nano)
		entry, err = logical.StorageEntryJSON("config/scep", config)
		if err != nil {
			return nil, err
		}
		if err = r.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
		return &logical.Response{Data: config, Warnings: []string{"Configuration stored only; SCEP enrollment and external validation are not implemented."}}, nil
	}
	return &framework.Path{Pattern: "config/scep", Fields: fields, Operations: map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation:   &framework.PathOperation{Callback: handler},
		logical.UpdateOperation: &framework.PathOperation{Callback: handler, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
	}}
}
