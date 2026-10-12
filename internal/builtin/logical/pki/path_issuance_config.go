// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Configuration is deliberately fail-closed: persisting disabled protocol settings
// does not advertise an enrollment implementation or register global EST routes.
func pathIssuanceConfig(protocol string) *framework.Path {
	fields := map[string]*framework.FieldSchema{
		"enabled":                 {Type: framework.TypeBool},
		"default_path_policy":     {Type: framework.TypeString},
		"enable_sentinel_parsing": {Type: framework.TypeBool},
		"audit_fields":            {Type: framework.TypeCommaStringSlice},
	}
	defaults := map[string]interface{}{"enabled": false, "default_path_policy": "", "enable_sentinel_parsing": false, "audit_fields": []string{"common_name", "alt_names", "ip_sans", "uri_sans"}, "last_updated": ""}
	if protocol == "est" {
		fields["default_mount"] = &framework.FieldSchema{Type: framework.TypeBool}
		fields["label_to_path_policy"] = &framework.FieldSchema{Type: framework.TypeMap}
		fields["authenticators"] = &framework.FieldSchema{Type: framework.TypeMap}
		defaults["default_mount"] = false
		defaults["label_to_path_policy"] = map[string]interface{}{}
		defaults["authenticators"] = map[string]interface{}{}
	} else {
		fields["disabled_validations"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
		defaults["disabled_validations"] = []string{}
	}
	return storedIssuanceConfig("config/"+protocol, fields, defaults, func(c map[string]interface{}) string {
		if c["enabled"] == true {
			return protocol + " enrollment is not implemented; configuration must remain disabled"
		}
		policy := c["default_path_policy"].(string)
		if policy != "" && policy != "sign-verbatim" && !(strings.HasPrefix(policy, "role:") && len(policy) > 5) {
			return "default_path_policy must be sign-verbatim or role:<role_name>"
		}
		d := &framework.FieldData{Raw: c, Schema: fields}
		allowed := strings.Fields("csr common_name alt_names ip_sans uri_sans other_sans signature_bits exclude_cn_from_sans ou organization country locality province street_address postal_code serial_number use_pss key_type key_bits add_basic_constraints")
		for _, v := range d.Get("audit_fields").([]string) {
			if !slices.Contains(allowed, v) {
				return "invalid audit_fields value: " + v
			}
		}
		if protocol == "cmp" {
			for _, v := range d.Get("disabled_validations").([]string) {
				if !slices.Contains([]string{"DisableMatchingKeyIdValidation", "DisableCertTimeValidation"}, v) {
					return "invalid disabled_validations value: " + v
				}
			}
		} else {
			if c["default_mount"] == true || len(d.Get("label_to_path_policy").(map[string]interface{})) > 0 {
				return "global EST route registration is not implemented"
			}
			if len(d.Get("authenticators").(map[string]interface{})) > 0 {
				return "EST authentication delegation is not implemented"
			}
		}
		return ""
	})
}

func storedIssuanceConfig(path string, fields map[string]*framework.FieldSchema, defaults map[string]interface{}, validate func(map[string]interface{}) string) *framework.Path {
	var mu sync.Mutex
	handler := func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		config := make(map[string]interface{}, len(defaults))
		for k, v := range defaults {
			config[k] = v
		}
		entry, err := r.Storage.Get(ctx, path)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err = entry.DecodeJSON(&config); err != nil {
				return nil, err
			}
		}
		if r.Operation == logical.ReadOperation {
			delete(config, "vault_client_cert_bundle")
			return &logical.Response{Data: config}, nil
		}
		for k := range fields {
			if v, ok := d.GetOk(k); ok {
				config[k] = v
			}
		}
		if msg := validate(config); msg != "" {
			return logical.ErrorResponse(msg), nil
		}
		if _, ok := defaults["last_updated"]; ok {
			config["last_updated"] = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if _, ok := defaults["external_service_last_updated"]; ok {
			config["external_service_last_updated"] = time.Now().UTC().Format(time.RFC3339Nano)
		}
		entry, err = logical.StorageEntryJSON(path, config)
		if err != nil {
			return nil, err
		}
		if err = r.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
		delete(config, "vault_client_cert_bundle")
		if path == "config/external-policy" {
			return &logical.Response{Data: config}, nil
		}
		return &logical.Response{Data: config, Warnings: []string{"Configuration only; protocol enrollment, Sentinel evaluation and external policy requests are not implemented."}}, nil
	}
	return &framework.Path{Pattern: path, Fields: fields, Operations: map[logical.Operation]framework.OperationHandler{
		logical.ReadOperation:   &framework.PathOperation{Callback: handler},
		logical.UpdateOperation: &framework.PathOperation{Callback: handler, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
	}}
}

func pathExternalPolicyConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{"enabled": {Type: framework.TypeBool}, "timeout": {Type: framework.TypeDurationSecond}}
	defaults := map[string]interface{}{"enabled": false, "timeout": 15, "external_service_validated": false, "external_service_last_updated": "", "last_successful_request": ""}
	for _, k := range []string{"external_service_url", "trusted_ca", "trusted_leaf_certificate_bundle", "vault_client_cert_bundle", "entity_jmespath", "group_jmespath"} {
		fields[k] = &framework.FieldSchema{Type: framework.TypeString}
		defaults[k] = ""
	}
	return storedIssuanceConfig("config/external-policy", fields, defaults, func(c map[string]interface{}) string {
		u, err := url.Parse(c["external_service_url"].(string))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return "external_service_url must be an HTTPS URL"
		}
		ca, leaf := c["trusted_ca"].(string), c["trusted_leaf_certificate_bundle"].(string)
		if ca == "" && leaf == "" {
			return "trusted_ca or trusted_leaf_certificate_bundle is required"
		}
		for _, pem := range []string{ca, leaf} {
			if pem != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) {
				return "invalid trust certificate bundle"
			}
		}
		d := &framework.FieldData{Raw: c, Schema: fields}
		if d.Get("timeout").(int) <= 0 {
			return "timeout must be positive"
		}
		return ""
	})
}
