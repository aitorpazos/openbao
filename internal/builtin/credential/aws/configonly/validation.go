// SPDX-License-Identifier: MPL-2.0

package configonly

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *Backend) validate(path string, m, old map[string]interface{}, r *logical.Request, d *framework.FieldData) error {
	for k, f := range d.Schema {
		if f.Type == framework.TypeDurationSecond && number(m, k) < 0 {
			return fmt.Errorf("%s cannot be negative", k)
		}
	}
	if path == "config" || path == "config/client" || path == "config/root" {
		p, w, s := number(m, "rotation_period"), number(m, "rotation_window"), str(m, "rotation_schedule")
		if p > 0 && p < 10 {
			return fmt.Errorf("rotation_period must be zero or at least 10 seconds")
		}
		if p > 0 && s != "" {
			return fmt.Errorf("rotation_period and rotation_schedule are mutually exclusive")
		}
		if w > 0 && (w < 3600 || p > 0 || s == "") {
			return fmt.Errorf("rotation_window requires a schedule and must be zero or at least 3600 seconds")
		}
		if s != "" {
			if e := validateSchedule(s); e != nil {
				return e
			}
		}
		if str(m, "identity_token_audience") != "" {
			switch b.provider {
			case "aws":
				if str(m, "access_key") != "" || str(m, "secret_key") != "" || str(m, "token") != "" || str(m, "session_token") != "" {
					return fmt.Errorf("identity_token_audience excludes static credentials")
				}
				if e := required(m, "role_arn"); e != nil {
					return e
				}
			case "azure":
				if str(m, "client_secret") != "" {
					return fmt.Errorf("identity_token_audience excludes client_secret")
				}
				if e := required(m, "client_id"); e != nil {
					return e
				}
			case "gcp":
				if str(m, "credentials") != "" {
					return fmt.Errorf("identity_token_audience excludes credentials")
				}
				if e := required(m, "service_account_email"); e != nil {
					return e
				}
			}
		}
		switch b.provider {
		case "aws":
			if (str(m, "access_key") == "") != (str(m, "secret_key") == "") {
				return fmt.Errorf("access_key and secret_key must be provided together")
			}
			if count(m, "sts_fallback_endpoints") != count(m, "sts_fallback_regions") {
				return fmt.Errorf("STS fallback endpoints and regions must have matching lengths")
			}
		case "azure":
			switch str(m, "environment") {
			case "AzurePublicCloud", "AzureUSGovernmentCloud", "AzureChinaCloud", "AzureGermanCloud":
			default:
				return fmt.Errorf("invalid environment")
			}
			if !b.secret {
				if e := required(m, "tenant_id", "resource"); e != nil {
					return e
				}
			}
		case "gcp":
			if c := str(m, "credentials"); c != "" {
				var v map[string]interface{}
				if json.Unmarshal([]byte(c), &v) != nil || v["type"] != "service_account" || v["client_email"] == nil || v["private_key"] == nil {
					return fmt.Errorf("credentials must be a service account JSON object with client_email and private_key")
				}
				key, _ := v["private_key"].(string)
				block, _ := pem.Decode([]byte(key))
				if block == nil {
					return fmt.Errorf("credentials contain an invalid private key")
				}
				if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
					return fmt.Errorf("credentials contain an invalid PKCS8 private key")
				}
			}
		}
	}
	if path == "role" {
		var tokens tokenutil.TokenParams
		if err := tokens.ParseTokenFields(r, d); err != nil {
			return err
		}
		if _, ok := d.Raw["policies"]; ok && count(m, "token_policies") == 0 {
			m["token_policies"] = m["policies"]
		}
		switch b.provider {
		case "aws":
			if str(m, "auth_type") != "iam" && str(m, "auth_type") != "ec2" {
				return fmt.Errorf("auth_type must be iam or ec2")
			}
			if old != nil && old["auth_type"] != m["auth_type"] {
				return fmt.Errorf("auth_type cannot be changed")
			}
			if str(m, "inferred_entity_type") != "" {
				if str(m, "inferred_entity_type") != "ec2_instance" {
					return fmt.Errorf("invalid inferred_entity_type")
				}
				if err := required(m, "inferred_aws_region"); err != nil {
					return err
				}
			}
			// Unique-ID resolution normally requires AWS. Never silently pretend it ran.
			if m["resolve_aws_unique_ids"] == true && count(m, "bound_iam_principal_arn") > 0 {
				return fmt.Errorf("%s Set resolve_aws_unique_ids=false to store ARN constraints without resolution", Limitation)
			}
		case "azure":
			if count(m, "bound_service_principal_ids") == 0 && count(m, "bound_group_ids") == 0 {
				return fmt.Errorf("bound_service_principal_ids or bound_group_ids is required")
			}
		case "gcp":
			switch str(m, "type") {
			case "iam":
				if count(m, "bound_service_accounts") == 0 {
					return fmt.Errorf("bound_service_accounts is required for iam")
				}
			case "gce":
				if count(m, "bound_instance_groups") > 0 && count(m, "bound_zones") == 0 && count(m, "bound_regions") == 0 {
					return fmt.Errorf("instance groups require bound_zones or bound_regions")
				}
			default:
				return fmt.Errorf("type must be iam or gce")
			}
		}
	}
	if path == "roles" {
		switch b.provider {
		case "aws":
			switch str(m, "credential_type") {
			case "iam_user", "federation_token", "session_token":
			case "assumed_role":
				if count(m, "role_arns") == 0 {
					return fmt.Errorf("role_arns is required for assumed_role")
				}
			default:
				return fmt.Errorf("invalid credential_type")
			}
			if p := str(m, "policy_document"); p != "" && !json.Valid([]byte(p)) {
				return fmt.Errorf("invalid policy_document JSON")
			}
		case "azure":
			if str(m, "application_object_id") == "" && str(m, "azure_roles") == "" {
				return fmt.Errorf("application_object_id or azure_roles is required")
			}
			if str(m, "application_object_id") != "" && m["permanently_delete"] == true {
				return fmt.Errorf("application_object_id excludes permanently_delete")
			}
			for _, k := range []string{"azure_roles", "azure_groups"} {
				if s := str(m, k); s != "" {
					var a []map[string]interface{}
					if json.Unmarshal([]byte(s), &a) != nil {
						return fmt.Errorf("%s must be a JSON array of objects", k)
					}
				}
			}
		}
	}
	if path == "roleset" || path == "static-account" {
		if str(m, "secret_type") != "access_token" && str(m, "secret_type") != "service_account_key" {
			return fmt.Errorf("invalid secret_type")
		}
		selector := "project"
		if path == "static-account" {
			selector = "service_account_email"
		}
		if e := required(m, selector); e != nil {
			return e
		}
		if path == "roleset" {
			if e := required(m, "bindings"); e != nil {
				return e
			}
		}
		if old != nil {
			for _, k := range []string{selector, "secret_type"} {
				if old[k] != m[k] {
					return fmt.Errorf("%s cannot be changed", k)
				}
			}
		}
		if raw := str(m, "bindings"); raw != "" {
			if decoded, e := base64.StdEncoding.DecodeString(raw); e == nil {
				raw = string(decoded)
			}
			if _, err := hcl.Parse(raw); err != nil {
				return fmt.Errorf("invalid bindings HCL or JSON")
			}
		}
	}
	if path == "config/sts" {
		return required(m, "sts_role")
	}
	if path == "config/certificate" {
		if str(m, "type") != "pkcs7" && str(m, "type") != "identity" {
			return fmt.Errorf("type must be pkcs7 or identity")
		}
		raw := []byte(str(m, "aws_public_cert"))
		if decoded, e := base64.StdEncoding.DecodeString(string(raw)); e == nil {
			raw = decoded
		}
		if block, _ := pem.Decode(raw); block != nil {
			raw = block.Bytes
		}
		if _, err := x509.ParseCertificate(raw); err != nil {
			return fmt.Errorf("aws_public_cert must contain an X.509 certificate")
		}
	}
	if path == "config/identity" {
		for _, k := range []string{"iam_alias", "ec2_alias", "gce_alias"} {
			v := str(m, k)
			if v != "" && !strings.Contains("|role_id|unique_id|instance_id|full_arn|", "|"+v+"|") {
				return fmt.Errorf("invalid %s", k)
			}
		}
	}
	if max := number(m, "max_ttl"); max > 0 && number(m, "ttl") > max {
		return fmt.Errorf("ttl exceeds max_ttl")
	}
	return nil
}
