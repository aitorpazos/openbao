// SPDX-License-Identifier: MPL-2.0

package configonly

import (
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
)

func (b *Backend) routes() {
	const s = framework.TypeString
	const a = framework.TypeCommaStringSlice
	const d = framework.TypeDurationSecond
	const flag = framework.TypeBool
	const kv = framework.TypeKVPairs
	f := fields(s, "identity_token_audience rotation_schedule")
	add(f, d, "identity_token_ttl rotation_period rotation_window")
	f["identity_token_ttl"].Default = 3600
	add(f, flag, "disable_automated_rotation verify_connection")
	path := "config"
	switch b.provider {
	case "aws":
		path = "config/client"
		if b.secret {
			path = "config/root"
		}
		add(f, s, "access_key secret_key token session_token region role_arn sts_endpoint sts_region iam_endpoint")
		add(f, framework.TypeInt, "max_retries")
		f["max_retries"].Default = -1
		if b.secret {
			add(f, s, "username_template")
			add(f, a, "sts_fallback_endpoints sts_fallback_regions")
		} else {
			add(f, s, "endpoint iam_server_id_header_value")
			add(f, a, "allowed_sts_header_values")
			add(f, flag, "use_sts_region_from_client")
		}
	case "azure":
		add(f, s, "tenant_id client_id client_secret environment subscription_id resource_group_name")
		f["environment"].Default = "AzurePublicCloud"
		if b.secret {
			add(f, s, "password_policy")
			add(f, d, "root_password_ttl")
			f["root_password_ttl"].Default = 15724800
		} else {
			add(f, s, "resource")
			add(f, framework.TypeInt, "max_retries")
			f["max_retries"].Default = 3
			add(f, d, "max_retry_delay retry_delay")
			f["max_retry_delay"].Default = 60
			f["retry_delay"].Default = 4
		}
	case "gcp":
		add(f, s, "credentials service_account_email")
		if b.secret {
			add(f, d, "ttl max_ttl")
		} else {
			add(f, a, "regions")
			add(f, kv, "custom_endpoint")
		}
	}
	b.singleton(path, f)
	if !b.secret {
		role := fields(s, "")
		tokenutil.AddTokenFields(role)
		role["token_type"].Default = "default"
		add(role, a, "policies")
		add(role, kv, "alias_metadata")
		switch b.provider {
		case "aws":
			add(role, s, "auth_type role_tag inferred_entity_type inferred_aws_region")
			role["auth_type"].Default = "iam"
			add(role, a, "bound_ami_id bound_account_id bound_region bound_vpc_id bound_subnet_id bound_iam_role_arn bound_iam_instance_profile_arn bound_ec2_instance_id bound_iam_principal_arn")
			add(role, flag, "resolve_aws_unique_ids allow_instance_migration disallow_reauthentication")
			role["resolve_aws_unique_ids"].Default = true
			cert := fields(s, "aws_public_cert type")
			cert["type"].Default = "pkcs7"
			b.collection("config/certificate", "config/certificates", cert)
			b.collection("config/sts", "config/sts", fields(s, "sts_role external_id"))
			identity := fields(s, "iam_alias ec2_alias")
			identity["iam_alias"].Default = "role_id"
			identity["ec2_alias"].Default = "role_id"
			add(identity, a, "iam_metadata ec2_metadata")
			b.singleton("config/identity", identity)
		case "azure":
			add(role, a, "bound_service_principal_ids bound_group_ids bound_locations bound_subscription_ids bound_resource_groups bound_scale_sets")
		case "gcp":
			add(role, s, "type")
			add(role, a, "bound_service_accounts bound_projects bound_zones bound_regions bound_instance_groups bound_labels")
			add(role, flag, "add_group_aliases allow_gce_inference")
			role["allow_gce_inference"].Default = true
			add(role, d, "max_jwt_exp")
			role["max_jwt_exp"].Default = 900
			identity := fields(s, "iam_alias gce_alias")
			identity["iam_alias"].Default = "role_id"
			identity["gce_alias"].Default = "role_id"
			add(identity, a, "iam_metadata gce_metadata")
			b.singleton("config/identity", identity)
		}
		b.collection("role", "role", role)
	} else {
		switch b.provider {
		case "aws":
			role := fields(s, "credential_type policy_document external_id user_path permissions_boundary_arn mfa_serial_number policy arn")
			add(role, a, "role_arns policy_arns iam_groups")
			add(role, kv, "iam_tags session_tags")
			add(role, d, "default_sts_ttl max_sts_ttl")
			b.collection("roles", "roles", role)
			b.singleton("config/lease", fields(d, "lease lease_max"))
		case "azure":
			role := fields(s, "azure_roles azure_groups application_object_id sign_in_audience tags")
			add(role, flag, "persist_app permanently_delete")
			add(role, d, "ttl max_ttl explicit_max_ttl")
			add(role, kv, "metadata")
			b.collection("roles", "roles", role)
		case "gcp":
			for _, kind := range []string{"roleset", "static-account"} {
				role := fields(s, "secret_type bindings")
				role["secret_type"].Default = "access_token"
				add(role, a, "token_scopes")
				if kind == "roleset" {
					add(role, s, "project")
				} else {
					add(role, s, "service_account_email")
				}
				b.collection(kind, kind+"s", role)
				b.reject(kind + "/[^/]+/(token|key|rotate|rotate-key)")
			}
		}
		b.reject("(creds|sts|static-creds|token|key)/[^/]+")
	}
	b.reject("(config/)?rotate-root")
	b.reject("rotate-role/[^/]+")
}
