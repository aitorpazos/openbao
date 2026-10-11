// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Configuration only: no remote operations are performed by this registry.
func (b *SystemBackend) managedKeyPaths() []*framework.Path {
	var mu sync.Mutex
	fields := map[string]*framework.FieldSchema{}
	for _, s := range strings.Fields("type name library key_label key_id mechanism pin slot token_label curve key_bits rsa_oaep_hash access_key secret_key session_token endpoint key_type kms_key region tenant_id client_id client_secret environment vault_name key_name resource encryption_mode credentials crypto_key crypto_key_version key_ring project algorithm") {
		fields[s] = &framework.FieldSchema{Type: framework.TypeString}
	}
	for _, s := range strings.Fields("allow_generate_key allow_replace_key allow_store_key any_mount force_rw_session") {
		fields[s] = &framework.FieldSchema{Type: framework.TypeBool}
	}
	fields["max_parallel"] = &framework.FieldSchema{Type: framework.TypeInt}
	fields["usages"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
	handler := func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		typ := d.Get("type").(string)
		switch typ {
		case "pkcs11", "awskms", "azurekeyvault", "gcpckms":
		default:
			return logical.ErrorResponse("unsupported managed key type"), nil
		}
		name := d.Get("name").(string)
		prefix := "managed-keys/" + typ + "/"
		path := prefix + name
		if r.Operation == logical.ListOperation {
			keys, err := r.Storage.List(ctx, prefix)
			return logical.ListResponse(keys), err
		}
		if name != strings.ToLower(name) {
			return logical.ErrorResponse("name must be lowercase"), nil
		}
		e, err := r.Storage.Get(ctx, path)
		if err != nil {
			return nil, err
		}
		data := map[string]interface{}{}
		if e != nil {
			if err = e.DecodeJSON(&data); err != nil {
				return nil, err
			}
		}
		switch r.Operation {
		case logical.ReadOperation:
			if e == nil {
				return nil, nil
			}
			for _, f := range strings.Fields("pin access_key secret_key session_token client_secret credentials") {
				if _, ok := data[f]; ok {
					data[f] = "redacted"
				}
			}
			return &logical.Response{Data: data}, nil
		case logical.DeleteOperation:
			return nil, r.Storage.Delete(ctx, path)
		case logical.UpdateOperation:
			for _, other := range []string{"pkcs11", "awskms", "azurekeyvault", "gcpckms"} {
				if other == typ {
					continue
				}
				entry, err := r.Storage.Get(ctx, "managed-keys/"+other+"/"+name)
				if err != nil {
					return nil, err
				}
				if entry != nil {
					return logical.ErrorResponse("name is already used by another managed key type"), nil
				}
			}
			if e == nil {
				for _, f := range strings.Fields("allow_generate_key allow_replace_key allow_store_key any_mount") {
					data[f] = false
				}
				data["usages"] = []string{"sign", "verify"}
				id, err := uuid.GenerateUUID()
				if err != nil {
					return nil, err
				}
				data["UUID"] = id
			}
			for f := range fields {
				if v, ok := d.GetOk(f); ok {
					data[f] = v
				}
			}
			data["name"] = name
			data["type"] = typ
			if err := validateManagedKey(typ, data); err != nil {
				return logical.ErrorResponse("%s", err), nil
			}
			if err = keyMgmtSave(ctx, r.Storage, path, data); err != nil {
				return nil, err
			}
			return &logical.Response{Warnings: []string{"Configuration stored locally only; cloud/HSM credentials are not validated. Remote signing, generation and mount-use integration are unavailable."}}, nil
		}
		return nil, logical.ErrUnsupportedOperation
	}
	callbacks := map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handler, logical.UpdateOperation: handler, logical.DeleteOperation: handler}
	return []*framework.Path{{Pattern: "managed-keys/(?P<type>[^/]+)/?", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: handler}}, {Pattern: "managed-keys/(?P<type>[^/]+)/(?P<name>[^/]+)", Fields: fields, Callbacks: callbacks}}
}
func validateManagedKey(typ string, m map[string]interface{}) error {
	str := func(k string) string { v, _ := m[k].(string); return v }
	required := func(names string) error {
		for _, k := range strings.Fields(names) {
			if str(k) == "" {
				return fmt.Errorf("%s is required", k)
			}
		}
		return nil
	}
	gen, _ := m["allow_generate_key"].(bool)
	bits := func() error {
		switch str("key_bits") {
		case "2048", "3072", "4096":
			return nil
		}
		return fmt.Errorf("key_bits must be 2048, 3072 or 4096")
	}
	curve := func() error {
		switch str("curve") {
		case "P256", "P384", "P521":
			return nil
		}
		return fmt.Errorf("curve must be P256, P384 or P521")
	}
	switch typ {
	case "pkcs11":
		if err := required("library mechanism pin"); err != nil {
			return err
		}
		if str("key_label") == "" && str("key_id") == "" {
			return fmt.Errorf("key_label or key_id is required")
		}
		if str("slot") == "" && str("token_label") == "" {
			return fmt.Errorf("slot or token_label is required")
		}
		if str("slot") != "" {
			if _, err := strconv.ParseUint(str("slot"), 10, 64); err != nil {
				return fmt.Errorf("slot must be decimal")
			}
		}
		mech, err := strconv.ParseUint(strings.TrimPrefix(str("mechanism"), "0x"), 16, 64)
		if err != nil || !strings.HasPrefix(str("mechanism"), "0x") {
			return fmt.Errorf("mechanism must be hexadecimal with 0x prefix")
		}
		if gen {
			switch mech {
			case 0x1041:
				if err := curve(); err != nil {
					return err
				}
			case 1, 9, 13:
				if err := bits(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("automatic generation is unavailable for this mechanism")
			}
		}
	case "awskms":
		if err := required("kms_key key_type"); err != nil {
			return err
		}
		switch strings.ToUpper(str("key_type")) {
		case "RSA":
			if err := bits(); err != nil {
				return err
			}
		case "ECDSA":
			if err := curve(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("key_type must be RSA or ECDSA")
		}
		if gen && !strings.HasPrefix(str("kms_key"), "alias/") && !strings.Contains(str("kms_key"), ":alias/") {
			return fmt.Errorf("generation requires an AWS alias")
		}
	case "azurekeyvault":
		if err := required("tenant_id vault_name key_name key_type"); err != nil {
			return err
		}
		if str("key_type") != "RSA-HSM" {
			return fmt.Errorf("key_type must be RSA-HSM")
		}
		if str("client_secret") != "" && str("client_id") == "" {
			return fmt.Errorf("client_id is required with client_secret")
		}
		if gen {
			if err := bits(); err != nil {
				return err
			}
		}
		if mode := str("encryption_mode"); mode != "" && mode != "raw" && mode != "envelope" {
			return fmt.Errorf("invalid encryption_mode")
		}
	case "gcpckms":
		for _, k := range []string{"project", "region"} {
			if str(k) == "" {
				m[k] = os.Getenv("GOOGLE_" + strings.ToUpper(k))
			}
		}
		if err := required("crypto_key key_ring project region algorithm"); err != nil {
			return err
		}
		switch str("algorithm") {
		case "EC_SIGN_P256_SHA256", "EC_SIGN_P384_SHA384", "RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PSS_3072_SHA256", "RSA_SIGN_PSS_4096_SHA256", "RSA_SIGN_PSS_4096_SHA512", "RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PKCS1_3072_SHA256", "RSA_SIGN_PKCS1_4096_SHA256", "RSA_SIGN_PKCS1_4096_SHA512":
		default:
			return fmt.Errorf("unsupported signing algorithm")
		}
	}
	// JSON persistence turns slices into []interface{}; normalize both forms.
	var usages []string
	switch v := m["usages"].(type) {
	case []string:
		usages = v
	case []interface{}:
		for _, u := range v {
			usages = append(usages, fmt.Sprint(u))
		}
	}
	for _, u := range usages {
		switch u {
		case "encrypt", "decrypt", "sign", "verify", "wrap", "unwrap", "mac", "generate_random":
		default:
			return fmt.Errorf("unsupported usage %q", u)
		}
	}
	return nil
}
