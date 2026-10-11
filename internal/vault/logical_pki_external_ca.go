// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// PKIExternalCAFactory provides isolated external ACME client configuration storage
// for the documented pki-external-ca mount type. It never registers an account,
// changes DNS, or pretends to issue certificates.
func PKIExternalCAFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &framework.Backend{BackendType: logical.TypeLogical, Help: "External ACME CA configuration. Remote ACME and DNS operations are not implemented."}
	var mu sync.Mutex
	add := func(pattern string, fields map[string]*framework.FieldSchema, handler framework.OperationFunc, ops ...logical.Operation) {
		p := &framework.Path{Pattern: pattern, Fields: fields, Operations: map[logical.Operation]framework.OperationHandler{}}
		for _, op := range ops {
			p.Operations[op] = &framework.PathOperation{Callback: handler, ForwardPerformanceStandby: op != logical.ReadOperation && op != logical.ListOperation, ForwardPerformanceSecondary: op != logical.ReadOperation && op != logical.ListOperation}
		}
		b.Paths = append(b.Paths, p)
	}
	name := framework.GenericNameRegex("name")
	accountFields := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "directory_url": {Type: framework.TypeString}, "email_contacts": {Type: framework.TypeCommaStringSlice}, "private_key": {Type: framework.TypeString}}
	add("config/acme-account/"+name+"(/import|/rotate-key)?", accountFields, func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		if r.Operation == logical.ReadOperation {
			return nil, nil
		}
		u, err := url.Parse(d.Get("directory_url").(string))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return logical.ErrorResponse("directory_url is required and must be an HTTP(S) URL"), nil
		}
		return logical.ErrorResponse("remote ACME account registration, import, rotation and deactivation are not implemented"), nil
	}, logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation)
	for _, prefix := range []string{"config/acme-account", "role"} {
		add(prefix+"/?", nil, func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
			keys, err := r.Storage.List(ctx, strings.TrimSuffix(r.Path, "/")+"/")
			if err != nil {
				return nil, err
			}
			return logical.ListResponse(keys), nil
		}, logical.ListOperation)
	}
	add("role/"+name, map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "acme_account_name": {Type: framework.TypeString}, "allowed_domains": {Type: framework.TypeCommaStringSlice}}, func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		if r.Operation == logical.ReadOperation {
			return nil, nil
		}
		if d.Get("acme_account_name") == "" {
			return logical.ErrorResponse("acme_account_name is required"), nil
		}
		return logical.ErrorResponse("a registered ACME account is required; remote ACME operations are not implemented"), nil
	}, logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation)
	dnsFields := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "provider": {Type: framework.TypeString}, "identifiers": {Type: framework.TypeCommaStringSlice}, "nameserver": {Type: framework.TypeString}, "tsig_key_name": {Type: framework.TypeString}, "tsig_secret": {Type: framework.TypeString}, "tsig_algorithm": {Type: framework.TypeString, Default: "hmac-sha1"}, "ttl": {Type: framework.TypeDurationSecond, Default: 60}}
	add("config/dns/(?P<provider>aws-route53|azure-dns|google-cloud-dns|rfc2136)/"+name, dnsFields, func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		path := r.Path
		if r.Operation == logical.DeleteOperation {
			return nil, r.Storage.Delete(ctx, path)
		}
		c := map[string]interface{}{"ttl": 60, "tsig_algorithm": "hmac-sha1"}
		entry, err := r.Storage.Get(ctx, path)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err = entry.DecodeJSON(&c); err != nil {
				return nil, err
			}
		}
		if r.Operation == logical.ReadOperation {
			if entry == nil {
				return nil, nil
			}
			delete(c, "tsig_secret")
			return &logical.Response{Data: c}, nil
		}
		for k := range dnsFields {
			if v, ok := d.GetOk(k); ok {
				c[k] = v
			}
		}
		fd := &framework.FieldData{Raw: c, Schema: dnsFields}
		if len(fd.Get("identifiers").([]string)) == 0 {
			return logical.ErrorResponse("identifiers is required"), nil
		}
		for _, identifier := range fd.Get("identifiers").([]string) {
			if strings.TrimSpace(identifier) == "" {
				return logical.ErrorResponse("identifiers must not contain empty domains"), nil
			}
		}
		if d.Get("provider") != "rfc2136" {
			return logical.ErrorResponse("cloud DNS provider configuration is not implemented"), nil
		}
		for _, k := range []string{"nameserver", "tsig_key_name", "tsig_secret"} {
			if fd.Get(k) == "" {
				return logical.ErrorResponse("%s is required", k), nil
			}
		}
		if _, err = base64.StdEncoding.DecodeString(fd.Get("tsig_secret").(string)); err != nil {
			return logical.ErrorResponse("tsig_secret must be base64 encoded"), nil
		}
		if !slices.Contains([]string{"hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"}, fd.Get("tsig_algorithm").(string)) {
			return logical.ErrorResponse("invalid tsig_algorithm"), nil
		}
		if fd.Get("ttl").(int) <= 0 {
			return logical.ErrorResponse("ttl must be positive"), nil
		}
		c["name"] = d.Get("name")
		c["type"] = d.Get("provider")
		delete(c, "provider")
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if entry == nil {
			c["creation_date"] = now
		}
		c["last_updated_date"] = now
		entry, err = logical.StorageEntryJSON(path, c)
		if err != nil {
			return nil, err
		}
		if err = r.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
		delete(c, "tsig_secret")
		return &logical.Response{Data: c, Warnings: []string{"Configuration stored only; DNS updates and remote ACME operations are not implemented."}}, nil
	}, logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation)
	add("config/dns/(?P<provider>aws-route53|azure-dns|google-cloud-dns|rfc2136)/?", dnsFields, func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		keys, err := r.Storage.List(ctx, "config/dns/"+d.Get("provider").(string)+"/")
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(keys), nil
	}, logical.ListOperation)
	add("config/dns/?", nil, func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		keys := []string{}
		info := map[string]interface{}{}
		for _, p := range []string{"aws-route53", "azure-dns", "google-cloud-dns", "rfc2136"} {
			names, err := r.Storage.List(ctx, "config/dns/"+p+"/")
			if err != nil {
				return nil, err
			}
			for _, n := range names {
				key := p + "/" + n
				keys = append(keys, key)
				info[key] = map[string]interface{}{"name": n, "type": p}
			}
		}
		slices.Sort(keys)
		resp := logical.ListResponse(keys)
		resp.Data["key_info"] = info
		return resp, nil
	}, logical.ListOperation)
	lookupOrdersHandler := func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		within := d.Get("within").(int)
		if within < 3600 || within > 604800 {
			return logical.ErrorResponse("within must be between 1h and 168h"), nil
		}
		return logical.ListResponse([]string{}), nil
	}
	lookupOrdersFields := map[string]*framework.FieldSchema{"within": {Type: framework.TypeDurationSecond, Default: 86400}}
	add("lookup/orders/recent", lookupOrdersFields, lookupOrdersHandler, logical.ReadOperation, logical.ListOperation)
	add("lookup/orders/recent/", lookupOrdersFields, lookupOrdersHandler, logical.ReadOperation, logical.ListOperation)
	add("dns/test/workflow", nil, func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
		return logical.ErrorResponse("remote DNS updates are not implemented"), nil
	}, logical.UpdateOperation)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
