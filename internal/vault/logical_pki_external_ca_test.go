// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestPKIExternalCAConfiguration(t *testing.T) {
	s := &logical.InmemStorage{}
	b, err := PKIExternalCAFactory(t.Context(), &logical.BackendConfig{StorageView: s, System: &logical.StaticSystemView{}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(op logical.Operation, path string, d map[string]interface{}, invalid bool) *logical.Response {
		t.Helper()
		r, e := b.HandleRequest(t.Context(), &logical.Request{Operation: op, Path: path, Storage: s, Data: d})
		if e != nil {
			t.Fatal(e)
		}
		if (r != nil && r.IsError()) != invalid {
			t.Fatalf("%s %s: %#v", op, path, r)
		}
		return r
	}
	for _, path := range []string{"config/acme-account/a", "config/acme-account/a/import", "role/r", "config/dns/aws-route53/d", "config/dns/azure-dns/d", "config/dns/google-cloud-dns/d", "config/dns/rfc2136/d"} {
		request(logical.UpdateOperation, path, map[string]interface{}{}, true)
	}
	for _, within := range []string{"30m", "169h"} {
		request(logical.ListOperation, "lookup/orders/recent", map[string]interface{}{"within": within}, true)
	}
	d := map[string]interface{}{"identifiers": []string{"example.invalid"}, "nameserver": "127.0.0.1:1", "tsig_key_name": "dummy", "tsig_secret": "c2VjcmV0", "tsig_algorithm": "hmac-sha256", "ttl": "60s"}
	for _, bad := range []map[string]interface{}{{"tsig_secret": "!"}, {"tsig_algorithm": "invalid"}, {"ttl": -1}} {
		data := map[string]interface{}{}
		for k, v := range d {
			data[k] = v
		}
		for k, v := range bad {
			data[k] = v
		}
		request(logical.UpdateOperation, "config/dns/rfc2136/d", data, true)
	}
	r := request(logical.UpdateOperation, "config/dns/rfc2136/d", d, false)
	if _, ok := r.Data["tsig_secret"]; ok {
		t.Fatal("secret leaked")
	}
	created := r.Data["creation_date"]
	request(logical.UpdateOperation, "config/dns/rfc2136/d", map[string]interface{}{"ttl": "120s"}, false)
	r = request(logical.ReadOperation, "config/dns/rfc2136/d", nil, false)
	if r.Data["ttl"] != json.Number("120") || r.Data["creation_date"] != created {
		t.Fatal(r.Data)
	}
	if _, ok := r.Data["tsig_secret"]; ok {
		t.Fatal("secret leaked")
	}
	r = request(logical.ListOperation, "config/dns", nil, false)
	if len(r.Data["keys"].([]string)) != 1 {
		t.Fatal(r)
	}
	request(logical.DeleteOperation, "config/dns/rfc2136/d", nil, false)
	if r = request(logical.ReadOperation, "config/dns/rfc2136/d", nil, false); r != nil {
		t.Fatal(r)
	}
}
