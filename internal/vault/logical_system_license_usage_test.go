// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

func licenseUsageTestRequest(t *testing.T, b *SystemBackend, storage logical.Storage, path string, op logical.Operation, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(namespace.RootContext(context.Background()), &logical.Request{Path: path, Operation: op, Data: data, Storage: storage})
	if err != nil {
		t.Fatalf("%s: %v (%#v)", path, err, resp)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("%s: %#v", path, resp)
	}
	return resp
}

func TestLicenseStatus(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	resp := licenseUsageTestRequest(t, c.systemBackend, &logical.InmemStorage{}, "license/status", logical.ReadOperation, nil)
	if resp.Data["autoloading_used"] != false {
		t.Fatal(resp)
	}
	for _, key := range []string{"autoloaded", "persisted_autoload"} {
		license := resp.Data[key].(map[string]any)
		if license["edition"] != "OpenBao" || license["license_id"] != "" {
			t.Fatal(license)
		}
		for _, field := range []string{"add_ons", "expiration_time", "issuer", "start_time", "termination_time"} {
			if _, ok := license[field].(string); !ok {
				t.Fatalf("%s missing string", field)
			}
		}
		if _, ok := license["features"].([]string); !ok {
			t.Fatal(license)
		}
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("license-free semantics must be explicit")
	}
}

func TestUtilizationReport(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	resp := licenseUsageTestRequest(t, c.systemBackend, &logical.InmemStorage{}, "utilization-report", logical.ReadOperation, nil)
	if resp.Data["auth_methods"].(map[string]int)["token"] != 1 {
		t.Fatal(resp.Data)
	}
	if resp.Data["secret_engines"].(map[string]int)["system"] != 1 {
		t.Fatal(resp.Data)
	}
	if _, ok := resp.Data["lease_count_quotas"].(map[string]any)["total_lease_count_quotas"].(int); !ok {
		t.Fatal(resp.Data)
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("unmeasured fields must be identified")
	}
}

func TestInternalCountersActivity(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	s := &logical.InmemStorage{}
	for _, suffix := range []string{"", "/cumulative", "/monthly"} {
		t.Run(suffix, func(t *testing.T) {
			resp := licenseUsageTestRequest(t, c.systemBackend, s, "internal/counters/activity"+suffix, logical.ReadOperation, nil)
			if suffix == "/cumulative" {
				if _, ok := resp.Data["by_namespace"].(map[string]any); !ok {
					t.Fatal(resp.Data)
				}
			} else {
				if v, ok := resp.Data["by_namespace"].([]any); !ok || v == nil {
					t.Fatal(resp.Data)
				}
			}
			counts := resp.Data
			if suffix != "/monthly" {
				counts = resp.Data["total"].(map[string]any)
			}
			for _, field := range []string{"entity_clients", "non_entity_clients", "clients", "secret_syncs", "acme_clients"} {
				if counts[field] != 0 {
					t.Fatal(counts)
				}
			}
			if len(resp.Warnings) == 0 {
				t.Fatal("uncollected billing data must not be presented as measured zero")
			}
		})
	}
	a := licenseUsageTestRequest(t, c.systemBackend, s, "internal/counters/activity", logical.ReadOperation, map[string]any{"start_time": "2025-06-01T00:00:00Z", "end_time": "2025-06-30T00:00:00Z", "limit_namespaces": 2})
	b := licenseUsageTestRequest(t, c.systemBackend, s, "internal/counters/activity", logical.ReadOperation, map[string]any{"start_time": "1748736000", "end_time": "1751241600"})
	if !reflect.DeepEqual(a.Data, b.Data) {
		t.Fatalf("RFC3339 and Unix differ: %v / %v", a.Data, b.Data)
	}
}

func TestInternalCountersConfig(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	s := &logical.InmemStorage{}
	path := "internal/counters/config"
	read := func() map[string]any {
		return licenseUsageTestRequest(t, c.systemBackend, s, path, logical.ReadOperation, nil).Data
	}
	before := read()
	licenseUsageTestRequest(t, c.systemBackend, s, path, logical.UpdateOperation, map[string]any{})
	if !reflect.DeepEqual(before, read()) {
		t.Fatal("empty write changed config")
	}
	licenseUsageTestRequest(t, c.systemBackend, s, path, logical.UpdateOperation, map[string]any{"enabled": "disable", "retention_months": 60})
	after := read()
	if after["enabled"] != "disable" || after["retention_months"] != 60 {
		t.Fatal(after)
	}
	licenseUsageTestRequest(t, c.systemBackend, s, path, logical.UpdateOperation, map[string]any{})
	if !reflect.DeepEqual(after, read()) {
		t.Fatal("empty write reset persisted config")
	}
	for _, data := range []map[string]any{{"enabled": "bad"}, {"retention_months": 47}, {"retention_months": 61}, {"enabled": "enable", "retention_months": 0}} {
		resp, err := c.systemBackend.HandleRequest(namespace.RootContext(context.Background()), &logical.Request{Path: path, Operation: logical.UpdateOperation, Data: data, Storage: s})
		if err != logical.ErrInvalidRequest || resp == nil || !resp.IsError() {
			t.Fatalf("invalid accepted: %v %v", resp, err)
		}
		if !reflect.DeepEqual(after, read()) {
			t.Fatal("invalid write mutated configuration")
		}
	}
}

func TestInternalCountersValidation(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	defer c.Shutdown()
	for _, tc := range []struct {
		suffix string
		data   map[string]any
	}{
		{"", map[string]any{"start_time": "invalid"}},
		{"/cumulative", map[string]any{"end_time": "invalid"}},
		{"", map[string]any{"start_time": "2025-06-30T00:00:00Z", "end_time": "2025-06-01T00:00:00Z"}},
		{"", map[string]any{"limit_namespaces": -1}},
		{"/export", map[string]any{"format": "bad"}},
		{"/export", map[string]any{"end_time": "bad", "format": "json"}},
	} {
		resp, err := c.systemBackend.HandleRequest(namespace.RootContext(context.Background()), &logical.Request{Path: "internal/counters/activity" + tc.suffix, Operation: logical.ReadOperation, Data: tc.data})
		if err != logical.ErrInvalidRequest || resp == nil || !resp.IsError() {
			t.Fatalf("%v: %v %v", tc, resp, err)
		}
	}
	child := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", Path: "child/"})
	for _, path := range []string{"license/status", "utilization-report", "internal/counters/activity", "internal/counters/activity/monthly", "internal/counters/config"} {
		_, err := c.systemBackend.HandleRequest(child, &logical.Request{Path: path, Operation: logical.ReadOperation})
		if err != logical.ErrPermissionDenied {
			t.Fatalf("%s: %v", path, err)
		}
	}
	resp, err := c.systemBackend.HandleRequest(child, &logical.Request{Path: "internal/counters/activity/cumulative", Operation: logical.ReadOperation})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("cumulative must allow child namespace: %v %v", resp, err)
	}
}
