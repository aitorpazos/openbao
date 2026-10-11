// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/quotas"
)

const activityUnavailable = "OpenBao does not collect billing activity: these are empty compatibility reports, not measured client utilization."

// licenseUsagePaths is a read-only license-free compatibility surface. In
// particular, identity inventory is NOT substituted for historical activity.
func (b *SystemBackend) licenseUsagePaths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"start_time": {Type: framework.TypeString}, "end_time": {Type: framework.TypeString},
		"limit_namespaces": {Type: framework.TypeInt}, "format": {Type: framework.TypeString, Default: "json"},
	}
	var configLock sync.Mutex
	config := func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		configLock.Lock()
		defer configLock.Unlock()
		return handleInternalCountersConfig(ctx, r, d)
	}
	paths := []*framework.Path{
		{Pattern: "license/status$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handleLicenseStatus}},
		{Pattern: "utilization-report$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.handleUtilizationReport}},
		{Pattern: "internal/counters/config$", Fields: map[string]*framework.FieldSchema{
			"enabled": {Type: framework.TypeString}, "retention_months": {Type: framework.TypeInt},
			"default_report_months": {Type: framework.TypeInt},
		}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: config, logical.UpdateOperation: config}},
	}
	for _, suffix := range []string{"", "/cumulative", "/monthly", "/export"} {
		paths = append(paths, &framework.Path{Pattern: "internal/counters/activity" + suffix + "$", Fields: fields,
			Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handleInternalCountersActivity}})
	}
	return paths
}

func handleLicenseStatus(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := licenseUsageRoot(ctx); err != nil {
		return nil, err
	}
	license := map[string]any{
		"add_ons": "", "architecture": []string{runtime.GOARCH}, "edition": "OpenBao",
		"expiration_time": "", "features": []string{}, "issuer": "", "license_id": "",
		"os": []string{runtime.GOOS}, "performance_standby_count": 0, "start_time": "", "termination_time": "",
	}
	return &logical.Response{Data: map[string]any{"autoloading_used": false, "autoloaded": license, "persisted_autoload": license},
		Warnings: []string{"OpenBao is license-free; no commercial license is loaded or required."}}, nil
}

func licenseUsageRoot(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrPermissionDenied
	}
	return nil
}

func emptyActivityCounts() map[string]any {
	return map[string]any{"entity_clients": 0, "non_entity_clients": 0, "clients": 0, "secret_syncs": 0, "acme_clients": 0}
}

func activityTime(s string) (time.Time, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Parse(time.RFC3339, s)
}

func handleInternalCountersActivity(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cumulative := strings.HasSuffix(r.Path, "/cumulative")
	if !cumulative {
		if err := licenseUsageRoot(ctx); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	start, end := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC), now
	for key, dest := range map[string]*time.Time{"start_time": &start, "end_time": &end} {
		if raw, ok := d.GetOk(key); ok {
			parsed, err := activityTime(raw.(string))
			if err != nil {
				return logical.ErrorResponse("invalid %s: expected RFC3339 or Unix seconds", key), logical.ErrInvalidRequest
			}
			*dest = parsed
		}
	}
	if start.After(end) {
		return logical.ErrorResponse("start_time must not be after end_time"), logical.ErrInvalidRequest
	}
	if d.Get("limit_namespaces").(int) < 0 {
		return logical.ErrorResponse("limit_namespaces must not be negative"), logical.ErrInvalidRequest
	}
	if strings.HasSuffix(r.Path, "/export") {
		format := d.Get("format").(string)
		if format != "json" && format != "csv" {
			return logical.ErrorResponse("format must be json or csv"), logical.ErrInvalidRequest
		}
		// Do not silently claim to export activity that OpenBao never collected.
		return logical.ErrorResponse("activity export is unavailable: OpenBao does not collect billing activity"), logical.ErrUnsupportedOperation
	}
	data := map[string]any{"start_time": start.Format(time.RFC3339), "end_time": end.Format(time.RFC3339),
		"total": emptyActivityCounts(), "by_namespace": []any{}, "months": []any{}}
	if cumulative {
		data["by_namespace"] = map[string]any{}
		delete(data, "months")
	}
	if strings.HasSuffix(r.Path, "/monthly") {
		data = emptyActivityCounts()
		data["by_namespace"] = []any{}
		data["months"] = []any{}
	}
	return &logical.Response{Data: data, Warnings: []string{activityUnavailable}}, nil
}

type internalCountersConfig struct {
	Enabled             string `json:"enabled"`
	RetentionMonths     int    `json:"retention_months"`
	DefaultReportMonths int    `json:"default_report_months"`
}

func handleInternalCountersConfig(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := licenseUsageRoot(ctx); err != nil {
		return nil, err
	}
	const key = "config/internal-counters"
	cfg := internalCountersConfig{Enabled: "default", RetentionMonths: 48, DefaultReportMonths: 12}
	entry, err := r.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		if err := entry.DecodeJSON(&cfg); err != nil {
			return nil, err
		}
	}
	if r.Operation == logical.UpdateOperation {
		if _, ok := d.Raw["enabled"]; ok {
			cfg.Enabled = d.Get("enabled").(string)
			if cfg.Enabled != "enable" && cfg.Enabled != "disable" && cfg.Enabled != "default" {
				return logical.ErrorResponse("enabled must be enable, disable, or default"), logical.ErrInvalidRequest
			}
		}
		if _, ok := d.Raw["retention_months"]; ok {
			cfg.RetentionMonths = d.Get("retention_months").(int)
			if cfg.RetentionMonths < 48 || cfg.RetentionMonths > 60 {
				return logical.ErrorResponse("retention_months must be between 48 and 60"), logical.ErrInvalidRequest
			}
		}
		if _, ok := d.Raw["default_report_months"]; ok {
			cfg.DefaultReportMonths = d.Get("default_report_months").(int)
			if cfg.DefaultReportMonths < 1 {
				return logical.ErrorResponse("default_report_months must be positive"), logical.ErrInvalidRequest
			}
		}
		if len(d.Raw) == 0 {
			return nil, nil
		}
		entry, err := logical.StorageEntryJSON(key, cfg)
		if err != nil {
			return nil, err
		}
		if err := r.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
		return &logical.Response{Warnings: []string{activityUnavailable}}, nil
	}
	enabled := cfg.Enabled
	if enabled == "default" {
		enabled = "default-disabled"
	}
	return &logical.Response{Data: map[string]any{"enabled": enabled, "retention_months": cfg.RetentionMonths,
		"default_report_months": cfg.DefaultReportMonths, "queries_available": false, "reporting_enabled": false,
		"billing_start_timestamp": ""}, Warnings: []string{activityUnavailable}}, nil
}

func (b *SystemBackend) handleUtilizationReport(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := licenseUsageRoot(ctx); err != nil {
		return nil, err
	}
	auth, engines := map[string]int{}, map[string]int{}
	b.Core.authLock.RLock()
	for _, e := range b.Core.auth.Entries {
		auth[e.Type]++
	}
	b.Core.authLock.RUnlock()
	b.Core.mountsLock.RLock()
	for _, e := range b.Core.mounts.Entries {
		engines[e.Type]++
	}
	b.Core.mountsLock.RUnlock()
	namespaces, err := b.Core.namespaceStore.ListNamespaces(ctx, ListNamespaceOpts{Recursive: true, IncludeSealed: true})
	if err != nil {
		return nil, err
	}
	names, err := b.Core.quotaManager.QuotaNames(quotas.TypeLeaseCount)
	if err != nil {
		return nil, fmt.Errorf("list lease quotas: %w", err)
	}
	return &logical.Response{Data: map[string]any{
		"auth_methods": auth, "secret_engines": engines, "namespaces": len(namespaces),
		"kvv1_secrets": 0, "kvv2_secrets": 0, "leases_by_auth_method": map[string]int{},
		"lease_count_quotas": map[string]any{"total_lease_count_quotas": len(names)},
		"pki":                map[string]int{"total_issuers": 0, "total_roles": 0},
		"replication_status": map[string]any{"dr_primary": false, "dr_state": "disabled", "pr_primary": false, "pr_state": "disabled"},
	}, Warnings: []string{"Partial snapshot: KV secret, PKI issuer/role and per-auth lease counts are not collected; zero/empty values for these fields mean unavailable, not measured zero. Replication fields describe native OpenBao replication only."}}, nil
}
