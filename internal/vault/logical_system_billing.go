// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// billingPaths implement the documented /sys/billing surfaces as a
// license-free compatibility contract. OpenBao does not measure
// usage-based-licensing activity, so reports are schema-shaped but
// zero/empty, and the warning text says so. Nothing is fabricated from
// identity inventory or other live state.
func (b *SystemBackend) billingPaths() []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern: "billing/config$",
			Fields: map[string]*framework.FieldSchema{
				"retention_months": {Type: framework.TypeInt},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleBillingConfig},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleBillingConfig},
			},
		},
		{
			Pattern: "billing/overview$",
			Fields: map[string]*framework.FieldSchema{
				"refresh_data": {Type: framework.TypeBool, Default: false},
				"start_month":  {Type: framework.TypeString},
				"end_month":    {Type: framework.TypeString},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleBillingOverview},
			},
		},
		{
			Pattern: "billing/certificates$",
			Fields: map[string]*framework.FieldSchema{
				"start_time": {Type: framework.TypeString},
				"end_time":   {Type: framework.TypeString},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleBillingCertificates},
			},
		},
	}
	return paths
}

// billingConfig is the persisted billing retention configuration.
type billingConfig struct {
	RetentionMonths int `json:"retention_months"`
}

// billingMonth validates and parses a documented YYYY-MM month stamp.
func billingMonth(s, field string) (time.Time, error) {
	t, err := time.Parse("2006-01", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must use the YYYY-MM format", field)
	}
	return t, nil
}

// billingWarning is shared across the billing surfaces; it states plainly
// that no usage-based-licensing activity is collected.
const billingWarning = "OpenBao does not collect billing activity: these are empty compatibility reports, not measured usage."

// billingMonthOf truncates a time to its YYYY-MM month in UTC.
func billingMonthOf(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// handleBillingConfig reads and updates the billing data retention
// configuration. The retention window holds between 13 (minimum) and 72
// (maximum) months including the current month; the documented default is
// 37. Increasing the retention period yields the documented warning; Vault
// does not restore historical data, and neither does OpenBao.
func (b *SystemBackend) handleBillingConfig(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := licenseUsageRoot(ctx); err != nil {
		return nil, err
	}
	const key = "config/billing"
	// The value is stored as an object on purpose: a bare integer's first
	// byte collides with the lz4 compression canary ('4') in the storage
	// JSON decode path.
	var current, previous billingConfig
	if entry, err := r.Storage.Get(ctx, key); err != nil {
		return nil, err
	} else if entry != nil {
		if err := entry.DecodeJSON(&current); err != nil {
			return nil, err
		}
	}
	previous = current
	if r.Operation == logical.UpdateOperation {
		retention, ok := d.GetOk("retention_months")
		if !ok {
			return logical.ErrorResponse("retention_months is required"), logical.ErrInvalidRequest
		}
		current.RetentionMonths = retention.(int)
		if current.RetentionMonths < 13 || current.RetentionMonths > 72 {
			return logical.ErrorResponse("retention_months must be between 13 and 72"), logical.ErrInvalidRequest
		}
		entry, err := logical.StorageEntryJSON(key, current)
		if err != nil {
			return nil, err
		}
		if err := r.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
	}
	retention := current.RetentionMonths
	if retention == 0 {
		retention = 37
	}
	resp := &logical.Response{Data: map[string]any{"retention_months": retention}}
	if previous.RetentionMonths != 0 && current.RetentionMonths > previous.RetentionMonths {
		resp.Warnings = []string{fmt.Sprintf("Retention period increased from %d to %d months. Historical data will only be available for months within the previous retention period. Data for months older than %d months ago will not be restored.", previous.RetentionMonths, current.RetentionMonths, previous.RetentionMonths)}
	}
	return resp, nil
}

// billingMetricDetails builds a documented type/count detail list.
func billingMetricDetails(types []string, value any) []map[string]any {
	details := make([]map[string]any, len(types))
	for i, t := range types {
		details[i] = map[string]any{"type": t, "count": value}
	}
	return details
}

// billingUsageMetrics returns the eleven documented usage metrics in the
// documented order, all at zero: no usage-based-licensing activity is
// measured.
func billingUsageMetrics() []map[string]any {
	return []map[string]any{
		{"metric_name": "static_secrets", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"kv"}, 0)}},
		{"metric_name": "dynamic_roles", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"aws_dynamic", "azure_dynamic", "database_dynamic", "gcp_dynamic", "ldap_dynamic", "ldap_library", "openldap_dynamic", "openldap_library", "alicloud_dynamic", "rabbitmq_dynamic", "consul_dynamic", "nomad_dynamic", "kubernetes_dynamic", "mongodbatlas_dynamic", "terraform_dynamic"}, 0)}},
		{"metric_name": "auto_rotated_roles", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"aws_static", "azure_static", "database_static", "gcp_static", "gcp_impersonated", "ldap_static", "openldap_static", "os_local_account_static"}, 0)}},
		{"metric_name": "kmip", "metric_data": map[string]any{"used_in_month": false}},
		{"metric_name": "pki_units", "metric_data": map[string]any{"total": 0}},
		{"metric_name": "ssh_units", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"otp_units", "certificate_units"}, 0)}},
		{"metric_name": "external_plugins", "metric_data": map[string]any{"total": 0}},
		{"metric_name": "data_protection_calls", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"transit", "transform", "gcpkms"}, 0)}},
		{"metric_name": "managed_keys", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"kmse", "totp"}, 0)}},
		{"metric_name": "id_token_units", "metric_data": map[string]any{"total": 0, "metric_details": billingMetricDetails([]string{"oidc", "spiffe"}, 0)}},
		{"metric_name": "external_ca_pki_units", "metric_data": map[string]any{"total": 0}},
	}
}

// handleBillingOverview returns the monthly usage overview. Only the
// current month is reported: OpenBao never accumulated historical billing
// data, and the docs describe the response as the months Vault has. The
// requested range is validated; months that carry no data are simply
// absent rather than synthesized.
func (b *SystemBackend) handleBillingOverview(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := licenseUsageRoot(ctx); err != nil {
		return nil, err
	}
	now := billingMonthOf(time.Now().UTC())
	var start, end time.Time
	haveStart, haveEnd := false, false
	if raw, ok := d.GetOk("start_month"); ok {
		t, err := billingMonth(raw.(string), "start_month")
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		start, haveStart = billingMonthOf(t), true
	}
	if raw, ok := d.GetOk("end_month"); ok {
		t, err := billingMonth(raw.(string), "end_month")
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		end, haveEnd = billingMonthOf(t), true
	}
	if haveStart && haveEnd && start.After(end) {
		return logical.ErrorResponse("start_month must not be after end_month"), logical.ErrInvalidRequest
	}
	months := []map[string]any{}
	if (!haveStart || !start.After(now)) && (!haveEnd || !end.Before(now)) {
		months = append(months, map[string]any{
			"month":         now.Format("2006-01"),
			"updated_at":    time.Now().UTC().Format(time.RFC3339),
			"usage_metrics": billingUsageMetrics(),
		})
	}
	return &logical.Response{Data: map[string]any{"months": months}, Warnings: []string{billingWarning}}, nil
}

// handleBillingCertificates reports the monthly PKI certificate counts.
// OpenBao does not track issued-certificate billing data, so each requested
// month carries the documented not-found error shape rather than a
// fabricated count.
func (b *SystemBackend) handleBillingCertificates(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := licenseUsageRoot(ctx); err != nil {
		return nil, err
	}
	rawStart, haveStart := d.GetOk("start_time")
	rawEnd, haveEnd := d.GetOk("end_time")
	if haveStart != haveEnd {
		return logical.ErrorResponse("start_time and end_time must be provided together"), logical.ErrInvalidRequest
	}
	now := billingMonthOf(time.Now().UTC())
	start, end := now, now
	if haveStart {
		t, err := billingMonth(rawStart.(string), "start_time")
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		start = billingMonthOf(t)
		t, err = billingMonth(rawEnd.(string), "end_time")
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		end = billingMonthOf(t)
	}
	if start.After(end) {
		return logical.ErrorResponse("start_time must not be after end_time"), logical.ErrInvalidRequest
	}
	months := []map[string]any{}
	for m := start; !m.After(end); m = m.AddDate(0, 1, 0) {
		stamp := m.Format("2006-01")
		months = append(months, map[string]any{
			"timestamp": stamp,
			"counts":    map[string]any{"issued_certificates": 0},
			"error":     fmt.Sprintf("certificate counts not found for %s", stamp),
		})
	}
	return &logical.Response{Data: map[string]any{"months": months}, Warnings: []string{billingWarning}}, nil
}
