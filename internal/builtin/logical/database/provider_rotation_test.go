// SPDX-License-Identifier: MPL-2.0

package database

import (
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

func TestProviderRotationRootlessValidation(t *testing.T) {
	for _, field := range []string{"username", "password"} {
		t.Run(field, func(t *testing.T) {
			ctx := namespace.RootContext(t.Context())
			conf := logical.TestBackendConfig()
			conf.StorageView = &logical.InmemStorage{}
			backend, err := Factory(ctx, conf)
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Cleanup(ctx)
			resp, err := backend.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "config/rootless", Storage: conf.StorageView, Data: map[string]any{"plugin_name": "postgresql-database-plugin", "self_managed": "true", field: "forbidden", "verify_connection": false}})
			if err != nil || resp == nil || !resp.IsError() {
				t.Fatalf("expected validation error: %#v %v", resp, err)
			}
			if !strings.Contains(resp.Error().Error(), "mutually exclusive") {
				t.Fatalf("wrong error: %v", resp.Error())
			}
			entry, err := conf.StorageView.Get(ctx, "config/rootless")
			if err != nil || entry != nil {
				t.Fatalf("invalid config persisted: %#v %v", entry, err)
			}
		})
	}
}

// No database or provider credentials are needed: import must not connect.
func TestProviderRotationStaticImport(t *testing.T) {
	for _, tc := range []struct {
		name                                                       string
		managed, connectionSkip, roleSkip, missing, legacy, denied bool
	}{
		{name: "explicit", roleSkip: true},
		{name: "inherited", connectionSkip: true},
		{name: "rootless", managed: true, roleSkip: true},
		{name: "legacy", managed: true, roleSkip: true, legacy: true},
		{name: "missing", roleSkip: true, missing: true},
		{name: "denied", roleSkip: true, denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := namespace.RootContext(t.Context())
			conf := logical.TestBackendConfig()
			conf.StorageView = &logical.InmemStorage{}
			backend, err := Factory(ctx, conf)
			if err != nil {
				t.Fatal(err)
			}
			b := backend.(*databaseBackend)
			defer b.Cleanup(ctx)
			allowed := []string{"*"}
			if tc.denied {
				allowed = nil
			}
			err = storeConfig(ctx, conf.StorageView, "test", &DatabaseConfig{AllowedRoles: allowed, SkipStaticRoleImportRotation: &tc.connectionSkip, ConnectionDetails: map[string]any{"self_managed": tc.managed}})
			if err != nil {
				t.Fatal(err)
			}
			data := map[string]any{"db_name": "test", "username": "imported", "rotation_period": 86400}
			if tc.roleSkip {
				data["skip_import_rotation"] = true
			}
			if !tc.missing {
				if tc.legacy {
					data["self_managed_password"] = "supplied-password"
				} else {
					data["password"] = "supplied-password"
				}
			}
			resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.CreateOperation, Path: "static-roles/imported", Storage: conf.StorageView, Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if tc.missing || tc.denied {
				if resp == nil || !resp.IsError() {
					t.Fatalf("expected rejection: %#v", resp)
				}
				return
			}
			if resp != nil && resp.IsError() {
				t.Fatal(resp)
			}
			role, err := b.StaticRole(ctx, conf.StorageView, "imported")
			if err != nil {
				t.Fatal(err)
			}
			if role == nil || role.StaticAccount.Password != "supplied-password" {
				t.Fatalf("imported password not persisted: %#v", role)
			}
			if role.StaticAccount.CredentialTTL() < 23*time.Hour {
				t.Fatal("import was scheduled for immediate rotation")
			}
			resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config/test", Storage: conf.StorageView})
			if err != nil || resp.Data["skip_static_role_import_rotation"] != tc.connectionSkip {
				t.Fatalf("config read: %#v %v", resp, err)
			}
		})
	}
}
