// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// Secrets Sync is a local configuration/association surface. Phase 2 must add
// credential-based provider clients, delivery, retries and reconciliation. Never
// report SYNCED/UNSYNCED without performing the corresponding remote operation.
// req.Storage is the namespace-scoped system view (core/); sync/ is additive.
const syncStoragePrefix = "sync/"

var syncDestinationTypes = []string{"aws-sm", "azure-kv", "gcp-sm", "gh", "vercel-project"}

func (b *SystemBackend) syncPaths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{}
	for _, name := range strings.Fields("type name action mount secret_name access_key_id secret_access_key role_arn external_id identity_token_audience identity_token_key region key_vault_uri client_id tenant_id client_secret cloud credentials project_id service_account_email global_kms_key enterprise_url secrets_location access_token app_name installation_id repository_owner repository_name environment_name organization_name organization_visibility team_id secret_name_template granularity app_id private_key") {
		fields[name] = &framework.FieldSchema{Type: framework.TypeString}
	}
	for _, name := range strings.Fields("allowed_ipv4_addresses allowed_ipv6_addresses replication_locations selected_repository_names deployment_environments") {
		fields[name] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
	}
	for _, name := range strings.Fields("custom_tags locational_kms_keys") {
		fields[name] = &framework.FieldSchema{Type: framework.TypeKVPairs}
	}
	for _, name := range strings.Fields("disable_strict_networking disabled purge force_delete") {
		fields[name] = &framework.FieldSchema{Type: framework.TypeBool}
	}
	fields["identity_token_ttl"] = &framework.FieldSchema{Type: framework.TypeDurationSecond}
	fields["queue_capacity"] = &framework.FieldSchema{Type: framework.TypeInt}
	fields["allowed_ports"] = &framework.FieldSchema{Type: framework.TypeSlice}
	// A backend-local lock serializes read/modify/write operations without adding
	// fields to Core or SystemBackend. Storage remains authoritative across reloads.
	var mu sync.Mutex
	handler := func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		return b.handleSync(ctx, req, d)
	}
	path := func(pattern string, ops ...logical.Operation) *framework.Path {
		callbacks := map[logical.Operation]framework.OperationFunc{}
		for _, op := range ops {
			callbacks[op] = handler
		}
		return &framework.Path{Pattern: pattern, Fields: fields, Callbacks: callbacks, HelpSynopsis: "Manage local Secrets Sync configuration and associations."}
	}
	typ := "(?P<type>aws-sm|azure-kv|gcp-sm|gh|vercel-project)"
	name := framework.GenericNameRegex("name")
	return []*framework.Path{
		path("sync/config$", logical.PatchOperation),
		path("sync/destinations/?$", logical.ListOperation, logical.ReadOperation),
		path("sync/destinations/"+typ+"/?$", logical.ListOperation, logical.ReadOperation),
		path("sync/destinations/"+typ+"/"+name+"/associations/(?P<action>set|remove)$", logical.UpdateOperation),
		path("sync/destinations/"+typ+"/"+name+"/associations$", logical.ReadOperation),
		path("sync/destinations/"+typ+"/"+name+"$", logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation),
		path("sync/associations/?$", logical.ListOperation, logical.ReadOperation),
		path("sync/associations/destinations$", logical.ReadOperation),
		path("sync/associations/(?P<mount>[^/]+)/(?P<secret_name>.+)$", logical.ReadOperation),
		path("sync/github-apps/"+name+"$", logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation),
	}
}

func syncLoad(ctx context.Context, storage logical.Storage, key string, out any) (bool, error) {
	entry, err := storage.Get(ctx, syncStoragePrefix+key)
	if err != nil || entry == nil {
		return false, err
	}
	return true, entry.DecodeJSON(out)
}

func syncSave(ctx context.Context, storage logical.Storage, key string, value any) error {
	entry, err := logical.StorageEntryJSON(syncStoragePrefix+key, value)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (b *SystemBackend) handleSync(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Path == "sync/config" {
		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, err
		}
		if ns.ID != namespace.RootNamespaceID {
			return nil, logical.ErrPermissionDenied
		}
		config := map[string]any{"disabled": false, "queue_capacity": 1000000}
		if _, err := syncLoad(ctx, req.Storage, "config", &config); err != nil {
			return nil, err
		}
		for _, key := range []string{"disabled", "queue_capacity"} {
			if _, ok := d.Raw[key]; ok {
				config[key] = d.Get(key)
			}
		}
		return &logical.Response{Data: config}, syncSave(ctx, req.Storage, "config", config)
	}
	if strings.HasPrefix(req.Path, "sync/github-apps/") {
		return b.handleSyncApp(ctx, req, d)
	}
	if strings.HasPrefix(req.Path, "sync/associations") || strings.Contains(req.Path, "/associations") {
		return b.handleSyncAssociations(ctx, req, d)
	}
	typ, name := d.Get("type").(string), d.Get("name").(string)
	if name == "" {
		return syncListDestinations(ctx, req.Storage, typ)
	}
	key := "destinations/" + typ + "/" + name
	config := map[string]any{}
	exists, err := syncLoad(ctx, req.Storage, key, &config)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case logical.ReadOperation:
		if !exists {
			return nil, nil
		}
		return syncDestinationResponse(typ, name, config), nil
	case logical.DeleteOperation:
		associations := map[string]syncAssociation{}
		if _, err := syncLoad(ctx, req.Storage, "associations", &associations); err != nil {
			return nil, err
		}
		for _, a := range associations {
			if a.Type == typ && a.Name == name {
				return logical.ErrorResponse("destination has associations; remove them before deletion (remote purge is not implemented)"), nil
			}
		}
		return nil, req.Storage.Delete(ctx, syncStoragePrefix+key)
	}
	allowed := " secret_name_template granularity disable_strict_networking allowed_ipv4_addresses allowed_ipv6_addresses allowed_ports "
	switch typ {
	case "aws-sm":
		allowed += "access_key_id secret_access_key role_arn external_id region custom_tags identity_token_audience identity_token_key identity_token_ttl "
	case "azure-kv":
		allowed += "key_vault_uri client_id tenant_id client_secret cloud custom_tags identity_token_audience identity_token_key identity_token_ttl "
	case "gcp-sm":
		allowed += "credentials project_id replication_locations locational_kms_keys global_kms_key service_account_email custom_tags identity_token_audience identity_token_key identity_token_ttl "
	case "gh":
		allowed += "enterprise_url secrets_location access_token app_name installation_id repository_owner repository_name environment_name organization_name organization_visibility selected_repository_names "
	case "vercel-project":
		allowed += "access_token project_id team_id deployment_environments "
	}
	for field := range d.Raw {
		if strings.Contains(allowed, " "+field+" ") {
			config[field] = d.Get(field)
		}
	}
	if _, ok := config["granularity"]; !ok {
		config["granularity"] = "secret-path"
		if typ == "gh" || typ == "vercel-project" {
			config["granularity"] = "secret-key"
		}
	}
	if err := validateSyncDestination(typ, config); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if err := syncSave(ctx, req.Storage, key, config); err != nil {
		return nil, err
	}
	resp := syncDestinationResponse(typ, name, config)
	resp.AddWarning("Only local configuration is stored; cloud synchronization is not implemented.")
	return resp, nil
}

func syncString(m map[string]any, key string) string { s, _ := m[key].(string); return s }
func syncStrings(v any) []string {
	switch v := v.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, s := range v {
			out = append(out, fmt.Sprint(s))
		}
		return out
	}
	return nil
}

func validateSyncDestination(typ string, config map[string]any) error {
	required := func(keys ...string) error {
		for _, k := range keys {
			if syncString(config, k) == "" {
				return fmt.Errorf("%s is required", k)
			}
		}
		return nil
	}
	granularity := syncString(config, "granularity")
	if granularity != "secret-path" && granularity != "secret-key" {
		return fmt.Errorf("invalid granularity")
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, cidr := range syncStrings(config["allowed_"+family+"_addresses"]) {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil || (family == "ipv4" && ip.To4() == nil) || (family == "ipv6" && ip.To4() != nil) {
				return fmt.Errorf("invalid %s CIDR %q", family, cidr)
			}
		}
	}
	if ttl, ok := config["identity_token_ttl"]; ok {
		var n float64
		switch v := ttl.(type) {
		case int:
			n = float64(v)
		case float64:
			n = v
		}
		if n < 0 {
			return fmt.Errorf("identity_token_ttl must not be negative")
		}
	}
	audience := syncString(config, "identity_token_audience")
	switch typ {
	case "aws-sm":
		if audience != "" {
			if syncString(config, "access_key_id") != "" {
				return fmt.Errorf("access_key_id and identity_token_audience are mutually exclusive")
			}
			return required("role_arn")
		}
	case "azure-kv":
		if audience != "" && syncString(config, "client_secret") != "" {
			return fmt.Errorf("client_secret and identity_token_audience are mutually exclusive")
		}
		return required("key_vault_uri", "client_id", "tenant_id")
	case "gcp-sm":
		credentials := syncString(config, "credentials")
		if audience != "" && credentials != "" {
			return fmt.Errorf("credentials and identity_token_audience are mutually exclusive")
		}
		if credentials != "" {
			var obj map[string]any
			if json.Unmarshal([]byte(credentials), &obj) != nil || obj == nil {
				return fmt.Errorf("credentials must be a JSON object")
			}
		}
		if audience != "" {
			return required("service_account_email")
		}
	case "gh":
		location := syncString(config, "secrets_location")
		if location != "" && location != "repository" && location != "organization" {
			return fmt.Errorf("invalid secrets_location")
		}
		visibility := syncString(config, "organization_visibility")
		if visibility != "" && visibility != "all" && visibility != "private" && visibility != "selected" {
			return fmt.Errorf("invalid organization_visibility")
		}
		if syncString(config, "app_name") != "" {
			return required("installation_id")
		}
	case "vercel-project":
		if err := required("access_token", "project_id"); err != nil {
			return err
		}
		envs := syncStrings(config["deployment_environments"])
		if len(envs) == 0 {
			return fmt.Errorf("deployment_environments is required")
		}
		for _, env := range envs {
			if env != "development" && env != "preview" && env != "production" {
				return fmt.Errorf("invalid deployment environment %q", env)
			}
		}
	}
	return nil
}

func syncDestinationResponse(typ, name string, config map[string]any) *logical.Response {
	connection, options := map[string]any{}, map[string]any{"secret_name_template": "", "granularity_level": config["granularity"]}
	for key, value := range config {
		switch key {
		case "granularity":
			continue
		case "secret_name_template", "custom_tags", "disable_strict_networking", "allowed_ipv4_addresses", "allowed_ipv6_addresses", "allowed_ports":
			options[key] = value
		case "access_key_id", "secret_access_key", "client_secret", "credentials", "access_token":
			if value != "" {
				connection[key] = "*****"
			} else {
				connection[key] = ""
			}
		default:
			connection[key] = value
		}
	}
	return &logical.Response{Data: map[string]any{"name": name, "type": typ, "connection_details": connection, "options": options}}
}

func syncListDestinations(ctx context.Context, storage logical.Storage, typ string) (*logical.Response, error) {
	if typ != "" {
		keys, err := storage.List(ctx, syncStoragePrefix+"destinations/"+typ+"/")
		if err != nil {
			return nil, err
		}
		if keys == nil {
			keys = []string{}
		}
		sort.Strings(keys)
		return &logical.Response{Data: map[string]any{"keys": keys, "total_destinations": len(keys)}}, nil
	}
	keys, info, total := []string{}, map[string]any{}, 0
	for _, typ := range syncDestinationTypes {
		names, err := storage.List(ctx, syncStoragePrefix+"destinations/"+typ+"/")
		if err != nil {
			return nil, err
		}
		if len(names) > 0 {
			sort.Strings(names)
			keys = append(keys, typ+"/")
			info[typ+"/"] = names
			total += len(names)
		}
	}
	return &logical.Response{Data: map[string]any{"keys": keys, "key_info": info, "total_destinations": total}}, nil
}

type syncAssociation struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Mount    string `json:"mount"`
	Accessor string `json:"accessor"`
	Secret   string `json:"secret_name"`
	Status   string `json:"sync_status"`
	Updated  string `json:"updated_at"`
}

func syncAssociationResponse(typ, name string, associations map[string]syncAssociation) *logical.Response {
	secrets := map[string]any{}
	for _, a := range associations {
		if a.Type == typ && a.Name == name {
			secrets[a.Accessor+"/"+a.Secret] = map[string]any{"accessor": a.Accessor, "secret_name": a.Secret, "sync_status": a.Status, "updated_at": a.Updated}
		}
	}
	return &logical.Response{Data: map[string]any{"store_name": name, "store_type": typ, "associated_secrets": secrets}}
}

func (b *SystemBackend) handleSyncAssociations(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	associations := map[string]syncAssociation{}
	if _, err := syncLoad(ctx, req.Storage, "associations", &associations); err != nil {
		return nil, err
	}
	typ, name := d.Get("type").(string), d.Get("name").(string)
	if typ == "" {
		if strings.TrimSuffix(req.Path, "/") == "sync/associations" {
			info := map[string]any{}
			keys := []string{}
			for _, a := range associations {
				key := a.Mount + "/" + a.Secret
				if _, ok := info[key]; !ok {
					keys = append(keys, key)
					info[key] = []map[string]any{{"mount": a.Mount, "secret_path": a.Secret}}
				}
			}
			sort.Strings(keys)
			return &logical.Response{Data: map[string]any{"keys": keys, "key_info": info, "total_associations": len(associations), "total_secrets": len(keys)}}, nil
		}
		mount, secret := strings.Trim(d.Get("mount").(string), "/"), d.Get("secret_name").(string)
		if mount == "" || secret == "" {
			return logical.ErrorResponse("mount and secret_name are required"), nil
		}
		destinations := map[string]any{}
		for _, a := range associations {
			if a.Mount == mount && a.Secret == secret {
				destinations[a.Type+"/"+a.Name] = map[string]any{"type": a.Type, "name": a.Name, "sync_status": a.Status, "updated_at": a.Updated}
			}
		}
		return &logical.Response{Data: map[string]any{"associated_destinations": destinations}}, nil
	}
	var config map[string]any
	exists, err := syncLoad(ctx, req.Storage, "destinations/"+typ+"/"+name, &config)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("destination does not exist"), nil
	}
	if req.Operation == logical.ReadOperation {
		return syncAssociationResponse(typ, name, associations), nil
	}
	mount, secret := strings.Trim(d.Get("mount").(string), "/"), d.Get("secret_name").(string)
	if mount == "" || secret == "" {
		return logical.ErrorResponse("mount and secret_name are required"), nil
	}
	// JSON tuple avoids collisions between slashes in mount and secret paths.
	tuple, _ := json.Marshal([]string{typ, name, mount, secret})
	key := string(tuple)
	if d.Get("action").(string) == "remove" {
		delete(associations, key)
	} else {
		me := b.Core.router.MatchingMountEntry(ctx, mount+"/")
		if me == nil || me.Path != mount+"/" || me.Type != "kv" || me.Options["version"] != "2" {
			return logical.ErrorResponse("mount must be an existing KV-v2 mount"), nil
		}
		read := &logical.Request{Operation: logical.ReadOperation, Path: mount + "/data/" + secret, ClientToken: req.ClientToken}
		acl, te, entity, _, err := b.Core.fetchACLTokenEntryAndEntity(ctx, req)
		if err != nil {
			return nil, err
		}
		if acl == nil || (entity != nil && entity.Disabled) || (te != nil && te.EntityID != "" && entity == nil) || !acl.AllowOperation(ctx, read, false).Allowed {
			return nil, logical.ErrPermissionDenied
		}
		result, err := b.Core.router.Route(ctx, read)
		if err != nil {
			return nil, err
		}
		if result == nil || result.IsError() || result.Data["data"] == nil {
			return logical.ErrorResponse("secret does not exist or has been deleted"), nil
		}
		associations[key] = syncAssociation{Type: typ, Name: name, Mount: mount, Accessor: me.Accessor, Secret: secret, Status: "PENDING", Updated: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	if err := syncSave(ctx, req.Storage, "associations", associations); err != nil {
		return nil, err
	}
	resp := syncAssociationResponse(typ, name, associations)
	resp.AddWarning("Only local associations are managed; remote sync/unsync is not implemented.")
	return resp, nil
}

func (b *SystemBackend) handleSyncApp(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	key := "github-apps/" + name
	config := map[string]any{}
	exists, err := syncLoad(ctx, req.Storage, key, &config)
	if err != nil {
		return nil, err
	}
	if req.Operation == logical.DeleteOperation {
		names, err := req.Storage.List(ctx, syncStoragePrefix+"destinations/gh/")
		if err != nil {
			return nil, err
		}
		for _, dest := range names {
			var c map[string]any
			if _, err := syncLoad(ctx, req.Storage, "destinations/gh/"+dest, &c); err != nil {
				return nil, err
			}
			if syncString(c, "app_name") == name {
				return logical.ErrorResponse("app is referenced by a destination"), nil
			}
		}
		return nil, req.Storage.Delete(ctx, syncStoragePrefix+key)
	}
	if req.Operation == logical.ReadOperation && !exists {
		return nil, nil
	}
	if req.Operation == logical.UpdateOperation {
		for _, field := range []string{"app_id", "private_key"} {
			if _, ok := d.Raw[field]; ok {
				config[field] = d.Get(field)
			}
			if syncString(config, field) == "" {
				return logical.ErrorResponse("%s is required", field), nil
			}
		}
		block, _ := pem.Decode([]byte(syncString(config, "private_key")))
		if block == nil {
			return logical.ErrorResponse("private_key must be a PEM private key"), nil
		}
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return logical.ErrorResponse("invalid private_key"), nil
			}
		}
		digest := sha256.Sum256(block.Bytes)
		config["fingerprint"] = hex.EncodeToString(digest[:])
		config["name"] = name
		if err := syncSave(ctx, req.Storage, key, config); err != nil {
			return nil, err
		}
	}
	config["private_key"] = "*****"
	return &logical.Response{Data: config}, nil
}
