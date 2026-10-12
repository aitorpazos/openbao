// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
)

// internalUIPaths registers the documented internal UI delivery endpoints
// (sources: developer.hashicorp.com/vault/api-docs/system/
// internal-ui-authenticated-messages, internal-ui-unauthenticated-messages and
// internal-ui-default-auth-methods, v2.x latest; all Enterprise-gated). The
// pages explicitly frame these as internal-UI plumbing without documented
// permission requirements, and the namespace is derived from the request's
// X-Vault-Namespace header rather than the caller identity — so they are
// registered in the Unauthenticated list and resolve per request namespace.
func (b *SystemBackend) internalUIPaths() []*framework.Path {
	fields := map[string]*framework.FieldSchema{}
	callbacks := map[logical.Operation]framework.OperationFunc{
		logical.ReadOperation: b.handleUIMessagesDelivery,
		logical.ListOperation: b.handleUIMessagesDelivery,
	}
	return []*framework.Path{
		{
			Pattern:   "internal/ui/authenticated-messages$",
			Fields:    fields,
			Callbacks: callbacks,
		},
		{
			Pattern:   "internal/ui/unauthenticated-messages$",
			Fields:    fields,
			Callbacks: callbacks,
		},
		{
			Pattern: "internal/ui/default-auth-methods$",
			Fields:  fields,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleUIDefaultAuthMethods,
				logical.ListOperation: b.handleUIDefaultAuthMethods,
			},
		},
	}
}

// uiMessageViews returns the storage views to consult for UI message
// delivery: the request namespace's own view first, then every ancestral
// namespace up to and including the root, as documented ("the results will
// include active messages from the current namespace along with custom
// messages that exist in all of the ancestral namespaces up to and including
// the root namespace"). A missing ancestor record skips that level.
func (b *SystemBackend) uiMessageViews(ctx context.Context, req *logical.Request) ([]logical.Storage, error) {
	views := []logical.Storage{req.Storage}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil || ns.ID == namespace.RootNamespaceID {
		return views, nil
	}
	ancestors, err := b.internalUIAncestorViews(ctx, ns)
	if err != nil {
		return nil, err
	}
	return append(views, ancestors...), nil
}

// handleUIMessagesDelivery serves GET /sys/internal/ui/authenticated-messages
// and /sys/internal/ui/unauthenticated-messages. Both return the active
// custom messages for the request's audience flag; the documented response
// shape is {key_info: {<id>: {title, message, type, authenticated,
// start_time, end_time, options, link}}, keys: [<ids>]}. The configuration
// API accepts the message body base64-encoded (enforced there); delivery
// returns the decoded plain text, matching the documented sample.
func (b *SystemBackend) handleUIMessagesDelivery(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	authenticated := req.Path == "internal/ui/authenticated-messages"
	views, err := b.uiMessageViews(ctx, req)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	keys, keyInfo := []string{}, map[string]interface{}{}
	seen := map[string]bool{}
	prefix := uiCustomMessagePath + "/"
	for _, view := range views {
		ids, err := view.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			entry, err := view.Get(ctx, prefix+id)
			if err != nil {
				return nil, err
			}
			if entry == nil {
				continue
			}
			var m uiCustomMessage
			if err := entry.DecodeJSON(&m); err != nil {
				return nil, err
			}
			if m.Authenticated != authenticated {
				continue
			}
			active := !now.Before(m.StartTime) && (m.EndTime == nil || now.Before(*m.EndTime))
			if !active {
				continue
			}
			message := m.Message
			if decoded, derr := base64.StdEncoding.DecodeString(m.Message); derr == nil {
				message = string(decoded)
			}
			seen[id] = true
			keys = append(keys, id)
			var end interface{}
			if m.EndTime != nil {
				end = m.EndTime.Format(time.RFC3339Nano)
			}
			keyInfo[id] = map[string]interface{}{
				"title":         m.Title,
				"message":       message,
				"type":          m.Type,
				"authenticated": m.Authenticated,
				"start_time":    m.StartTime.Format(time.RFC3339Nano),
				"end_time":      end,
				"options":       m.Options,
				"link":          m.Link,
			}
		}
	}
	return &logical.Response{Data: map[string]interface{}{"keys": keys, "key_info": keyInfo}}, nil
}

// handleUIDefaultAuthMethods serves GET /sys/internal/ui/default-auth-methods:
// "return the explicit, or inherited, default and backup auth method types
// for a given namespace", where the namespace is derived from the request.
// Configurations are stored in the root namespace's system view (the config
// route is root-only) tagged with their target namespace_path; the docs'
// special value "root" targets the root namespace. Resolution walks from the
// request namespace up to the root and applies the most specific matching
// configuration, skipping ancestors marked disable_inheritance (documented:
// "Setting disable_inheritance to true disallows inheritance" by child
// namespaces). With no applicable configuration the UI's built-in default,
// the token method, is returned.
func (b *SystemBackend) handleUIDefaultAuthMethods(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}
	targetSegments := splitNamespaceSegments(ns.Path)
	// System data is stored under the sys/ barrier prefix; req.Storage is
	// the sys-prefixed view of the request namespace. Ancestors (root
	// included, when the request is namespaced) are reached through their
	// namespace views with the sys/ prefix applied.
	views := []logical.Storage{req.Storage}
	if ns.ID != namespace.RootNamespaceID {
		ancestorViews, err := b.internalUIAncestorViews(ctx, ns)
		if err != nil {
			return nil, err
		}
		views = append(views, ancestorViews...)
	}
	configs := map[string]uiDefaultAuth{}
	for _, view := range views {
		ids, err := view.List(ctx, uiDefaultAuthPath+"/")
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			entry, err := view.Get(ctx, uiDefaultAuthPath+"/"+id)
			if err != nil {
				return nil, err
			}
			if entry == nil {
				continue
			}
			var cfg uiDefaultAuth
			if err := entry.DecodeJSON(&cfg); err != nil {
				return nil, err
			}
			// Dedupe by namespace_path; nearer views win.
			key := strings.Trim(cfg.NamespacePath, "/")
			if strings.EqualFold(key, "root") {
				key = ""
			}
			if _, exists := configs[key]; !exists {
				configs[key] = cfg
			}
		}
	}
	bestLen, best := -1, (*uiDefaultAuth)(nil)
	for key, cfg := range configs {
		cfgSegments := splitNamespaceSegments(key)
		if len(cfgSegments) > len(targetSegments) {
			continue
		}
		match := true
		for i := range cfgSegments {
			if cfgSegments[i] != targetSegments[i] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		// A disable_inheritance configuration applies only to its own
		// namespace; deeper namespaces must not inherit it.
		if cfg.DisableInheritance && len(cfgSegments) < len(targetSegments) {
			continue
		}
		if len(cfgSegments) > bestLen {
			best, bestLen = &cfg, len(cfgSegments)
		}
	}
	if best == nil {
		return &logical.Response{Data: map[string]interface{}{
			"default_auth_type":   "token",
			"backup_auth_types":   []string{},
			"disable_inheritance": false,
		}}, nil
	}
	backup := best.BackupAuthTypes
	if backup == nil {
		backup = []string{}
	}
	return &logical.Response{Data: map[string]interface{}{
		"default_auth_type":   best.DefaultAuthType,
		"backup_auth_types":   backup,
		"disable_inheritance": best.DisableInheritance,
	}}, nil
}

// internalUIAncestorViews returns the sys-prefixed storage views of every
// ancestral namespace of ns up to and including the root, nearest first.
// Path resolution is performed against the root namespace context:
// GetNamespaceByPath canonicalizes relative to the request's namespace.
func (b *SystemBackend) internalUIAncestorViews(ctx context.Context, ns *namespace.Namespace) ([]logical.Storage, error) {
	trimmed := strings.Trim(ns.Path, "/")
	if trimmed == "" {
		return nil, nil
	}
	rootCtx := namespace.ContextWithNamespace(ctx, namespace.RootNamespace)
	segments := strings.Split(trimmed, "/")
	var views []logical.Storage
	for i := len(segments) - 1; i >= 0; i-- {
		ancestorPath := ""
		if i > 0 {
			ancestorPath = strings.Join(segments[:i], "/") + "/"
		}
		ancestor, err := b.Core.namespaceStore.GetNamespaceByPath(rootCtx, ancestorPath)
		if err != nil || ancestor == nil {
			continue
		}
		views = append(views, b.Core.NamespaceView(ancestor).SubView(barrier.SystemBarrierPrefix))
	}
	return views, nil
}

func splitNamespaceSegments(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}
