// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/policy"
	"google.golang.org/protobuf/proto"
	"os"
	"sync"
	"time"
)

var eventBuses = struct {
	sync.Mutex
	cores map[*Core]*EventBus
}{cores: make(map[*Core]*EventBus)}

type EventBus struct {
	core        *Core
	mu          sync.RWMutex
	subscribers map[*EventSubscription]struct{}
}
type EventNotification struct {
	Event     *logical.EventReceived
	Namespace *namespace.Namespace
}
type EventSubscription struct {
	Events                     chan EventNotification
	ctx                        context.Context
	accessor, token, eventType string
	connection                 *logical.Connection
	ns                         *namespace.Namespace
	namespaces                 []string
	filter                     EventFilter
}

// EventBusFor installs a single sink for existing and future mounts without
// coupling Core construction to the notifications extension.
func EventBusFor(c *Core) *EventBus {
	eventBuses.Lock()
	defer eventBuses.Unlock()
	if b := eventBuses.cores[c]; b != nil {
		return b
	}
	b := &EventBus{core: c, subscribers: make(map[*EventSubscription]struct{})}
	eventBuses.cores[c] = b
	c.router.SetEventSink(b)
	return b
}

// Subscribe authenticates before the HTTP upgrade. Policy is checked afresh at
// delivery, including the subscribe-path grant and token revocation.
func (b *EventBus) Subscribe(ctx context.Context, req *logical.Request, eventType string, namespaces []string, filter EventFilter) (*EventSubscription, error) {
	if b.core.Sealed() {
		return nil, consts.ErrSealed
	}
	ns, path := b.core.namespaceStore.ResolveNamespaceFromRequest(namespace.HeaderFromContext(ctx), req.Path)
	if ns == nil || path != "sys/events/subscribe/"+eventType {
		return nil, logical.ErrPermissionDenied
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)
	acl, te, entity, _, err := b.core.fetchACLTokenEntryAndEntity(ctx, req)
	if err != nil {
		return nil, err
	}
	if entity != nil && entity.Disabled {
		return nil, logical.ErrPermissionDenied
	}
	if !acl.AllowOperation(ctx, req, false).Allowed {
		return nil, logical.ErrPermissionDenied
	}
	s := &EventSubscription{Events: make(chan EventNotification, 256), ctx: ctx, accessor: te.Accessor, eventType: eventType, connection: req.Connection, ns: ns, namespaces: namespaces, filter: filter}
	// Batch tokens have no accessor; lookup of the original token still validates
	// their expiration and parent on every notification.
	if te.Accessor == "" {
		s.token = req.ClientToken
	}
	b.Register(s)
	return s, nil
}
func (b *EventBus) Register(s *EventSubscription) {
	b.mu.Lock()
	b.subscribers[s] = struct{}{}
	b.mu.Unlock()
}
func (b *EventBus) Unregister(s *EventSubscription) {
	b.mu.Lock()
	delete(b.subscribers, s)
	b.mu.Unlock()
}
func (s *EventSubscription) matches(n EventNotification) bool {
	if !EventTypeMatches(s.eventType, n.Event.GetData().GetEventType()) {
		return false
	}
	if n.Namespace.Path == s.ns.Path {
		return true
	}
	for _, p := range s.namespaces {
		if EventTypeMatches(s.ns.Path+p, n.Namespace.Path) {
			return true
		}
	}
	return false
}
func EventPolicyAllows(acl *policy.ACL, ctx context.Context, e *logical.EventReceived) bool {
	if e.GetData().GetPluginInfo() == nil {
		return true
	}
	path := e.Data.Event.Metadata["data_path"]
	if path == "" {
		path = e.Data.Event.Metadata["path"]
	}
	r := acl.AllowOperation(ctx, &logical.Request{Path: path, Operation: logical.ListOperation}, true)
	if r.IsRoot {
		return true
	}
	required := policy.ListCapabilityInt | policy.SubscribeCapabilityInt
	if r.CapabilitiesBitmap&policy.DenyCapabilityInt != 0 || r.CapabilitiesBitmap&required != required {
		return false
	}
	for _, p := range r.SubscribeEventTypes {
		if EventTypeMatches(p, e.Data.EventType) {
			return true
		}
	}
	return false
}

// Allowed runs on the stream's consumer, never on the mutating request. A slow
// policy store or client therefore cannot block a backend's SendEvent call.
func (b *EventBus) Allowed(s *EventSubscription, n EventNotification) bool {
	if b.core.Sealed() {
		return false
	}
	token := s.token
	if s.accessor != "" {
		ae, err := b.core.tokenStore.lookupByAccessor(s.ctx, s.accessor, false, false)
		if err != nil || ae == nil {
			return false
		}
		token = ae.TokenID
	}
	req := &logical.Request{Path: "sys/events/subscribe/" + s.eventType, Operation: logical.ReadOperation, ClientToken: token, Connection: s.connection}
	acl, _, entity, _, err := b.core.fetchACLTokenEntryAndEntity(s.ctx, req)
	if err != nil || (entity != nil && entity.Disabled) || !acl.AllowOperation(s.ctx, req, false).Allowed {
		return false
	}
	ctx := namespace.ContextWithNamespace(s.ctx, n.Namespace)
	return EventPolicyAllows(acl, ctx, n.Event) && (s.filter == nil || s.filter(n.Event, n.Namespace.Path))
}
func (b *EventBus) SendEvent(ctx context.Context, event *logical.EventReceived) error {
	b.Publish(ctx, event)
	return nil
}
func (b *EventBus) Publish(ctx context.Context, event *logical.EventReceived) {
	if event == nil || event.Data == nil || event.Data.Event == nil {
		return
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return
	}
	e := proto.Clone(event).(*logical.EventReceived)
	id, err := uuid.GenerateUUID()
	if err != nil {
		return
	}
	host, err := os.Hostname()
	if err != nil {
		b.core.logger.Warn("event hostname unavailable", "error", err)
		return
	}
	e.Id = id
	e.Data.Event.Id = id
	e.Source = "vault://" + host
	e.Specversion = "1.0"
	e.Type = "*"
	e.Datacontentype = "application/cloudevents"
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	if e.Data.Event.Metadata == nil {
		e.Data.Event.Metadata = make(map[string]string)
	}
	if e.Data.EventType != "lease/expired" {
		if index := b.core.MaybeGetLatestStorageIndex(ctx); index != "" {
			iv := api.IndexValue{Cluster: b.core.ClusterID(), Value: index}
			encoded, err := iv.Encode()
			if err == nil {
				e.Data.Event.Metadata["vault_index"] = encoded
			}
		}
	}
	n := EventNotification{Event: e, Namespace: ns}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subscribers {
		if !s.matches(n) {
			continue
		}
		select {
		case s.Events <- n:
		default:
			b.core.logger.Warn("event dropped: subscriber queue full")
		}
	}
}
