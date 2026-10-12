// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"context"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"google.golang.org/protobuf/proto"
)

func (r *Router) SetEventSink(s logical.EventSender) {
	r.l.Lock()
	defer r.l.Unlock()
	r.eventSink = s
	for _, v := range r.root.ToMap() {
		r.installEventSink(v.(*RouteEntry))
	}
}
func (r *Router) installEventSink(re *RouteEntry) {
	if b, ok := re.Backend.(interface{ SetEventSink(logical.EventSender) }); ok && r.eventSink != nil {
		b.SetEventSink(&mountEventSink{sink: r.eventSink, mount: re.MountEntry})
	}
}

type mountEventSink struct {
	sink  logical.EventSender
	mount *MountEntry
}

func (s *mountEventSink) SendEvent(ctx context.Context, event *logical.EventReceived) error {
	e := proto.Clone(event).(*logical.EventReceived)
	if e.Data == nil || e.Data.Event == nil {
		return nil
	}
	m := s.mount
	class := "secret"
	mountPath := m.Path
	if m.Table == CredentialTableType {
		class = "auth"
		mountPath = CredentialRoutePrefix + mountPath
	}
	e.Data.PluginInfo = &logical.PluginInfo{MountClass: class, MountAccessor: m.Accessor, MountPath: mountPath, Plugin: m.Type}
	for _, k := range []string{"path", "data_path"} {
		if v, ok := e.Data.Event.Metadata[k]; ok {
			e.Data.Event.Metadata[k] = mountPath + v
		}
	}
	return s.sink.SendEvent(namespace.ContextWithNamespace(ctx, m.Namespace), e)
}
