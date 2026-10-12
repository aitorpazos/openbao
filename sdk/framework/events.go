// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package framework

import (
	"context"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type EventSink = logical.EventSender

var ErrNoEvents = logical.ErrNoEvents

// SetEventSink installs a sink before the backend is exposed to requests.
func (b *Backend) SetEventSink(s EventSink) {
	b.eventSinkMu.Lock()
	b.eventSink = s
	b.eventSinkMu.Unlock()
}
func (b *Backend) SendEvent(ctx context.Context, e *logical.EventReceived) error {
	b.eventSinkMu.RLock()
	sink := b.eventSink
	b.eventSinkMu.RUnlock()
	if sink == nil {
		return ErrNoEvents
	}
	err := sink.SendEvent(ctx, e)
	if err != nil {
		b.Logger().Warn("event delivery failed", "error", err)
	}
	return err
}
