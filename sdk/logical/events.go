// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"errors"
	"github.com/hashicorp/go-uuid"
)

// EventSender accepts notifications without waiting for subscribers.
type EventSender interface {
	SendEvent(context.Context, *EventReceived) error
}

var ErrNoEvents = errors.New("event notifications are not available")

// SendEvent constructs a notification. Sinks must be nonblocking and best effort.
func SendEvent(ctx context.Context, sender EventSender, eventType string, metadata ...string) error {
	if sender == nil {
		return ErrNoEvents
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}
	values := make(map[string]string)
	for i := 0; i < len(metadata); i += 2 {
		value := ""
		if i+1 < len(metadata) {
			value = metadata[i+1]
		}
		values[metadata[i]] = value
	}
	return sender.SendEvent(ctx, &EventReceived{Data: &EventData{EventType: eventType, Event: &Event{Id: id, Metadata: values}}})
}
