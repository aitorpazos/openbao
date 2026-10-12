// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/openbao/openbao/v2/internal/vault"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"net/http"
	"strings"
	"time"
)

func handleEvents(core *vault.Core) http.Handler {
	bus := vault.EventBusFor(core)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
			return
		}
		req, status, err := buildLogicalRequest(core, w, r)
		if err != nil || status != 0 {
			respondError(w, status, err)
			return
		}
		if req.ClientToken == "" {
			respondError(w, http.StatusUnauthorized, fmt.Errorf("missing client token"))
			return
		}
		eventType := strings.TrimPrefix(r.URL.Path, "/v1/sys/events/subscribe/")
		if eventType == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("event type required"))
			return
		}
		filter, err := vault.ParseEventFilter(r.URL.Query().Get("filter"))
		if err != nil {
			respondError(w, 400, err)
			return
		}
		sub, err := bus.Subscribe(r.Context(), req, eventType, r.URL.Query()["namespaces"], filter)
		if err != nil {
			respondError(w, 403, err)
			return
		}
		defer bus.Unregister(sub)
		// gorilla implements RFC 6455 handshake, masking, control frames, fragmented
		// input, and concurrent control writes. Origin checks retain its safe default.
		upgrader := websocket.Upgrader{HandshakeTimeout: 10 * time.Second}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadLimit(16384)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for {
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			case n := <-sub.Events:
				if !bus.Allowed(sub, n) {
					continue
				}
				messageType := websocket.BinaryMessage
				var data []byte
				var err error
				if r.URL.Query().Get("json") == "true" {
					messageType = websocket.TextMessage
					data, err = protojson.MarshalOptions{UseProtoNames: true}.Marshal(n.Event)
				} else {
					data, err = proto.Marshal(n.Event)
				}
				if err != nil {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if conn.WriteMessage(messageType, data) != nil {
					return
				}
			}
		}
	})
}
