// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) sealRewrapPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:      "sealwrap/rewrap$",
			HelpSynopsis: "Read seal rewrap progress or start a rewrap.",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: handleRootNamespaceOnly(b.handleSealRewrapStatus)},
				logical.UpdateOperation: &framework.PathOperation{Callback: handleRootNamespaceOnly(b.handleSealRewrapStart)},
			},
		},
		{
			Pattern:      "seal-backend-status$",
			HelpSynopsis: "Read public backing-seal health information.",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: handleRootNamespaceOnly(b.handleSealBackendStatus)},
			},
		},
	}
}

func (b *SystemBackend) handleSealRewrapStatus(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// The default seal does not maintain seal-wrapped storage entries. Its
	// empty rewrap completes synchronously, with no persisted job or counters.
	return &logical.Response{Data: map[string]any{
		"is_running": false,
		"entries":    map[string]any{"failed": 0, "processed": 0, "succeeded": 0},
	}}, nil
}

func (b *SystemBackend) handleSealRewrapStart(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if _, ok := b.Core.seal.(*defaultSeal); !ok {
		// Do not claim to have re-encrypted entries under a configured backing
		// seal: OpenBao does not implement that storage rewrap operation here.
		return logical.ErrorResponse("seal-wrapped storage rewrap is not supported for this seal"), logical.ErrInvalidRequest
	}
	resp, err := b.handleSealRewrapStatus(ctx, req, data)
	if err != nil {
		return nil, err
	}
	// A newly accepted empty operation has already completed by this point.
	return logical.RespondWithStatusCode(resp, req, http.StatusAccepted)
}

type sealBackendHealth struct {
	Name           string `json:"name"`
	Configured     bool   `json:"configured"`
	Disabled       bool   `json:"disabled"`
	Healthy        bool   `json:"healthy"`
	UnhealthySince string `json:"unhealthy_since,omitempty"`
}

func (b *SystemBackend) handleSealBackendStatus(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	s := b.Core.seal
	backend := sealBackendHealth{Name: s.BarrierType().String(), Configured: true, Healthy: true}
	if auto, ok := s.(*autoSeal); ok {
		if since := auto.backendUnhealthySince.Load(); since != nil {
			backend.Healthy = false
			backend.UnhealthySince = since.UTC().Format(time.RFC3339Nano)
		}
	}
	_, defaultSeal := s.(*defaultSeal)
	body := map[string]any{
		"healthy": backend.Healthy,
		// Only the default seal's empty set is known to be fully wrapped. Do not
		// advertise completion of unsupported auto-seal storage wrapping.
		"fully_wrapped": defaultSeal,
		"backends":      []sealBackendHealth{backend},
	}
	if backend.UnhealthySince != "" {
		body["unhealthy_since"] = backend.UnhealthySince
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		logical.HTTPStatusCode:  http.StatusOK,
		logical.HTTPContentType: "application/json",
		logical.HTTPRawBody:     raw,
	}}, nil
}
