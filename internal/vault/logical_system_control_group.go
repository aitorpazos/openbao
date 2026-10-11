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

const controlGroupConfigPath = "config/control-group"

type controlGroupConfig struct {
	MaxTTL time.Duration `json:"max_ttl"`
}

func (b *SystemBackend) controlGroupConfigPaths() []*framework.Path {
	return []*framework.Path{{
		Pattern: controlGroupConfigPath + "$",
		Fields: map[string]*framework.FieldSchema{
			"max_ttl": {Type: framework.TypeDurationSecond, Description: "Maximum control group wrapping token TTL, in seconds or as a duration."},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleControlGroupConfig,
			logical.ReadOperation:   b.handleControlGroupConfig,
			logical.DeleteOperation: b.handleControlGroupConfig,
		},
		HelpSynopsis: "Configure the maximum TTL of control group wrapping tokens.",
	}}
}

func readControlGroupConfig(ctx context.Context, storage logical.Storage) (*controlGroupConfig, error) {
	entry, err := storage.Get(ctx, controlGroupConfigPath)
	if err != nil {
		return nil, err
	}
	config := &controlGroupConfig{}
	if entry != nil {
		if err := entry.DecodeJSON(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func (b *SystemBackend) handleControlGroupConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	switch req.Operation {
	case logical.DeleteOperation:
		return nil, req.Storage.Delete(ctx, controlGroupConfigPath)
	case logical.ReadOperation:
		config, err := readControlGroupConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		return &logical.Response{Data: map[string]interface{}{"max_ttl": config.MaxTTL.String()}}, nil
	default:
		seconds := d.Get("max_ttl").(int)
		if seconds < 0 || int64(seconds) > int64((1<<63-1)/time.Second) {
			return logical.ErrorResponse("max_ttl must be a non-negative duration within range"), logical.ErrInvalidRequest
		}
		entry, err := logical.StorageEntryJSON(controlGroupConfigPath, &controlGroupConfig{MaxTTL: time.Duration(seconds) * time.Second})
		if err != nil {
			return nil, err
		}
		return nil, req.Storage.Put(ctx, entry)
	}
}

// A missing configuration (or zero maximum) leaves the existing wrapping TTL
// unchanged. Read from the same namespace-local system storage as the API;
// ordinary response wrapping must not be affected by control group settings.
func (c *Core) controlGroupWrappingTTL(ctx context.Context, ttl time.Duration, extraData map[string]string) (time.Duration, error) {
	if _, ok := extraData["control_group"]; !ok {
		return ttl, nil
	}
	storage := c.router.MatchingStorageByAPIPath(ctx, "sys/")
	if storage == nil {
		return 0, fmt.Errorf("control group system storage unavailable")
	}
	config, err := readControlGroupConfig(ctx, storage)
	if err != nil {
		return 0, err
	}
	if config.MaxTTL > 0 && ttl > config.MaxTTL {
		return config.MaxTTL, nil
	}
	return ttl, nil
}
