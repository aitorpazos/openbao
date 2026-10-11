// SPDX-License-Identifier: MPL-2.0

// Package aws implements local cloud configuration, not cloud operations.
// Source: https://developer.hashicorp.com/vault/api-docs/auth/aws (v2.x latest).
package aws

import (
	"context"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/credential/aws/configonly"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	return b, b.Setup(ctx, conf)
}

func Backend() *configonly.Backend { return configonly.New("aws", false) }
