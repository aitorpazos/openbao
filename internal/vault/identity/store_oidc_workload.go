// Copyright (c) OpenBao, a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// oidcWorkloadPaths exposes discovery for the plugin and secrets-sync issuers.
// Their public keys share the existing OIDC key store and rotation/cache lifecycle.
func oidcWorkloadPaths(i *IdentityStore) []*framework.Path {
	var paths []*framework.Path
	for _, issuer := range []string{"plugins", "secrets-sync"} {
		paths = append(paths,
			&framework.Path{
				Pattern: "oidc/" + issuer + "/\\.well-known/openid-configuration/?$",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationPrefix: "oidc", OperationSuffix: issuer + "-open-id-configuration",
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
							return i.oidcDiscovery(ctx, req, "/"+issuer)
						},
					},
				},
				HelpSynopsis: "Query workload identity OIDC configuration",
			},
			&framework.Path{
				Pattern: "oidc/" + issuer + "/\\.well-known/keys/?$",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationPrefix: "oidc", OperationSuffix: issuer + "-public-keys",
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{Callback: i.pathOIDCReadPublicKeys},
				},
				HelpSynopsis: "Retrieve workload identity public keys",
			},
		)
	}
	return paths
}
