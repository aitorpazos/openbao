// Copyright (c) OpenBao, a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestOIDCWorkloadDiscovery(t *testing.T) {
	i := &IdentityStore{OidcCache: NewOIDCCache(time.Hour, 0), redirectAddr: "https://api.example"}
	i.Backend = &framework.Backend{Paths: append(oidcPaths(i), oidcWorkloadPaths(i)...)}
	for _, ns := range []*namespace.Namespace{namespace.RootNamespace, {ID: "test", Path: "team/"}} {
		ctx := namespace.ContextWithNamespace(context.Background(), ns)
		storage := &logical.InmemStorage{}
		for _, base := range []string{"https://api.example", "https://issuer.example"} {
			if base != i.redirectAddr {
				entry, err := logical.StorageEntryJSON(oidcConfigStorageKey, &oidcConfig{Issuer: base})
				require.NoError(t, err)
				require.NoError(t, storage.Put(ctx, entry))
				require.NoError(t, i.OidcCache.Flush(ns))
			}
			// Repeated interleaved reads exercise cache isolation and preserve generic discovery.
			for range 2 {
				for _, suffix := range []string{"/plugins", "", "/secrets-sync"} {
					for _, trailing := range []string{"", "/"} {
						resp, err := i.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "oidc" + suffix + "/.well-known/openid-configuration" + trailing, Storage: storage})
						require.NoError(t, err)
						require.Equal(t, 200, resp.Data[logical.HTTPStatusCode])
						require.Equal(t, "application/json", resp.Data[logical.HTTPContentType])
						var disc Discovery
						require.NoError(t, json.Unmarshal(resp.Data[logical.HTTPRawBody].([]byte), &disc))
						require.Equal(t, base+"/v1/"+ns.Path+"identity/oidc"+suffix, disc.Issuer)
						require.Equal(t, disc.Issuer+"/.well-known/keys", disc.Keys)
						require.Equal(t, []string{"id_token"}, disc.ResponseTypes)
						require.Equal(t, []string{"public"}, disc.Subjects)
						require.Equal(t, SupportedAlgs, disc.IDTokenAlgs)
					}
				}
			}
		}
	}
}

func TestOIDCWorkloadPublicKeys(t *testing.T) {
	ctx := namespace.RootContext(context.Background())
	i := &IdentityStore{OidcCache: NewOIDCCache(time.Hour, 0)}
	i.Backend = &framework.Backend{Paths: append(oidcPaths(i), oidcWorkloadPaths(i)...)}
	storage := &logical.InmemStorage{}
	for _, suffix := range []string{"", "/plugins", "/secrets-sync"} {
		resp, err := i.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "oidc" + suffix + "/.well-known/keys", Storage: storage})
		require.NoError(t, err)
		require.Equal(t, 200, resp.Data[logical.HTTPStatusCode])
		require.JSONEq(t, `{"keys":[]}`, string(resp.Data[logical.HTTPRawBody].([]byte)))
	}
	// The aliases must serve the shared cached public-key response, not separate keys.
	public := []byte(`{"keys":[{"kty":"RSA","kid":"shared","use":"sig","alg":"RS256"}]}`)
	require.NoError(t, i.OidcCache.Set(namespace.RootNamespace, "jwksResponse", public))
	for _, suffix := range []string{"", "/plugins", "/secrets-sync"} {
		resp, err := i.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "oidc" + suffix + "/.well-known/keys/", Storage: storage})
		require.NoError(t, err)
		require.Equal(t, public, resp.Data[logical.HTTPRawBody])
	}
}
