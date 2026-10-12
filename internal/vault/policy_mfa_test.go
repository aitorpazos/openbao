// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/vault/policy"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestNamedMFAEnforcement(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	resp, err := c.identityStore.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "entity", Data: map[string]interface{}{"name": "stepup-test"}})
	require.NoError(t, err)
	te := &logical.TokenEntry{EntityID: resp.Data["id"].(string), NamespaceID: namespace.RootNamespaceID}
	storage := c.NamespaceView(namespace.RootNamespace).SubView(barrier.SystemBarrierPrefix)
	const secret = "JBSWY3DPEHPK3PXP"
	install := func(name, algorithm string, digits int, skew uint, max uint32) {
		t.Helper()
		entry, err := logical.StorageEntryJSON(namedMFAMethodPrefix+"totp/"+name, map[string]interface{}{"id": name, "algorithm": algorithm, "digits": digits, "period": 60, "skew": skew, "max_validation_attempts": max})
		require.NoError(t, err)
		require.NoError(t, storage.Put(ctx, entry))
		require.NoError(t, c.PersistTOTPKey(ctx, name, te.EntityID, secret))
	}
	call := func(names []string, headers ...string) error {
		t.Helper()
		req := &logical.Request{Headers: map[string][]string{"X-Vault-Mfa": headers}}
		require.NoError(t, req.ParseMFAHeaders())
		return c.validateNamedMFA(ctx, req, te, names).ErrorOrNil()
	}
	t.Run("no requirement has no dependencies or allocations", func(t *testing.T) {
		var empty *Core
		require.Nil(t, empty.validateNamedMFA(nil, nil, nil, nil))
		require.Zero(t, testing.AllocsPerRun(100, func() { empty.validateNamedMFA(nil, nil, nil, nil) }))
	})
	for _, algorithm := range []otp.Algorithm{otp.AlgorithmSHA1, otp.AlgorithmSHA256, otp.AlgorithmSHA512} {
		for _, digits := range []otp.Digits{otp.DigitsSix, otp.DigitsEight} {
			for _, skew := range []uint{0, 1} {
				name := fmt.Sprintf("%s-%d-%d", algorithm.String(), digits, skew)
				t.Run(name, func(t *testing.T) {
					install(name, algorithm.String(), int(digits), skew, 5)
					code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 60, Digits: digits, Algorithm: algorithm})
					require.NoError(t, err)
					require.NoError(t, call([]string{name, name}, name+":passcode="+code))
					require.ErrorContains(t, call([]string{name}, name+":"+code), "invalid passcode")
				})
			}
		}
	}
	install("entity-bound", "SHA1", 6, 0, 5)
	boundCode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 60, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	boundReq := &logical.Request{EntityID: te.EntityID, MFACreds: logical.MFACreds{"entity-bound": []string{boundCode}}}
	require.ErrorContains(t, c.validateNamedMFA(ctx, boundReq, &logical.TokenEntry{}, []string{"entity-bound"}).ErrorOrNil(), "entity-backed token")
	require.NoError(t, c.validateNamedMFA(ctx, boundReq, te, []string{"entity-bound"}).ErrorOrNil())
	otherResp, err := c.identityStore.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "entity", Data: map[string]interface{}{"name": "stepup-other"}})
	require.NoError(t, err)
	otherTE := &logical.TokenEntry{EntityID: otherResp.Data["id"].(string), NamespaceID: namespace.RootNamespaceID}
	require.NoError(t, c.PersistTOTPKey(ctx, "entity-bound", otherTE.EntityID, secret))
	// Same code under the same method is independent for each calling entity.
	require.NoError(t, c.validateNamedMFA(ctx, boundReq, otherTE, []string{"entity-bound"}).ErrorOrNil())
	install("required", "SHA1", 6, 0, 5)
	require.ErrorContains(t, call([]string{"required"}), "required")
	require.ErrorContains(t, call([]string{"required"}, "required"), "not supported yet")
	require.ErrorContains(t, call([]string{"required"}, "required:bad"), "invalid passcode")
	require.ErrorContains(t, call([]string{"required"}, "required:password=secret"), "invalid credentials")
	require.ErrorContains(t, call([]string{"unknown"}), "unknown method")
	for _, kind := range []string{"duo", "okta", "pingid"} {
		entry, err := logical.StorageEntryJSON(namedMFAMethodPrefix+kind+"/"+kind, map[string]interface{}{"type": kind})
		require.NoError(t, err)
		require.NoError(t, storage.Put(ctx, entry))
		require.ErrorContains(t, call([]string{kind}), kind+" provider is not supported yet")
	}
	install("and-first", "SHA1", 6, 0, 5)
	install("and-second", "SHA1", 6, 0, 5)
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 60, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	require.ErrorContains(t, call([]string{"and-first", "and-second"}, "and-first:"+code), "and-second")
	install("both-first", "SHA1", 6, 0, 5)
	install("both-second", "SHA1", 6, 0, 5)
	require.NoError(t, call([]string{"both-first", "both-second"}, "both-first:"+code, "both-second:passcode="+code))
	install("limited", "SHA1", 6, 0, 2)
	for range 2 {
		require.ErrorContains(t, call([]string{"limited"}, "limited:bad"), "invalid passcode")
	}
	require.ErrorContains(t, call([]string{"limited"}, "limited:"+code), "maximum TOTP validation attempts")
	c.loginMFABackend.rateLimits.Delete("stepup:limited:" + te.EntityID)
	require.NoError(t, call([]string{"limited"}, "limited:"+code))
	for _, skew := range []uint{0, 1} {
		name := fmt.Sprintf("skew-%d", skew)
		install(name, "SHA1", 6, skew, 5)
		code, err := totp.GenerateCodeCustom(secret, time.Now().Add(-60*time.Second), totp.ValidateOpts{Period: 60, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		require.NoError(t, err)
		err = call([]string{name}, name+":"+code)
		if skew == 0 {
			require.ErrorContains(t, err, "invalid passcode")
		} else {
			require.NoError(t, err)
		}
	}
}

func TestNamedMFAPolicyPropagation(t *testing.T) {
	ctx := namespace.RootContext(t.Context())
	for _, suffix := range []string{"", `mfa_methods = ["first", "second"]`} {
		p, err := policy.ParseACLPolicy(namespace.RootNamespace, `path "secret/test" { capabilities = ["read"] `+suffix+` }`)
		require.NoError(t, err)
		acl, err := policy.NewACL(ctx, []*policy.Policy{p})
		require.NoError(t, err)
		result := acl.AllowOperation(ctx, &logical.Request{Path: "secret/test", Operation: logical.ReadOperation}, false)
		require.True(t, result.Allowed)
		if suffix == "" {
			require.Empty(t, result.MFAMethods)
		} else {
			require.Equal(t, []string{"first", "second"}, result.MFAMethods)
		}
	}
}

func TestNamedMFAPolicyRequirementsPropagation(t *testing.T) {
	ctx := namespace.RootContext(t.Context())
	t.Run("all-names", func(t *testing.T) {
		p, err := policy.ParseACLPolicy(namespace.RootNamespace, `path "secret/test" {
	capabilities = ["read"]
	mfa_requirements {
		mfa_method_names = ["first", "second"]
	}
}`)
		require.NoError(t, err)
		acl, err := policy.NewACL(ctx, []*policy.Policy{p})
		require.NoError(t, err)
		result := acl.AllowOperation(ctx, &logical.Request{Path: "secret/test", Operation: logical.ReadOperation}, false)
		require.True(t, result.Allowed)
		require.Len(t, result.MFARequirements, 1)
		require.False(t, result.MFARequirements[0].AnyNameToProceed)
		require.Equal(t, []string{"first", "second"}, result.MFARequirements[0].MFAAllNames)
		require.Nil(t, result.MFARequirements[0].MFAAnyNames)
	})
	t.Run("any-names", func(t *testing.T) {
		p, err := policy.ParseACLPolicy(namespace.RootNamespace, `path "secret/test" {
	capabilities = ["read"]
	mfa_requirements {
		mfa_method_names = ["first", "second"]
		any_name_to_proceed = true
	}
}`)
		require.NoError(t, err)
		acl, err := policy.NewACL(ctx, []*policy.Policy{p})
		require.NoError(t, err)
		result := acl.AllowOperation(ctx, &logical.Request{Path: "secret/test", Operation: logical.ReadOperation}, false)
		require.True(t, result.Allowed)
		require.Len(t, result.MFARequirements, 1)
		require.True(t, result.MFARequirements[0].AnyNameToProceed)
		require.Equal(t, []string{"first", "second"}, result.MFARequirements[0].MFAAnyNames)
	})
	t.Run("absent", func(t *testing.T) {
		p, err := policy.ParseACLPolicy(namespace.RootNamespace, `path "secret/test" { capabilities = ["read"] }`)
		require.NoError(t, err)
		acl, err := policy.NewACL(ctx, []*policy.Policy{p})
		require.NoError(t, err)
		result := acl.AllowOperation(ctx, &logical.Request{Path: "secret/test", Operation: logical.ReadOperation}, false)
		require.True(t, result.Allowed)
		require.Empty(t, result.MFARequirements)
	})
}
