// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// validateNamedMFA implements single-phase step-up, not login MFA. The public
// step-up documentation does not specify failure status/body: we deliberately
// choose HTTP 403 with named method errors, not a challenge (compatibility choice).
// Call only after ACL and sudo checks succeed, and only for nonempty methods.
// Root retains its existing ACL bypass. Names are ANDed, not alternatives.
func (c *Core) validateNamedMFA(ctx context.Context, req *logical.Request, te *logical.TokenEntry, methods []string) *multierror.Error {
	if len(methods) == 0 {
		return nil
	}
	var result *multierror.Error
	seen := make(map[string]bool, len(methods))
	for _, name := range methods {
		if seen[name] {
			continue
		}
		seen[name] = true
		if err := c.validateNamedMFAMethod(ctx, req, te, name); err != nil {
			result = multierror.Append(result, fmt.Errorf("step-up MFA method %q: %w", name, err))
		}
	}
	return result
}

func (c *Core) validateNamedMFAMethod(ctx context.Context, req *logical.Request, te *logical.TokenEntry, name string) error {
	// Reject storage-path traversal even for policies written by administrators.
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return fmt.Errorf("unknown method")
	}
	storage := c.NamespaceView(namespace.RootNamespace).SubView(barrier.SystemBarrierPrefix)
	var config *logical.StorageEntry
	for _, kind := range []string{"totp", "duo", "okta", "pingid"} {
		entry, err := storage.Get(ctx, namedMFAMethodPrefix+kind+"/"+name)
		if err != nil {
			return fmt.Errorf("cannot read method configuration")
		}
		if entry == nil {
			continue
		}
		if config != nil {
			return fmt.Errorf("ambiguous method name")
		}
		if kind != "totp" {
			return fmt.Errorf("%s provider is not supported yet", kind)
		}
		config = entry
	}
	if config == nil {
		return fmt.Errorf("unknown method")
	}
	var cfg struct {
		namedTOTPEnrollmentConfig
		MaxValidationAttempts uint32 `json:"max_validation_attempts"`
	}
	if err := config.DecodeJSON(&cfg); err != nil {
		return fmt.Errorf("invalid method configuration")
	}
	algorithm, ok := map[string]otp.Algorithm{"SHA1": otp.AlgorithmSHA1, "SHA256": otp.AlgorithmSHA256, "SHA512": otp.AlgorithmSHA512}[cfg.Algorithm]
	if !ok || cfg.ID == "" || cfg.Period == 0 || (cfg.Digits != 6 && cfg.Digits != 8) || cfg.Skew > 1 || cfg.MaxValidationAttempts == 0 {
		return fmt.Errorf("invalid method configuration")
	}
	// HTTP request handling already calls logical.Request.ParseMFAHeaders. Reuse
	// its name[:key[=value]] parsing and parseMfaFactors from login MFA; never echo
	// malformed factors, since those may contain secrets.
	factors, err := parseMfaFactors(req.MFACreds[name])
	if err != nil {
		return fmt.Errorf("invalid credentials")
	}
	if factors == nil || factors.passcode == "" {
		return fmt.Errorf("missing passcode; passcode-less validation is not supported yet")
	}
	// Trust the authenticated token, not body fields or a caller-provided EntityID.
	if te == nil || te.EntityID == "" {
		return fmt.Errorf("an entity-backed token is required")
	}
	entity, err := c.identityStore.MemDBEntityByID(ctx, te.EntityID, false)
	if err != nil || entity == nil || entity.Disabled {
		return fmt.Errorf("invalid calling entity")
	}
	ns, err := c.NamespaceByID(ctx, entity.NamespaceID)
	if err != nil || ns == nil {
		return fmt.Errorf("invalid entity namespace")
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)
	// Follow login MFA's expiring per-method+entity attempt counter and atomic
	// used-code insertion. Prefix and entity scope isolate step-up from login MFA
	// and prevent equal codes belonging to different entities from colliding.
	rateID := "stepup:" + cfg.ID + ":" + entity.ID
	ttl := time.Duration(cfg.Period) * time.Second * time.Duration(2*cfg.Skew+1)
	_ = c.loginMFABackend.rateLimits.AddWithExpire(rateID, 0, ttl)
	attempts, ok := c.loginMFABackend.rateLimits.Modify(rateID, func(n uint32) uint32 {
		if n == ^uint32(0) {
			return n
		}
		return n + 1
	})
	if !ok || attempts > cfg.MaxValidationAttempts {
		return fmt.Errorf("maximum TOTP validation attempts exceeded; retry after %s", ttl)
	}
	key, err := c.fetchTOTPKey(ctx, cfg.ID, entity.ID)
	if err != nil || key == "" {
		return fmt.Errorf("entity is not enrolled")
	}
	valid, err := totp.ValidateCustom(factors.passcode, key, time.Now(), totp.ValidateOpts{Period: cfg.Period, Skew: uint(cfg.Skew), Digits: otp.Digits(cfg.Digits), Algorithm: algorithm})
	if err != nil || !valid {
		return fmt.Errorf("invalid passcode")
	}
	usedID := rateID + ":" + factors.passcode
	if err := c.loginMFABackend.usedCodes.AddWithExpire(usedID, struct{}{}, ttl); err != nil {
		return fmt.Errorf("invalid passcode")
	}
	c.loginMFABackend.rateLimits.Delete(rateID)
	return nil
}
