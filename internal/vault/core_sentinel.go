// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/v2/internal/vault/sentinel"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Sentinel-shaped policy gate, clean-roomed from public Vault Enterprise
// documentation only (see compat/specs/sentinel/notes.md). Enforcement
// semantics follow the documented evaluation order: token ACLs must grant,
// then RGPs on the token must pass, then EGPs on the requested path (exact
// match plus prefix-matching EGPs on less-specific paths) must pass. Root
// tokens are not subject to Sentinel policy checks (handled by the caller,
// which returns before this hook runs). Unauthenticated requests skip ACL
// and RGP evaluation and evaluate EGPs only.
//
// The policy document language is the evaluator's documented condition
// subset (sentinel package); the policy string itself round-trips verbatim
// through the API, matching the documented read shape.

// sentinelCacheTTL bounds cross-node staleness of the policy cache: writes
// land on the active node, other nodes refresh within one TTL.
const sentinelCacheTTL = 30 * time.Second

// getSentinelStore returns the governing-policy store, creating it on first
// use. It is safe for concurrent use.
func (c *Core) getSentinelStore() *sentinel.Store {
	c.sentinelStoreLock.Lock()
	defer c.sentinelStoreLock.Unlock()
	if c.sentinelStore == nil {
		c.sentinelStore = sentinel.NewStore(c.systemBarrierView, sentinelCacheTTL)
	}
	return c.sentinelStore
}

// sentinelPoliciesForPath returns the EGP policies that apply to a request
// path: those with an exact path match and those whose glob path matches the
// request as a prefix (a less-specific path). "*" applies to all requests.
func sentinelPoliciesForPath(path string, egps map[string]*sentinel.Policy) []*sentinel.Policy {
	normalized := "/" + trimSlashes(path)
	var applicable []*sentinel.Policy
	for _, name := range sentinel.SortedNames(egps) {
		policy := egps[name]
		for _, pattern := range policy.Paths {
			if sentinel.PathMatches(pattern, normalized) {
				applicable = append(applicable, policy)
				break
			}
		}
	}
	return applicable
}

func trimSlashes(p string) string {
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	for len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

// evaluateSentinelPolicies enforces the governing policies for a request.
// unauth selects the documented unauthenticated flow: EGPs only.
func (c *Core) evaluateSentinelPolicies(ctx context.Context, req *logical.Request, te *logical.TokenEntry, unauth bool) error {
	if req == nil {
		return nil
	}
	store := c.getSentinelStore()

	egps, err := store.List(ctx, sentinel.TypeEGP)
	if err != nil {
		return fmt.Errorf("failed to load EGP policies: %w", err)
	}
	for _, policy := range sentinelPoliciesForPath(req.Path, egps) {
		if err := c.evaluateSentinelPolicy(ctx, req, nil, policy, unauth); err != nil {
			return err
		}
	}

	if unauth || te == nil {
		return nil
	}

	rgps, err := store.List(ctx, sentinel.TypeRGP)
	if err != nil {
		return fmt.Errorf("failed to load RGP policies: %w", err)
	}
	for _, policyName := range te.Policies {
		if policy, ok := rgps[policyName]; ok {
			if err := c.evaluateSentinelPolicy(ctx, req, te, policy, unauth); err != nil {
				return err
			}
		}
	}

	return nil
}

// evaluateSentinelPolicy evaluates one governing policy against the request
// and enforces its documented level. An override relaxes soft-mandatory
// policies only; failures and overrides are logged, and the override is
// visible on the request (and therefore in the audit log).
func (c *Core) evaluateSentinelPolicy(ctx context.Context, req *logical.Request, te *logical.TokenEntry, policy *sentinel.Policy, unauth bool) error {
	doc, err := sentinel.DecodePolicyDocument(policy.Policy)
	if err != nil {
		return fmt.Errorf("governing policy %q is invalid: %w", policy.Name, err)
	}
	rule := new(sentinel.Rule)
	if err := rule.Unmarshal(doc); err != nil {
		return fmt.Errorf("governing policy %q is invalid: %w", policy.Name, err)
	}

	passed := rule.When.Evaluate(&sentinel.EvaluateContext{Req: req, TokenEntry: te})
	if passed {
		return nil
	}

	switch policy.EnforcementLevel {
	case sentinel.EnforcementAdvisory:
		// Advisory policies are allowed to fail (educational).
		c.logger.Debug("advisory governing policy failed", "policy", policy.Name, "path", req.Path)
		return nil
	case sentinel.EnforcementSoftMandatory:
		if req.PolicyOverride {
			c.logger.Warn("soft-mandatory governing policy failed; allowing request due to policy override", "policy", policy.Name, "path", req.Path)
			return nil
		}
		c.logger.Warn("request denied by governing policy", "policy", policy.Name, "enforcement_level", policy.EnforcementLevel, "path", req.Path)
		return fmt.Errorf("denied by soft-mandatory governing policy %q; resend the request with a policy override to bypass", policy.Name)
	case sentinel.EnforcementHardMandatory:
		c.logger.Warn("request denied by governing policy", "policy", policy.Name, "enforcement_level", policy.EnforcementLevel, "path", req.Path)
		return fmt.Errorf("denied by hard-mandatory governing policy %q", policy.Name)
	}
	return nil
}
