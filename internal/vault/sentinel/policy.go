// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package sentinel implements a Sentinel-shaped policy gate, clean-roomed
// from public Vault Enterprise documentation only (see
// compat/specs/sentinel/notes.md): the sys/policies/{egp,rgp} API surface and
// the documented enforcement semantics (advisory / soft-mandatory /
// hard-mandatory, path-scoped EGPs with prefix globs, token-scoped RGPs,
// policy override, root bypass).
//
// The policy document language is NOT the Sentinel language. This package
// accepts a documented declarative condition subset (see eval.go) instead;
// the API surface keeps the documented shape and round-trips the stored
// policy string verbatim. This restriction is a documented deviation.
package sentinel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// EnforcementLevel values documented for both EGP and RGP policies
// (docs/enterprise/sentinel, "Policy enforcement levels").
const (
	EnforcementAdvisory       = "advisory"
	EnforcementSoftMandatory  = "soft-mandatory"
	EnforcementHardMandatory  = "hard-mandatory"
)

// Policy is a Sentinel-shaped governing policy.
type Policy struct {
	// Name of the policy (unique per type; RGPs additionally cannot share
	// a name with an ACL policy).
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// Policy is the policy document. Stored verbatim; validated at write
	// time against the evaluator's documented subset (after an optional
	// base64 decode, per the documented API contract).
	Policy string `json:"policy" structs:"policy" mapstructure:"policy"`

	// EnforcementLevel is one of the documented values above.
	EnforcementLevel string `json:"enforcement_level" structs:"enforcement_level" mapstructure:"enforcement_level"`

	// Paths applies to EGPs only: the paths on which the EGP is enforced.
	// A trailing glob ("*") performs a prefix match; "*" alone matches all
	// requests. Empty for RGPs.
	Paths []string `json:"paths,omitempty" structs:"paths,omitempty" mapstructure:"paths"`
}

// ValidEnforcement reports whether s is a documented enforcement level.
func ValidEnforcement(s string) bool {
	switch s {
	case EnforcementAdvisory, EnforcementSoftMandatory, EnforcementHardMandatory:
		return true
	}
	return false
}

// PolicyType is the governing-policy type: EGP (path-scoped) or RGP
// (token-scoped). This type is local to the gate; it does not alter the
// ACL policy store's namespace.
type PolicyType int

const (
	TypeEGP PolicyType = iota
	TypeRGP
)

func (t PolicyType) String() string {
	switch t {
	case TypeEGP:
		return "egp"
	case TypeRGP:
		return "rgp"
	}
	return ""
}

// StorageKey returns the storage key for a policy of the given type.
func StorageKey(t PolicyType, name string) string {
	return "core/sentinel/" + t.String() + "/" + name
}

// Validate checks a policy against the documented API contract.
// isEGP selects the EGP-specific path rules; aclPolicyNames, when non-nil,
// is the set of existing ACL policy names used to enforce the documented
// RGP/ACL name-space rule.
func (p *Policy) Validate(isEGP bool, aclPolicyNames func() ([]string, error)) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Name != SanitizeName(p.Name) {
		return fmt.Errorf("policy name must be lowercase, without slashes or whitespace")
	}
	if strings.TrimSpace(p.Policy) == "" {
		return fmt.Errorf("policy is required")
	}
	if !ValidEnforcement(p.EnforcementLevel) {
		return fmt.Errorf("enforcement_level must be one of %s, %s, %s",
			EnforcementAdvisory, EnforcementSoftMandatory, EnforcementHardMandatory)
	}

	if !isEGP {
		if len(p.Paths) != 0 {
			return fmt.Errorf("RGP policies do not take paths; RGPs are tied to tokens")
		}
		if aclPolicyNames != nil {
			names, err := aclPolicyNames()
			if err != nil {
				return fmt.Errorf("failed to check ACL policy names: %w", err)
			}
			for _, existing := range names {
				if existing == p.Name {
					return fmt.Errorf("RGP policies cannot share names with ACL policies: %q already exists as an ACL policy", p.Name)
				}
			}
		}
	}

	// Decode an optional base64-encoded policy document, per the documented
	// API contract ("can be base64-encoded to avoid string escaping").
	doc, err := DecodePolicyDocument(p.Policy)
	if err != nil {
		return err
	}
	if err := ValidateDocument(doc); err != nil {
		return err
	}

	if isEGP {
		if len(p.Paths) == 0 {
			return fmt.Errorf("paths is required for EGP policies")
		}
		for _, path := range p.Paths {
			if err := ValidateEGPPath(path); err != nil {
				return err
			}
		}
	}

	return nil
}

// DecodePolicyDocument returns the evaluation-ready policy document. If the
// stored string decodes as base64, the decoded bytes are returned (the
// documented API accepts base64-encoded documents); otherwise the string is
// returned as-is.
func DecodePolicyDocument(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil &&
		utf8Printable(decoded) {
		trimmed = string(decoded)
	}
	return trimmed, nil
}

func utf8Printable(b []byte) bool {
	for _, r := range string(b) {
		if r == 0xFFFD || r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
	}
	return true
}

// ValidateEGPPath checks one documented EGP path entry. Glob characters may
// only denote suffixes (a trailing "*"); a path of "*" applies to all
// requests.
func ValidateEGPPath(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("EGP paths must not be empty")
	}
	if i := strings.IndexByte(p, '*'); i != -1 {
		if i != len(p)-1 {
			return fmt.Errorf("EGP path globs must be suffixes: %q", p)
		}
	}
	return nil
}

// SanitizeName normalizes a policy name the way the ACL policy store does
// (lowercase, trimmed, path-cleaned).
func SanitizeName(name string) string {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if u, err := url.PathUnescape(sanitized); err == nil {
		sanitized = u
	}
	sanitized = strings.TrimSuffix(strings.TrimPrefix(sanitized, "/"), "/")
	return sanitized
}

// Decode parses raw storage bytes into a Policy.
func Decode(data []byte) (*Policy, error) {
	p := new(Policy)
	if err := json.Unmarshal(data, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Encode serializes a Policy for storage.
func (p *Policy) Encode() ([]byte, error) {
	return json.Marshal(p)
}

// SortedNames returns policy names in stable order for LIST responses.
func SortedNames(policies map[string]*Policy) []string {
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
