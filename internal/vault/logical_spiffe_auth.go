// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func spiffeRoleFields() map[string]*framework.FieldSchema {
	m := map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "template": {Type: framework.TypeString}, "ttl": {Type: framework.TypeDurationSecond, Default: 300}, "use_jti_claim": {Type: framework.TypeBool}, "workload_id_patterns": {Type: framework.TypeCommaStringSlice}, "display_name": {Type: framework.TypeString}, "alias_metadata": {Type: framework.TypeKVPairs}, "policies": {Type: framework.TypeCommaStringSlice}}
	tokenutil.AddTokenFields(m)
	return m
}
func spiffePattern(p string) (*regexp.Regexp, error) {
	if p == "" || strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("patterns must be nonempty workload paths without leading slash")
	}
	var out strings.Builder
	out.WriteString("^")
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if i > 0 {
			out.WriteString("/")
		}
		if s == "+" {
			out.WriteString("[^/]+")
			continue
		}
		if strings.Contains(s, "+") || strings.Contains(s, "*") && (!strings.HasSuffix(p, "*") || i != len(parts)-1 || strings.Count(s, "*") != 1) {
			return nil, fmt.Errorf("invalid workload wildcard")
		}
		out.WriteString(regexp.QuoteMeta(strings.TrimSuffix(s, "*")))
		if strings.HasSuffix(s, "*") {
			out.WriteString(".*")
		}
	}
	out.WriteString("$")
	return regexp.Compile(out.String())
}
func (b *spiffeBackend) roles(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Operation == logical.ListOperation {
		k, e := r.Storage.List(ctx, "role/")
		return logical.ListResponse(k), e
	}
	name := d.Get("name").(string)
	key := "role/" + name
	if r.Operation == logical.DeleteOperation {
		return nil, r.Storage.Delete(ctx, key)
	}
	m, e := spiffeLoad(ctx, r.Storage, key)
	if e != nil {
		return nil, e
	}
	if r.Operation == logical.ReadOperation {
		if m == nil {
			return nil, nil
		}
		return &logical.Response{Data: m}, nil
	}
	if m == nil {
		m = map[string]interface{}{"ttl": 300, "use_jti_claim": false}
	}
	for k := range d.Schema {
		if k != "name" {
			if _, ok := d.Raw[k]; ok {
				m[k] = d.Get(k)
			}
		}
	}
	if b.auth {
		patterns := spiffeStrings(m["workload_id_patterns"])
		if len(patterns) == 0 {
			return logical.ErrorResponse("workload_id_patterns is required"), nil
		}
		seen := map[string]bool{}
		for _, p := range patterns {
			if _, e := spiffePattern(p); e != nil {
				return logical.ErrorResponse("%s", e), nil
			}
			if seen[p] {
				return logical.ErrorResponse("duplicate workload pattern"), nil
			}
			seen[p] = true
		}
		names, e := r.Storage.List(ctx, "role/")
		if e != nil {
			return nil, e
		}
		for _, other := range names {
			if other == name {
				continue
			}
			role, e := spiffeLoad(ctx, r.Storage, "role/"+other)
			if e != nil {
				return nil, e
			}
			for _, p := range spiffeStrings(role["workload_id_patterns"]) {
				if seen[p] {
					return logical.ErrorResponse("workload pattern already belongs to another role"), nil
				}
			}
		}
		if _, ok := m["token_policies"]; !ok {
			if v, ok := m["policies"]; ok {
				m["token_policies"] = v
			}
		}
		td := &framework.FieldData{Raw: m, Schema: spiffeRoleFields()}
		var params tokenutil.TokenParams
		if e = params.ParseTokenFields(r, td); e != nil {
			return logical.ErrorResponse("%s", e), nil
		}
	} else {
		tmpl := spiffeString(m, "template")
		if decoded, e := base64.StdEncoding.DecodeString(tmpl); e == nil {
			tmpl = string(decoded)
		}
		var claims map[string]interface{}
		if json.Unmarshal([]byte(tmpl), &claims) != nil || spiffeString(claims, "sub") == "" {
			return logical.ErrorResponse("template must be JSON containing sub"), nil
		}
		if strings.Contains(tmpl, "{{") {
			return logical.ErrorResponse("dynamic identity templates are not supported"), nil
		}
		if spiffeSeconds(m, "ttl") <= 0 {
			return logical.ErrorResponse("ttl must be positive"), nil
		}
		m["template"] = tmpl
	}
	return nil, spiffePut(ctx, r.Storage, key, m)
}
func spiffeBundle(bundle string) (*jose.JSONWebKeySet, error) {
	var keys jose.JSONWebKeySet
	if json.Unmarshal([]byte(bundle), &keys) == nil && len(keys.Keys) > 0 {
		for _, k := range keys.Keys {
			if !k.Valid() || !k.IsPublic() {
				return nil, fmt.Errorf("bundle must contain valid public keys only")
			}
		}
		return &keys, nil
	}
	rest := []byte(bundle)
	count := 0
	for len(rest) > 0 {
		block, left := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("invalid trust bundle")
		}
		rest = left
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected certificate")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, e
		}
		keys.Keys = append(keys.Keys, jose.JSONWebKey{Key: cert.PublicKey, Use: "sig"})
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("bundle is required")
	}
	return &keys, nil
}
func (b *spiffeBackend) configureBundle(ctx context.Context, r *logical.Request, m map[string]interface{}) error {
	profile := spiffeString(m, "profile")
	switch profile {
	case "static", "https_web_pem", "https_web_bundle", "https_spiffe_bundle":
	default:
		return fmt.Errorf("valid profile is required")
	}
	bundle := spiffeString(m, "bundle")
	if profile == "static" || profile == "https_spiffe_bundle" {
		if _, e := spiffeBundle(bundle); e != nil {
			return e
		}
	}
	if profile != "static" {
		u, e := url.Parse(spiffeString(m, "endpoint_url"))
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("HTTPS endpoint_url is required")
		}
		if profile == "https_spiffe_bundle" {
			if _, e = spiffeSubject(spiffeString(m, "endpoint_spiffe_id"), spiffeString(m, "trust_domain")); e != nil {
				return fmt.Errorf("valid endpoint_spiffe_id is required")
			}
			return fmt.Errorf("HTTPS SPIFFE bundle transport is not yet supported")
		}
		if m["defer_bundle_fetch"] == true && len(r.Data) > 0 {
			return nil
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		defer transport.CloseIdleConnections()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if roots := spiffeString(m, "endpoint_root_ca_truststore_pem"); roots != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(roots)) {
				return fmt.Errorf("invalid endpoint root truststore")
			}
			transport.TLSClientConfig.RootCAs = pool
		}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("bundle redirects are not permitted") }}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if e != nil {
			return e
		}
		resp, e := client.Do(req)
		if e != nil {
			return fmt.Errorf("bundle fetch failed: %w", e)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("bundle fetch returned %d", resp.StatusCode)
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
		if e != nil {
			return e
		}
		if len(raw) > 4*1024*1024 {
			return fmt.Errorf("trust bundle too large")
		}
		bundle = string(raw)
	}
	if _, e := spiffeBundle(bundle); e != nil {
		return e
	}
	m["cached_bundle"] = bundle
	m["cached_bundle_fetch_time"] = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// Pattern priority follows the documented ACL-style ordering: later wildcard,
// non-glob, fewer segment wildcards, longer pattern, then lexical ordering.
func spiffePatternLess(a, b string) bool {
	wild := func(s string) int {
		i := strings.IndexAny(s, "*+")
		if i < 0 {
			return len(s) + 1
		}
		return i
	}
	if wild(a) != wild(b) {
		return wild(a) < wild(b)
	}
	if strings.HasSuffix(a, "*") != strings.HasSuffix(b, "*") {
		return strings.HasSuffix(a, "*")
	}
	if strings.Count(a, "+") != strings.Count(b, "+") {
		return strings.Count(a, "+") > strings.Count(b, "+")
	}
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}
func (b *spiffeBackend) login(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, e := spiffeLoad(ctx, r.Storage, "config")
	if e != nil {
		return nil, e
	}
	if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}
	typ := d.Get("type").(string)
	if typ != "auto" && typ != "jwt" && typ != "cert" {
		return logical.ErrorResponse("invalid login type"), nil
	}
	if typ == "cert" {
		return logical.ErrorResponse("certificate login is not supported"), nil
	}
	bearer := ""
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Authorization") && len(v) == 1 {
			bearer = v[0]
		}
	}
	parts := strings.Fields(bearer)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return logical.ErrorResponse("JWT-SVID bearer is required"), nil
	}
	keys, e := spiffeBundle(spiffeString(c, "cached_bundle"))
	if e != nil {
		return logical.ErrorResponse("trust bundle unavailable"), nil
	}
	token, e := jwt.ParseSigned(parts[1], spiffeAlgorithms)
	if e != nil {
		return logical.ErrorResponse("invalid JWT-SVID"), nil
	}
	var claims jwt.Claims
	verified := false
	for _, key := range keys.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if len(token.Headers) != 1 {
			continue
		}
		h := token.Headers[0]
		if key.KeyID != "" && h.KeyID != key.KeyID {
			continue
		}
		if key.Algorithm != "" && string(h.Algorithm) != key.Algorithm {
			continue
		}
		if token.Claims(key.Key, &claims) == nil {
			verified = true
			break
		}
	}
	if !verified || claims.Expiry == nil || claims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, 0) != nil {
		return logical.ErrorResponse("JWT-SVID verification failed"), nil
	}
	allowed := false
	for _, a := range spiffeStrings(c["audience"]) {
		if claims.Audience.Contains(a) {
			allowed = true
		}
	}
	if !allowed {
		return logical.ErrorResponse("JWT-SVID audience denied"), nil
	}
	sub, e := spiffeSubject(claims.Subject, spiffeString(c, "trust_domain"))
	if e != nil || !strings.HasPrefix(claims.Subject, "spiffe://") {
		return logical.ErrorResponse("invalid SPIFFE ID"), nil
	}
	u, _ := url.Parse(sub)
	workload := strings.TrimPrefix(u.Path, "/")
	names, e := r.Storage.List(ctx, "role/")
	if e != nil {
		return nil, e
	}
	requested := d.Get("role").(string)
	type match struct {
		pattern, name string
		role          map[string]interface{}
	}
	matches := []match{}
	for _, name := range names {
		if requested != "" && name != requested {
			continue
		}
		role, e := spiffeLoad(ctx, r.Storage, "role/"+name)
		if e != nil {
			return nil, e
		}
		for _, p := range spiffeStrings(role["workload_id_patterns"]) {
			re, e := spiffePattern(p)
			if e == nil && re.MatchString(workload) {
				matches = append(matches, match{p, name, role})
			}
		}
	}
	if len(matches) == 0 {
		return logical.ErrorResponse("no matching workload role"), nil
	}
	sort.Slice(matches, func(i, j int) bool { return spiffePatternLess(matches[i].pattern, matches[j].pattern) })
	selected := matches[len(matches)-1]
	var params tokenutil.TokenParams
	if e = params.ParseTokenFields(r, &framework.FieldData{Raw: selected.role, Schema: spiffeRoleFields()}); e != nil {
		return nil, e
	}
	auth := &logical.Auth{DisplayName: spiffeString(selected.role, "display_name"), Alias: &logical.Alias{Name: sub}, Metadata: map[string]string{"spiffe_id": sub, "role": selected.name}, InternalData: map[string]interface{}{"role": selected.name}}
	if auth.DisplayName == "" {
		auth.DisplayName = selected.name
	}
	raw, _ := json.Marshal(selected.role["alias_metadata"])
	_ = json.Unmarshal(raw, &auth.Alias.Metadata)
	params.PopulateTokenAuth(auth, r)
	return &logical.Response{Auth: auth}, nil
}
