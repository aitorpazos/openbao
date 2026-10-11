// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var spiffeAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512}

type spiffeBackend struct {
	*framework.Backend
	mu     sync.Mutex
	auth   bool
	issuer string
}
type spiffeSigningKey struct {
	Key     jose.JSONWebKey `json:"key"`
	Expires int64           `json:"expires"`
}

func spiffeFactory(auth bool, issuer string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := &spiffeBackend{auth: auth, issuer: issuer}
		fields := map[string]*framework.FieldSchema{}
		for _, s := range []string{"trust_domain", "profile", "bundle", "endpoint_url", "endpoint_spiffe_id", "endpoint_root_ca_truststore_pem", "jwt_issuer_url", "jwt_signing_algorithm"} {
			fields[s] = &framework.FieldSchema{Type: framework.TypeString}
		}
		for _, s := range []string{"defer_bundle_fetch", "jwt_oidc_compatibility_mode"} {
			fields[s] = &framework.FieldSchema{Type: framework.TypeBool}
		}
		fields["audience"] = &framework.FieldSchema{Type: framework.TypeCommaStringSlice}
		for _, s := range []string{"key_lifetime", "bundle_refresh_hint"} {
			fields[s] = &framework.FieldSchema{Type: framework.TypeDurationSecond}
		}
		b.Backend = &framework.Backend{BackendType: logical.TypeLogical, Help: "SPIFFE JWT-SVID issuance and workload authentication.", Paths: []*framework.Path{
			{Pattern: "config", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.config, logical.UpdateOperation: b.config}},
			{Pattern: "role/?$", Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: b.roles}},
			{Pattern: "role/" + framework.GenericNameRegex("name"), Fields: spiffeRoleFields(), Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.roles, logical.UpdateOperation: b.roles, logical.DeleteOperation: b.roles}},
		}}
		if auth {
			b.BackendType = logical.TypeCredential
			b.PathsSpecial = &logical.Paths{Unauthenticated: []string{"login"}}
			b.Paths = append(b.Paths, &framework.Path{Pattern: "login", Fields: map[string]*framework.FieldSchema{"role": {Type: framework.TypeString}, "type": {Type: framework.TypeString, Default: "auto"}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.login}})
		} else {
			b.PathsSpecial = &logical.Paths{Unauthenticated: []string{".well-known/openid-configuration", ".well-known/keys"}, SealWrapStorage: []string{"signing/"}}
			b.Paths = append(b.Paths,
				&framework.Path{Pattern: "role/" + framework.GenericNameRegex("name") + "/mintjwt", Fields: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "audience": {Type: framework.TypeCommaStringSlice}}, Callbacks: map[logical.Operation]framework.OperationFunc{logical.UpdateOperation: b.mint}},
				&framework.Path{Pattern: `\.well-known/(openid-configuration|keys)`, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: b.discovery}})
		}
		return b, b.Setup(ctx, conf)
	}
}
func spiffeLoad(ctx context.Context, s logical.Storage, key string) (map[string]interface{}, error) {
	e, err := s.Get(ctx, key)
	if err != nil || e == nil {
		return nil, err
	}
	var m map[string]interface{}
	err = e.DecodeJSON(&m)
	return m, err
}
func spiffePut(ctx context.Context, s logical.Storage, key string, v interface{}) error {
	e, err := logical.StorageEntryJSON(key, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, e)
}
func spiffeString(m map[string]interface{}, k string) string { s, _ := m[k].(string); return s }
func spiffeSeconds(m map[string]interface{}, k string) int64 {
	switch v := m[k].(type) {
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}
func spiffeStrings(v interface{}) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []interface{}:
		r := []string{}
		for _, v := range x {
			if s, ok := v.(string); ok {
				r = append(r, s)
			}
		}
		return r
	}
	return nil
}
func spiffeDomain(s string) bool {
	u, e := url.Parse("spiffe://" + s)
	return e == nil && u.Host == s && u.Hostname() == s && s != "" && u.User == nil && !strings.ContainsAny(s, "/:?#%@ ")
}
func (b *spiffeBackend) config(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, err := spiffeLoad(ctx, r.Storage, "config")
	if err != nil {
		return nil, err
	}
	if r.Operation == logical.ReadOperation {
		if m == nil {
			return nil, nil
		}
		return &logical.Response{Data: m}, nil
	}
	if m == nil {
		m = map[string]interface{}{}
		if !b.auth {
			m["key_lifetime"] = 86400
			m["bundle_refresh_hint"] = 3600
			m["jwt_signing_algorithm"] = "RS256"
			m["jwt_oidc_compatibility_mode"] = false
			m["jwt_issuer_url"] = b.issuer
		}
	}
	for k := range d.Schema {
		if _, ok := d.Raw[k]; ok {
			m[k] = d.Get(k)
		}
	}
	domain := strings.TrimPrefix(spiffeString(m, "trust_domain"), "spiffe://")
	if !spiffeDomain(domain) {
		return logical.ErrorResponse("valid trust_domain is required"), nil
	}
	m["trust_domain"] = domain
	if b.auth {
		if err := b.configureBundle(ctx, r, m); err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
	} else {
		alg := jose.SignatureAlgorithm(spiffeString(m, "jwt_signing_algorithm"))
		found := false
		for _, a := range spiffeAlgorithms {
			if a == alg {
				found = true
			}
		}
		if !found {
			return logical.ErrorResponse("unsupported jwt_signing_algorithm"), nil
		}
		life, hint := spiffeSeconds(m, "key_lifetime"), spiffeSeconds(m, "bundle_refresh_hint")
		if life <= 0 || hint <= 0 || hint > life/10 {
			return logical.ErrorResponse("bundle_refresh_hint must be positive and at most key_lifetime/10"), nil
		}
		if issuer := spiffeString(m, "jwt_issuer_url"); issuer != "" {
			u, e := url.Parse(issuer)
			if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return logical.ErrorResponse("invalid jwt_issuer_url"), nil
			}
		}
		if _, err := b.signingKey(ctx, r.Storage, m); err != nil {
			return nil, err
		}
	}
	return nil, spiffePut(ctx, r.Storage, "config", m)
}

// Old public keys remain published until their expiry; tokens never outlive their signing key.
func (b *spiffeBackend) signingKey(ctx context.Context, s logical.Storage, c map[string]interface{}) (*spiffeSigningKey, error) {
	alg := spiffeString(c, "jwt_signing_algorithm")
	e, err := s.Get(ctx, "signing/current")
	if err != nil {
		return nil, err
	}
	if e != nil {
		var k spiffeSigningKey
		if err = e.DecodeJSON(&k); err != nil {
			return nil, err
		}
		if k.Key.Algorithm == alg && k.Expires > time.Now().Add(time.Duration(spiffeSeconds(c, "bundle_refresh_hint"))*time.Second).Unix() {
			return &k, nil
		}
	}
	var private interface{}
	switch alg {
	case "ES256":
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		private, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		private, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		private, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, err
	}
	key := jose.JSONWebKey{Key: private, Algorithm: alg, Use: "sig"}
	pub, _ := json.Marshal(key.Public())
	sum := sha256.Sum256(pub)
	key.KeyID = base64.RawURLEncoding.EncodeToString(sum[:])
	k := &spiffeSigningKey{Key: key, Expires: time.Now().Unix() + spiffeSeconds(c, "key_lifetime")}
	if err = spiffePut(ctx, s, "signing/public/"+key.KeyID, spiffeSigningKey{Key: key.Public(), Expires: k.Expires}); err != nil {
		return nil, err
	}
	return k, spiffePut(ctx, s, "signing/current", k)
}
func spiffeSubject(sub, domain string) (string, error) {
	if strings.HasPrefix(sub, "/") {
		sub = "spiffe://" + domain + sub
	}
	u, e := url.Parse(sub)
	if e != nil || u.Scheme != "spiffe" || u.Host != domain || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(sub, " %\\?#") {
		return "", fmt.Errorf("invalid SPIFFE ID or mismatched trust domain")
	}
	for _, p := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if p == "." || p == ".." || p == "" {
			return "", fmt.Errorf("invalid workload path")
		}
	}
	return sub, nil
}
func (b *spiffeBackend) mint(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, e := spiffeLoad(ctx, r.Storage, "config")
	if e != nil {
		return nil, e
	}
	if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}
	role, e := spiffeLoad(ctx, r.Storage, "role/"+d.Get("name").(string))
	if e != nil || role == nil {
		return nil, e
	}
	var claims map[string]interface{}
	if e = json.Unmarshal([]byte(spiffeString(role, "template")), &claims); e != nil {
		return nil, e
	}
	sub, e := spiffeSubject(spiffeString(claims, "sub"), spiffeString(c, "trust_domain"))
	if e != nil {
		return logical.ErrorResponse("%s", e), nil
	}
	if c["jwt_oidc_compatibility_mode"] == true && len(sub) > 255 {
		return logical.ErrorResponse("SPIFFE ID exceeds 255 characters"), nil
	}
	aud := d.Get("audience").([]string)
	if len(aud) == 0 {
		return logical.ErrorResponse("audience is required"), nil
	}
	k, e := b.signingKey(ctx, r.Storage, c)
	if e != nil {
		return nil, e
	}
	now := time.Now().Unix()
	exp := now + spiffeSeconds(role, "ttl")
	if exp > k.Expires {
		exp = k.Expires
	}
	claims["sub"] = sub
	claims["iss"] = spiffeString(c, "jwt_issuer_url")
	claims["aud"] = aud
	claims["iat"] = now
	claims["exp"] = exp
	delete(claims, "nbf")
	delete(claims, "jti")
	claims["vault.entity.id"] = r.EntityID
	if role["use_jti_claim"] == true {
		v := make([]byte, 16)
		if _, e = rand.Read(v); e != nil {
			return nil, e
		}
		claims["jti"] = base64.RawURLEncoding.EncodeToString(v)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.Key.Algorithm), Key: k.Key}, (&jose.SignerOptions{}).WithType("JWT"))
	if e != nil {
		return nil, e
	}
	token, e := jwt.Signed(signer).Claims(claims).Serialize()
	if e != nil {
		return nil, e
	}
	return &logical.Response{Data: map[string]interface{}{"token": token}}, nil
}
func (b *spiffeBackend) discovery(ctx context.Context, r *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, e := spiffeLoad(ctx, r.Storage, "config")
	if e != nil || c == nil {
		return nil, e
	}
	var v interface{}
	if strings.HasSuffix(r.Path, "keys") {
		if _, e = b.signingKey(ctx, r.Storage, c); e != nil {
			return nil, e
		}
		ids, e := r.Storage.List(ctx, "signing/public/")
		if e != nil {
			return nil, e
		}
		keys := []jose.JSONWebKey{}
		for _, id := range ids {
			entry, e := r.Storage.Get(ctx, "signing/public/"+id)
			if e != nil {
				return nil, e
			}
			if entry == nil {
				continue
			}
			var k spiffeSigningKey
			if e = entry.DecodeJSON(&k); e != nil {
				return nil, e
			}
			if k.Expires > time.Now().Unix() {
				keys = append(keys, k.Key)
			}
		}
		v = jose.JSONWebKeySet{Keys: keys}
	} else {
		issuer := strings.TrimRight(spiffeString(c, "jwt_issuer_url"), "/")
		v = map[string]interface{}{"issuer": issuer, "jwks_uri": issuer + "/v1/" + r.MountPoint + ".well-known/keys", "response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": spiffeAlgorithms}
	}
	body, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return &logical.Response{Data: map[string]interface{}{logical.HTTPStatusCode: 200, logical.HTTPContentType: "application/json", logical.HTTPRawBody: body}}, nil
}
