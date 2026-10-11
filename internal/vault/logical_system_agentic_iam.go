// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// Configuration only: these records do not enable JWT authentication or RAR enforcement.
type oauthResourceProfile struct {
	ConfigID                     string             `json:"config_id"`
	Name                         string             `json:"profile_name"`
	Issuer                       string             `json:"issuer_id"`
	UseJWKS                      bool               `json:"use_jwks"`
	JWKSURI                      string             `json:"jwks_uri,omitempty"`
	JWKSCAPEM                    string             `json:"jwks_ca_pem,omitempty"`
	PublicKeys                   []oauthResourceKey `json:"public_keys,omitempty"`
	Audiences                    []string           `json:"audiences"`
	NoDefaultPolicy              bool               `json:"no_default_policy"`
	OptionalAuthorizationDetails bool               `json:"optional_authorization_details"`
	UserClaim                    string             `json:"user_claim"`
	Algorithms                   []string           `json:"supported_algorithms"`
	JWTType                      string             `json:"jwt_type"`
	ClockSkew                    int                `json:"clock_skew_leeway"`
	Enabled                      bool               `json:"enabled"`
	UniqueIDClaim                string             `json:"unique_id_claim"`
	ActorClaim                   string             `json:"actor_claim"`
}
type oauthResourceKey struct {
	KeyID string `json:"key_id"`
	PEM   string `json:"pem"`
}

func agenticFields(stringsFields, boolFields, sliceFields []string) map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{}
	for _, name := range stringsFields {
		fields[name] = &framework.FieldSchema{Type: framework.TypeString}
	}
	for _, name := range boolFields {
		fields[name] = &framework.FieldSchema{Type: framework.TypeBool}
	}
	for _, name := range sliceFields {
		fields[name] = &framework.FieldSchema{Type: framework.TypeStringSlice}
	}
	return fields
}

func agenticDecode(d *framework.FieldData, out any) error {
	values := map[string]any{}
	for name := range d.Schema {
		if _, present := d.Raw[name]; present {
			values[name] = d.Get(name)
		}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
func agenticResponse(value any) (*logical.Response, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}
func agenticPrefix(ctx context.Context, family string) (string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", err
	}
	return "agentic-iam/" + ns.ID + "/" + family + "/", nil
}
func agenticLoad(ctx context.Context, storage logical.Storage, key string, out any) (bool, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil || entry == nil {
		return false, err
	}
	return true, entry.DecodeJSON(out)
}
func agenticSave(ctx context.Context, storage logical.Storage, key string, value any) error {
	entry, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (b *SystemBackend) oauthResourceServerPaths() []*framework.Path {
	fields := agenticFields([]string{"name", "config_id", "issuer_id", "jwks_uri", "jwks_ca_pem", "user_claim", "jwt_type", "unique_id_claim", "actor_claim"}, []string{"use_jwks", "no_default_policy", "optional_authorization_details", "enabled"}, []string{"audiences", "supported_algorithms"})
	fields["public_keys"] = &framework.FieldSchema{Type: framework.TypeSlice}
	fields["clock_skew_leeway"] = &framework.FieldSchema{Type: framework.TypeInt}
	// The system backend is shared by namespaces. Serialize uniqueness checks and writes.
	var mu sync.Mutex
	handler := func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		prefix, err := agenticPrefix(ctx, "oauth-profiles")
		if err != nil {
			return nil, err
		}
		names, err := req.Storage.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		if req.Operation == logical.ListOperation {
			return logical.ListResponse(names), nil
		}
		name := d.Get("name").(string)
		lookupID := strings.HasPrefix(req.Path, "config/oauth-resource-server/id/")
		if lookupID {
			for _, candidate := range names {
				var p oauthResourceProfile
				ok, err := agenticLoad(ctx, req.Storage, prefix+candidate, &p)
				if err != nil {
					return nil, err
				}
				if ok && p.ConfigID == d.Get("config_id").(string) {
					return agenticResponse(p)
				}
			}
			return nil, nil
		}
		var p oauthResourceProfile
		exists, err := agenticLoad(ctx, req.Storage, prefix+name, &p)
		if err != nil {
			return nil, err
		}
		switch req.Operation {
		case logical.ReadOperation:
			if !exists {
				return nil, nil
			}
			return agenticResponse(p)
		case logical.DeleteOperation:
			return nil, req.Storage.Delete(ctx, prefix+name)
		}
		if !exists {
			p = oauthResourceProfile{Name: name, UseJWKS: true, UserClaim: "sub", JWTType: "access_token", Enabled: true, UniqueIDClaim: "jti", ActorClaim: "act.sub", Audiences: []string{}, Algorithms: []string{}}
			p.ConfigID, err = uuid.GenerateUUID()
			if err != nil {
				return nil, err
			}
		}
		old := p
		if err := agenticDecode(d, &p); err != nil {
			return logical.ErrorResponse("invalid profile: %s", err), nil
		}
		// Generated and path-addressed attributes cannot be supplied by the body.
		p.ConfigID, p.Name = old.ConfigID, name
		p.Issuer = strings.TrimRight(strings.ToLower(p.Issuer), "/")
		if exists && (p.Issuer != old.Issuer || p.UniqueIDClaim != old.UniqueIDClaim) {
			return logical.ErrorResponse("issuer_id and unique_id_claim are immutable"), nil
		}
		if old.UseJWKS != p.UseJWKS {
			if p.UseJWKS {
				if _, supplied := d.Raw["public_keys"]; !supplied {
					p.PublicKeys = nil
				}
			} else {
				if _, supplied := d.Raw["jwks_uri"]; !supplied {
					p.JWKSURI = ""
				}
				if _, supplied := d.Raw["jwks_ca_pem"]; !supplied {
					p.JWKSCAPEM = ""
				}
			}
		}
		if err := p.validate(); err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		for _, candidate := range names {
			if candidate == name {
				continue
			}
			var other oauthResourceProfile
			_, err := agenticLoad(ctx, req.Storage, prefix+candidate, &other)
			if err != nil {
				return nil, err
			}
			if other.Issuer == p.Issuer {
				return logical.ErrorResponse("issuer_id already exists in this namespace"), nil
			}
		}
		return nil, agenticSave(ctx, req.Storage, prefix+name, &p)
	}
	return []*framework.Path{
		{Pattern: "config/oauth-resource-server/?$", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ListOperation: handler}, HelpSynopsis: "List OAuth resource server profiles."},
		{Pattern: "config/oauth-resource-server/id/(?P<config_id>[^/]+)$", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handler}, HelpSynopsis: "Read an OAuth profile by ID."},
		{Pattern: "config/oauth-resource-server/(?P<name>[^/]+)$", Fields: fields, Callbacks: map[logical.Operation]framework.OperationFunc{logical.ReadOperation: handler, logical.UpdateOperation: handler, logical.DeleteOperation: handler}, HelpSynopsis: "Manage OAuth resource server configuration."},
	}
}

func (p *oauthResourceProfile) validate() error {
	if p.Issuer == "" {
		return fmt.Errorf("issuer_id is required")
	}
	if p.JWTType != "access_token" {
		return fmt.Errorf("jwt_type must be access_token")
	}
	if p.UseJWKS {
		if len(p.PublicKeys) != 0 {
			return fmt.Errorf("public_keys cannot be used with JWKS")
		}
		u, err := url.Parse(p.JWKSURI)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("jwks_uri must be an HTTP(S) URI")
		}
		if p.JWKSCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(p.JWKSCAPEM)) {
			return fmt.Errorf("jwks_ca_pem must contain CA certificates")
		}
		return nil
	}
	if p.JWKSURI != "" || p.JWKSCAPEM != "" {
		return fmt.Errorf("JWKS configuration cannot be used with static keys")
	}
	if len(p.PublicKeys) == 0 {
		return fmt.Errorf("public_keys are required")
	}
	seen := map[string]bool{}
	for _, key := range p.PublicKeys {
		if key.KeyID == "" || seen[key.KeyID] {
			return fmt.Errorf("each key_id must be nonempty and unique")
		}
		seen[key.KeyID] = true
		block, rest := pem.Decode([]byte(key.PEM))
		if block == nil || strings.TrimSpace(string(rest)) != "" {
			return fmt.Errorf("invalid public key PEM")
		}
		var pub any
		var err error
		switch block.Type {
		case "PUBLIC KEY":
			pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			return fmt.Errorf("PEM must contain a public key")
		}
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		default:
			return fmt.Errorf("unsupported public key type")
		}
	}
	return nil
}
