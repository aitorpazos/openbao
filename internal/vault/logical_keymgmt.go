// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type keyMgmtBackend struct {
	*framework.Backend
	mu sync.Mutex
}
type keyMgmtVersion struct {
	CreationTime string `json:"creation_time"`
	PublicKey    string `json:"public_key,omitempty"`
	PrivateKey   []byte `json:"private_key"`
}
type keyMgmtKey struct {
	Name              string                    `json:"name"`
	Type              string                    `json:"type"`
	DeletionAllowed   bool                      `json:"deletion_allowed"`
	LatestVersion     int                       `json:"latest_version"`
	MinEnabledVersion int                       `json:"min_enabled_version"`
	Keys              map[string]keyMgmtVersion `json:"keys"`
}

func KeyMgmtBackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &keyMgmtBackend{Backend: &framework.Backend{BackendType: logical.TypeLogical, Help: "Local key management. Cloud distribution is not implemented.", PathsSpecial: &logical.Paths{SealWrapStorage: []string{"key/", "kms/"}}}}
	fields := map[string]*framework.FieldSchema{}
	for _, s := range strings.Fields("name type provider key_collection") {
		fields[s] = &framework.FieldSchema{Type: framework.TypeString}
	}
	fields["credentials"] = &framework.FieldSchema{Type: framework.TypeMap}
	fields["deletion_allowed"] = &framework.FieldSchema{Type: framework.TypeBool}
	fields["min_enabled_version"] = &framework.FieldSchema{Type: framework.TypeInt}
	add := func(p string, f framework.OperationFunc, ops ...logical.Operation) {
		c := map[logical.Operation]framework.OperationFunc{}
		for _, o := range ops {
			c[o] = f
		}
		b.Paths = append(b.Paths, &framework.Path{Pattern: p, Fields: fields, Callbacks: c})
	}
	add("key/?", b.key, logical.ListOperation)
	add("key/(?P<name>[^/]+)/kms/?", b.key, logical.ListOperation)
	add("key/(?P<name>[^/]+)/rotate", b.key, logical.UpdateOperation)
	add("key/(?P<name>[^/]+)", b.key, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	add("kms/?", b.provider, logical.ListOperation)
	add("kms/(?P<name>[^/]+)", b.provider, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation)
	return b, b.Setup(ctx, conf)
}

func keyMgmtSave(ctx context.Context, s logical.Storage, path string, v interface{}) error {
	e, err := logical.StorageEntryJSON(path, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, e)
}
func (k *keyMgmtKey) rotate() error {
	var private interface{}
	var public interface{}
	var err error
	switch k.Type {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		bits, _ := strconv.Atoi(strings.TrimPrefix(k.Type, "rsa-"))
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, bits)
		if err == nil {
			private = key
			public = &key.PublicKey
		}
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		curve := elliptic.P256()
		if k.Type == "ecdsa-p384" {
			curve = elliptic.P384()
		}
		if k.Type == "ecdsa-p521" {
			curve = elliptic.P521()
		}
		var key *ecdsa.PrivateKey
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err == nil {
			private = key
			public = &key.PublicKey
		}
	case "aes256-gcm96":
	default:
		return fmt.Errorf("unsupported key type")
	}
	if err != nil {
		return err
	}
	v := keyMgmtVersion{CreationTime: time.Now().UTC().Format(time.RFC3339Nano)}
	if private != nil {
		v.PrivateKey, err = x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return err
		}
		der, e := x509.MarshalPKIXPublicKey(public)
		if e != nil {
			return e
		}
		v.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	} else {
		v.PrivateKey = make([]byte, 32)
		if _, err = rand.Read(v.PrivateKey); err != nil {
			return err
		}
	}
	k.LatestVersion++
	k.Keys[strconv.Itoa(k.LatestVersion)] = v
	return nil
}
func (b *keyMgmtBackend) key(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	name := d.Get("name").(string)
	path := "key/" + name
	if r.Operation == logical.ListOperation {
		if name != "" {
			return logical.ListResponse(nil), nil
		}
		keys, err := r.Storage.List(ctx, "key/")
		return logical.ListResponse(keys), err
	}
	e, err := r.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	var k keyMgmtKey
	if e != nil {
		if err = e.DecodeJSON(&k); err != nil {
			return nil, err
		}
	}
	switch r.Operation {
	case logical.ReadOperation:
		if e == nil {
			return nil, nil
		}
		versions := map[string]interface{}{}
		for n, v := range k.Keys {
			value := map[string]interface{}{"creation_time": v.CreationTime}
			if v.PublicKey != "" {
				value["public_key"] = v.PublicKey
			}
			versions[n] = value
		}
		return &logical.Response{Data: map[string]interface{}{"name": k.Name, "type": k.Type, "deletion_allowed": k.DeletionAllowed, "latest_version": k.LatestVersion, "min_enabled_version": k.MinEnabledVersion, "keys": versions}}, nil
	case logical.DeleteOperation:
		if e == nil {
			return nil, nil
		}
		if !k.DeletionAllowed {
			return logical.ErrorResponse("key deletion is not allowed"), nil
		}
		return nil, r.Storage.Delete(ctx, path)
	case logical.UpdateOperation:
		rotating := strings.HasSuffix(r.Path, "/rotate")
		if e == nil {
			if rotating {
				return logical.ErrorResponse("key not found"), nil
			}
			typ := d.Get("type").(string)
			if typ == "" {
				typ = "rsa-2048"
			}
			k = keyMgmtKey{Name: name, Type: typ, MinEnabledVersion: 0, Keys: map[string]keyMgmtVersion{}}
			switch typ {
			case "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "aes256-gcm96":
			default:
				return logical.ErrorResponse("unsupported key type"), nil
			}
		}
		if typ, ok := d.GetOk("type"); ok && typ.(string) != k.Type {
			return logical.ErrorResponse("key type is immutable"), nil
		}
		if rotating || e == nil {
			if err = k.rotate(); err != nil {
				return nil, err
			}
		}
		if v, ok := d.GetOk("deletion_allowed"); ok {
			k.DeletionAllowed = v.(bool)
		}
		if v, ok := d.GetOk("min_enabled_version"); ok {
			n := v.(int)
			if n < 0 || n > k.LatestVersion {
				return logical.ErrorResponse("min_enabled_version must reference an existing version"), nil
			}
			k.MinEnabledVersion = n
		}
		return nil, keyMgmtSave(ctx, r.Storage, path, &k)
	}
	return nil, logical.ErrUnsupportedOperation
}
func (b *keyMgmtBackend) provider(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Operation == logical.ListOperation {
		keys, err := r.Storage.List(ctx, "kms/")
		return logical.ListResponse(keys), err
	}
	path := "kms/" + d.Get("name").(string)
	e, err := r.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{}
	if e != nil {
		if err = e.DecodeJSON(&data); err != nil {
			return nil, err
		}
	}
	switch r.Operation {
	case logical.ReadOperation:
		if e == nil {
			return nil, nil
		}
		delete(data, "credentials")
		return &logical.Response{Data: data}, nil
	case logical.DeleteOperation:
		return nil, r.Storage.Delete(ctx, path)
	case logical.UpdateOperation:
		for _, f := range []string{"provider", "key_collection"} {
			if v, ok := d.GetOk(f); ok {
				if e != nil && data[f] != v {
					return logical.ErrorResponse("%s is immutable", f), nil
				}
				data[f] = v
			}
			if data[f] == nil || data[f] == "" {
				return logical.ErrorResponse("%s is required", f), nil
			}
		}
		switch data["provider"] {
		case "awskms", "azurekeyvault", "gcpckms":
		default:
			return logical.ErrorResponse("unsupported provider"), nil
		}
		if v, ok := d.GetOk("credentials"); ok {
			data["credentials"] = v
		}
		if err = keyMgmtSave(ctx, r.Storage, path, data); err != nil {
			return nil, err
		}
		return &logical.Response{Warnings: []string{"Configuration stored locally only; cloud credentials are not validated and key distribution is unavailable."}}, nil
	}
	return nil, logical.ErrUnsupportedOperation
}
