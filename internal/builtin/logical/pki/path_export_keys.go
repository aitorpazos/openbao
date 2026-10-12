// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type exportKeyRecord struct {
	Public  map[string]interface{} `json:"public"`
	Private []byte                 `json:"private"`
	MACKey  []byte                 `json:"mac_key"`
}

// The private key is barrier-stored and never included in API responses. CA
// key wrapping for cross-mount migration is implemented separately in
// path_keys_export.go (POST /pki/keys/:key_ref/export) — those wrapped
// blobs import via POST /pki/keys/import with the wrapped_key +
// export_key_hmac pair.
func pathsExportKeys() []*framework.Path {
	var mu sync.Mutex
	handler := func(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		id, _ := d.GetOk("export_key_uuid")
		if id != nil {
			path := "config/export-keys/" + id.(string)
			if r.Operation == logical.DeleteOperation {
				return nil, r.Storage.Delete(ctx, path)
			}
			e, err := r.Storage.Get(ctx, path)
			if err != nil || e == nil {
				return nil, err
			}
			var rec exportKeyRecord
			if err = e.DecodeJSON(&rec); err != nil {
				return nil, err
			}
			return &logical.Response{Data: rec.Public}, nil
		}
		keys, err := r.Storage.List(ctx, "config/export-keys/")
		if err != nil {
			return nil, err
		}
		info := map[string]interface{}{}
		for _, k := range keys {
			e, err := r.Storage.Get(ctx, "config/export-keys/"+k)
			if err != nil {
				return nil, err
			}
			if e == nil {
				continue
			}
			var rec exportKeyRecord
			if err = e.DecodeJSON(&rec); err != nil {
				return nil, err
			}
			info[k] = rec.Public
			if r.Operation == logical.UpdateOperation && d.Get("name").(string) != "" && rec.Public["name"] == d.Get("name") {
				return logical.ErrorResponse("export key name already exists"), nil
			}
		}
		if r.Operation == logical.ListOperation {
			resp := logical.ListResponse(keys)
			resp.Data["key_info"] = info
			return resp, nil
		}
		kind := d.Get("key_type").(string)
		var private interface{}
		var public interface{}
		switch kind {
		case "ec-p256", "ec-p384", "ec-p521":
			curve := elliptic.P256()
			if kind == "ec-p384" {
				curve = elliptic.P384()
			}
			if kind == "ec-p521" {
				curve = elliptic.P521()
			}
			key, e := ecdsa.GenerateKey(curve, rand.Reader)
			err = e
			if e == nil {
				private = key
				public = &key.PublicKey
			}
		case "rsa-2048", "rsa-3072", "rsa-4096":
			bits := 2048
			if kind == "rsa-3072" {
				bits = 3072
			}
			if kind == "rsa-4096" {
				bits = 4096
			}
			key, e := rsa.GenerateKey(rand.Reader, bits)
			err = e
			if e == nil {
				private = key
				public = &key.PublicKey
			}
		default:
			return logical.ErrorResponse("unsupported export key algorithm %q", kind), nil
		}
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, err
		}
		priv, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(der)
		uuid, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
		rec := exportKeyRecord{Private: priv, MACKey: key, Public: map[string]interface{}{"export_key_uuid": uuid, "key_type": kind, "name": d.Get("name"), "public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "export_key_hmac": "sha256:" + hex.EncodeToString(mac.Sum(nil)), "created_at": time.Now().UTC().Format(time.RFC3339Nano)}}
		e, err := logical.StorageEntryJSON("config/export-keys/"+uuid, rec)
		if err != nil {
			return nil, err
		}
		if err = r.Storage.Put(ctx, e); err != nil {
			return nil, err
		}
		return &logical.Response{Data: rec.Public, Warnings: []string{"Export key management only; CA key wrapping and wrapped import are not implemented. The fingerprint is local to this mount."}}, nil
	}
	ops := func(methods ...logical.Operation) map[logical.Operation]framework.OperationHandler {
		m := map[logical.Operation]framework.OperationHandler{}
		for _, op := range methods {
			m[op] = &framework.PathOperation{Callback: handler, ForwardPerformanceStandby: op != logical.ReadOperation && op != logical.ListOperation, ForwardPerformanceSecondary: op != logical.ReadOperation && op != logical.ListOperation}
		}
		return m
	}
	return []*framework.Path{
		{Pattern: "export/?", Fields: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}, "key_type": {Type: framework.TypeString}}, Operations: ops(logical.UpdateOperation, logical.ListOperation)},
		{Pattern: "export/" + framework.GenericNameRegex("export_key_uuid"), Fields: map[string]*framework.FieldSchema{"export_key_uuid": {Type: framework.TypeString}}, Operations: ops(logical.ReadOperation, logical.DeleteOperation)},
	}
}
