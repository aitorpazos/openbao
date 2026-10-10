// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/identity/mfa"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (b *SystemBackend) namedMFATOTPEnrollmentPaths() []*framework.Path {
	var paths []*framework.Path
	// The public table omits /totp/ for admin-destroy; use the documented curl route.
	for _, action := range []string{"generate", "admin-generate", "admin-destroy"} {
		op := logical.UpdateOperation
		if action == "generate" {
			op = logical.ReadOperation
		}
		paths = append(paths, &framework.Path{
			Pattern: "mfa/method/totp/" + framework.GenericNameRegex("name") + "/" + action,
			Fields: map[string]*framework.FieldSchema{
				"name":      {Type: framework.TypeString, Description: "Named TOTP method."},
				"entity_id": {Type: framework.TypeString, Description: "Target entity for administrative enrollment."},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{op: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
				return b.handleNamedMFATOTPEnrollment(ctx, req, d, action)
			}},
			HelpSynopsis: "Generate or destroy a named TOTP method's per-entity secret.",
		})
	}
	return paths
}

type namedTOTPEnrollmentConfig struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	Algorithm string `json:"algorithm"`
	Period    uint   `json:"period"`
	KeySize   uint   `json:"key_size"`
	QRSize    int    `json:"qr_size"`
	Digits    int    `json:"digits"`
	Skew      uint32 `json:"skew"`
}

func (b *SystemBackend) handleNamedMFATOTPEnrollment(ctx context.Context, req *logical.Request, d *framework.FieldData, action string) (*logical.Response, error) {
	entityID := d.Get("entity_id").(string)
	if action == "generate" {
		// EntityID is populated by authenticated request handling, never from the body.
		entityID = req.EntityID
		if entityID == "" {
			return logical.ErrorResponse("an entity-backed token is required"), nil
		}
	} else if entityID == "" {
		return logical.ErrorResponse("entity_id is required"), nil
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	b.namedMFAMethodLock.Lock()
	defer b.namedMFAMethodLock.Unlock()
	// Configurations live in root, but enrollment secrets belong to the caller's namespace.
	storage := req.Storage
	if ns.ID != namespace.RootNamespaceID {
		storage = b.Core.NamespaceView(namespace.RootNamespace).SubView(barrier.SystemBarrierPrefix)
	}
	entry, err := storage.Get(ctx, namedMFAMethodPrefix+"totp/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("unknown named TOTP method"), nil
	}
	cfg := namedTOTPEnrollmentConfig{Period: 30, KeySize: 20, QRSize: 200, Digits: 6, Algorithm: "SHA1"}
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	if cfg.ID == "" {
		return nil, fmt.Errorf("named TOTP method has no identifier")
	}
	b.Core.identityStore.Lock()
	defer b.Core.identityStore.Unlock()
	entity, err := b.Core.identityStore.MemDBEntityByID(ctx, entityID, true)
	if err != nil {
		return nil, err
	}
	if entity == nil || entity.NamespaceID != ns.ID {
		return logical.ErrorResponse("invalid entity ID in this namespace"), nil
	}
	if action == "admin-destroy" {
		// Destroying an absent secret is deliberately an idempotent no-content success.
		if err := b.Core.NamespaceView(ns).SubView(mfaTOTPKeysPrefix+cfg.ID+"/").Delete(ctx, entity.ID); err != nil {
			return nil, err
		}
		delete(entity.MFASecrets, cfg.ID)
		return nil, b.Core.identityStore.UpsertEntity(ctx, entity, nil, true)
	}
	algorithm := map[string]otp.Algorithm{"SHA1": otp.AlgorithmSHA1, "SHA256": otp.AlgorithmSHA256, "SHA512": otp.AlgorithmSHA512}[cfg.Algorithm]
	key, err := totp.Generate(totp.GenerateOpts{Issuer: cfg.Issuer, AccountName: entity.ID, Period: cfg.Period, SecretSize: cfg.KeySize, Digits: otp.Digits(cfg.Digits), Algorithm: algorithm, Rand: rand.Reader})
	if err != nil {
		return nil, err
	}
	image, err := key.Image(cfg.QRSize, cfg.QRSize)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, image); err != nil {
		return nil, err
	}
	// Re-enrollment replaces the existing method+entity secret, without changing the method ID.
	if err := b.Core.PersistTOTPKey(ctx, cfg.ID, entity.ID, key.Secret()); err != nil {
		return nil, err
	}
	if entity.MFASecrets == nil {
		entity.MFASecrets = make(map[string]*mfa.Secret)
	}
	entity.MFASecrets[cfg.ID] = &mfa.Secret{MethodName: d.Get("name").(string), Value: &mfa.Secret_TOTPSecret{TOTPSecret: &mfa.TOTPSecret{
		Issuer: cfg.Issuer, AccountName: entity.ID, Period: uint32(cfg.Period), KeySize: uint32(cfg.KeySize), Digits: int32(cfg.Digits), Algorithm: int32(algorithm), Skew: cfg.Skew,
	}}}
	if err := b.Core.identityStore.UpsertEntity(ctx, entity, nil, true); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{"barcode": base64.StdEncoding.EncodeToString(buf.Bytes()), "url": key.String()}}, nil
}
