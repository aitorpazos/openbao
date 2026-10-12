// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/pgpkeys"
)

// DR operation-token routes per
// https://developer.hashicorp.com/vault/api-docs/system/replication/replication-dr
// (v2.x latest). All are restricted to the root namespace and, absent the
// enable_unauthenticated_access opt-in, require authentication.
func (b *SystemBackend) drOperationTokenPaths() []*framework.Path {
	drPrefix := "replication/dr"
	attempt := &framework.Path{
		Pattern: drPrefix + "/secondary/generate-operation-token/attempt$",
		Fields: map[string]*framework.FieldSchema{
			"pgp_key": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleDROperationTokenAttemptRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleDROperationTokenAttemptStart,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleDROperationTokenAttemptCancel,
			},
		},
	}
	update := &framework.Path{
		Pattern: drPrefix + "/secondary/generate-operation-token/update$",
		Fields: map[string]*framework.FieldSchema{
			"key":   {Type: framework.TypeString},
			"nonce": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleDROperationTokenUpdate,
			},
		},
	}
	revoke := &framework.Path{
		Pattern: drPrefix + "/secondary/operation-token/delete$",
		Fields: map[string]*framework.FieldSchema{
			"dr_operation_token": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleDROperationTokenDelete,
			},
		},
	}
	reindex := &framework.Path{
		Pattern: drPrefix + "/secondary/reindex$",
		Fields: map[string]*framework.FieldSchema{
			"diff":               {Type: framework.TypeBool, Default: false},
			"force":              {Type: framework.TypeBool, Default: false},
			"skip_flush":         {Type: framework.TypeBool, Default: false},
			"dr_operation_token": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleDRSecondaryReindex,
			},
		},
	}
	merkle := &framework.Path{
		Pattern: drPrefix + "/secondary/merkle-check$",
		Fields: map[string]*framework.FieldSchema{
			"dr_operation_token": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleDRSecondaryMerkleCheck,
			},
		},
	}
	return []*framework.Path{attempt, update, revoke, reindex, merkle}
}

// drTokenRootNamespace enforces the documented root-namespace restriction.
func (b *SystemBackend) drTokenRootNamespace(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		// No namespace in the context: the HTTP layer injects the root
		// namespace for every real request; unit-level direct calls
		// (without context) are treated as root.
		return nil
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.CodedError(http.StatusBadRequest, "this endpoint must be called from the root namespace")
	}
	return nil
}

// handleDROperationTokenAttemptRead reports the current generation attempt.
func (b *SystemBackend) handleDROperationTokenAttemptRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	required, err := b.Core.RekeyThreshold(ctx, false)
	if err != nil {
		return nil, err
	}
	b.drTokenState.mu.Lock()
	defer b.drTokenState.mu.Unlock()
	data := map[string]any{
		"started":         false,
		"nonce":           "",
		"progress":        0,
		"required":        required,
		"encoded_token":   "",
		"pgp_fingerprint": "",
		"complete":        false,
	}
	if b.drTokenState.attempt != nil {
		data = b.drTokenState.attempt.shape()
		data["required"] = b.drTokenState.attempt.required
	}
	return &logical.Response{Data: data}, nil
}

// handleDROperationTokenAttemptStart initializes a generation attempt.
func (b *SystemBackend) handleDROperationTokenAttemptStart(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	pgpKey := d.Get("pgp_key").(string)
	pgpPrint := ""
	if pgpKey != "" {
		prints, err := drTokenFingerprints(pgpKey)
		if err != nil {
			return logical.ErrorResponse("failed to parse PGP key: %s", err.Error()), nil
		}
		pgpPrint = prints
	}
	required, err := b.Core.RekeyThreshold(ctx, false)
	if err != nil {
		return nil, err
	}
	attempt, attemptErr := drTokenNewAttempt(required, pgpKey)
	if attemptErr != nil {
		return nil, attemptErr
	}
	attempt.pgpPrint = pgpPrint

	b.drTokenState.mu.Lock()
	defer b.drTokenState.mu.Unlock()
	if b.drTokenState.attempt != nil && !b.drTokenState.attempt.complete {
		return logical.ErrorResponse("a DR operation token generation attempt is already in progress"), nil
	}
	b.drTokenState.attempt = attempt

	data := map[string]any{
		"started":       true,
		"nonce":         attempt.nonce,
		"progress":      0,
		"required":      required,
		"encoded_token": "",
		"otp":           attempt.otp,
		"otp_length":    len(attempt.otp),
		"complete":      false,
	}
	if pgpPrint != "" {
		data["pgp_fingerprint"] = pgpPrint
	}
	return &logical.Response{Data: data}, nil
}

// handleDROperationTokenAttemptCancel cancels any in-progress attempt.
func (b *SystemBackend) handleDROperationTokenAttemptCancel(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	b.drTokenState.mu.Lock()
	b.drTokenState.attempt = nil
	b.drTokenState.mu.Unlock()
	return nil, nil
}

// handleDROperationTokenUpdate records a root key share for the attempt.
func (b *SystemBackend) handleDROperationTokenUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	keyStr := d.Get("key").(string)
	nonce := d.Get("nonce").(string)
	if keyStr == "" {
		return logical.ErrorResponse("'key' must be specified in request body as JSON"), nil
	}
	if nonce == "" {
		return logical.ErrorResponse("'nonce' must be specified in request body as JSON"), nil
	}

	// Decode the key, which is base64 or hex encoded (same contract as
	// /sys/rekey/update). Prefer hex only when it decodes to a plausible
	// barrier-key length, so base64 strings that are also valid hex
	// decode as base64. Shamir shares carry ShareOverhead bytes on top of
	// the barrier key length (rekey.go applies the same rule).
	min, max := b.Core.BarrierKeyLength()
	max += shamir.ShareOverhead
	key, hexErr := hex.DecodeString(keyStr)
	var decodeErr error
	if hexErr != nil || len(key) < min || len(key) > max {
		key, decodeErr = base64.StdEncoding.DecodeString(keyStr)
		if decodeErr != nil {
			return logical.ErrorResponse("'key' must be a valid hex or base64 string"), nil
		}
	}
	if len(key) < min {
		return logical.ErrorResponse("'key' is shorter than the minimum %d bytes", min), nil
	}
	if len(key) > max {
		return logical.ErrorResponse("'key' is longer than the maximum %d bytes", max), nil
	}

	b.drTokenState.mu.Lock()
	defer b.drTokenState.mu.Unlock()
	attempt := b.drTokenState.attempt
	if attempt == nil || attempt.complete {
		return logical.ErrorResponse("no DR operation token generation attempt is in progress"), nil
	}
	if attempt.nonce != nonce {
		return logical.ErrorResponse("incorrect attempt nonce"), nil
	}
	if attempt.shareSeen(key) {
		return logical.ErrorResponse("root key share already provided"), nil
	}
	attempt.progress = append(attempt.progress, key)

	if len(attempt.progress) < attempt.required {
		data := attempt.shape()
		data["required"] = attempt.required
		return &logical.Response{Data: data}, nil
	}

	token, err := attempt.finish()
	if err != nil {
		return nil, err
	}
	b.drTokenState.ensureLocked()
	b.drTokenState.live[hex.EncodeToString(token)] = struct{}{}
	data := attempt.shape()
	data["required"] = attempt.required
	return &logical.Response{Data: data}, nil
}

// handleDROperationTokenDelete revokes a previously issued operation token.
func (b *SystemBackend) handleDROperationTokenDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	tok := d.Get("dr_operation_token").(string)
	if tok == "" {
		return logical.ErrorResponse("dr_operation_token is required"), nil
	}
	if !b.drTokenState.revokeDROperationToken(tok) {
		return nil, logical.ErrPermissionDenied
	}
	return nil, nil
}

// handleDRSecondaryReindex validates the operation token and reindexes the
// local data storage (the fork recomputes the merkle root, mirroring the
// general /sys/replication/reindex implementation).
func (b *SystemBackend) handleDRSecondaryReindex(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	tok := d.Get("dr_operation_token").(string)
	if tok == "" {
		return logical.ErrorResponse("dr_operation_token is required"), nil
	}
	if !b.drTokenState.verifyDROperationToken(tok) {
		return nil, logical.ErrPermissionDenied
	}
	if _, err := b.Core.merkleRoot(ctx); err != nil {
		return nil, err
	}
	return &logical.Response{Warnings: []string{}}, nil
}

// handleDRSecondaryMerkleCheck validates the operation token and reports
// the Merkle corruption status (delegating to the shared check logic).
func (b *SystemBackend) handleDRSecondaryMerkleCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.drTokenRootNamespace(ctx); err != nil {
		return nil, err
	}
	tok := d.Get("dr_operation_token").(string)
	if tok == "" {
		return logical.ErrorResponse("dr_operation_token is required"), nil
	}
	if !b.drTokenState.verifyDROperationToken(tok) {
		return nil, logical.ErrPermissionDenied
	}
	return b.handleReplicationMerkleCheck(ctx, req, nil)
}

// drTokenFingerprints validates a base64 PGP key and returns its fingerprint.
func drTokenFingerprints(pgpKey string) (string, error) {
	prints, err := pgpkeys.GetFingerprints([]string{pgpKey}, nil)
	if err != nil {
		return "", err
	}
	if len(prints) != 1 {
		return "", fmt.Errorf("expected one fingerprint, got %d", len(prints))
	}
	return prints[0], nil
}
