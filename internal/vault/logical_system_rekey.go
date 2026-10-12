// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/pgpkeys"
)

// handleRekeyInit implements the token-authenticated
// /sys/rekey/init and /sys/rekey-recovery-key/init operations (GET/POST/PUT
// and DELETE). It mirrors the http-package rekey handlers
// (internal/http/sys_rekey.go) and the documented rekey/rekey-recovery-key
// API contracts.
func (b *SystemBackend) handleRekeyInit(recovery bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		if recovery && !b.Core.SealAccess().RecoveryKeySupported() {
			return logical.ErrorResponse("recovery rekeying not supported"), nil
		}

		switch req.Operation {
		case logical.ReadOperation:
			return b.rekeyInitStatus(ctx, recovery)
		case logical.UpdateOperation:
			secretShares := data.Get("secret_shares").(int)
			secretThreshold := data.Get("secret_threshold").(int)
			pgpKeys := data.Get("pgp_keys").([]string)
			backup := data.Get("backup").(bool)
			requireVerification := data.Get("require_verification").(bool)

			if backup && len(pgpKeys) == 0 {
				return logical.ErrorResponse("cannot request a backup of the new keys without providing PGP keys for encryption"), nil
			}
			if len(pgpKeys) > 0 && len(pgpKeys) != secretShares {
				return logical.ErrorResponse("incorrect number of PGP keys for rekey"), nil
			}

			if err := b.Core.RekeyInit(&SealConfig{
				SecretShares:         secretShares,
				SecretThreshold:      secretThreshold,
				PGPKeys:              pgpKeys,
				Backup:               backup,
				VerificationRequired: requireVerification,
			}, recovery); err != nil {
				return nil, err
			}
			return b.rekeyInitStatus(ctx, recovery)
		case logical.DeleteOperation:
			if err := b.Core.RekeyCancel(recovery); err != nil {
				return nil, err
			}
			return nil, nil
		default:
			return logical.ErrorResponse("unsupported operation"), nil
		}
	}
}

// rekeyInitStatus formats the rekey status response used by the init read,
// the init update (Vault returns the new status after initialization) and
// the update endpoint when more shares are still required.
func (b *SystemBackend) rekeyInitStatus(ctx context.Context, recovery bool) (*logical.Response, error) {
	barrierConfig, err := b.Core.SealAccess().BarrierConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to read barrier configuration: %w", err)
	}
	if barrierConfig == nil {
		return logical.ErrorResponse("server is not yet initialized"), nil
	}

	rekeyConf, err := b.Core.RekeyConfig(recovery)
	if err != nil {
		return nil, err
	}

	sealThreshold, err := b.Core.RekeyThreshold(ctx, recovery)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"started":               false,
		"t":                     0,
		"n":                     0,
		"progress":              0,
		"required":              sealThreshold,
		"pgp_fingerprints":      []string{},
		"backup":                false,
		"verification_required": false,
	}
	if rekeyConf != nil {
		started, progress, err := b.Core.RekeyProgress(recovery, false)
		if err != nil {
			return nil, err
		}
		data["nonce"] = rekeyConf.Nonce
		data["started"] = started
		data["t"] = rekeyConf.SecretThreshold
		data["n"] = rekeyConf.SecretShares
		data["progress"] = progress
		data["verification_required"] = rekeyConf.VerificationRequired
		if rekeyConf.VerificationNonce != "" {
			data["verification_nonce"] = rekeyConf.VerificationNonce
		}
		if len(rekeyConf.PGPKeys) != 0 {
			pgpFingerprints, err := pgpkeys.GetFingerprints(rekeyConf.PGPKeys, nil)
			if err != nil {
				return nil, fmt.Errorf("unable to read PGP fingerprints: %w", err)
			}
			data["pgp_fingerprints"] = pgpFingerprints
			data["backup"] = rekeyConf.Backup
		}
	}
	return &logical.Response{Data: data}, nil
}

// handleRekeyUpdate implements the token-authenticated /sys/rekey/update and
// /sys/rekey-recovery-key/update operations.
func (b *SystemBackend) handleRekeyUpdate(recovery bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		keyStr := data.Get("key").(string)
		nonce := data.Get("nonce").(string)
		if keyStr == "" {
			return logical.ErrorResponse("'key' must be specified in request body as JSON"), nil
		}

		// Decode the key, which is base64 or hex encoded
		min, max := b.Core.BarrierKeyLength()
		key, err := hex.DecodeString(keyStr)
		// We check min and max here to ensure that a string that is base64
		// encoded but also valid hex will not be valid and we instead base64
		// decode it
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(keyStr)
			if err != nil {
				return logical.ErrorResponse("'key' must be a valid hex or base64 string"), nil
			}
		}

		result, rekeyErr := b.Core.RekeyUpdate(ctx, key, nonce, recovery)
		if rekeyErr != nil {
			return nil, rekeyErr
		}

		if result == nil {
			return b.rekeyInitStatus(ctx, recovery)
		}

		keys := make([]string, 0, len(result.SecretShares))
		keysB64 := make([]string, 0, len(result.SecretShares))
		for _, k := range result.SecretShares {
			keys = append(keys, hex.EncodeToString(k))
			keysB64 = append(keysB64, base64.StdEncoding.EncodeToString(k))
		}

		resp := &logical.Response{
			Data: map[string]any{
				"nonce":                 nonce,
				"complete":              true,
				"keys":                  keys,
				"keys_base64":           keysB64,
				"pgp_fingerprints":      result.PGPFingerprints,
				"backup":                result.Backup,
				"verification_required": result.VerificationRequired,
			},
		}
		if result.VerificationNonce != "" {
			resp.Data["verification_nonce"] = result.VerificationNonce
		}
		return resp, nil
	}
}

// handleRekeyVerify implements the token-authenticated /sys/rekey/verify and
// /sys/rekey-recovery-key/verify operations.
func (b *SystemBackend) handleRekeyVerify(recovery bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		if recovery && !b.Core.SealAccess().RecoveryKeySupported() {
			return logical.ErrorResponse("recovery rekeying not supported"), nil
		}

		switch req.Operation {
		case logical.ReadOperation:
			return b.rekeyVerifyStatus(ctx, recovery)
		case logical.UpdateOperation:
			keyStr := data.Get("key").(string)
			nonce := data.Get("nonce").(string)
			if keyStr == "" {
				return logical.ErrorResponse("'key' must be specified in request body as JSON"), nil
			}

			min, max := b.Core.BarrierKeyLength()
			key, err := hex.DecodeString(keyStr)
			if err != nil || len(key) < min || len(key) > max {
				key, err = base64.StdEncoding.DecodeString(keyStr)
				if err != nil {
					return logical.ErrorResponse("'key' must be a valid hex or base64 string"), nil
				}
			}

			result, rekeyErr := b.Core.RekeyVerify(ctx, key, nonce, recovery)
			if rekeyErr != nil {
				return nil, rekeyErr
			}
			if result == nil {
				return b.rekeyVerifyStatus(ctx, recovery)
			}
			return &logical.Response{Data: map[string]any{
				"nonce":    result.Nonce,
				"complete": true,
			}}, nil
		case logical.DeleteOperation:
			if err := b.Core.RekeyVerifyRestart(recovery); err != nil {
				return nil, err
			}
			return b.rekeyVerifyStatus(ctx, recovery)
		default:
			return logical.ErrorResponse("unsupported operation"), nil
		}
	}
}

// rekeyVerifyStatus formats the rekey-verification status response.
func (b *SystemBackend) rekeyVerifyStatus(ctx context.Context, recovery bool) (*logical.Response, error) {
	barrierConfig, err := b.Core.SealAccess().BarrierConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to read barrier configuration: %w", err)
	}
	if barrierConfig == nil {
		return logical.ErrorResponse("server is not yet initialized"), nil
	}
	rekeyConf, err := b.Core.RekeyConfig(recovery)
	if err != nil {
		return nil, err
	}
	if rekeyConf == nil {
		return logical.ErrorResponse("no rekey configuration found"), nil
	}
	started, progress, err := b.Core.RekeyProgress(recovery, true)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"nonce":    rekeyConf.VerificationNonce,
		"started":  started,
		"t":        rekeyConf.SecretThreshold,
		"n":        rekeyConf.SecretShares,
		"progress": progress,
	}}, nil
}
