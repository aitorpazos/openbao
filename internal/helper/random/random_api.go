// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The documented random API caps: up to 10MB may be fetched with the
// platform source or when using the DRBG option, while seal/all sources are
// limited to 128KB to avoid depleting HSM entropy. Without entropy
// augmentation the seal and all sources degrade to platform sampling, but
// they keep their documented, tighter cap.
const (
	MaxPlatformBytes = 10 * 1024 * 1024
	MaxSealBytes     = 128 * 1024
)

func HandleRandomAPI(d *framework.FieldData) (*logical.Response, error) {
	by := 0
	// Parsing is convoluted here, but allows operators to ACL both source and byte count
	maybeUrlBytes := d.Raw["urlbytes"]
	maybeSource := d.Raw["source"]
	source := "platform"
	var err error
	if maybeSource == "" {
		by = d.Get("bytes").(int)
	} else if maybeUrlBytes == "" && isValidSource(maybeSource.(string)) {
		source = maybeSource.(string)
		by = d.Get("bytes").(int)
	} else if maybeUrlBytes == "" {
		by, err = strconv.Atoi(maybeSource.(string))
		if err != nil {
			return logical.ErrorResponse("error parsing url-set byte count: %s", err), nil
		}
	} else {
		source = maybeSource.(string)
		by, err = strconv.Atoi(maybeUrlBytes.(string))
		if err != nil {
			return logical.ErrorResponse("error parsing url-set byte count: %s", err), nil
		}
	}
	format := d.Get("format").(string)
	// The drbg field only exists on the sys/tools/random path schema; the
	// same helper also serves the transit random path (which documents
	// source but not drbg). FieldData.Get panics on fields that are not in
	// the schema, so read the raw map and treat an absent key as unset.
	drbg, _ := d.Raw["drbg"].(string)

	if by < 1 {
		return logical.ErrorResponse("'bytes' cannot be less than 1"), nil
	}

	// Up to 10MB with the platform source (or when using the DRBG option);
	// seal/all are capped at 128KB to avoid depleting HSM entropy.
	maxBytes := MaxPlatformBytes
	if source == "seal" || source == "all" {
		maxBytes = MaxSealBytes
	}
	if by > maxBytes {
		return logical.ErrorResponse("'bytes' should be less than %d", maxBytes), nil
	}

	switch format {
	case "hex":
	case "base64":
	default:
		return logical.ErrorResponse("unsupported encoding format %q; must be \"hex\" or \"base64\"", format), nil
	}

	switch drbg {
	case "", "auto", "hmacdrbg":
	default:
		return logical.ErrorResponse("unsupported drbg mode %q; must be \"auto\" or \"hmacdrbg\"", drbg), nil
	}

	var randBytes []byte
	var warning string
	switch {
	case drbg == "auto" || drbg == "hmacdrbg":
		if !isValidSource(source) {
			return logical.ErrorResponse("unsupported entropy source %q; must be \"platform\" or \"seal\", or \"all\"", source), nil
		}
		// Seed the generator with a fixed-size sample from the chosen
		// source, then stretch it to the requested volume. The seed is 64
		// bytes (twice the SHA-256 output) for a 256-bit generator per SP
		// 800-90A. The seal/all sources keep their degradation semantics.
		seed, serr := uuid.GenerateRandomBytes(64)
		if serr != nil {
			return nil, serr
		}
		if source == "seal" {
			warning = "no seal/entropy augmentation available, using platform entropy source"
		}
		randBytes = NewHMACDRBG(seed).Generate(by)
	default:
		switch source {
		case "", "platform":
			randBytes, err = uuid.GenerateRandomBytes(by)
		case "seal":
			warning = "no seal/entropy augmentation available, using platform entropy source"
			fallthrough
		case "all":
			randBytes, err = uuid.GenerateRandomBytes(by)
		default:
			return logical.ErrorResponse("unsupported entropy source %q; must be \"platform\" or \"seal\", or \"all\"", source), nil
		}
		if err != nil {
			return nil, err
		}
	}

	var retStr string
	switch format {
	case "hex":
		retStr = hex.EncodeToString(randBytes)
	case "base64":
		retStr = base64.StdEncoding.EncodeToString(randBytes)
	}

	// Generate the response
	resp := &logical.Response{
		Data: map[string]any{
			"random_bytes": retStr,
		},
	}
	if warning != "" {
		resp.Warnings = []string{warning}
	}
	return resp, nil
}

func isValidSource(s string) bool {
	switch s {
	case "", "platform", "seal", "all":
		return true
	}
	return false
}
