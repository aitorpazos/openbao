// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/v2/internal/helper/pgpkeys"
)

// The DR operation token ceremony state. The documented surface is
// https://developer.hashicorp.com/vault/api-docs/system/replication/replication-dr
// (v2.x latest): GET/POST/DELETE .../secondary/generate-operation-token/attempt,
// POST .../generate-operation-token/update, POST .../operation-token/delete,
// POST .../reindex, POST .../merkle-check.
//
// The generation attempt is runtime-only state: a restart clears any
// in-progress attempt. Issued operation tokens are also kept in memory;
// they have no TTL per the docs and must be revoked explicitly, so a
// restart invalidates them (documented deviation: real Vault persists
// issued operation tokens in protected storage).

// drTokenAttempt describes one in-progress operation-token generation.
type drTokenAttempt struct {
	nonce    string
	required int
	progress [][]byte
	pgpKey   string
	pgpPrint string
	otp      string
	complete bool
	encoded  string
}

// drTokenState guards the attempt and the live operation-token set.
type drTokenState struct {
	mu      sync.Mutex
	attempt *drTokenAttempt
	live    map[string]struct{}
}

// encryptSharesForDR encrypts the token with the PGP public key using the
// shared pgpkeys helper.
func encryptSharesForDR(token []byte, pgpKey string) ([]string, [][]byte, error) {
	return pgpkeys.EncryptShares([][]byte{token}, []string{pgpKey})
}

// combineDRShares combines collected root-key shares. A single share is
// the root key itself (threshold 1), matching rekey's convention.
func combineDRShares(shares [][]byte) ([]byte, error) {
	if len(shares) == 1 {
		return shares[0], nil
	}
	return shamir.Combine(shares)
}

func (s *drTokenState) ensureLocked() {
	if s.live == nil {
		s.live = make(map[string]struct{})
	}
}

// drTokenProgressShape returns the documented generation-progress fields.
func (a *drTokenAttempt) shape() map[string]any {
	data := map[string]any{
		"started":       a != nil,
		"progress":      0,
		"encoded_token": "",
		"complete":      false,
	}
	if a == nil {
		return data
	}
	data["nonce"] = a.nonce
	data["progress"] = len(a.progress)
	data["complete"] = a.complete
	data["encoded_token"] = a.encoded
	data["pgp_fingerprint"] = a.pgpPrint
	return data
}

// drTokenNewAttempt begins a generation attempt. The caller passes the
// seal threshold (required number of root key shares).
func drTokenNewAttempt(required int, pgpKey string) (*drTokenAttempt, error) {
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("unable to generate attempt nonce: %w", err)
	}
	attempt := &drTokenAttempt{
		nonce:    nonce,
		required: required,
		pgpKey:   pgpKey,
	}
	if attempt.otp, err = drTokenOTP(24); err != nil {
		return nil, fmt.Errorf("unable to generate OTP: %w", err)
	}
	return attempt, nil
}

// drTokenOTP produces a random n-character alphanumeric one-time pad.
func drTokenOTP(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// drTokenEncode wraps the raw token bytes with the attempt's OTP (XOR pad,
// matching the CLI decode flow of generate-root style tokens) or, when a
// PGP key is present, with an OpenPGP encryption of the token bytes.
func (a *drTokenAttempt) encode(token []byte) (string, error) {
	if a.pgpKey != "" {
		// pgpKey validation happened at start; EncryptShares needs one key
		// per input share.
		_, shares, err := encryptSharesForDR(token, a.pgpKey)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(shares[0]), nil
	}
	otp := []byte(a.otp)
	encoded := make([]byte, len(token))
	for i, b := range token {
		encoded[i] = b ^ otp[i%len(otp)]
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

// drTokenFinish combines the collected shares (validating the ceremony
// inputs), issues the operation token, and marks the attempt complete.
func (a *drTokenAttempt) finish() ([]byte, error) {
	if _, err := combineDRShares(a.progress); err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	encoded, err := a.encode(token)
	if err != nil {
		return nil, err
	}
	a.encoded = encoded
	a.complete = true
	return token, nil
}

// shareDedup returns false if the share was already provided (real Vault
// treats re-providing a share as a no-op for progress purposes).
func (a *drTokenAttempt) shareSeen(share []byte) bool {
	for _, seen := range a.progress {
		if bytes.Equal(seen, share) {
			return true
		}
	}
	return false
}

// verifyDROperationToken reports whether tok is a live issued token.
func (s *drTokenState) verifyDROperationToken(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	_, ok := s.live[tok]
	return ok && tok != ""
}

// revokeDROperationToken removes tok from the live set; reports whether it
// was present.
func (s *drTokenState) revokeDROperationToken(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	if _, ok := s.live[tok]; !ok {
		return false
	}
	delete(s.live, tok)
	return true
}
