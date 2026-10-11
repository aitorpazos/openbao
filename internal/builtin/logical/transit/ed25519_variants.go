// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
)

// signatureContext is distinct from the context used for key derivation.
func signatureContext(encoded string, options *keysutil.SigningOptions, input []byte) (*ed25519.Options, error) {
	context, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(context) > 255 {
		return nil, errutil.UserError{Err: "signature_context must be base64 encoded and at most 255 bytes"}
	}
	opts := &ed25519.Options{Context: string(context)}
	if options.Prehashed {
		if options.HashAlgorithm != keysutil.HashTypeSHA2512 || len(input) != 64 {
			return nil, errutil.UserError{Err: "Ed25519ph requires sha2-512 and a 64-byte prehash"}
		}
		opts.Hash = crypto.SHA512
	}
	return opts, nil
}

func signatureEncoding(options *keysutil.SigningOptions) *base64.Encoding {
	if options.Marshaling == keysutil.MarshalingTypeJWS {
		return base64.RawURLEncoding
	}
	return base64.StdEncoding
}

// signWithContext leaves the existing policy implementation responsible for all
// other algorithms. Ed25519 variants use the same keys and version restrictions.
func signWithContext(p *keysutil.Policy, ver int, context, input []byte, options *keysutil.SigningOptions, encodedContext string) (*keysutil.SigningResult, error) {
	if p.Type != keysutil.KeyType_ED25519 || (encodedContext == "" && !options.Prehashed) {
		if encodedContext != "" {
			return nil, errutil.UserError{Err: "signature_context is only supported for Ed25519"}
		}
		return p.SignWithOptions(ver, context, input, options)
	}
	opts, err := signatureContext(encodedContext, options, input)
	if err != nil {
		return nil, err
	}
	if p.SoftDeleted {
		return nil, errutil.UserError{Err: keysutil.ErrSoftDeleted}
	}
	if ver == 0 {
		ver = p.LatestVersion
	}
	if ver < 1 || ver > p.LatestVersion || ver < p.MinEncryptionVersion {
		return nil, errutil.UserError{Err: "invalid signing key version"}
	}
	entry, ok := p.Keys[strconv.Itoa(ver)]
	if !ok || entry.IsPrivateKeyMissing() {
		return nil, errutil.UserError{Err: "signing key version does not contain a private key"}
	}
	key, err := p.GetKey(context, ver, 32)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}
	sig, err := ed25519.PrivateKey(key).Sign(rand.Reader, input, opts)
	if err != nil {
		return nil, errutil.UserError{Err: err.Error()}
	}
	template := p.VersionTemplate
	if template == "" {
		template = keysutil.DefaultVersionTemplate
	}
	result := &keysutil.SigningResult{Signature: strings.ReplaceAll(template, "{{version}}", strconv.Itoa(ver)) + signatureEncoding(options).EncodeToString(sig)}
	if p.Derived {
		result.PublicKey = ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	}
	return result, nil
}

func verifyWithContext(p *keysutil.Policy, context, input []byte, sig string, options *keysutil.SigningOptions, encodedContext string) (bool, error) {
	if p.Type != keysutil.KeyType_ED25519 || (encodedContext == "" && !options.Prehashed) {
		if encodedContext != "" {
			return false, errutil.UserError{Err: "signature_context is only supported for Ed25519"}
		}
		return p.VerifySignatureWithOptions(context, input, sig, options)
	}
	opts, err := signatureContext(encodedContext, options, input)
	if err != nil {
		return false, err
	}
	if p.SoftDeleted {
		return false, errutil.UserError{Err: keysutil.ErrSoftDeleted}
	}
	template := p.VersionTemplate
	if template == "" {
		template = keysutil.DefaultVersionTemplate
	}
	parts := strings.Split(template, "{{version}}")
	if len(parts) != 2 || parts[1] == "" || !strings.HasPrefix(sig, parts[0]) {
		return false, errutil.UserError{Err: "invalid signature prefix"}
	}
	fields := strings.SplitN(strings.TrimPrefix(sig, parts[0]), parts[1], 2)
	if len(fields) != 2 {
		return false, errutil.UserError{Err: "invalid signature fields"}
	}
	ver, err := strconv.Atoi(fields[0])
	if err != nil || ver < 1 || ver > p.LatestVersion || ver < p.MinDecryptionVersion {
		return false, errutil.UserError{Err: "invalid verification key version"}
	}
	entry, ok := p.Keys[strconv.Itoa(ver)]
	if !ok {
		return false, errutil.UserError{Err: "verification key version not found"}
	}
	raw, err := signatureEncoding(options).DecodeString(fields[1])
	if err != nil {
		return false, errutil.UserError{Err: "invalid base64 signature"}
	}
	var public []byte
	if p.Derived {
		key, err := p.GetKey(context, ver, 32)
		if err != nil {
			return false, err
		}
		if len(key) != ed25519.PrivateKeySize {
			return false, fmt.Errorf("invalid Ed25519 private key size")
		}
		public = ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	} else {
		public, err = base64.StdEncoding.DecodeString(entry.FormattedPublicKey)
		if err != nil {
			return false, err
		}
	}
	if len(public) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid Ed25519 public key size")
	}
	return ed25519.VerifyWithOptions(public, input, raw, opts) == nil, nil
}
