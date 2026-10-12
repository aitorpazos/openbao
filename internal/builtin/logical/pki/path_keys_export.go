// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/hkdf"
)

// CA key export/import implements the documented Enterprise migration
// surface: https://developer.hashicorp.com/vault/api-docs/secret/pki (v2.x
// latest) — "Export CA key" (POST /pki/keys/:key_ref/export, wraps the CA
// private key to a caller-supplied public key; requires root token or
// sudo) and the wrapped-key import on POST /pki/keys/import (wrapped_key +
// export_key_hmac pair, mutually exclusive with pem_bundle).
//
// Wrapping scheme (clean-room, self-consistent between the two endpoints):
// the CA private key DER is encrypted with AES-256-GCM. For RSA
// recipients, a random 32-byte content key (CEK) is wrapped with
// RSA-OAEP(SHA-256). For EC recipients, the AES-GCM key is derived directly
// from the ECDH shared secret with an ephemeral key pair via HKDF-SHA-256
// (ECDH-ES). The envelope is a base64 JSON blob:
//
//	{"alg": "pki-ent-ca-key-wrap/v1", "wrap_alg": "RSA-OAEP-256" |
//	 "ECDH-ES+A256GCM", "ca_key_type": ..., "ek": ..., "epk": (EC only),
//	 "iv": ..., "ct": ...}
//
// export_key_hmac = "sha256:" + hex(SHA-256 of the recipient public key
// DER) — deterministic on both mounts; the destination import matches the
// local export key whose public key hashes to that value. Deviations:
// ml-kem-768/1024 recipients are documented as supported upstream but are
// not implemented in this build (400); the doc sample's HMAC value is a
// placeholder (SHA-256 of the empty string), so no wire-level HMAC match
// is asserted against real Vault. AES-GCM's own tag provides integrity;
// the HMAC is used purely for export-key identification.

const (
	caKeyWrapAlgVersion = "pki-ent-ca-key-wrap/v1"
	caKeyWrapAlgRSA     = "RSA-OAEP-256"
	caKeyWrapAlgEC      = "ECDH-ES+A256GCM"
	caKeyWrapHKDFInfo   = "pki-ent-ca-key-wrap/v1/cek"
)

type caKeyWrapEnvelope struct {
	Alg       string `json:"alg"`
	WrapAlg   string `json:"wrap_alg"`
	CAKeyType string `json:"ca_key_type"`
	EK        string `json:"ek"`
	EPK       string `json:"epk,omitempty"`
	IV        string `json:"iv"`
	CT        string `json:"ct"`
}

func pathExportCAKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex(keyRefParam) + "/export$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "export",
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			keyRefParam: {
				Type:        framework.TypeString,
				Description: `Reference to the CA key to export; key UUID or name.`,
			},
			"public_key": {
				Type: framework.TypeString,
				Description: `PEM-encoded public key used to wrap the CA
private key; obtain it from Create export key on the destination mount.
Supported: rsa-2048/3072/4096, ec-p256/384/521, ml-kem-768/1024.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathExportCAKeyHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"ca_key_uuid":     {Type: framework.TypeString, Required: true},
							"wrapped_key":     {Type: framework.TypeString, Required: true},
							"export_key_hmac": {Type: framework.TypeString, Required: true},
							"exported_at":     {Type: framework.TypeString, Required: true},
						},
					}},
				},
			},
		},

		HelpSynopsis:    "Export a CA key, wrapping it for a caller-supplied public key.",
		HelpDescription: `Wraps the private key of the specified CA key entry using the caller-supplied public key and returns the encrypted blob. Requires root or sudo. Not supported for managed (external) keys.`,
	}
}

func (b *backend) pathExportCAKeyHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	keyRef := data.Get(keyRefParam).(string)
	if keyRef == "" {
		return logical.ErrorResponse("missing key reference"), nil
	}
	publicPEM := data.Get("public_key").(string)
	if publicPEM == "" {
		return logical.ErrorResponse("public_key is required"), nil
	}

	keyID, err := sc.resolveKeyReference(keyRef)
	if err != nil {
		if keyID == KeyRefNotFound {
			return logical.ErrorResponse("unable to find PKI key for reference: %s", keyRef), nil
		}
		return nil, err
	}
	key, err := sc.fetchKeyById(keyID)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", keyRef), nil
	}
	if key.PrivateKeyType == certutil.ExternalPrivateKey {
		return logical.ErrorResponse("exporting managed (external) keys is not supported"), nil
	}

	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return logical.ErrorResponse("unable to decode CA private key"), nil
	}
	caKeyDER := block.Bytes

	recipient, err := parseWrapRecipientPublicPEM(publicPEM)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	gcm, err := newGCM(aesKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, iv, caKeyDER, nil)

	env := caKeyWrapEnvelope{
		Alg:       caKeyWrapAlgVersion,
		CAKeyType: string(key.PrivateKeyType),
		IV:        base64.StdEncoding.EncodeToString(iv),
		CT:        base64.StdEncoding.EncodeToString(ct),
	}

	switch pub := recipient.(type) {
	case *rsa.PublicKey:
		env.WrapAlg = caKeyWrapAlgRSA
		ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
		if err != nil {
			return nil, err
		}
		env.EK = base64.StdEncoding.EncodeToString(ek)
	case *ecdsa.PublicKey:
		env.WrapAlg = caKeyWrapAlgEC
		ek, epk, err := wrapAESKeyECDHES(pub, aesKey)
		if err != nil {
			return nil, err
		}
		env.EK = ek
		env.EPK = epk
	default:
		return logical.ErrorResponse("unsupported recipient key type"), nil
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(recipient)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)

	return &logical.Response{Data: map[string]any{
		"ca_key_uuid":     key.ID.String(),
		"wrapped_key":     base64.StdEncoding.EncodeToString(raw),
		"export_key_hmac": "sha256:" + hex.EncodeToString(sum[:]),
		"exported_at":     time.Now().UTC().Format(time.RFC3339),
	}}, nil
}

// importWrappedCAKey decrypts a wrapped CA key blob with the export key
// identified by export_key_hmac and returns the private key PEM (PKCS#8).
func (b *backend) importWrappedCAKey(ctx context.Context, req *logical.Request, wrappedKey, exportKeyHMAC string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(wrappedKey)
	if err != nil {
		return "", errors.New("wrapped_key must be base64 encoded")
	}
	var env caKeyWrapEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", errors.New("wrapped_key is not a valid wrapped CA key envelope")
	}
	if env.Alg != caKeyWrapAlgVersion {
		return "", fmt.Errorf("unsupported wrapping algorithm %q", env.Alg)
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	recipient, err := findExportKeyByHMAC(sc, exportKeyHMAC)
	if err != nil {
		return "", err
	}

	iv, err := base64.StdEncoding.DecodeString(env.IV)
	if err != nil {
		return "", errors.New("wrapped_key has invalid iv")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return "", errors.New("wrapped_key has invalid ciphertext")
	}

	var aesKey []byte
	switch env.WrapAlg {
	case caKeyWrapAlgRSA:
		rsaPriv, ok := recipient.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("wrapped key was not produced for this export key's algorithm")
		}
		ek, err := base64.StdEncoding.DecodeString(env.EK)
		if err != nil {
			return "", errors.New("wrapped_key has invalid ek")
		}
		aesKey, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, ek, nil)
		if err != nil {
			return "", errors.New("unable to unwrap content key with the export key")
		}
	case caKeyWrapAlgEC:
		ecPriv, ok := recipient.(*ecdsa.PrivateKey)
		if !ok {
			return "", errors.New("wrapped key was not produced for this export key's algorithm")
		}
		ek, err := base64.StdEncoding.DecodeString(env.EK)
		if err != nil {
			return "", errors.New("wrapped_key has invalid ek")
		}
		ekBytes, err := base64.StdEncoding.DecodeString(env.EPK)
		if err != nil {
			return "", errors.New("wrapped_key has invalid ephemeral public key")
		}
		parsed, err := x509.ParsePKIXPublicKey(ekBytes)
		if err != nil {
			return "", errors.New("wrapped_key has invalid ephemeral public key")
		}
		ephemeralPub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return "", errors.New("wrapped_key has invalid ephemeral public key")
		}
		aesKey, err = unwrapAESKeyECDHES(ecPriv, ephemeralPub, ek)
		if err != nil {
			return "", errors.New("unable to unwrap content key with the export key")
		}
	default:
		return "", fmt.Errorf("unsupported wrap algorithm %q", env.WrapAlg)
	}

	gcm, err := newGCM(aesKey)
	if err != nil {
		return "", err
	}
	caKeyDER, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return "", errors.New("wrapped key decryption failed (wrong export key or corrupted blob)")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(caKeyDER)
	if err != nil {
		// Fall back to raw PKCS#1 / EC SEC1 forms.
		if k, kerr := x509.ParsePKCS1PrivateKey(caKeyDER); kerr == nil {
			privKey = k
		} else if k, kerr := x509.ParseECPrivateKey(caKeyDER); kerr == nil {
			privKey = k
		} else {
			return "", errors.New("wrapped key does not contain a parseable private key")
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// findExportKeyByHMAC enumerates the mount's export keys and returns the
// private key of the one whose public key hash matches the given HMAC.
func findExportKeyByHMAC(sc *storageContext, exportKeyHMAC string) (any, error) {
	if exportKeyHMAC == "" {
		return nil, errors.New("export_key_hmac is required")
	}
	keys, err := sc.Storage.List(sc.Context, "config/export-keys/")
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		entry, err := sc.Storage.Get(sc.Context, "config/export-keys/"+k)
		if err != nil || entry == nil {
			continue
		}
		var rec exportKeyRecord
		if err := entry.DecodeJSON(&rec); err != nil {
			continue
		}
		pubAny, ok := rec.Public["public_key"]
		if !ok {
			continue
		}
		block, _ := pem.Decode([]byte(fmt.Sprintf("%v", pubAny)))
		if block == nil {
			continue
		}
		sum := sha256.Sum256(block.Bytes)
		if "sha256:"+hex.EncodeToString(sum[:]) == exportKeyHMAC {
			priv, err := x509.ParsePKCS8PrivateKey(rec.Private)
			if err != nil {
				continue
			}
			return priv, nil
		}
	}
	return nil, errors.New("no export key matches the provided export_key_hmac")
}

// parseWrapRecipientPublicPEM validates the caller-supplied wrapping public
// key and returns the typed public key.
func parseWrapRecipientPublicPEM(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("public_key must be PEM encoded")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("public_key is not a parseable public key")
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048, 3072, 4096:
			return k, nil
		default:
			return nil, errors.New("unsupported RSA key size; allowed: rsa-2048, rsa-3072, rsa-4096")
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return k, nil
		default:
			return nil, errors.New("unsupported EC curve; allowed: ec-p256, ec-p384, ec-p521")
		}
	default:
		return nil, errors.New("unsupported recipient key type; allowed: rsa-2048/3072/4096, ec-p256/384/521, ml-kem-768/1024 (ml-kem not implemented in this build)")
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// wrapAESKeyECDHES wraps the AES content key for an EC recipient:
// ephemeral ECDH shared secret -> HKDF-SHA256 -> AES-GCM over the AES key.
func wrapAESKeyECDHES(recipient *ecdsa.PublicKey, aesKey []byte) (string, string, error) {
	eph, err := ecdsa.GenerateKey(recipient.Curve, rand.Reader)
	if err != nil {
		return "", "", err
	}
	x, _ := recipient.ScalarMult(recipient.X, recipient.Y, eph.D.FillBytes(make([]byte, 32)))
	shared := x.FillBytes(make([]byte, (recipient.Curve.Params().BitSize+7)/8))
	kek, err := deriveKEK(shared)
	if err != nil {
		return "", "", err
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	ct := gcm.Seal(nonce, nonce, aesKey, nil)
	epkDER, err := x509.MarshalPKIXPublicKey(&eph.PublicKey)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(ct), base64.StdEncoding.EncodeToString(epkDER), nil
}

// unwrapAESKeyECDHES reverses wrapAESKeyECDHES with the recipient private
// key.
func unwrapAESKeyECDHES(recipient *ecdsa.PrivateKey, ephemeral *ecdsa.PublicKey, ek []byte) ([]byte, error) {
	x, _ := recipient.Curve.ScalarMult(ephemeral.X, ephemeral.Y, recipient.D.FillBytes(make([]byte, 32)))
	shared := x.FillBytes(make([]byte, (recipient.Curve.Params().BitSize+7)/8))
	kek, err := deriveKEK(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(ek) < gcm.NonceSize() {
		return nil, errors.New("wrapped content key too short")
	}
	nonce, body := ek[:gcm.NonceSize()], ek[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

// deriveKEK derives the AES-256 key-encryption key from the ECDH shared
// secret via HKDF-SHA-256.
func deriveKEK(shared []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, shared, nil, []byte(caKeyWrapHKDFInfo))
	out := make([]byte, 32)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}
	return out, nil
}
