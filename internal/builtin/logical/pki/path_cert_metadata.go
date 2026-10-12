// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Certificate metadata storage implements the documented Enterprise surface:
// https://developer.hashicorp.com/vault/api-docs/secret/pki (v2.x latest) —
// "Read Certificate Metadata" (GET /pki/cert-metadata/:serial), "List
// Certificate Metadata" (LIST /pki/cert-metadata), and "Read Batch
// Certificate" (POST /pki/batch/certs). The issue/sign parameter
// `cert_metadata` associates a base64 value with the issued certificate's
// serial number, gated by the role's no_store_metadata flag.
//
// Storage deviation: entries live under `certs-metadata/<hyphen-serial>` —
// a separate top-level prefix so that LIST /pki/cert (certs/) is not
// polluted. The storage layout is not part of the public API contract.
// When a certificate is deleted (tidy), its metadata entry is not
// automatically removed in this build; tidy_cert_metadata is a documented
// deviation (tidy's metadata deletion is not wired).

const (
	certMetadataPrefix = "certs-metadata/"
)

type certMetadataEntry struct {
	IssuerID     string    `json:"issuer_id"`
	Expiration   time.Time `json:"expiration"`
	CertMetadata string    `json:"cert_metadata"`
	Role         string    `json:"role"`
	SerialNumber string    `json:"serial_number"`
}

// storeCertMetadata writes a metadata entry for the given serial. Called
// after the certificate itself is stored.
func (sc *storageContext) storeCertMetadata(issuerID string, cert *x509.Certificate, role, certMetadata string) error {
	hyphen := normalizeSerialFromBigInt(cert.SerialNumber)
	entry := certMetadataEntry{
		IssuerID:     issuerID,
		Expiration:   cert.NotAfter,
		CertMetadata: certMetadata,
		Role:         role,
		SerialNumber: denormalizeSerial(hyphen),
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return sc.Storage.Put(sc.Context, &logical.StorageEntry{
		Key:   certMetadataPrefix + hyphen,
		Value: raw,
	})
}

// fetchCertMetadata loads one metadata entry by serial (any documented
// form: colon-separated, hyphen-separated, or decimal).
func (sc *storageContext) fetchCertMetadata(serial string) (*certMetadataEntry, error) {
	hyphen := normalizeSerial(serial)
	entry, err := sc.Storage.Get(sc.Context, certMetadataPrefix+hyphen)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var meta certMetadataEntry
	if err := json.Unmarshal(entry.Value, &meta); err != nil {
		return nil, fmt.Errorf("unable to decode certificate metadata for serial %s: %w", serial, err)
	}
	return &meta, nil
}

// metadataSerialPattern accepts the documented colon-separated serial form
// plus hyphen and plain hex forms, both URL-embedded.
const metadataSerialPattern = "(?P<serial>[0-9a-fA-F:.-]+)"

func pathsCertMetadata(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "cert-metadata/" + metadataSerialPattern,
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "read",
				OperationSuffix: "cert-metadata",
			},
			Fields: map[string]*framework.FieldSchema{
				"serial": {Type: framework.TypeString},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCertMetadataRead,
				},
			},
		},
		{
			Pattern: "cert-metadata/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "list",
				OperationSuffix: "cert-metadata",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathCertMetadataList,
				},
			},
		},
		{
			Pattern: "batch/certs/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "read",
				OperationSuffix: "batch-certs",
			},
			Fields: map[string]*framework.FieldSchema{
				"serial_numbers": {
					Type: framework.TypeStringSlice,
					Description: `Specifies a list of serial numbers of
certificates to be fetched.`,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathBatchCerts,
				},
			},
		},
	}
}

func (b *backend) pathCertMetadataRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := data.Get("serial").(string)
	if serial == "" {
		return logical.ErrorResponse("missing serial"), nil
	}
	sc := b.makeStorageContext(ctx, req.Storage)
	meta, err := sc.fetchCertMetadata(serial)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, nil
	}
	return &logical.Response{Data: map[string]any{
		"issuer_id":     meta.IssuerID,
		"expiration":    meta.Expiration.Format(time.RFC3339Nano),
		"cert_metadata": meta.CertMetadata,
		"role":          meta.Role,
		"serial_number": meta.SerialNumber,
	}}, nil
}

func (b *backend) pathCertMetadataList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, certMetadataPrefix)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, denormalizeSerial(e))
	}
	return logical.ListResponse(keys), nil
}

func (b *backend) pathBatchCerts(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serials, _ := data.Get("serial_numbers").([]string)
	if len(serials) == 0 {
		return logical.ErrorResponse("missing serial_numbers"), nil
	}
	sc := b.makeStorageContext(ctx, req.Storage)
	certificates := map[string]any{}
	for _, serial := range serials {
		entry, err := fetchCertBySerial(sc, "certs/", serial)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			certificates[denormalizeSerial(normalizeSerial(serial))] = nil
			continue
		}
		cert, err := x509.ParseCertificate(entry.Value)
		if err != nil {
			return nil, err
		}
		pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		certificates[denormalizeSerial(normalizeSerialFromBigInt(cert.SerialNumber))] = string(pem.EncodeToMemory(pemBlock))
	}
	return &logical.Response{Data: map[string]any{
		"certificates": certificates,
	}}, nil
}
