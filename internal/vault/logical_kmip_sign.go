// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

// Sign intentionally only signs using the authenticated credential, never a
// different role's key. SHA-256 with ECDSA or RSA-PSS is the subset's default.
func kmipSign(ctx context.Context, s logical.Storage, path string, cert *x509.Certificate, p k.Node) (k.Node, uint32, error) {
	fail := func(reason uint32, msg string) (k.Node, uint32, error) { return k.Node{}, reason, errors.New(msg) }
	id := kmipSerial(cert)
	if p.Find(k.UniqueIdentifier).Text() != id {
		return fail(1, "signing identifier must be the authenticated credential serial")
	}
	for _, v := range p.Children() {
		if v.Tag != k.UniqueIdentifier && v.Tag != k.Data {
			return fail(5, "only single-part SHA-256 signing with default parameters is supported")
		}
	}
	data, ok := p.Find(k.Data).Value.([]byte)
	if !ok {
		return fail(4, "Data ByteString required")
	}
	entry, e := s.Get(ctx, path+"/credential/"+id+"/signing-key")
	if e != nil || entry == nil {
		return fail(5, "credential signing material unavailable; reissue generated credential")
	}
	block, _ := pem.Decode(entry.Value)
	if block == nil {
		return fail(0x100, "invalid signing material")
	}
	raw, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return fail(0x100, "invalid signing material")
	}
	digest := sha256.Sum256(data)
	var signature []byte
	switch key := raw.(type) {
	case *rsa.PrivateKey:
		signature, e = rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case *ecdsa.PrivateKey:
		signature, e = ecdsa.SignASN1(rand.Reader, key, digest[:])
	default:
		return fail(5, "unsupported signing key")
	}
	if e != nil {
		return fail(0x100, "signing failed")
	}
	return k.S(k.ResponsePayload, k.T(k.UniqueIdentifier, id), k.B(k.SignatureData, signature)), 0, nil
}
