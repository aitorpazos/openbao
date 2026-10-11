// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

// Zero is the legacy persisted AES object discriminator.
func (o *kmipObject) objectType() uint32 {
	if o.ObjectType == 0 {
		return 2
	}
	return o.ObjectType
}
func (o *kmipObject) wireObject() k.Node {
	if o.objectType() == 1 {
		return k.S(k.Certificate, k.E(k.CertificateType, 1), k.B(k.CertificateValue, o.Material))
	}
	tag := k.PublicKey
	if o.objectType() == 4 {
		tag = k.PrivateKey
	}
	return k.S(tag, k.S(k.KeyBlock, k.E(k.KeyFormatType, o.Format), k.S(k.KeyValue, k.B(k.KeyMaterial, o.Material)), k.E(k.CryptographicAlgorithm, o.Algorithm), k.I(k.CryptographicLength, o.Bits)))
}
func kmipObjectID(o *kmipObject) error {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return e
	}
	o.ID = hex.EncodeToString(id[:])
	o.State = 1
	return nil
}

// Parse only the supported factory attributes. Unknown fields are never ignored.
func kmipFactoryAttrs(n k.Node) (map[string]k.Node, error) {
	out := map[string]k.Node{}
	if n.Tag == 0 {
		return out, nil
	}
	if n.Type != k.Structure {
		return nil, errors.New("invalid attributes")
	}
	for _, a := range n.Children() {
		name := a.Find(k.AttributeName).Text()
		v := a.Find(k.AttributeValue)
		if a.Tag != k.Attribute || a.Type != k.Structure || !kmipWireFields(a, k.AttributeName, k.AttributeValue) || a.Find(k.AttributeName).Type != k.TextString || v.Tag == 0 {
			return nil, errors.New("invalid attribute")
		}
		if _, ok := out[name]; ok {
			return nil, errors.New("duplicate attribute")
		}
		switch name {
		case "Cryptographic Algorithm":
			if v.Type != k.Enumeration {
				return nil, errors.New("invalid algorithm")
			}
		case "Cryptographic Length", "Cryptographic Usage Mask", "Certificate Length":
			if v.Type != k.Integer || int32(v.Number()) < 0 {
				return nil, errors.New("invalid integer attribute")
			}
		case "Cryptographic Domain Parameters":
			if v.Type != k.Structure || !kmipWireFields(v, k.RecommendedCurve) || v.Find(k.RecommendedCurve).Type != k.Enumeration {
				return nil, errors.New("only Recommended Curve domain parameters supported")
			}
		case "Cryptographic Parameters":
			if v.Type != k.Structure || !kmipWireFields(v, k.CryptographicAlgorithm) || v.Find(k.CryptographicAlgorithm).Type != k.Enumeration {
				return nil, errors.New("only Cryptographic Algorithm parameters supported")
			}
		default:
			return nil, fmt.Errorf("unsupported attribute %q", name)
		}
		out[name] = v
	}
	return out, nil
}
func kmipApplyAttrs(o *kmipObject, a map[string]k.Node) error {
	if v, ok := a["Cryptographic Algorithm"]; ok {
		if o.Algorithm != 0 && o.Algorithm != v.Number() {
			return errors.New("algorithm mismatch")
		}
		o.Algorithm = v.Number()
	}
	if v, ok := a["Cryptographic Parameters"]; ok {
		alg := v.Find(k.CryptographicAlgorithm).Number()
		if o.Algorithm != 0 && o.Algorithm != alg {
			return errors.New("algorithm mismatch")
		}
		o.Algorithm = alg
	}
	if v, ok := a["Cryptographic Length"]; ok {
		if o.Bits != 0 && o.Bits != int32(v.Number()) {
			return errors.New("length mismatch")
		}
		o.Bits = int32(v.Number())
	}
	if v, ok := a["Cryptographic Usage Mask"]; ok {
		o.Usage = int32(v.Number())
	}
	if v, ok := a["Cryptographic Domain Parameters"]; ok {
		curve := v.Find(k.RecommendedCurve).Number()
		if o.Curve != 0 && o.Curve != curve {
			return errors.New("curve mismatch")
		}
		o.Curve = curve
	}
	if v, ok := a["Certificate Length"]; ok {
		if o.ObjectType != 1 || o.CertificateBytes != int32(v.Number()) {
			return errors.New("certificate length mismatch")
		}
	}
	return nil
}
func kmipKeyMetadata(o *kmipObject, pub crypto.PublicKey) error {
	switch v := pub.(type) {
	case *rsa.PublicKey:
		o.Algorithm = 4
		o.Bits = int32(v.N.BitLen())
		if o.Bits != 2048 && o.Bits != 3072 && o.Bits != 4096 {
			return errors.New("RSA length must be 2048, 3072 or 4096")
		}
	case *ecdsa.PublicKey:
		o.Algorithm = 6
		o.Bits = int32(v.Curve.Params().BitSize)
		switch o.Bits {
		case 256:
			o.Curve = 7
		case 384:
			o.Curve = 10
		case 521:
			o.Curve = 13
		default:
			return errors.New("unsupported curve")
		}
	default:
		return errors.New("only RSA and EC keys supported")
	}
	return nil
}
func kmipDER(raw []byte, typ string) ([]byte, error) {
	if bytes.HasPrefix(raw, []byte("-----BEGIN")) {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != typ || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
			return nil, errors.New("invalid PEM")
		}
		return block.Bytes, nil
	}
	return raw, nil
}
func kmipRegisterObject(p k.Node) (*kmipObject, error) {
	typ := p.Find(k.ObjectType)
	if typ.Type != k.Enumeration {
		return nil, errors.New("Object Type required")
	}
	o := &kmipObject{ObjectType: typ.Number()}
	tag := uint32(0)
	switch o.ObjectType {
	case 1:
		tag = k.Certificate
	case 3:
		tag = k.PublicKey
	case 4:
		tag = k.PrivateKey
	default:
		return nil, errors.New("only certificates and public/private keys can be registered")
	}
	if !kmipWireFields(p, k.ObjectType, k.TemplateAttribute, tag) {
		return nil, errors.New("unsupported Register field")
	}
	attrs, e := kmipFactoryAttrs(p.Find(k.TemplateAttribute))
	if e != nil {
		return nil, e
	}
	obj := p.Find(tag)
	if obj.Type != k.Structure {
		return nil, errors.New("missing object")
	}
	if tag == k.Certificate {
		for name := range attrs {
			if name != "Cryptographic Usage Mask" && name != "Certificate Length" {
				return nil, errors.New("unsupported certificate attribute")
			}
		}
		if !kmipWireFields(obj, k.CertificateType, k.CertificateValue) || obj.Find(k.CertificateType).Type != k.Enumeration || obj.Find(k.CertificateType).Number() != 1 || obj.Find(k.CertificateValue).Type != k.ByteString {
			return nil, errors.New("X.509 certificate required")
		}
		o.Material = obj.Find(k.CertificateValue).Value.([]byte)
		der, e := kmipDER(o.Material, "CERTIFICATE")
		if e != nil {
			return nil, e
		}
		if _, e = x509.ParseCertificate(der); e != nil {
			return nil, errors.New("invalid certificate")
		}
		o.CertificateBytes = int32(len(der))
	} else {
		if !kmipWireFields(obj, k.KeyBlock) {
			return nil, errors.New("unsupported key object field")
		}
		block := obj.Find(k.KeyBlock)
		value := block.Find(k.KeyValue)
		material := value.Find(k.KeyMaterial)
		if block.Type != k.Structure || !kmipWireFields(block, k.KeyFormatType, k.KeyValue, k.CryptographicAlgorithm, k.CryptographicLength) || block.Find(k.KeyFormatType).Type != k.Enumeration || value.Type != k.Structure || !kmipWireFields(value, k.KeyMaterial) || material.Type != k.ByteString {
			return nil, errors.New("unwrapped encoded key required")
		}
		o.Material = material.Value.([]byte)
		o.Format = block.Find(k.KeyFormatType).Number()
		var pub crypto.PublicKey
		if tag == k.PublicKey {
			if o.Format != 5 {
				return nil, errors.New("public key requires X.509 SubjectPublicKeyInfo")
			}
			pub, e = x509.ParsePKIXPublicKey(o.Material)
		} else {
			var priv crypto.PrivateKey
			switch o.Format {
			case 3:
				priv, e = x509.ParsePKCS1PrivateKey(o.Material)
			case 4:
				priv, e = x509.ParsePKCS8PrivateKey(o.Material)
			case 6:
				priv, e = x509.ParseECPrivateKey(o.Material)
			default:
				return nil, errors.New("private key requires PKCS#1, PKCS#8 or ECPrivateKey")
			}
			if e == nil {
				switch key := priv.(type) {
				case *rsa.PrivateKey:
					e = key.Validate()
					pub = &key.PublicKey
				case *ecdsa.PrivateKey:
					pub = &key.PublicKey
				default:
					return nil, errors.New("unsupported private key")
				}
			}
		}
		if e != nil {
			return nil, errors.New("invalid encoded key")
		}
		if e = kmipKeyMetadata(o, pub); e != nil {
			return nil, e
		}
		// Generic EC and ECDSA have identical supported key material.
		alg := block.Find(k.CryptographicAlgorithm)
		if alg.Tag != 0 {
			if alg.Type != k.Enumeration {
				return nil, errors.New("invalid algorithm")
			}
			if alg.Number() == 26 && o.Algorithm == 6 {
				o.Algorithm = 26
			}
			if alg.Number() != o.Algorithm {
				return nil, errors.New("algorithm mismatch")
			}
		}
		if a, ok := attrs["Cryptographic Algorithm"]; ok && a.Number() == 26 && o.Algorithm == 6 {
			o.Algorithm = 26
		}
		bits := block.Find(k.CryptographicLength)
		if bits.Tag != 0 && (bits.Type != k.Integer || int32(bits.Number()) != o.Bits) {
			return nil, errors.New("length mismatch")
		}
	}
	if e = kmipApplyAttrs(o, attrs); e != nil {
		return nil, e
	}
	if o.Algorithm == 4 && o.Curve != 0 {
		return nil, errors.New("RSA cannot have an EC curve")
	}
	return o, nil
}
func kmipGeneratePair(p k.Node) (*kmipObject, *kmipObject, error) {
	if !kmipWireFields(p, k.CommonTemplateAttribute, k.PrivateKeyTemplateAttribute, k.PublicKeyTemplateAttribute) {
		return nil, nil, errors.New("unsupported Create Key Pair field")
	}
	common, e := kmipFactoryAttrs(p.Find(k.CommonTemplateAttribute))
	if e != nil {
		return nil, nil, e
	}
	objs := []*kmipObject{{ObjectType: 4, Format: 4}, {ObjectType: 3, Format: 5}}
	for i, tag := range []uint32{k.PrivateKeyTemplateAttribute, k.PublicKeyTemplateAttribute} {
		own, e := kmipFactoryAttrs(p.Find(tag))
		if e != nil {
			return nil, nil, e
		}
		merged := map[string]k.Node{}
		for name, v := range common {
			merged[name] = v
		}
		for name, v := range own {
			merged[name] = v
		}
		if e = kmipApplyAttrs(objs[i], merged); e != nil {
			return nil, nil, e
		}
	}
	priv, pub := objs[0], objs[1]
	if priv.Algorithm != pub.Algorithm || priv.Bits != pub.Bits || priv.Curve != pub.Curve {
		return nil, nil, errors.New("key pair algorithm, length and domain parameters must agree")
	}
	var key crypto.Signer
	switch priv.Algorithm {
	case 4:
		if priv.Curve != 0 || (priv.Bits != 2048 && priv.Bits != 3072 && priv.Bits != 4096) {
			return nil, nil, errors.New("RSA length must be 2048, 3072 or 4096")
		}
		key, e = rsa.GenerateKey(rand.Reader, int(priv.Bits))
	case 6, 26:
		var curve elliptic.Curve
		if priv.Curve == 0 {
			switch priv.Bits {
			case 256:
				priv.Curve = 7
			case 384:
				priv.Curve = 10
			case 521:
				priv.Curve = 13
			}
		}
		switch priv.Curve {
		case 7:
			curve = elliptic.P256()
		case 10:
			curve = elliptic.P384()
		case 13:
			curve = elliptic.P521()
		}
		if curve == nil || (priv.Bits != 0 && priv.Bits != int32(curve.Params().BitSize)) {
			return nil, nil, errors.New("P-256, P-384 or P-521 with matching length required")
		}
		priv.Bits = int32(curve.Params().BitSize)
		pub.Bits = priv.Bits
		pub.Curve = priv.Curve
		key, e = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, nil, errors.New("RSA or EC algorithm required")
	}
	if e != nil {
		return nil, nil, e
	}
	priv.Material, e = x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, e
	}
	pub.Material, e = x509.MarshalPKIXPublicKey(key.Public())
	return priv, pub, e
}

// KMIP 1.4 sections 4.2-4.3; KMIP 2.0 sections 6.1.9 and 6.1.39.
func kmipAsymmetric(ctx context.Context, s logical.Storage, prefix string, op uint32, p k.Node) (k.Node, uint32, error) {
	fail := func(reason uint32, e error) (k.Node, uint32, error) { return k.Node{}, reason, e }
	if op == k.OpRegister {
		o, e := kmipRegisterObject(p)
		if e != nil {
			return fail(4, e)
		}
		if e = kmipObjectID(o); e != nil {
			return fail(0x100, e)
		}
		if e = kmipObjectSave(ctx, s, prefix, o); e != nil {
			return fail(0x100, e)
		}
		return k.S(k.ResponsePayload, k.T(k.UniqueIdentifier, o.ID)), 0, nil
	}
	priv, pub, e := kmipGeneratePair(p)
	if e != nil {
		return fail(4, e)
	}
	for _, o := range []*kmipObject{priv, pub} {
		if e = kmipObjectID(o); e != nil {
			return fail(0x100, e)
		}
	}
	priv.Peer = pub.ID
	pub.Peer = priv.ID
	if e = kmipObjectSave(ctx, s, prefix, priv); e != nil {
		return fail(0x100, e)
	}
	if e = kmipObjectSave(ctx, s, prefix, pub); e != nil {
		cleanup := s.Delete(ctx, prefix+priv.ID)
		return fail(0x100, errors.Join(e, cleanup))
	}
	return k.S(k.ResponsePayload, k.T(k.PrivateKeyUniqueIdentifier, priv.ID), k.T(k.PublicKeyUniqueIdentifier, pub.ID)), 0, nil
}
