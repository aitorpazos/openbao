// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

func kmipDRequest(v2 bool, op uint32, nodes ...k.Node) k.Node {
	version := kmipVersion()
	if v2 {
		version = kmipVersion20()
	}
	return k.S(k.RequestMessage, k.S(k.RequestHeader, version, k.I(k.BatchCount, 1)), k.S(k.BatchItem, k.E(k.Operation, op), k.S(k.RequestPayload, nodes...)))
}
func kmipDAttrs(v2 bool, tag uint32, attrs ...k.Node) k.Node {
	if v2 {
		return k.S(tag, attrs...)
	}
	legacy := []k.Node{}
	for _, a := range attrs {
		n, e := kmipLegacyAttribute(a)
		if e != nil {
			panic(e)
		}
		legacy = append(legacy, n)
	}
	switch tag {
	case k.Attributes:
		tag = k.TemplateAttribute
	case k.CommonAttributes:
		tag = k.CommonTemplateAttribute
	case k.PrivateKeyAttributes:
		tag = k.PrivateKeyTemplateAttribute
	case k.PublicKeyAttributes:
		tag = k.PublicKeyTemplateAttribute
	}
	return k.S(tag, legacy...)
}
func kmipDRun(t *testing.T, f *kmipFixture, n k.Node, ok bool) k.Node {
	t.Helper()
	raw, e := k.Marshal(n)
	if e != nil {
		t.Fatal(e)
	}
	n, e = k.Read(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	result := f.b.kmipDispatch(f.ctx, f.s, f.cert, n)
	raw, e = k.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	result, e = k.Read(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	return kmipResult(t, result, ok)
}
func TestKMIP20NegotiationAttributes(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	for _, v2 := range []bool{false, true} {
		r := kmipDRun(t, f, kmipDRequest(v2, k.OpDiscoverVersions), true)
		if len(r.Children()) != 2 || r.Children()[0].Find(k.ProtocolVersionMajor).Number() != 2 || r.Children()[1].Find(k.ProtocolVersionMinor).Number() != 4 {
			t.Fatal(r)
		}
		r = kmipDRun(t, f, kmipDRequest(v2, k.OpDiscoverVersions, kmipVersion(), kmipVersion()), true)
		if len(r.Children()) != 1 || r.Find(k.ProtocolVersion).Find(k.ProtocolVersionMajor).Number() != 1 {
			t.Fatal(r)
		}
	}
	r := f.b.kmipDispatch(f.ctx, f.s, f.cert, kmipDRequest(true, k.OpQuery, k.E(k.QueryFunction, 13), k.E(k.QueryFunction, 14)))
	if r.Find(k.ResponseHeader).Find(k.ProtocolVersion).Find(k.ProtocolVersionMajor).Number() != 2 {
		t.Fatal(r)
	}
	p := kmipResult(t, r, true)
	if len(p.Find(k.DefaultsInformation).Children()) != 4 || p.Find(k.ProtectionStorageMasks).Type != k.Structure {
		t.Fatal(p)
	}
	request := kmipDRequest(true, k.OpCreate, k.E(k.ObjectType, 2), kmipDAttrs(true, k.Attributes, k.E(k.CryptographicAlgorithm, 3), k.I(k.CryptographicLength, 256)))
	id := kmipDRun(t, f, request, true).Find(k.UniqueIdentifier).Text()
	p = kmipDRun(t, f, kmipDRequest(true, k.OpGetAttributes, k.T(k.UniqueIdentifier, id), k.E(k.AttributeReference, k.CryptographicLength)), true)
	if p.Find(k.Attributes).Find(k.CryptographicLength).Number() != 256 || len(p.Find(k.Attributes).Children()) != 1 {
		t.Fatal(p)
	}
	p = kmipDRun(t, f, kmipDRequest(true, k.OpGetAttributeList, k.T(k.UniqueIdentifier, id)), true)
	if p.Find(k.AttributeReference).Type != k.Enumeration || p.Find(k.AttributeName).Tag != 0 {
		t.Fatal(p)
	}
	kmipDRun(t, f, kmipDRequest(true, k.OpGet, k.T(k.UniqueIdentifier, id)), true)
	kmipDRun(t, f, kmipDRequest(true, k.OpRekey, k.T(k.UniqueIdentifier, id)), true)
	kmipDRun(t, f, kmipDRequest(true, k.OpActivate, k.T(k.UniqueIdentifier, id)), true)
	p = kmipDRun(t, f, kmipDRequest(true, k.OpLocate, k.S(k.Attributes, k.E(k.State, 2))), true)
	if p.Find(k.UniqueIdentifier).Text() != id {
		t.Fatal(p)
	}
	bad := kmipDRequest(true, k.OpQuery, k.E(k.QueryFunction, 1))
	bad.Children()[0].Children()[0] = k.S(k.ProtocolVersion, k.I(k.ProtocolVersionMajor, 2), k.I(k.ProtocolVersionMinor, 1))
	kmipDRun(t, f, bad, false)
	kmipDRun(t, f, kmipDRequest(true, k.OpCreate, kmipCreateRequest().Find(k.BatchItem).Find(k.RequestPayload).Children()...), false)
}
func TestKMIPRegisterCertificateLifecycleBatch(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		t.Run(fmt.Sprint(v2), func(t *testing.T) {
			f := newKMIPFixture(t, "ec")
			makeReq := func(raw []byte) k.Node {
				return kmipDRequest(v2, k.OpRegister, k.E(k.ObjectType, 1), kmipDAttrs(v2, k.Attributes), k.S(k.Certificate, k.E(k.CertificateType, 1), k.B(k.CertificateValue, raw)))
			}
			for _, raw := range [][]byte{f.cert.Raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw})} {
				id := kmipDRun(t, f, makeReq(raw), true).Find(k.UniqueIdentifier).Text()
				get := kmipDRequest(v2, k.OpGet, k.T(k.UniqueIdentifier, id))
				p := kmipDRun(t, f, get, true)
				if p.Find(k.ObjectType).Number() != 1 || !bytes.Equal(p.Find(k.Certificate).Find(k.CertificateValue).Value.([]byte), raw) {
					t.Fatal(p)
				}
				attrs := kmipDRun(t, f, kmipDRequest(v2, k.OpGetAttributes, k.T(k.UniqueIdentifier, id)), true)
				if len(attrs.Children()) == 0 {
					t.Fatal(attrs)
				}
				kmipDRun(t, f, kmipDRequest(v2, k.OpGetAttributeList, k.T(k.UniqueIdentifier, id)), true)
				batch := kmipBatchRequest(nil, makeReq(raw), get)
				if v2 {
					batch.Children()[0].Children()[0] = kmipVersion20()
				}
				r := f.b.kmipDispatch(f.ctx, f.s, f.cert, batch)
				if r.Find(k.ResponseHeader).Find(k.BatchCount).Number() != 2 {
					t.Fatal(r)
				}
				for _, item := range r.Children()[1:] {
					if item.Find(k.ResultStatus).Number() != 0 {
						t.Fatal(item)
					}
				}
				kmipDRun(t, f, kmipDRequest(v2, k.OpDestroy, k.T(k.UniqueIdentifier, id)), true)
				kmipDRun(t, f, get, false)
				stored, e := kmipObjectLoad(f.ctx, f.s, "scope/s/role/r/objects/", id)
				if e != nil || stored.State != 5 || len(stored.Material) != 0 {
					t.Fatal(stored, e)
				}
				id = kmipDRun(t, f, makeReq(raw), true).Find(k.UniqueIdentifier).Text()
				kmipDRun(t, f, kmipDRequest(v2, k.OpActivate, k.T(k.UniqueIdentifier, id)), true)
				kmipDRun(t, f, kmipDRequest(v2, k.OpDestroy, k.T(k.UniqueIdentifier, id)), false)
			}
			kmipDRun(t, f, makeReq([]byte("invalid certificate")), false)
		})
	}
}
func TestKMIPCreateKeyPairRegisterLocate(t *testing.T) {
	cases := []struct {
		alg   uint32
		bits  int32
		curve uint32
	}{{4, 2048, 0}, {4, 3072, 0}, {4, 4096, 0}, {6, 256, 7}, {26, 384, 10}, {26, 521, 13}}
	for _, v2 := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("v2=%t/alg=%d/bits=%d", v2, tc.alg, tc.bits), func(t *testing.T) {
				f := newKMIPFixture(t, "ec")
				attrs := []k.Node{k.E(k.CryptographicAlgorithm, tc.alg), k.I(k.CryptographicLength, tc.bits)}
				if tc.curve != 0 {
					attrs = append(attrs, k.S(k.CryptographicDomainParameters, k.E(k.RecommendedCurve, tc.curve)))
				}
				p := kmipDRun(t, f, kmipDRequest(v2, k.OpCreateKeyPair, kmipDAttrs(v2, k.CommonAttributes, attrs...), kmipDAttrs(v2, k.PrivateKeyAttributes, k.I(k.CryptographicUsageMask, 1)), kmipDAttrs(v2, k.PublicKeyAttributes, k.I(k.CryptographicUsageMask, 2))), true)
				privID, pubID := p.Find(k.PrivateKeyUniqueIdentifier).Text(), p.Find(k.PublicKeyUniqueIdentifier).Text()
				if privID == "" || pubID == "" || privID == pubID {
					t.Fatal(p)
				}
				priv, e := kmipObjectLoad(f.ctx, f.s, "scope/s/role/r/objects/", privID)
				if e != nil {
					t.Fatal(e)
				}
				pub, e := kmipObjectLoad(f.ctx, f.s, "scope/s/role/r/objects/", pubID)
				if e != nil {
					t.Fatal(e)
				}
				if priv.Peer != pubID || pub.Peer != privID || priv.Usage != 1 || pub.Usage != 2 || priv.State != 1 || pub.State != 1 {
					t.Fatal(priv, pub)
				}
				key, e := x509.ParsePKCS8PrivateKey(priv.Material)
				if e != nil {
					t.Fatal(e)
				}
				der, e := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
				if e != nil || !bytes.Equal(der, pub.Material) {
					t.Fatal("key halves mismatch", e)
				}
				for _, o := range []*kmipObject{priv, pub} {
					attrs := kmipDRun(t, f, kmipDRequest(v2, k.OpGetAttributes, k.T(k.UniqueIdentifier, o.ID)), true)
					if v2 {
						if attrs.Find(k.Attributes).Find(k.Link).Find(k.LinkedObjectIdentifier).Text() != o.Peer {
							t.Fatal(attrs)
						}
					} else {
						found := false
						for _, a := range attrs.Children() {
							if a.Find(k.AttributeName).Text() == "Link" {
								found = a.Find(k.AttributeValue).Find(k.LinkedObjectIdentifier).Text() == o.Peer
							}
						}
						if !found {
							t.Fatal(attrs)
						}
					}
					got := kmipDRun(t, f, kmipDRequest(v2, k.OpGet, k.T(k.UniqueIdentifier, o.ID)), true)
					tag := k.PrivateKey
					if o.ObjectType == 3 {
						tag = k.PublicKey
					}
					reg := kmipDRun(t, f, kmipDRequest(v2, k.OpRegister, k.E(k.ObjectType, o.ObjectType), kmipDAttrs(v2, k.Attributes, k.I(k.CryptographicUsageMask, o.Usage)), got.Find(tag)), true)
					id := reg.Find(k.UniqueIdentifier).Text()
					if id == o.ID {
						t.Fatal("Register reused identifier")
					}
					got = kmipDRun(t, f, kmipDRequest(v2, k.OpGet, k.T(k.UniqueIdentifier, id)), true)
					if !bytes.Equal(got.Find(tag).Find(k.KeyBlock).Find(k.KeyValue).Find(k.KeyMaterial).Value.([]byte), o.Material) {
						t.Fatal("key changed")
					}
					kmipDRun(t, f, kmipDRequest(v2, k.OpSign, k.T(k.UniqueIdentifier, id), k.B(k.Data, []byte("not a credential"))), false)
					kmipDRun(t, f, kmipDRequest(v2, k.OpRekey, k.T(k.UniqueIdentifier, id)), false)
					if _, reason, err := kmipExecute(f.ctx, f.s, "scope/s/role/other", k.OpGet, k.S(k.RequestPayload, k.T(k.UniqueIdentifier, id))); err == nil || reason != 1 {
						t.Fatal("cross-role key access")
					}
					kmipDRun(t, f, kmipDRequest(v2, k.OpDestroy, k.T(k.UniqueIdentifier, id)), true)
					kmipDRun(t, f, kmipDRequest(v2, k.OpGet, k.T(k.UniqueIdentifier, id)), false)
					kmipDRun(t, f, kmipDRequest(v2, k.OpActivate, k.T(k.UniqueIdentifier, o.ID)), true)
					kmipDRun(t, f, kmipDRequest(v2, k.OpDestroy, k.T(k.UniqueIdentifier, o.ID)), false)
				}
				cert := kmipDRequest(v2, k.OpRegister, k.E(k.ObjectType, 1), kmipDAttrs(v2, k.Attributes), k.S(k.Certificate, k.E(k.CertificateType, 1), k.B(k.CertificateValue, f.cert.Raw)))
				kmipDRun(t, f, cert, true)
				kmipDRun(t, f, kmipDRequest(v2, k.OpCreate, k.E(k.ObjectType, 2), kmipDAttrs(v2, k.Attributes, k.E(k.CryptographicAlgorithm, 3), k.I(k.CryptographicLength, 128))), true)
				located := kmipDRun(t, f, kmipDRequest(v2, k.OpLocate), true)
				if len(located.Children()) != 6 {
					t.Fatal(located)
				}
				filter := kmipDAttrs(v2, k.Attributes, k.E(k.ObjectType, 3))
				filters := []k.Node{filter}
				if !v2 {
					filters = filter.Children()
				}
				located = kmipDRun(t, f, kmipDRequest(v2, k.OpLocate, filters...), true)
				if len(located.Children()) != 2 {
					t.Fatal(located)
				}
			})
		}
	}
}
func TestKMIPFactoryAuthorizationValidation(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	bad := []k.Node{
		kmipDRequest(true, k.OpCreateKeyPair, kmipDAttrs(true, k.CommonAttributes, k.E(k.CryptographicAlgorithm, 4), k.I(k.CryptographicLength, 1024))),
		kmipDRequest(true, k.OpCreateKeyPair, kmipDAttrs(true, k.CommonAttributes, k.E(k.CryptographicAlgorithm, 6), k.I(k.CryptographicLength, 256), k.S(k.CryptographicDomainParameters, k.E(k.RecommendedCurve, 10)))),
		kmipDRequest(true, k.OpCreateKeyPair, kmipDAttrs(true, k.CommonAttributes, k.E(k.CryptographicAlgorithm, 4), k.I(k.CryptographicLength, 2048)), kmipDAttrs(true, k.PublicKeyAttributes, k.I(k.CryptographicLength, 3072))),
	}
	for _, req := range bad {
		kmipDRun(t, f, req, false)
	}
	ids, e := f.s.List(f.ctx, "scope/s/role/r/objects/")
	if e != nil || len(ids) != 0 {
		t.Fatal(ids, e)
	}
	f.call(logical.UpdateOperation, "scope/s/role/r", map[string]interface{}{"operation_all": false, "operation_create_keypair": true})
	kmipDRun(t, f, kmipDRequest(true, k.OpCreateKeyPair, kmipDAttrs(true, k.CommonAttributes, k.E(k.CryptographicAlgorithm, 6), k.I(k.CryptographicLength, 256))), true)
	kmipDRun(t, f, kmipDRequest(true, k.OpRegister, k.E(k.ObjectType, 1), kmipDAttrs(true, k.Attributes), k.S(k.Certificate, k.E(k.CertificateType, 1), k.B(k.CertificateValue, f.cert.Raw))), false)
}
