// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"

	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

func kmipVersion20() k.Node {
	return k.S(k.ProtocolVersion, k.I(k.ProtocolVersionMajor, 2), k.I(k.ProtocolVersionMinor, 0))
}
func kmipSupportedVersion(v k.Node) bool {
	if v.Type != k.Structure || !kmipWireFields(v, k.ProtocolVersionMajor, k.ProtocolVersionMinor) || len(v.Children()) != 2 || v.Find(k.ProtocolVersionMajor).Type != k.Integer || v.Find(k.ProtocolVersionMinor).Type != k.Integer {
		return false
	}
	major, minor := v.Find(k.ProtocolVersionMajor).Number(), v.Find(k.ProtocolVersionMinor).Number()
	return major == 1 && minor == 4 || major == 2 && minor == 0
}

// KMIP 2.0 sections 5.1-5.5: attributes carry their own tags, not
// Attribute Name/Value wrappers. Translate at the protocol boundary only.
func kmipLegacyAttribute(a k.Node) (k.Node, error) {
	name := kmipAttributeName(a.Tag)
	if name == "" {
		return k.Node{}, errors.New("unsupported attribute")
	}
	a.Tag = k.AttributeValue
	return k.S(k.Attribute, k.T(k.AttributeName, name), a), nil
}
func kmipExecuteVersion(ctx context.Context, s logical.Storage, path string, op uint32, p k.Node, v2 bool) (k.Node, uint32, error) {
	if !v2 {
		return kmipExecute(ctx, s, path, op, p)
	}
	fail := func(msg string) (k.Node, uint32, error) { return k.Node{}, 5, errors.New(msg) }
	if op == k.OpRegister && p.Find(k.Attributes).Type != k.Structure {
		return fail("Register requires Attributes")
	}
	fields := []k.Node{}
	defaults, masks := false, false
	seenContainers := map[uint32]bool{}
	for _, f := range p.Children() {
		switch f.Tag {
		case k.TemplateAttribute, k.CommonTemplateAttribute, k.PrivateKeyTemplateAttribute, k.PublicKeyTemplateAttribute, k.Attribute, k.AttributeName:
			return fail("legacy attribute structure is not valid in KMIP 2.0")
		case k.Attributes, k.CommonAttributes, k.PrivateKeyAttributes, k.PublicKeyAttributes:
			if seenContainers[f.Tag] {
				return fail("duplicate attributes structure")
			}
			seenContainers[f.Tag] = true
			if f.Tag == k.Attributes {
				if op != k.OpCreate && op != k.OpRegister && op != k.OpLocate {
					return fail("unexpected Attributes")
				}
			} else if op != k.OpCreateKeyPair {
				return fail("unexpected key pair attributes")
			}
			if f.Type != k.Structure {
				return fail("attributes must be a structure")
			}
			attrs := []k.Node{}
			for _, a := range f.Children() {
				legacy, e := kmipLegacyAttribute(a)
				if e != nil {
					return fail(e.Error())
				}
				attrs = append(attrs, legacy)
			}
			if op == k.OpLocate && f.Tag == k.Attributes {
				fields = append(fields, attrs...)
				continue
			}
			tags := map[uint32]uint32{k.Attributes: k.TemplateAttribute, k.CommonAttributes: k.CommonTemplateAttribute, k.PrivateKeyAttributes: k.PrivateKeyTemplateAttribute, k.PublicKeyAttributes: k.PublicKeyTemplateAttribute}
			f = k.S(tags[f.Tag], attrs...)
		case k.AttributeReference:
			if op != k.OpGetAttributes || f.Type != k.Enumeration || kmipAttributeName(f.Number()) == "" {
				return fail("unsupported attribute reference")
			}
			f = k.T(k.AttributeName, kmipAttributeName(f.Number()))
		case k.QueryFunction:
			if op == k.OpQuery && f.Type == k.Enumeration {
				if f.Number() == 13 {
					defaults = true
					continue
				}
				if f.Number() == 14 {
					masks = true
					continue
				}
			}
		}
		fields = append(fields, f)
	}
	var out k.Node
	var reason uint32
	var err error
	if op == k.OpQuery && len(fields) == 0 && (defaults || masks) {
		out = k.S(k.ResponsePayload)
	} else {
		out, reason, err = kmipExecute(ctx, s, path, op, k.S(k.RequestPayload, fields...))
	}
	if err != nil {
		return out, reason, err
	}
	result := []k.Node{}
	attrs := []k.Node{}
	for _, f := range out.Children() {
		if op == k.OpGetAttributeList && f.Tag == k.AttributeName {
			f = k.E(k.AttributeReference, k.Tags[f.Text()])
		}
		if op == k.OpGetAttributes && f.Tag == k.Attribute {
			a := f.Find(k.AttributeValue)
			a.Tag = k.Tags[f.Find(k.AttributeName).Text()]
			attrs = append(attrs, a)
			continue
		}
		result = append(result, f)
	}
	if op == k.OpGetAttributes {
		result = append(result, k.S(k.Attributes, attrs...))
	}
	// 2.0 sections 6.1.37, 7.7, 7.18: advertise the actual usage default.
	if defaults {
		objects := []k.Node{}
		for _, typ := range []uint32{1, 2, 3, 4} {
			objects = append(objects, k.S(k.ObjectDefaults, k.E(k.ObjectType, typ), k.S(k.Attributes, k.I(k.CryptographicUsageMask, 0))))
		}
		result = append(result, k.S(k.DefaultsInformation, objects...))
	}
	if masks {
		result = append(result, k.S(k.ProtectionStorageMasks))
	}
	return k.S(k.ResponsePayload, result...), 0, nil
}
