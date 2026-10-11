// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

type kmipObject struct {
	ID         string
	Material   []byte
	Algorithm  uint32
	Bits       int32
	State      uint32
	Activation int64
	Usage      int32
}

func kmipVersion() k.Node {
	return k.S(k.ProtocolVersion, k.I(k.ProtocolVersionMajor, 1), k.I(k.ProtocolVersionMinor, 4))
}
func kmipFailure(op uint32, reason uint32, msg string) k.Node {
	return k.S(k.BatchItem, k.E(k.Operation, op), k.E(k.ResultStatus, 1), k.E(k.ResultReason, reason), k.T(k.ResultMessage, msg))
}

// Authentication rechecks the exact stored certificate on every operation, so
// removing a credential revokes even already-established TLS sessions.
func kmipIdentity(ctx context.Context, s logical.Storage, cert *x509.Certificate) (string, map[string]interface{}, error) {
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return "", nil, errors.New("credential expired or not yet valid")
	}
	if len(cert.Subject.OrganizationalUnit) != 1 {
		return "", nil, errors.New("invalid credential scope")
	}
	scope, role := cert.Subject.OrganizationalUnit[0], cert.Subject.CommonName
	for _, v := range []string{scope, role} {
		if v == "" || strings.ContainsAny(v, "/\\") || v == "." || v == ".." {
			return "", nil, errors.New("invalid credential identity")
		}
	}
	path := "scope/" + scope + "/role/" + role
	r, e := kmipLoad(ctx, s, path)
	if e != nil || r == nil {
		return "", nil, errors.New("unknown role")
	}
	credential, e := kmipLoad(ctx, s, path+"/credential/"+kmipSerial(cert))
	if e != nil || credential == nil {
		return "", nil, errors.New("unknown credential")
	}
	stored, e := kmipParseCert(kmipString(credential, "certificate"))
	if e != nil || !bytes.Equal(stored.Raw, cert.Raw) {
		return "", nil, errors.New("credential mismatch")
	}
	return path, r, nil
}
func (b *kmipBackend) kmipDispatch(ctx context.Context, s logical.Storage, cert *x509.Certificate, n k.Node) k.Node {
	b.mu.Lock()
	defer b.mu.Unlock()
	item := n.Find(k.BatchItem)
	op := item.Find(k.Operation).Number()
	result := func() k.Node {
		if n.Tag != k.RequestMessage || n.Type != k.Structure {
			return kmipFailure(op, 4, "expected Request Message")
		}
		header := n.Find(k.RequestHeader)
		version := header.Find(k.ProtocolVersion)
		if header.Find(k.BatchCount).Number() != 1 || len(n.Children()) != 2 || item.Type != k.Structure {
			return kmipFailure(op, 4, "exactly one batch item is supported")
		}
		if version.Find(k.ProtocolVersionMajor).Number() != 1 || version.Find(k.ProtocolVersionMinor).Number() != 4 {
			return kmipFailure(op, 4, "only KMIP 1.4 is supported")
		}
		if len(header.Children()) != 2 || item.Find(k.RequestPayload).Type != k.Structure {
			return kmipFailure(op, 4, "unsupported header or missing payload")
		}
		for _, v := range item.Children() {
			if v.Tag != k.Operation && v.Tag != k.RequestPayload && v.Tag != k.UniqueBatchItemID {
				return kmipFailure(op, 4, "unsupported batch field")
			}
		}
		path, role, e := kmipIdentity(ctx, s, cert)
		if e != nil {
			return kmipFailure(op, 12, "credential is not authorized")
		}
		name, ok := k.Operations[op]
		if !ok {
			return kmipFailure(op, 5, "operation is not supported")
		}
		if role["operation_none"] == true || (role["operation_all"] != true && role["operation_"+name] != true) {
			return kmipFailure(op, 12, "operation is not permitted by role")
		}
		var payload k.Node
		var reason uint32
		if op == k.OpSign {
			payload, reason, e = kmipSign(ctx, s, path, cert, item.Find(k.RequestPayload))
		} else {
			payload, reason, e = kmipExecute(ctx, s, path, op, item.Find(k.RequestPayload))
		}
		if e != nil {
			return kmipFailure(op, reason, e.Error())
		}
		return k.S(k.BatchItem, k.E(k.Operation, op), k.E(k.ResultStatus, 0), payload)
	}()
	if id := item.Find(k.UniqueBatchItemID); id.Type == k.ByteString {
		result.Value = append(result.Children(), id)
	}
	return k.S(k.ResponseMessage, k.S(k.ResponseHeader, kmipVersion(), k.Node{Tag: k.TimeStamp, Type: k.DateTime, Value: time.Now().Unix()}, k.I(k.BatchCount, 1)), result)
}
func kmipAttributes(o *kmipObject) []k.Node {
	out := []k.Node{k.T(k.UniqueIdentifier, o.ID), k.E(k.ObjectType, 2), k.E(k.CryptographicAlgorithm, o.Algorithm), k.I(k.CryptographicLength, o.Bits), k.I(k.CryptographicUsageMask, o.Usage), k.E(k.State, o.State)}
	if o.Activation != 0 {
		out = append(out, k.Node{Tag: k.ActivationDate, Type: k.DateTime, Value: o.Activation})
	}
	return out
}
func kmipAttributeName(tag uint32) string {
	for name, t := range k.Tags {
		if t == tag {
			return name
		}
	}
	return ""
}
func kmipObjectSave(ctx context.Context, s logical.Storage, prefix string, o *kmipObject) error {
	entry, e := logical.StorageEntryJSON(prefix+o.ID, o)
	if e != nil {
		return e
	}
	return s.Put(ctx, entry)
}
func kmipObjectLoad(ctx context.Context, s logical.Storage, prefix, id string) (*kmipObject, error) {
	raw, e := hex.DecodeString(id)
	if e != nil || len(raw) != 16 {
		return nil, errors.New("object not found")
	}
	entry, e := s.Get(ctx, prefix+id)
	if e != nil {
		return nil, e
	}
	if entry == nil {
		return nil, errors.New("object not found")
	}
	var o kmipObject
	e = entry.DecodeJSON(&o)
	return &o, e
}
func kmipNewObject(ctx context.Context, s logical.Storage, prefix string, o *kmipObject) error {
	id := make([]byte, 16)
	if _, e := rand.Read(id); e != nil {
		return e
	}
	o.ID = hex.EncodeToString(id)
	o.Material = make([]byte, o.Bits/8)
	if _, e := rand.Read(o.Material); e != nil {
		return e
	}
	o.State = 1
	o.Activation = 0
	return kmipObjectSave(ctx, s, prefix, o)
}

// kmipExecute uses reason codes defined in KMIP 1.4 section 9.1.3.2.29.
func kmipExecute(ctx context.Context, s logical.Storage, path string, op uint32, p k.Node) (k.Node, uint32, error) {
	fail := func(reason uint32, msg string) (k.Node, uint32, error) { return k.Node{}, reason, errors.New(msg) }
	prefix := path + "/objects/"
	out := []k.Node{}
	switch op {
	case k.OpDiscoverVersions:
		if len(p.Children()) == 0 {
			return k.S(k.ResponsePayload, kmipVersion()), 0, nil
		}
		for _, v := range p.Children() {
			if v.Tag != k.ProtocolVersion {
				return fail(4, "invalid version request")
			}
			if v.Find(k.ProtocolVersionMajor).Number() == 1 && v.Find(k.ProtocolVersionMinor).Number() == 4 {
				out = append(out, kmipVersion())
			}
		}
	case k.OpQuery:
		if len(p.Children()) == 0 {
			return fail(4, "Query Function required")
		}
		seen := map[uint32]bool{}
		for _, v := range p.Children() {
			if v.Tag != k.QueryFunction || v.Type != k.Enumeration {
				return fail(4, "invalid Query Function")
			}
			if seen[v.Number()] {
				continue
			}
			seen[v.Number()] = true
			switch v.Number() {
			case 1:
				ops := []int{}
				for op := range k.Operations {
					ops = append(ops, int(op))
				}
				sort.Ints(ops)
				for _, op := range ops {
					out = append(out, k.E(k.Operation, uint32(op)))
				}
			case 2:
				out = append(out, k.E(k.ObjectType, 2))
			case 3:
				out = append(out, k.T(k.VendorIdentification, "OpenBao"))
			default:
				return fail(5, "Query Function unsupported")
			}
		}
	case k.OpCreate:
		if p.Find(k.ObjectType).Number() != 2 {
			return fail(5, "only AES Symmetric Key creation is supported")
		}
		o := &kmipObject{}
		for _, v := range p.Children() {
			if v.Tag != k.ObjectType && v.Tag != k.TemplateAttribute {
				return fail(4, "unsupported Create field")
			}
		}
		seen := map[string]bool{}
		for _, a := range p.Find(k.TemplateAttribute).Children() {
			name := a.Find(k.AttributeName).Text()
			value := a.Find(k.AttributeValue)
			if a.Tag != k.Attribute || seen[name] {
				return fail(4, "invalid or duplicate attribute")
			}
			seen[name] = true
			switch name {
			case "Cryptographic Algorithm":
				if value.Type != k.Enumeration {
					return fail(4, "invalid algorithm")
				}
				o.Algorithm = value.Number()
			case "Cryptographic Length":
				if value.Type != k.Integer {
					return fail(4, "invalid length")
				}
				o.Bits = int32(value.Number())
			case "Cryptographic Usage Mask":
				if value.Type != k.Integer {
					return fail(4, "invalid usage")
				}
				o.Usage = int32(value.Number())
			default:
				return fail(5, "unsupported attribute")
			}
		}
		if o.Algorithm != 3 || (o.Bits != 128 && o.Bits != 192 && o.Bits != 256) {
			return fail(4, "AES with length 128, 192 or 256 is required")
		}
		if e := kmipNewObject(ctx, s, prefix, o); e != nil {
			return fail(0x100, "object storage failed")
		}
		out = append(out, k.E(k.ObjectType, 2), k.T(k.UniqueIdentifier, o.ID))
	case k.OpLocate:
		for _, a := range p.Children() {
			name := a.Find(k.AttributeName).Text()
			v := a.Find(k.AttributeValue)
			if a.Tag != k.Attribute || v.Type != k.Enumeration || (name != "State" && name != "Cryptographic Algorithm") {
				return fail(5, "only state and algorithm Locate filters supported")
			}
		}
		ids, e := s.List(ctx, prefix)
		if e != nil {
			return fail(0x100, "object storage failed")
		}
		sort.Strings(ids)
		if len(ids) > 4096 {
			return fail(0x100, "Locate result limit exceeded")
		}
		for _, id := range ids {
			o, e := kmipObjectLoad(ctx, s, prefix, id)
			if e != nil {
				return fail(0x100, "object storage failed")
			}
			match := true
			for _, a := range p.Children() {
				v := a.Find(k.AttributeValue).Number()
				switch a.Find(k.AttributeName).Text() {
				case "State":
					match = match && o.State == v
				case "Cryptographic Algorithm":
					match = match && o.Algorithm == v
				}
			}
			if match {
				out = append(out, k.T(k.UniqueIdentifier, id))
			}
		}
	default:
		for _, v := range p.Children() {
			if v.Tag != k.UniqueIdentifier && !(op == k.OpGetAttributes && v.Tag == k.AttributeName) {
				return fail(5, "unsupported operation parameter")
			}
		}
		id := p.Find(k.UniqueIdentifier).Text()
		o, e := kmipObjectLoad(ctx, s, prefix, id)
		if e != nil {
			return fail(1, "object not found")
		}
		out = append(out, k.T(k.UniqueIdentifier, id))
		switch op {
		case k.OpGet:
			if o.State == 5 {
				return fail(11, "object is destroyed")
			}
			out = append([]k.Node{k.E(k.ObjectType, 2)}, out...)
			out = append(out, k.S(k.SymmetricKey, k.S(k.KeyBlock, k.E(k.KeyFormatType, 1), k.S(k.KeyValue, k.B(k.KeyMaterial, o.Material)), k.E(k.CryptographicAlgorithm, o.Algorithm), k.I(k.CryptographicLength, o.Bits))))
		case k.OpActivate:
			if o.State != 1 {
				return fail(11, "only Pre-Active objects can be activated")
			}
			o.State = 2
			o.Activation = time.Now().Unix()
			if e := kmipObjectSave(ctx, s, prefix, o); e != nil {
				return fail(0x100, "object storage failed")
			}
		case k.OpDestroy:
			if o.State != 1 {
				return fail(11, "only Pre-Active objects can be destroyed in this subset")
			}
			o.Material = nil
			o.State = 5
			if e := kmipObjectSave(ctx, s, prefix, o); e != nil {
				return fail(0x100, "object storage failed")
			}
		case k.OpRekey:
			if o.State == 5 {
				return fail(11, "object is destroyed")
			}
			if e := kmipNewObject(ctx, s, prefix, o); e != nil {
				return fail(0x100, "object storage failed")
			}
			out = []k.Node{k.T(k.UniqueIdentifier, o.ID)}
		case k.OpGetAttributeList:
			for _, a := range kmipAttributes(o) {
				out = append(out, k.T(k.AttributeName, kmipAttributeName(a.Tag)))
			}
		case k.OpGetAttributes:
			wanted := map[string]bool{}
			for _, v := range p.Children() {
				if v.Tag == k.AttributeName {
					if v.Type != k.TextString {
						return fail(4, "invalid attribute name")
					}
					wanted[v.Text()] = true
				}
			}
			all := len(wanted) == 0
			for _, a := range kmipAttributes(o) {
				name := kmipAttributeName(a.Tag)
				if all || wanted[name] {
					a.Tag = k.AttributeValue
					out = append(out, k.S(k.Attribute, k.T(k.AttributeName, name), a))
					delete(wanted, name)
				}
			}
			if len(wanted) > 0 {
				return fail(1, "attribute not found")
			}
		default:
			return fail(5, fmt.Sprintf("unsupported operation %x", op))
		}
	}
	return k.S(k.ResponsePayload, out...), 0, nil
}
