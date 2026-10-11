// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func kmipPrivateKey(typ string, bits int) (crypto.Signer, error) {
	if !kmipKeyValid(typ, bits) {
		return nil, fmt.Errorf("invalid key type or size")
	}
	if typ == "rsa" {
		return rsa.GenerateKey(rand.Reader, bits)
	}
	curves := map[int]elliptic.Curve{224: elliptic.P224(), 256: elliptic.P256(), 384: elliptic.P384(), 521: elliptic.P521()}
	return ecdsa.GenerateKey(curves[bits], rand.Reader)
}
func kmipParseCert(text string) (*x509.Certificate, error) {
	p, _ := pem.Decode([]byte(text))
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected PEM certificate")
	}
	return x509.ParseCertificate(p.Bytes)
}
func kmipSerial(c *x509.Certificate) string {
	h := fmt.Sprintf("%x", c.SerialNumber)
	if len(h)%2 != 0 {
		h = "0" + h
	}
	a := []string{}
	for i := 0; i < len(h); i += 2 {
		a = append(a, h[i:i+2])
	}
	return strings.Join(a, ":")
}
func kmipTemplate(subject pkix.Name, ttl int, ca bool) (*x509.Certificate, error) {
	if ttl <= 0 || ttl > 315360000 {
		return nil, fmt.Errorf("TTL must be positive and no greater than ten years")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	t := &x509.Certificate{SerialNumber: serial, Subject: subject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Duration(ttl) * time.Second), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		t.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	return t, nil
}
func kmipIssue(t, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (map[string]interface{}, error) {
	der, err := x509.CreateCertificate(rand.Reader, t, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return map[string]interface{}{"certificate": text, "serial_number": kmipSerial(cert), "ca_chain": []string{}}, nil
}
func kmipEncodeKey(k crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
func (b *kmipBackend) caWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	name := d.Get("name").(string)
	path := "ca/" + name
	existing, err := kmipLoad(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("CA already exists; delete it before replacing it"), nil
	}
	data := map[string]interface{}{}
	if d.Get("action").(string) == "import" {
		data = kmipFields(d, "scope_name scope_field role_name role_field")
		if err := kmipSelectors(data); err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		text := d.Get("ca_pem").(string)
		c, err := kmipParseCert(text)
		if err != nil || !c.IsCA {
			return logical.ErrorResponse("ca_pem must contain a CA certificate"), nil
		}
		data["certificate"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		data["ca_chain"] = []string{data["certificate"].(string)}
		data["serial_number"] = kmipSerial(c)
		data["imported"] = true
	} else {
		typ, bits := d.Get("key_type").(string), d.Get("key_bits").(int)
		if !kmipKeyValid(typ, bits) {
			return logical.ErrorResponse("key_type and valid key_bits are required"), nil
		}
		ttl := 31536000
		if _, ok := d.Raw["ttl"]; ok {
			ttl = d.Get("ttl").(int)
		}
		t, err := kmipTemplate(pkix.Name{CommonName: name}, ttl, true)
		if err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		k, err := kmipPrivateKey(typ, bits)
		if err != nil {
			return nil, err
		}
		data, err = kmipIssue(t, t, k.Public(), k)
		if err != nil {
			return nil, err
		}
		key, err := kmipEncodeKey(k)
		if err != nil {
			return nil, err
		}
		data["private_key"] = key
		data["ca_chain"] = []string{data["certificate"].(string)}
		data["key_type"] = typ
		data["key_bits"] = bits
		data["imported"] = false
	}
	if err := kmipSave(ctx, req.Storage, path, data); err != nil {
		return nil, err
	}
	return &logical.Response{Data: kmipPublic(data)}, nil
}
func kmipFormat(data map[string]interface{}, format string) map[string]interface{} {
	out := kmipPublic(data)
	if key, ok := data["private_key"]; ok {
		out["private_key"] = key
	}
	if format == "der" {
		for _, k := range []string{"certificate", "private_key"} {
			if p, _ := pem.Decode([]byte(kmipString(out, k))); p != nil {
				out[k] = base64.StdEncoding.EncodeToString(p.Bytes)
			}
		}
	} else if format == "pem_bundle" {
		bundle := kmipString(out, "private_key") + kmipString(out, "certificate")
		if a, ok := out["ca_chain"].([]string); ok {
			for _, v := range a {
				bundle += v
			}
		} else if a, ok := out["ca_chain"].([]interface{}); ok {
			for _, v := range a {
				bundle += v.(string)
			}
		}
		out["certificate"] = bundle
	}
	return out
}
func (b *kmipBackend) credential(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rolePath := "scope/" + d.Get("scope").(string) + "/role/" + d.Get("role").(string)
	role, err := kmipLoad(ctx, req.Storage, rolePath)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role does not exist"), nil
	}
	prefix := rolePath + "/credential"
	if req.Operation == logical.ListOperation {
		return kmipList(ctx, req.Storage, prefix)
	}
	action := d.Get("action").(string)
	format := d.Get("format").(string)
	if format == "" {
		format = "pem_bundle"
	}
	if format != "pem" && format != "pem_bundle" && format != "der" {
		return logical.ErrorResponse("invalid credential format"), nil
	}
	serial := d.Get("serial_number").(string)
	if action == "lookup" || action == "revoke" {
		if action == "revoke" {
			text := d.Get("certificate").(string)
			if (serial == "") == (text == "") {
				return logical.ErrorResponse("exactly one of serial_number or certificate is required"), nil
			}
			if text != "" {
				c, err := kmipParseCert(text)
				if err != nil {
					return logical.ErrorResponse("%s", err), nil
				}
				serial = kmipSerial(c)
			}
		}
		if serial == "" || strings.ContainsAny(serial, "/\\") || serial == "." || serial == ".." {
			return logical.ErrorResponse("valid serial_number is required"), nil
		}
		key := prefix + "/" + serial
		if action == "revoke" {
			return nil, kmipRemove(ctx, req.Storage, key+"/")
		}
		data, err := kmipLoad(ctx, req.Storage, key)
		if err != nil || data == nil {
			return nil, err
		}
		return &logical.Response{Data: kmipFormat(data, format)}, nil
	}
	typ := kmipString(role, "tls_client_key_type")
	if typ == "" {
		typ = "ec"
	}
	bits := kmipInt(role, "tls_client_key_bits", 0)
	if bits == 0 {
		if typ == "rsa" {
			bits = 2048
		} else {
			bits = 521
		}
	}
	ttl := kmipInt(role, "tls_client_ttl", 86400)
	t, err := kmipTemplate(pkix.Name{CommonName: d.Get("role").(string), OrganizationalUnit: []string{d.Get("scope").(string)}}, ttl, false)
	if err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	var key crypto.Signer
	var pub crypto.PublicKey
	if action == "sign" {
		p, _ := pem.Decode([]byte(d.Get("csr").(string)))
		if p == nil {
			return logical.ErrorResponse("PEM csr is required"), nil
		}
		csr, err := x509.ParseCertificateRequest(p.Bytes)
		if err != nil {
			return logical.ErrorResponse("invalid CSR"), nil
		}
		if err := csr.CheckSignature(); err != nil {
			return logical.ErrorResponse("invalid CSR signature"), nil
		}
		valid := false
		switch k := csr.PublicKey.(type) {
		case *rsa.PublicKey:
			valid = typ == "rsa" && k.N.BitLen() == bits
		case *ecdsa.PublicKey:
			valid = typ == "ec" && k.Curve.Params().BitSize == bits
		}
		if !valid {
			return logical.ErrorResponse("CSR key must match role type and size"), nil
		}
		pub = csr.PublicKey
	} else {
		key, err = kmipPrivateKey(typ, bits)
		if err != nil {
			return nil, err
		}
		pub = key.Public()
	}
	parent := t
	signer := key
	chain := []string{}
	warnings := []string{}
	if name := kmipString(role, "ca"); name != "" {
		ca, err := kmipLoad(ctx, req.Storage, "ca/"+name)
		if err != nil {
			return nil, err
		}
		if ca == nil || ca["imported"] == true {
			return logical.ErrorResponse("credential issuance requires a generated CA"), nil
		}
		parent, err = kmipParseCert(kmipString(ca, "certificate"))
		if err != nil {
			return nil, err
		}
		p, _ := pem.Decode([]byte(kmipString(ca, "private_key")))
		if p == nil {
			return nil, fmt.Errorf("stored CA key is invalid")
		}
		k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		signer, ok = k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("stored CA key cannot sign")
		}
		chain = []string{kmipString(ca, "certificate")}
		if t.NotAfter.After(parent.NotAfter) {
			t.NotAfter = parent.NotAfter
		}
		if !t.NotAfter.After(time.Now()) {
			return logical.ErrorResponse("CA has expired"), nil
		}
	} else {
		if action == "sign" {
			return logical.ErrorResponse("signing requires a generated CA selected on the role"), nil
		}
		warnings = append(warnings, "No CA selected: generated a self-signed credential for the HTTP-only implementation; native KMIP is not available.")
	}
	data, err := kmipIssue(t, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	data["ca_chain"] = chain
	if err := kmipSave(ctx, req.Storage, prefix+"/"+kmipString(data, "serial_number"), data); err != nil {
		return nil, err
	}
	if key != nil {
		encoded, err := kmipEncodeKey(key)
		if err != nil {
			return nil, err
		}
		// Keep signing material separate from credential metadata: lookup never
		// returns it, while revocation recursively removes both records.
		if err := req.Storage.Put(ctx, &logical.StorageEntry{Key: prefix + "/" + kmipString(data, "serial_number") + "/signing-key", Value: []byte(encoded)}); err != nil {
			_ = kmipRemove(ctx, req.Storage, prefix+"/"+kmipString(data, "serial_number")+"/")
			return nil, err
		}
		data["private_key"] = encoded
	}
	return &logical.Response{Data: kmipFormat(data, format), Warnings: warnings}, nil
}
