// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

type kmipFixture struct {
	b      *kmipBackend
	s      *logical.InmemStorage
	cert   *x509.Certificate
	config *tls.Config
	ctx    context.Context
	call   func(logical.Operation, string, map[string]interface{}) *logical.Response
}

func newKMIPFixture(t *testing.T, keyType string) *kmipFixture {
	t.Helper()
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	backend, e := KMIPBackendFactory(ctx, logical.TestBackendConfig())
	if e != nil {
		t.Fatal(e)
	}
	b := backend.(*kmipBackend)
	t.Cleanup(func() { b.Cleanup(ctx) })
	f := &kmipFixture{b: b, s: storage, ctx: ctx}
	f.call = func(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
		t.Helper()
		r, e := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Data: data, Storage: storage})
		if e != nil {
			t.Fatal(e)
		}
		if r.IsError() {
			t.Fatal(r.Error())
		}
		return r
	}
	f.call(logical.UpdateOperation, "ca/root/generate", map[string]interface{}{"key_type": "ec", "key_bits": 256})
	f.call(logical.UpdateOperation, "scope/s", nil)
	bits := 256
	if keyType == "rsa" {
		bits = 2048
	}
	f.call(logical.UpdateOperation, "scope/s/role/r", map[string]interface{}{"ca": "root", "operation_all": true, "tls_client_key_type": keyType, "tls_client_key_bits": bits})
	r := f.call(logical.UpdateOperation, "scope/s/role/r/credential/generate", map[string]interface{}{"format": "pem"})
	cert, e := tls.X509KeyPair([]byte(r.Data["certificate"].(string)), []byte(r.Data["private_key"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	f.cert, e = x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	root := f.call(logical.ReadOperation, "ca/root", nil)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(root.Data["certificate"].(string))) {
		t.Fatal("CA")
	}
	f.config = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}
	return f
}
func kmipRequest(op uint32, children ...k.Node) k.Node {
	return k.S(k.RequestMessage, k.S(k.RequestHeader, kmipVersion(), k.I(k.BatchCount, 1)), k.S(k.BatchItem, k.E(k.Operation, op), k.S(k.RequestPayload, children...)))
}
func kmipCreateRequest() k.Node {
	return kmipRequest(k.OpCreate, k.E(k.ObjectType, 2), k.S(k.TemplateAttribute, k.S(k.Attribute, k.T(k.AttributeName, "Cryptographic Algorithm"), k.E(k.AttributeValue, 3)), k.S(k.Attribute, k.T(k.AttributeName, "Cryptographic Length"), k.I(k.AttributeValue, 256))))
}
func kmipResult(t *testing.T, n k.Node, success bool) k.Node {
	t.Helper()
	item := n.Find(k.BatchItem)
	if (item.Find(k.ResultStatus).Number() == 0) != success {
		t.Fatalf("unexpected result %#v", item)
	}
	return item.Find(k.ResponsePayload)
}
func TestKMIPNativeTLS(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	f.call(logical.UpdateOperation, "listener/native", map[string]interface{}{"ca": "root", "address": "127.0.0.1:0"})
	f.b.listeners.mu.Lock()
	addr := f.b.listeners.servers["native"].Addr().String()
	f.b.listeners.mu.Unlock()
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	exchange := func(request k.Node) k.Node {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b, e := k.Marshal(request)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = conn.Write(b); e != nil {
			t.Fatal(e)
		}
		n, e := k.Read(conn)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	response := kmipResult(t, exchange(kmipRequest(k.OpDiscoverVersions)), true)
	if len(response.Children()) != 2 || response.Children()[0].Find(k.ProtocolVersionMajor).Number() != 2 || response.Children()[1].Find(k.ProtocolVersionMinor).Number() != 4 {
		t.Fatal(response)
	}
	response20 := exchange(kmipDRequest(true, k.OpQuery, k.E(k.QueryFunction, 13)))
	if response20.Find(k.ResponseHeader).Find(k.ProtocolVersion).Find(k.ProtocolVersionMajor).Number() != 2 || kmipResult(t, response20, true).Find(k.DefaultsInformation).Type != k.Structure {
		t.Fatal(response20)
	}
	response = kmipResult(t, exchange(kmipCreateRequest()), true)
	id := response.Find(k.UniqueIdentifier).Text()
	if id == "" {
		t.Fatal("missing identifier")
	}
	response = kmipResult(t, exchange(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id))), true)
	material := response.Find(k.SymmetricKey).Find(k.KeyBlock).Find(k.KeyValue).Find(k.KeyMaterial).Value.([]byte)
	if len(material) != 32 || bytes.Equal(material, make([]byte, 32)) {
		t.Fatal("bad AES material")
	}
	kmipResult(t, exchange(kmipRequest(k.OpDestroy, k.T(k.UniqueIdentifier, id))), true)
	kmipResult(t, exchange(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id))), false)
	// Revoke immediately, including the live session.
	f.call(logical.UpdateOperation, "scope/s/role/r/credential/revoke", map[string]interface{}{"serial_number": kmipSerial(f.cert)})
	kmipResult(t, exchange(kmipRequest(k.OpDiscoverVersions)), false)
	// Require a client certificate: TLS 1.3 may report failure on first read.
	unauthed := f.config.Clone()
	unauthed.Certificates = nil
	bad, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, unauthed)
	if e == nil {
		defer bad.Close()
		_ = bad.SetDeadline(time.Now().Add(3 * time.Second))
		b, _ := k.Marshal(kmipRequest(k.OpDiscoverVersions))
		_, _ = bad.Write(b)
		if _, e = k.Read(bad); e == nil {
			t.Fatal("accepted unauthenticated client")
		}
	}
	f.call(logical.DeleteOperation, "listener/native", nil)
	if c, e := net.DialTimeout("tcp", addr, time.Second); e == nil {
		c.Close()
		t.Fatal("listener not stopped")
	}
}
func TestKMIPOperations(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	dispatch := func(n k.Node, ok bool) k.Node { return kmipResult(t, f.b.kmipDispatch(f.ctx, f.s, f.cert, n), ok) }
	dispatch(kmipRequest(k.OpQuery, k.E(k.QueryFunction, 1), k.E(k.QueryFunction, 2)), true)
	dispatch(kmipRequest(k.OpQuery, k.E(k.QueryFunction, 99)), false)
	dispatch(kmipRequest(k.OpCreateKeyPair), false)
	id := dispatch(kmipCreateRequest(), true).Find(k.UniqueIdentifier).Text()
	dispatch(kmipRequest(k.OpGetAttributes, k.T(k.UniqueIdentifier, id)), true)
	list := dispatch(kmipRequest(k.OpGetAttributeList, k.T(k.UniqueIdentifier, id)), true)
	if len(list.Children()) != 7 {
		t.Fatal(list)
	}
	dispatch(kmipRequest(k.OpGetAttributes, k.T(k.UniqueIdentifier, id), k.T(k.AttributeName, "unsupported")), false)
	dispatch(kmipRequest(k.OpActivate, k.T(k.UniqueIdentifier, id)), true)
	dispatch(kmipRequest(k.OpActivate, k.T(k.UniqueIdentifier, id)), false)
	dispatch(kmipRequest(k.OpDestroy, k.T(k.UniqueIdentifier, id)), false)
	result := dispatch(kmipRequest(k.OpLocate, k.S(k.Attribute, k.T(k.AttributeName, "State"), k.E(k.AttributeValue, 2))), true)
	if result.Find(k.UniqueIdentifier).Text() != id {
		t.Fatal(result)
	}
	replacement := dispatch(kmipRequest(k.OpRekey, k.T(k.UniqueIdentifier, id)), true).Find(k.UniqueIdentifier).Text()
	if replacement == id {
		t.Fatal("Rekey reused identifier")
	}
	old, _ := kmipObjectLoad(f.ctx, f.s, "scope/s/role/r/objects/", id)
	fresh, _ := kmipObjectLoad(f.ctx, f.s, "scope/s/role/r/objects/", replacement)
	if bytes.Equal(old.Material, fresh.Material) {
		t.Fatal("Rekey reused material")
	}
	f.call(logical.UpdateOperation, "scope/s/role/other", map[string]interface{}{"operation_all": true})
	if _, _, e := kmipExecute(f.ctx, f.s, "scope/s/role/other", k.OpGet, k.S(k.RequestPayload, k.T(k.UniqueIdentifier, id))); e == nil {
		t.Fatal("cross-role object exposure")
	}
	f.call(logical.UpdateOperation, "scope/s/role/r", map[string]interface{}{"operation_none": true})
	dispatch(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id)), false)
}
func TestKMIPSigning(t *testing.T) {
	for _, typ := range []string{"ec", "rsa"} {
		t.Run(typ, func(t *testing.T) {
			f := newKMIPFixture(t, typ)
			data := []byte("KMIP signing test")
			response := kmipResult(t, f.b.kmipDispatch(f.ctx, f.s, f.cert, kmipRequest(k.OpSign, k.T(k.UniqueIdentifier, kmipSerial(f.cert)), k.B(k.Data, data))), true)
			signature := response.Find(k.SignatureData).Value.([]byte)
			digest := sha256.Sum256(data)
			switch pub := f.cert.PublicKey.(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pub, digest[:], signature) {
					t.Fatal("ECDSA signature invalid")
				}
			case *rsa.PublicKey:
				if e := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); e != nil {
					t.Fatal(e)
				}
			}
			r := f.call(logical.ReadOperation, "scope/s/role/r/credential/lookup", map[string]interface{}{"serial_number": kmipSerial(f.cert)})
			if _, ok := r.Data["private_key"]; ok {
				t.Fatal("lookup exposed key")
			}
		})
	}
}
func TestKMIPConcurrentLifecycle(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	f.call(logical.UpdateOperation, "listener/native", map[string]interface{}{"ca": "root", "address": "127.0.0.1:0"})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := f.b.kmipReconcile(f.ctx, f.s); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	f.b.listeners.mu.Lock()
	if len(f.b.listeners.servers) != 1 {
		t.Fatal("duplicate listener")
	}
	f.b.listeners.mu.Unlock()
	f.b.Cleanup(f.ctx)
}
