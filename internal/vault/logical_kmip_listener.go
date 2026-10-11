// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

type kmipListeners struct {
	mu      sync.Mutex
	servers map[string]*k.Server
	configs map[string]string
	closed  bool
}

func kmipStrings(m map[string]interface{}, key string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case []interface{}:
		out := []string{}
		for _, s := range v {
			if text, ok := s.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}
func kmipListenerTLS(ctx context.Context, s logical.Storage, cfg map[string]interface{}) (*tls.Config, error) {
	ca, e := kmipLoad(ctx, s, "ca/"+kmipString(cfg, "ca"))
	if e != nil {
		return nil, e
	}
	if ca == nil {
		return nil, fmt.Errorf("listener CA missing")
	}
	parent, e := kmipParseCert(kmipString(ca, "certificate"))
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode([]byte(kmipString(ca, "private_key")))
	if block == nil {
		return nil, fmt.Errorf("listener CA key missing")
	}
	raw, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	signer, ok := raw.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("listener CA key cannot sign")
	}
	key, e := kmipPrivateKey("ec", 256)
	if e != nil {
		return nil, e
	}
	template, e := kmipTemplate(pkix.Name{CommonName: "OpenBao KMIP"}, 86400, false)
	if e != nil {
		return nil, e
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.DNSNames = kmipStrings(cfg, "server_hostnames")
	for _, text := range kmipStrings(cfg, "server_ips") {
		ip := net.ParseIP(text)
		if ip == nil {
			return nil, fmt.Errorf("invalid server IP")
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	if template.NotAfter.After(parent.NotAfter) {
		template.NotAfter = parent.NotAfter
	}
	der, e := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	pool.AddCert(parent)
	for _, name := range kmipStrings(cfg, "additional_client_cas") {
		m, e := kmipLoad(ctx, s, "ca/"+name)
		if e != nil {
			return nil, e
		}
		cert, e := kmipParseCert(kmipString(m, "certificate"))
		if e != nil {
			return nil, e
		}
		pool.AddCert(cert)
	}
	if cfg["also_use_legacy_ca"] == true {
		return nil, fmt.Errorf("legacy CA is unavailable")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{der, parent.Raw}, PrivateKey: key}}}
	if kmipString(cfg, "tls_min_version") == "tls13" {
		config.MinVersion = tls.VersionTLS13
	}
	switch kmipString(cfg, "tls_max_version") {
	case "tls12":
		config.MaxVersion = tls.VersionTLS12
	case "tls13":
		config.MaxVersion = tls.VersionTLS13
	}
	if kmipString(cfg, "tls_cipher_suites") != "" {
		return nil, fmt.Errorf("custom TLS cipher suites are not supported")
	}
	return config, nil
}
func (b *kmipBackend) kmipReconcile(ctx context.Context, s logical.Storage) error {
	if b.System().ReplicationState().HasState(consts.ReplicationDRSecondary | consts.ReplicationPerformanceStandby) {
		return nil
	}
	state := &b.listeners
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	if state.servers == nil {
		state.servers = map[string]*k.Server{}
		state.configs = map[string]string{}
	}
	names, e := s.List(ctx, "listener/")
	if e != nil {
		return e
	}
	wanted := map[string]bool{}
	for _, name := range names {
		if !strings.HasSuffix(name, "/") {
			continue
		}
		name = strings.TrimSuffix(name, "/")
		wanted[name] = true
		cfg, e := kmipLoad(ctx, s, "listener/"+name)
		if e != nil {
			return e
		}
		encoded, e := json.Marshal(cfg)
		if e != nil {
			return e
		}
		if state.configs[name] == string(encoded) {
			continue
		}
		tlsConfig, e := kmipListenerTLS(ctx, s, cfg)
		if e != nil {
			return e
		}
		if old := state.servers[name]; old != nil {
			_ = old.Close()
			delete(state.servers, name)
			delete(state.configs, name)
		}
		// Issue a fresh short-lived server leaf at each handshake; do not let
		// a long-running mount keep serving an expired startup certificate.
		tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return kmipListenerTLS(hello.Context(), s, cfg)
		}
		server, e := k.Listen(kmipString(cfg, "address"), tlsConfig, func(ctx context.Context, cert *x509.Certificate, n k.Node) k.Node {
			return b.kmipDispatch(ctx, s, cert, n)
		})
		if e != nil {
			return e
		}
		state.servers[name] = server
		state.configs[name] = string(encoded)
	}
	for name, server := range state.servers {
		if !wanted[name] {
			_ = server.Close()
			delete(state.servers, name)
			delete(state.configs, name)
		}
	}
	return nil
}
func (b *kmipBackend) kmipCleanup(context.Context) {
	state := &b.listeners
	state.mu.Lock()
	defer state.mu.Unlock()
	state.closed = true
	for name, server := range state.servers {
		_ = server.Close()
		delete(state.servers, name)
	}
}
func (b *kmipBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	response, e := b.Backend.HandleRequest(ctx, req)
	if e != nil || response.IsError() {
		return response, e
	}
	if e := b.kmipReconcile(ctx, req.Storage); e != nil {
		return nil, fmt.Errorf("KMIP listener configuration persisted but listener reconciliation failed: %w", e)
	}
	return response, nil
}
