// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"
)

type Handler func(context.Context, *x509.Certificate, Node) Node

// Server owns its listener and all accepted connections. Close waits for handlers.
type Server struct {
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	wg          sync.WaitGroup
	cancel      context.CancelFunc
}

func Listen(address string, config *tls.Config, handler Handler) (*Server, error) {
	if config == nil || config.ClientCAs == nil || len(config.Certificates) == 0 || handler == nil {
		return nil, errors.New("KMIP requires server certificate, client CA and handler")
	}
	config = config.Clone()
	config.ClientAuth = tls.RequireAndVerifyClientCert
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
	}
	l, e := tls.Listen("tcp", address, config)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{listener: l, connections: map[net.Conn]struct{}{}, cancel: cancel}
	s.wg.Add(1)
	go s.serve(ctx, handler)
	return s, nil
}
func (s *Server) Addr() net.Addr { return s.listener.Addr() }
func (s *Server) serve(ctx context.Context, h Handler) {
	defer s.wg.Done()
	for {
		c, e := s.listener.Accept()
		if e != nil {
			return
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= 128 {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.connections[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.connection(ctx, c, h)
	}
}
func (s *Server) connection(ctx context.Context, c net.Conn, h Handler) {
	defer s.wg.Done()
	defer func() { _ = c.Close(); s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	conn := c.(*tls.Conn)
	if conn.HandshakeContext(ctx) != nil {
		return
	}
	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	for {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		n, e := Read(c)
		if e != nil {
			return
		}
		response := h(ctx, cert, n)
		b, e := Marshal(response)
		if e != nil {
			return
		}
		for len(b) > 0 {
			n, e := c.Write(b)
			if e != nil || n == 0 {
				return
			}
			b = b[n:]
		}
	}
}
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	e := s.listener.Close()
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return e
}
