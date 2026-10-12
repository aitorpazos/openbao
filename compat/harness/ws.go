// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Minimal RFC 6455 WebSocket client, sufficient for subscribing to Vault's
// /v1/sys/events/subscribe endpoint: one HTTP upgrade, then unidirectional
// server-to-client text/binary frames with pong replies and close handling.
// No compression extension is negotiated.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
}

// wsDial performs the RFC 6455 opening handshake against the given
// subscription URL (http(s)://host/v1/sys/events/subscribe/<type>?...).
// It returns the upgrade response (also on non-101 rejections) so callers
// can inspect status codes, plus the established connection when the
// upgrade succeeded.
func wsDial(rawURL, token string, extraHeaders map[string]string, timeout time.Duration) (*http.Response, *wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	hostPort := u.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		if u.Scheme == "https" {
			hostPort = net.JoinHostPort(hostPort, "443")
		} else {
			hostPort = net.JoinHostPort(hostPort, "80")
		}
	}
	var conn net.Conn
	if u.Scheme == "https" {
		d := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(d, "tcp", hostPort, &tls.Config{ServerName: u.Hostname()})
	} else {
		conn, err = net.DialTimeout("tcp", hostPort, timeout)
	}
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := u.RequestURI()
	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   u.Host,
		Header: http.Header{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-WebSocket-Key":     {key},
			"Sec-WebSocket-Version": {"13"},
		},
		RequestURI: path,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Rejection before the upgrade; hand the response back for status
		// inspection and close the connection.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		conn.Close()
		return resp, nil, nil
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		resp.Body.Close()
		conn.Close()
		return resp, nil, fmt.Errorf("invalid Sec-WebSocket-Accept")
	}
	// The upgrade succeeded; streaming sockets have no deadline beyond the
	// caller-driven read timeouts.
	conn.SetDeadline(time.Time{})
	return resp, &wsConn{conn: conn, br: br}, nil
}

func acceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// readMessage returns one complete message payload. Server frames are
// unmasked per RFC 6455. Control frames (ping/close) are handled here; a
// close returns an error wrapping the close status.
func (c *wsConn) readMessage(deadline time.Time) (byte, []byte, error) {
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case 0x1, 0x2: // text, binary
			return opcode, payload, nil
		case 0x8: // close
			status := 1000
			if len(payload) >= 2 {
				status = int(binary.BigEndian.Uint16(payload))
			}
			_ = c.writeFrame(0x8, payload)
			return 0x8, payload, fmt.Errorf("connection closed by server (status %d)", status)
		case 0x9: // ping -> pong
			if err := c.writeFrame(0xA, payload); err != nil {
				return 0, nil, err
			}
		case 0xA: // unsolicited pong
			continue
		default:
			return 0, nil, fmt.Errorf("unexpected opcode %d", opcode)
		}
	}
}

func (c *wsConn) readFrame() (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[0]&0x70 != 0 {
		return 0, nil, errors.New("reserved bits set (compression not negotiated)")
	}
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if masked {
		return 0, nil, errors.New("server frames must not be masked")
	}
	if length > 32<<20 {
		return 0, nil, fmt.Errorf("frame too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return err
	}
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)|0x80)
	case n <= 0xFFFF:
		hdr = append(hdr, 126|0x80)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		hdr = append(hdr, ext[:]...)
	default:
		hdr = append(hdr, 127|0x80)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	hdr = append(hdr, maskKey[:]...)
	for i := range payload {
		payload[i] ^= maskKey[i%4]
	}
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.conn.Write(append(hdr, payload...))
	return err
}

func (c *wsConn) close() {
	_ = c.writeFrame(0x8, []byte{0x03, 0xE8}) // 1000 normal closure
	c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	c.conn.Close()
}

// wsSubscription holds one established subscription with an event channel.
type wsSubscription struct {
	conn     *wsConn
	events   chan wsEvent
	errs     chan error
	close    func()
	eventCap int
}

type wsEvent struct {
	opcode  byte
	payload []byte
}

// startWSReader pumps messages into a buffered channel until the deadline
// or an error occurs. The connection is closed when the returned cancel
// func is called.
func (c *wsConn) pump(deadline time.Time) *wsSubscription {
	sub := &wsSubscription{
		events:   make(chan wsEvent, 256),
		errs:     make(chan error, 1),
		eventCap: 256,
	}
	done := make(chan struct{})
	sub.close = func() {
		close(done)
		c.close()
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				select {
				case sub.errs <- fmt.Errorf("reader panic: %v", r):
				default:
				}
			}
		}()
		for {
			opcode, payload, err := c.readMessage(deadline)
			if err != nil {
				select {
				case sub.errs <- err:
				default:
				}
				if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") {
					return
				}
				// Timeout expiry is a normal end-of-window condition; the
				// connection stays open for later cleanup.
				if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
					return
				}
				return
			}
			select {
			case sub.events <- wsEvent{opcode: opcode, payload: payload}:
			case <-done:
				return
			}
		}
	}()
	return sub
}

// jsonExtractable reports whether the payload parses as a JSON object.
func jsonExtractable(payload []byte) bool {
	trimmed := bytes.TrimSpace(payload)
	return bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("["))
}
