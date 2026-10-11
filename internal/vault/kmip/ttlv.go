// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

// Package kmip implements the bounded KMIP 1.4 TTLV wire format.
package kmip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

type Type byte

const (
	Structure   Type = 1
	Integer     Type = 2
	LongInteger Type = 3
	BigInteger  Type = 4
	Enumeration Type = 5
	Boolean     Type = 6
	TextString  Type = 7
	ByteString  Type = 8
	DateTime    Type = 9
	Interval    Type = 10
)
const MaxMessage = 4 << 20
const maxDepth = 32

// Value is []Node for Structure, int32 for Integer, int64 for LongInteger
// and DateTime, uint32 for Enumeration/Interval, bool for Boolean, string for
// TextString, and []byte for ByteString/BigInteger. BigInteger holds signed
// two's-complement bytes in multiples of eight, preserving sign extension.
type Node struct {
	Tag   uint32
	Type  Type
	Value interface{}
}

func S(tag uint32, children ...Node) Node { return Node{tag, Structure, children} }
func I(tag uint32, value int32) Node      { return Node{tag, Integer, value} }
func E(tag uint32, value uint32) Node     { return Node{tag, Enumeration, value} }
func T(tag uint32, value string) Node     { return Node{tag, TextString, value} }
func B(tag uint32, value []byte) Node     { return Node{tag, ByteString, value} }
func (n Node) Children() []Node           { v, _ := n.Value.([]Node); return v }
func (n Node) Find(tag uint32) Node {
	for _, v := range n.Children() {
		if v.Tag == tag {
			return v
		}
	}
	return Node{}
}
func (n Node) Text() string { v, _ := n.Value.(string); return v }
func (n Node) Number() uint32 {
	switch v := n.Value.(type) {
	case uint32:
		return v
	case int32:
		return uint32(v)
	}
	return 0
}
func Marshal(n Node) ([]byte, error) { return marshal(n, 0) }
func marshal(n Node, depth int) ([]byte, error) {
	if depth > maxDepth || n.Tag > 0xffffff {
		return nil, errors.New("invalid TTLV tag or nesting")
	}
	var value []byte
	switch n.Type {
	case Structure:
		c, ok := n.Value.([]Node)
		if !ok {
			return nil, errors.New("invalid structure")
		}
		for _, v := range c {
			b, e := marshal(v, depth+1)
			if e != nil {
				return nil, e
			}
			if len(value)+len(b) > MaxMessage {
				return nil, errors.New("TTLV too large")
			}
			value = append(value, b...)
		}
	case Integer:
		v, ok := n.Value.(int32)
		if !ok {
			return nil, errors.New("invalid integer")
		}
		value = binary.BigEndian.AppendUint32(nil, uint32(v))
	case Enumeration, Interval:
		v, ok := n.Value.(uint32)
		if !ok {
			return nil, errors.New("invalid enumeration/interval")
		}
		value = binary.BigEndian.AppendUint32(nil, v)
	case LongInteger, DateTime:
		v, ok := n.Value.(int64)
		if !ok {
			return nil, errors.New("invalid long/date")
		}
		value = binary.BigEndian.AppendUint64(nil, uint64(v))
	case Boolean:
		v, ok := n.Value.(bool)
		if !ok {
			return nil, errors.New("invalid boolean")
		}
		value = make([]byte, 8)
		if v {
			value[7] = 1
		}
	case TextString:
		v, ok := n.Value.(string)
		if !ok || !utf8.ValidString(v) {
			return nil, errors.New("invalid text")
		}
		value = []byte(v)
	case ByteString, BigInteger:
		v, ok := n.Value.([]byte)
		if !ok {
			return nil, errors.New("invalid bytes")
		}
		if n.Type == BigInteger && (len(v) == 0 || len(v)%8 != 0) {
			return nil, errors.New("invalid big integer")
		}
		value = v
	default:
		return nil, fmt.Errorf("unsupported TTLV type %x", n.Type)
	}
	if len(value) > MaxMessage-8 {
		return nil, errors.New("TTLV too large")
	}
	out := make([]byte, 8+(len(value)+7)&^7)
	out[0] = byte(n.Tag >> 16)
	out[1] = byte(n.Tag >> 8)
	out[2] = byte(n.Tag)
	out[3] = byte(n.Type)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out, nil
}
func Unmarshal(data []byte) (Node, error) {
	r := bytes.NewReader(data)
	n, e := decode(r, 0)
	if e == nil && r.Len() != 0 {
		e = errors.New("trailing TTLV data")
	}
	return n, e
}

// Read reads one framed TTLV message; size is checked before allocation.
func Read(r io.Reader) (Node, error) { return decode(r, 0) }
func decode(r io.Reader, depth int) (Node, error) {
	var n Node
	if depth > maxDepth {
		return n, errors.New("TTLV nesting limit")
	}
	h := make([]byte, 8)
	if _, e := io.ReadFull(r, h); e != nil {
		return n, e
	}
	n.Tag = uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])
	n.Type = Type(h[3])
	length := uint64(binary.BigEndian.Uint32(h[4:]))
	if length > MaxMessage-8 {
		return n, errors.New("TTLV size limit")
	}
	b := make([]byte, (length+7)&^7)
	if _, e := io.ReadFull(r, b); e != nil {
		return n, e
	}
	for _, v := range b[length:] {
		if v != 0 {
			return n, errors.New("nonzero TTLV padding")
		}
	}
	b = b[:length]
	switch n.Type {
	case Structure:
		if length%8 != 0 {
			return n, errors.New("unaligned structure")
		}
		c := []Node{}
		reader := bytes.NewReader(b)
		for reader.Len() > 0 {
			v, e := decode(reader, depth+1)
			if e != nil {
				return n, e
			}
			c = append(c, v)
		}
		n.Value = c
	case Integer, Enumeration, Interval:
		if length != 4 {
			return n, errors.New("invalid 32-bit length")
		}
		v := binary.BigEndian.Uint32(b)
		if n.Type == Integer {
			n.Value = int32(v)
		} else {
			n.Value = v
		}
	case LongInteger, DateTime, Boolean:
		if length != 8 {
			return n, errors.New("invalid 64-bit length")
		}
		v := binary.BigEndian.Uint64(b)
		if n.Type == Boolean {
			if v > 1 {
				return n, errors.New("invalid boolean")
			}
			n.Value = v == 1
		} else {
			n.Value = int64(v)
		}
	case TextString:
		if !utf8.Valid(b) {
			return n, errors.New("invalid UTF-8")
		}
		n.Value = string(b)
	case ByteString, BigInteger:
		if n.Type == BigInteger && (length == 0 || length%8 != 0) {
			return n, errors.New("invalid big integer length")
		}
		n.Value = b
	default:
		return n, fmt.Errorf("unsupported TTLV type %x", n.Type)
	}
	return n, nil
}
