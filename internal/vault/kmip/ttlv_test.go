// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestKMIPTTLV(t *testing.T) {
	nodes := []Node{I(CryptographicLength, -32), {Tag: ArchiveDate, Type: LongInteger, Value: int64(-2)}, {Tag: KeyMaterial, Type: BigInteger, Value: []byte{255, 255, 255, 255, 255, 255, 255, 254}}, E(Operation, OpCreate), {Tag: Data, Type: Boolean, Value: true}, T(AttributeName, "é AES"), B(OpaqueDataValue, []byte{1, 2, 3}), {Tag: ActivationDate, Type: DateTime, Value: int64(1234)}, {Tag: Data, Type: Interval, Value: uint32(100)}, S(OpaqueObject, B(OpaqueDataValue, []byte{})), S(TemplateAttribute, S(Attribute, T(AttributeName, "State"), E(AttributeValue, 1)))}
	for _, n := range nodes {
		encoded, e := Marshal(n)
		if e != nil {
			t.Fatal(e)
		}
		if len(encoded)%8 != 0 {
			t.Fatal("alignment")
		}
		decoded, e := Unmarshal(encoded)
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(n, decoded) {
			t.Fatalf("%#v != %#v", n, decoded)
		}
	}
	// Independent OASIS header vector: Structure is 0x01, not 0x0c.
	b, e := Marshal(S(RequestMessage, I(BatchCount, 1)))
	if e != nil {
		t.Fatal(e)
	}
	want, _ := hex.DecodeString("420078010000001042000d02000000040000000100000000")
	if !bytes.Equal(b, want) {
		t.Fatalf("wire: %x", b)
	}
	for size := 0; size < 24; size++ {
		n := B(Data, bytes.Repeat([]byte{3}, size))
		b, e := Marshal(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Unmarshal(b); e != nil {
			t.Fatal(e)
		}
		if size%8 != 0 {
			b[len(b)-1] = 1
			if _, e = Unmarshal(b); e == nil {
				t.Fatal("accepted nonzero padding")
			}
		}
	}
}
func TestKMIPTTLVReject(t *testing.T) {
	for _, text := range []string{"4200780100400001", "4200780c00000000", "42000d020000000000000000", "42000006000000080000000000000002", "420000040000000000000000", "4200000700000001ff00000000000000", "42000001000000080102030405060708"} {
		b, _ := hex.DecodeString(text)
		if _, e := Unmarshal(b); e == nil {
			t.Fatalf("accepted %s", text)
		}
	}
	n := B(Data, []byte{1})
	for i := 0; i < 40; i++ {
		n = S(RequestMessage, n)
	}
	if _, e := Marshal(n); e == nil {
		t.Fatal("nesting accepted")
	}
	b, _ := Marshal(T(Data, "test"))
	for i := 0; i < len(b); i++ {
		if _, e := Unmarshal(b[:i]); e == nil {
			t.Fatal("accepted truncation", i)
		}
	}
	if _, e := Unmarshal(append(b, 0)); e == nil {
		t.Fatal("accepted trailing data")
	}
}
func FuzzKMIPTTLV(f *testing.F) {
	b, _ := Marshal(S(RequestMessage, I(BatchCount, 1)))
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		n, e := Unmarshal(b)
		if e != nil {
			return
		}
		encoded, e := Marshal(n)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b, encoded) {
			t.Fatal("noncanonical accepted")
		}
	})
}
