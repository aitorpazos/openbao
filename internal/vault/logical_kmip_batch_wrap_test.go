// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

func kmipBatchRequest(control []k.Node, requests ...k.Node) k.Node {
	h := k.S(k.RequestHeader, append([]k.Node{kmipVersion(), k.I(k.BatchCount, int32(len(requests)))}, control...)...)
	nodes := []k.Node{h}
	for i, r := range requests {
		item := r.Find(k.BatchItem)
		item.Value = append(item.Children(), k.B(k.UniqueBatchItemID, []byte{byte(i)}))
		nodes = append(nodes, item)
	}
	return k.S(k.RequestMessage, nodes...)
}

func TestKMIPBatch(t *testing.T) {
	for _, mode := range []uint32{0, 1, 2} {
		t.Run(map[uint32]string{0: "DefaultContinue", 1: "Continue", 2: "Stop"}[mode], func(t *testing.T) {
			f := newKMIPFixture(t, "ec")
			run := func(n k.Node) k.Node { // Exercise actual framing in both directions.
				wire, err := k.Marshal(n)
				if err != nil {
					t.Fatal(err)
				}
				n, err = k.Read(bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				response := f.b.kmipDispatch(f.ctx, f.s, f.cert, n)
				wire, err = k.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				response, err = k.Read(bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				return response
			}
			id := kmipResult(t, run(kmipCreateRequest()), true).Find(k.UniqueIdentifier).Text()
			controls := []k.Node{}
			if mode != 0 {
				controls = append(controls, k.E(k.BatchErrorContinuationOption, mode))
			}
			// Independent Create plus Get/Destroy of an existing object: placeholders
			// intentionally remain outside this subset.
			response := run(kmipBatchRequest(controls, kmipCreateRequest(), kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id)), kmipRequest(k.OpDestroy, k.T(k.UniqueIdentifier, id))))
			if response.Find(k.ResponseHeader).Find(k.BatchCount).Number() != 3 {
				t.Fatal(response)
			}
			for i, item := range response.Children()[1:] {
				if item.Find(k.ResultStatus).Number() != 0 || !bytes.Equal(item.Find(k.UniqueBatchItemID).Value.([]byte), []byte{byte(i)}) {
					t.Fatal(item)
				}
			}
			response = run(kmipBatchRequest(controls, kmipCreateRequest(), kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id)), kmipCreateRequest()))
			want := 3
			if mode == 2 {
				want = 2
			}
			if len(response.Children()) != want+1 || response.Find(k.ResponseHeader).Find(k.BatchCount).Number() != uint32(want) {
				t.Fatal(response)
			}
			ids, err := f.s.List(f.ctx, "scope/s/role/r/objects/")
			if err != nil || len(ids) != want+1 {
				t.Fatalf("unexpected side effects: %v %v", ids, err)
			}
			for i, item := range response.Children()[1:] {
				failed := item.Find(k.ResultStatus).Number() != 0
				if failed != (i == 1) {
					t.Fatal(item)
				}
				if !bytes.Equal(item.Find(k.UniqueBatchItemID).Value.([]byte), []byte{byte(i)}) {
					t.Fatal("ID not echoed")
				}
			}
		})
	}
}

func TestKMIPBatchRejectControls(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	for _, control := range []k.Node{k.E(k.BatchErrorContinuationOption, 3), k.E(k.BatchErrorContinuationOption, 4), k.I(k.MaximumResponseSize, 100), {Tag: k.AsynchronousIndicator, Type: k.Boolean, Value: true}} {
		response := f.b.kmipDispatch(f.ctx, f.s, f.cert, kmipBatchRequest([]k.Node{control}, kmipCreateRequest(), kmipCreateRequest()))
		for _, item := range response.Children()[1:] {
			if item.Find(k.ResultStatus).Number() != 1 {
				t.Fatal(response)
			}
		}
	}
	ids, err := f.s.List(f.ctx, "scope/s/role/r/objects/")
	if err != nil || len(ids) != 0 {
		t.Fatalf("rejected requests had side effects: %v %v", ids, err)
	}
}

func TestKMIPWrappedGet(t *testing.T) {
	f := newKMIPFixture(t, "ec")
	run := func(n k.Node, ok bool) k.Node { return kmipResult(t, f.b.kmipDispatch(f.ctx, f.s, f.cert, n), ok) }
	id := run(kmipCreateRequest(), true).Find(k.UniqueIdentifier).Text()
	create := kmipCreateRequest().Find(k.BatchItem).Find(k.RequestPayload)
	attrs := create.Find(k.TemplateAttribute)
	attrs.Value = append(attrs.Children(), k.S(k.Attribute, k.T(k.AttributeName, "Cryptographic Usage Mask"), k.I(k.AttributeValue, 0x10)))
	kekID := run(kmipRequest(k.OpCreate, k.E(k.ObjectType, 2), attrs), true).Find(k.UniqueIdentifier).Text()
	run(kmipRequest(k.OpActivate, k.T(k.UniqueIdentifier, kekID)), true)
	plainRequest := kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id))
	before := run(plainRequest, true)
	plain := before.Find(k.SymmetricKey).Find(k.KeyBlock).Find(k.KeyValue).Find(k.KeyMaterial).Value.([]byte)
	kek := run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, kekID)), true).Find(k.SymmetricKey).Find(k.KeyBlock).Find(k.KeyValue).Find(k.KeyMaterial).Value.([]byte)
	spec := func(key string, enc uint32) k.Node {
		return k.S(k.KeyWrappingSpecification, k.E(k.WrappingMethod, 1), k.S(k.EncryptionKeyInformation, k.T(k.UniqueIdentifier, key), k.S(k.CryptographicParameters, k.E(k.BlockCipherMode, 0x0d))), k.E(k.EncodingOption, enc))
	}
	wrapped := run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec(kekID, 1)), true).Find(k.SymmetricKey).Find(k.KeyBlock)
	data := wrapped.Find(k.KeyWrappingData)
	if data.Find(k.EncryptionKeyInformation).Find(k.UniqueIdentifier).Text() != kekID || data.Find(k.EncodingOption).Number() != 1 || data.Find(k.WrappingMethod).Number() != 1 || data.Find(k.EncryptionKeyInformation).Find(k.CryptographicParameters).Find(k.BlockCipherMode).Number() != 0x0d {
		t.Fatal(data)
	}
	encrypted := wrapped.Find(k.KeyValue).Value.([]byte)
	if bytes.Equal(encrypted, plain) || !bytes.Equal(kmipTestUnwrap(t, kek, encrypted), plain) {
		t.Fatal("wrap round trip failed")
	}
	after := run(plainRequest, true)
	a, _ := k.Marshal(before)
	b, _ := k.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatal("Get mutated stored object or plain response")
	}
	run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec(id, 1)), false)
	run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec(kekID, 2)), false)
	run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec("00000000000000000000000000000000", 1)), false)
	invalid := []k.Node{
		k.S(k.KeyWrappingSpecification, spec(kekID, 1).Children()[:2]...), // absent encoding defaults to unsupported TTLV
		k.S(k.KeyWrappingSpecification, k.E(k.WrappingMethod, 2), spec(kekID, 1).Find(k.EncryptionKeyInformation), k.E(k.EncodingOption, 1)),
		k.S(k.KeyWrappingSpecification, append(spec(kekID, 1).Children(), k.E(k.EncodingOption, 1))...),
		k.S(k.KeyWrappingSpecification, k.E(k.WrappingMethod, 1), k.S(k.EncryptionKeyInformation, k.T(k.UniqueIdentifier, kekID), k.S(k.CryptographicParameters, k.E(k.BlockCipherMode, 1))), k.E(k.EncodingOption, 1)),
	}
	for _, w := range invalid {
		run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), w), false)
	}
	// A valid target in another role still cannot use this role's wrapping key.
	other := &kmipObject{Algorithm: 3, Bits: 128}
	if err := kmipNewObject(f.ctx, f.s, "scope/s/role/other/objects/", other); err != nil {
		t.Fatal(err)
	}
	if _, reason, err := kmipExecute(f.ctx, f.s, "scope/s/role/other", k.OpGet, k.S(k.RequestPayload, k.T(k.UniqueIdentifier, other.ID), spec(kekID, 1))); err == nil || reason != 1 {
		t.Fatal("cross-role wrapping key access")
	}
	inactive := run(kmipRequest(k.OpCreate, k.E(k.ObjectType, 2), attrs), true).Find(k.UniqueIdentifier).Text()
	run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec(inactive, 1)), false)
	run(kmipRequest(k.OpDestroy, k.T(k.UniqueIdentifier, inactive)), true)
	run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec(inactive, 1)), false)
	noUsage := run(kmipCreateRequest(), true).Find(k.UniqueIdentifier).Text()
	run(kmipRequest(k.OpActivate, k.T(k.UniqueIdentifier, noUsage)), true)
	run(kmipRequest(k.OpGet, k.T(k.UniqueIdentifier, id), spec(noUsage, 1)), false)
	if _, _, err := kmipExecute(f.ctx, f.s, "scope/s/role/other", k.OpGet, k.S(k.RequestPayload, k.T(k.UniqueIdentifier, id), spec(kekID, 1))); err == nil {
		t.Fatal("cross-role access")
	}
}

func kmipTestUnwrap(t *testing.T, kek, wrapped []byte) []byte {
	t.Helper()
	c, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), wrapped...)
	n := len(data)/8 - 1
	var block [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(block[:8], binary.BigEndian.Uint64(data[:8])^uint64(n*j+i))
			copy(block[8:], data[8*i:8*i+8])
			c.Decrypt(block[:], block[:])
			copy(data[:8], block[:8])
			copy(data[8*i:8*i+8], block[8:])
		}
	}
	if !bytes.Equal(data[:8], bytes.Repeat([]byte{0xa6}, 8)) {
		t.Fatal("integrity register mismatch")
	}
	return data[8:]
}

func TestKMIPAESWrapVector(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// RFC 3394 section 4.1 published known-answer vector.
	key := decode("000102030405060708090A0B0C0D0E0F")
	plain := decode("00112233445566778899AABBCCDDEEFF")
	want := decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	got, err := kmipAESWrap(key, plain)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("wrap: %x %v", got, err)
	}
	for _, bits := range []int{16, 24, 32} {
		for _, size := range []int{16, 24, 32} {
			p := bytes.Repeat([]byte{1}, size)
			key := bytes.Repeat([]byte{2}, bits)
			w, err := kmipAESWrap(key, p)
			if err != nil || !bytes.Equal(kmipTestUnwrap(t, key, w), p) {
				t.Fatal("round trip")
			}
		}
	}
}
