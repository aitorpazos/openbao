// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"

	"github.com/openbao/openbao/sdk/v2/logical"
	k "github.com/openbao/openbao/v2/internal/vault/kmip"
)

// kmipWrapGet implements the narrow Encrypt/NISTKeyWrap/No Encoding slice of
// KMIP 1.4 sections 2.1.5-2.1.6. See NOTES.md for parameter-model limitations.
func kmipWrapGet(ctx context.Context, s logical.Storage, prefix string, o *kmipObject, w k.Node) (k.Node, uint32, error) {
	fail := func(r uint32, msg string) (k.Node, uint32, error) { return k.Node{}, r, errors.New(msg) }
	if !kmipWireFields(w, k.WrappingMethod, k.EncryptionKeyInformation, k.EncodingOption) || w.Find(k.WrappingMethod).Type != k.Enumeration || w.Find(k.WrappingMethod).Number() != 1 || w.Find(k.EncodingOption).Type != k.Enumeration || w.Find(k.EncodingOption).Number() != 1 {
		return fail(5, "only Encrypt with explicit No Encoding is supported")
	}
	info := w.Find(k.EncryptionKeyInformation)
	params := info.Find(k.CryptographicParameters)
	if !kmipWireFields(info, k.UniqueIdentifier, k.CryptographicParameters) || info.Find(k.UniqueIdentifier).Type != k.TextString || !kmipWireFields(params, k.BlockCipherMode, k.CryptographicAlgorithm) || params.Find(k.BlockCipherMode).Type != k.Enumeration || params.Find(k.BlockCipherMode).Number() != 0x0d {
		return fail(5, "explicit NISTKeyWrap parameters required")
	}
	if a := params.Find(k.CryptographicAlgorithm); a.Tag != 0 && (a.Type != k.Enumeration || a.Number() != 3) {
		return fail(5, "only AES wrapping supported")
	}
	id := info.Find(k.UniqueIdentifier).Text()
	if id == o.ID {
		return fail(4, "wrapping key must be a different object")
	}
	kek, err := kmipObjectLoad(ctx, s, prefix, id)
	if err != nil {
		return fail(1, "wrapping key not found")
	}
	if kek.State != 2 {
		return fail(11, "wrapping key must be Active")
	}
	if kek.Usage&0x10 == 0 {
		return fail(12, "wrapping key requires Wrap Key usage")
	}
	if kek.Algorithm != 3 {
		return fail(5, "only AES wrapping supported")
	}
	wrapped, err := kmipAESWrap(kek.Material, o.Material)
	if err != nil {
		return fail(4, "invalid AES key material")
	}
	data := k.S(k.KeyWrappingData, k.E(k.WrappingMethod, 1), info, k.E(k.EncodingOption, 1))
	return k.S(k.KeyBlock, k.E(k.KeyFormatType, 1), k.B(k.KeyValue, wrapped), k.E(k.CryptographicAlgorithm, o.Algorithm), k.I(k.CryptographicLength, o.Bits), data), 0, nil
}

// Reject unknown and duplicate fields rather than silently weakening a request.
func kmipWireFields(n k.Node, allowed ...uint32) bool {
	if n.Type != k.Structure {
		return false
	}
	seen := map[uint32]bool{}
	for _, f := range n.Children() {
		ok := false
		for _, tag := range allowed {
			if f.Tag == tag {
				ok = true
			}
		}
		if !ok || seen[f.Tag] {
			return false
		}
		seen[f.Tag] = true
	}
	return true
}

// RFC 3394 section 2.2.1, default integrity register, without padding.
func kmipAESWrap(kek, plain []byte) ([]byte, error) {
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(plain) < 16 || len(plain)%8 != 0 {
		return nil, errors.New("invalid wrap length")
	}
	out := make([]byte, len(plain)+8)
	for i := 0; i < 8; i++ {
		out[i] = 0xa6
	}
	copy(out[8:], plain)
	n := len(plain) / 8
	var block [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(block[:8], out[:8])
			copy(block[8:], out[8*i:8*i+8])
			c.Encrypt(block[:], block[:])
			binary.BigEndian.PutUint64(out[:8], binary.BigEndian.Uint64(block[:8])^uint64(n*j+i))
			copy(out[8*i:8*i+8], block[8:])
		}
	}
	return out, nil
}
