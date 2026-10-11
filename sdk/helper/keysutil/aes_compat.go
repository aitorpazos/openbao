// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
)

func (kt KeyType) IsCBC() bool { return kt == KeyType_AES128_CBC || kt == KeyType_AES256_CBC }
func (kt KeyType) IsCMAC() bool {
	return kt == KeyType_AES128_CMAC || kt == KeyType_AES192_CMAC || kt == KeyType_AES256_CMAC
}
func (kt KeyType) AESKeyBytes() int {
	switch kt {
	case KeyType_AES128_CMAC, KeyType_AES128_CBC:
		return 16
	case KeyType_AES192_CMAC:
		return 24
	default:
		return 32
	}
}

// CBC is unauthenticated encryption (SP 800-38A). Its wire payload is IV ||
// ciphertext; PKCS#7 always adds padding, including for block-aligned input.
func encryptCBC(key, plaintext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != 0 && len(iv) != aes.BlockSize {
		return nil, errutil.UserError{Err: "iv must be 16 bytes"}
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	out := make([]byte, aes.BlockSize+len(plaintext)+padding)
	if len(iv) == 0 {
		if _, err := rand.Read(out[:aes.BlockSize]); err != nil {
			return nil, err
		}
	} else {
		copy(out, iv)
	}
	copy(out[aes.BlockSize:], plaintext)
	for i := aes.BlockSize + len(plaintext); i < len(out); i++ {
		out[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], out[aes.BlockSize:])
	return out, nil
}
func decryptCBC(key, ciphertext []byte) ([]byte, error) {
	bad := errutil.UserError{Err: "invalid CBC ciphertext"}
	if len(ciphertext) < 2*aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, bad
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, ciphertext[:aes.BlockSize]).CryptBlocks(out, ciphertext[aes.BlockSize:])
	padding := int(out[len(out)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aes.BlockSize)
	for i := 1; i <= aes.BlockSize; i++ {
		check := subtle.ConstantTimeLessOrEq(i, padding)
		valid &= 1 ^ (check & (1 ^ subtle.ConstantTimeByteEq(out[len(out)-i], byte(padding))))
	}
	if valid != 1 {
		return nil, bad
	}
	return out[:len(out)-padding], nil
}

// aesCMAC implements NIST SP 800-38B, including the empty-message case.
func aesCMAC(key, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var l, k1, k2, x, last [aes.BlockSize]byte
	block.Encrypt(l[:], l[:])
	double := func(dst *[aes.BlockSize]byte, src [aes.BlockSize]byte) {
		for i := 0; i < aes.BlockSize-1; i++ {
			dst[i] = src[i]<<1 | src[i+1]>>7
		}
		dst[15] = src[15] << 1
		dst[15] ^= 0x87 & (byte(0) - (src[0] >> 7))
	}
	double(&k1, l)
	double(&k2, k1)
	for len(message) > aes.BlockSize {
		for i := range x {
			x[i] ^= message[i]
		}
		block.Encrypt(x[:], x[:])
		message = message[aes.BlockSize:]
	}
	copy(last[:], message)
	subkey := k1
	if len(message) != aes.BlockSize {
		last[len(message)] = 0x80
		subkey = k2
	}
	for i := range x {
		x[i] ^= last[i] ^ subkey[i]
	}
	block.Encrypt(x[:], x[:])
	return x[:], nil
}

// CMAC returns a versioned, base64 encoded authentication tag. It is not an
// encryption operation: CMAC keys intentionally do not support encrypt/decrypt.
func (p *Policy) CMAC(version int, context, input []byte, length int) (string, error) {
	if p.SoftDeleted {
		return "", errutil.UserError{Err: ErrSoftDeleted}
	}
	if !p.Type.IsCMAC() {
		return "", errutil.UserError{Err: "key does not support CMAC"}
	}
	if length == 0 {
		length = aes.BlockSize
	}
	if length < 1 || length > aes.BlockSize {
		return "", errutil.UserError{Err: "mac_length must be between 1 and 16 bytes"}
	}
	if version == 0 {
		version = p.LatestVersion
	}
	if version < 1 || version > p.LatestVersion || version < p.MinEncryptionVersion {
		return "", errutil.UserError{Err: "invalid key version"}
	}
	key, err := p.GetKey(context, version, p.Type.AESKeyBytes())
	if err != nil {
		return "", err
	}
	tag, err := aesCMAC(key, input)
	if err != nil {
		return "", err
	}
	return p.getVersionPrefix(version) + base64.StdEncoding.EncodeToString(tag[:length]), nil
}
