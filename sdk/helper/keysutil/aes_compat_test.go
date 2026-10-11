// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESCMACNIST(t *testing.T) {
	// NIST SP 800-38B examples, AES-128, messages of 0, 16, 40 and 64 bytes.
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	msg, err := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" + "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		n   int
		tag string
	}{{0, "bb1d6929e95937287fa37d129b756746"}, {16, "070a16b46b4d4144f79bdd9dd04a287c"}, {40, "dfa66747de9ae63030ca32611497c827"}, {64, "51f0bebf7e3b9d92fc49741779363cfe"}} {
		got, err := aesCMAC(key, msg[:tc.n])
		if err != nil || hex.EncodeToString(got) != tc.tag {
			t.Fatalf("n=%d: %x %v", tc.n, got, err)
		}
	}
}

func TestCBCPaddingAndNIST(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	msg, err := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := encryptCBC(key, msg, iv)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ct[16:32]) != "7649abac8119b246cee98e9b12e9197d" {
		t.Fatalf("NIST CBC mismatch: %x", ct)
	}
	for _, size := range []int{16, 32} {
		for n := 0; n < 100; n++ {
			plain := bytes.Repeat([]byte{byte(n)}, n)
			ct, err := encryptCBC(make([]byte, size), plain, nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decryptCBC(make([]byte, size), ct)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("size=%d n=%d: %v", size, n, err)
			}
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 16), make([]byte, 17)} {
		if _, err := decryptCBC(key, bad); err == nil {
			t.Fatal("accepted malformed ciphertext")
		}
	}
	// Corrupt the final padding byte through the previous ciphertext block.
	ct[len(ct)-17] ^= 16
	if _, err := decryptCBC(key, ct); err == nil {
		t.Fatal("accepted zero padding")
	}
}
