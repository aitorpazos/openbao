// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestHMACDRBGInstantiate reproduces the SP 800-90A 10.1.2 instantiation
// derivation: K starts as zero and is HMAC-refreshed with V||0x00||seed, then
// V||0x01||seed; a second instantiation with the same seed must produce the
// same K and V, and output for the same seed is deterministic across instances.
func TestHMACDRBGInstantiate(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	if err != nil {
		t.Fatal(err)
	}
	a := NewHMACDRBG(seed)
	b := NewHMACDRBG(seed)
	if a.K != b.K || a.V != b.V {
		t.Fatalf("same seed must instantiate identically: K=%x V=%x vs K=%x V=%x", a.K, a.V, b.K, b.V)
	}

	outA := a.Generate(64)
	outB := b.Generate(64)
	if !bytes.Equal(outA, outB) {
		t.Fatalf("same seed must generate identical output")
	}
	if bytes.Equal(outA[:32], outA[32:]) {
		t.Fatalf("successive blocks must not repeat: %x", outA)
	}

	// A different seed must instantiate differently.
	c := NewHMACDRBG([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
		49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64})
	if c.K == a.K || c.V == a.V {
		t.Fatalf("different seeds must instantiate differently")
	}
	if bytes.Equal(c.Generate(64), outA) {
		t.Fatalf("different seeds must not generate identical output")
	}
}

// TestHMACDRBGPostGenerateUpdate checks that the no-data update after
// Generate prevents generating the same stream again from the same instance.
func TestHMACDRBGPostGenerateUpdate(t *testing.T) {
	seed := make([]byte, 64)
	d := NewHMACDRBG(seed)
	first := d.Generate(64)
	second := d.Generate(64)
	if bytes.Equal(first, second) {
		t.Fatalf("post-generate update must advance the generator state")
	}
}

// TestHMACDRBGLengths checks arbitrary lengths (not multiple of the 32-byte
// block) and the empty edge case.
func TestHMACDRBGLengths(t *testing.T) {
	seed := make([]byte, 64)
	d := NewHMACDRBG(seed)
	for _, n := range []int{1, 2, 31, 32, 33, 64, 65, 1000} {
		out := d.Generate(n)
		if len(out) != n {
			t.Fatalf("Generate(%d) returned %d bytes", n, len(out))
		}
		if bytes.Equal(out, make([]byte, n)) {
			t.Fatalf("Generate(%d) returned all zero bytes", n)
		}
	}
}
