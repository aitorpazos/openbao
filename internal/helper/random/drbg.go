// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACDRBG implements the HMAC-mode Hash_DRBG per NIST SP 800-90A Rev 1
// using SHA-256 (256-bit security strength). It is the deterministic
// generator behind the documented drbg option of the random API, which
// "seeds a cryptographically secure random generator with a seed from the
// chosen source in order to efficiently generate a larger volume of random
// bytes". The derivation function is skipped and the seed material is taken
// directly from the source, as the documented behavior passes the sampled
// entropy straight to the generator. Reseed interval is unlimited for the
// lifetime of the object (the API creates one generator per request).
type HMACDRBG struct {
	K [sha256.Size]byte
	V [sha256.Size]byte
}

// NewHMACDRBG instantiates the generator from seed material. Per SP
// 800-90A section 10.1.2 the seed must be at least the security strength
// plus the requested strength; callers should supply 64 bytes (twice the
// SHA-256 output) sampled from the configured source.
func NewHMACDRBG(seed []byte) *HMACDRBG {
	d := &HMACDRBG{}
	for i := range d.K {
		d.K[i] = 0x00
	}
	for i := range d.V {
		d.V[i] = 0x01
	}
	d.update(seed)
	return d
}

// update is the HMAC_DRBG_Update function (SP 800-90A 10.1.2.2): K and V are
// refreshed by iterating HMAC over V||0x00||provided_data and V||0x01||
// provided_data.
func (d *HMACDRBG) update(seed []byte) {
	mac := hmac.New(sha256.New, d.K[:])
	mac.Write(d.V[:])
	mac.Write([]byte{0x00})
	mac.Write(seed)
	copy(d.K[:], mac.Sum(nil))

	mac = hmac.New(sha256.New, d.K[:])
	mac.Write(d.V[:])
	copy(d.V[:], mac.Sum(nil))

	if len(seed) > 0 {
		mac = hmac.New(sha256.New, d.K[:])
		mac.Write(d.V[:])
		mac.Write([]byte{0x01})
		mac.Write(seed)
		copy(d.K[:], mac.Sum(nil))

		mac = hmac.New(sha256.New, d.K[:])
		mac.Write(d.V[:])
		copy(d.V[:], mac.Sum(nil))
	}
}

// Generate produces n bytes. Each iteration output block is HMAC(K, V) with V
// advancing per SP 800-90A 10.1.2.5; after generation K and V are refreshed
// with the no-provided-data update so the generator cannot be rolled back to
// reproduce output.
func (d *HMACDRBG) Generate(n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for len(out) < n {
		mac := hmac.New(sha256.New, d.K[:])
		mac.Write(d.V[:])
		copy(d.V[:], mac.Sum(nil))
		out = append(out, d.V[:]...)
	}
	out = out[:n]
	d.update(nil)
	return out
}
