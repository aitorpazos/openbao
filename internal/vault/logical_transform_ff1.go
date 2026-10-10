// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"math/big"
)

// transformFF1 implements the ten-round FF1 construction in NIST SP 800-38G,
// Algorithms 7 and 8. Digits are big-endian radix values, not encoded bytes.
// The minimum domain is one million, as required by the revised guidance.
func transformFF1(key, tweak []byte, radix int, digits []int, decrypt bool) ([]int, error) {
	n := len(digits)
	if radix < 2 || radix > 65536 || n < 2 || n > 4096 || len(tweak) > 4096 {
		return nil, fmt.Errorf("invalid FF1 parameters")
	}
	r := big.NewInt(int64(radix))
	power := func(n int) *big.Int { return new(big.Int).Exp(r, big.NewInt(int64(n)), nil) }
	if power(n).Cmp(big.NewInt(1000000)) < 0 {
		return nil, fmt.Errorf("FF1 domain must contain at least one million values")
	}
	for _, v := range digits {
		if v < 0 || v >= radix {
			return nil, fmt.Errorf("digit outside alphabet")
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	u := n / 2
	v := n - u
	// ceil(ceil(v*log2(radix))/8), computed exactly without floating point.
	b := (new(big.Int).Sub(power(v), big.NewInt(1)).BitLen() + 7) / 8
	d := 4*((b+3)/4) + 4
	p := make([]byte, 16)
	p[0] = 1
	p[1] = 2
	p[2] = 1
	p[3] = byte(radix >> 16)
	p[4] = byte(radix >> 8)
	p[5] = byte(radix)
	p[6] = 10
	p[7] = byte(u)
	binary.BigEndian.PutUint32(p[8:12], uint32(n))
	binary.BigEndian.PutUint32(p[12:], uint32(len(tweak)))
	num := func(x []int) *big.Int {
		z := new(big.Int)
		for _, a := range x {
			z.Mul(z, r)
			z.Add(z, big.NewInt(int64(a)))
		}
		return z
	}
	str := func(x *big.Int, m int) []int {
		out := make([]int, m)
		z := new(big.Int).Set(x)
		rem := new(big.Int)
		for j := m - 1; j >= 0; j-- {
			z.QuoRem(z, r, rem)
			out[j] = int(rem.Int64())
		}
		return out
	}
	a := append([]int(nil), digits[:u]...)
	bb := append([]int(nil), digits[u:]...)
	for round := 0; round < 10; round++ {
		i := round
		if decrypt {
			i = 9 - round
		}
		m := u
		if i%2 != 0 {
			m = v
		}
		half := bb
		if decrypt {
			half = a
		}
		q := append([]byte(nil), tweak...)
		q = append(q, make([]byte, (16-(len(tweak)+b+1)%16)%16)...)
		q = append(q, byte(i))
		nb := make([]byte, b)
		num(half).FillBytes(nb)
		q = append(q, nb...)
		state := make([]byte, 16)
		for _, data := range [][]byte{p, q} {
			for k := 0; k < len(data); k += 16 {
				for j := 0; j < 16; j++ {
					state[j] ^= data[k+j]
				}
				block.Encrypt(state, state)
			}
		}
		s := append([]byte(nil), state...)
		for j := 1; len(s) < d; j++ {
			x := append([]byte(nil), state...)
			counter := make([]byte, 16)
			binary.BigEndian.PutUint64(counter[8:], uint64(j))
			for k := range x {
				x[k] ^= counter[k]
			}
			block.Encrypt(x, x)
			s = append(s, x...)
		}
		y := new(big.Int).SetBytes(s[:d])
		c := new(big.Int)
		if decrypt {
			c.Sub(num(bb), y)
		} else {
			c.Add(num(a), y)
		}
		c.Mod(c, power(m))
		if decrypt {
			bb = a
			a = str(c, m)
		} else {
			a = bb
			bb = str(c, m)
		}
	}
	return append(a, bb...), nil
}
