// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package cmac implements the fast CMAC MAC based on
// a block cipher. This mode of operation fixes security
// deficiencies of CBC-MAC (CBC-MAC is secure only for
// fixed-length messages). CMAC is equal to OMAC1.
// This implementations supports block ciphers with a
// block size of:
//   - 64 bit
//   - 128 bit
//   - 256 bit
//   - 512 bit
//   - 1024 bit
//
// Common ciphers like AES, Serpent etc. operate on 128 bit
// blocks. 256, 512 and 1024 are supported for the Threefish
// tweakable block cipher. Ciphers with 64 bit blocks are
// supported, but not recommended.
// CMAC (with AES) is specified in RFC 4493 and RFC 4494.
package cmac // import "github.com/nvx/cmac"

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

const (
	// minimal irreducible polynomial for blocksize
	p64   = 0x1B    // for 64  bit block ciphers
	p128  = 0x87    // for 128 bit block ciphers (like AES)
	p256  = 0x425   // special for large block ciphers (Threefish)
	p512  = 0x125   // special for large block ciphers (Threefish)
	p1024 = 0x80043 // special for large block ciphers (Threefish)
)

var (
	errUnsupportedCipher = errors.New("cipher block size not supported")
	errInvalidTagSize    = errors.New("tags size must between 1 and the cipher's block size")
)

// Sum computes the CMAC checksum with the given tagSize of msg using the cipher.Block.
func Sum(msg []byte, c cipher.Block, tagSize int) ([]byte, error) {
	h, err := NewWithTagSize(c, tagSize)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// Verify computes the CMAC checksum with the given tagSize of msg and compares
// it with the given mac. This functions returns true if and only if the given mac
// is equal to the computed one.
func Verify(mac, msg []byte, c cipher.Block, tagSize int) bool {
	sum, err := Sum(msg, c, tagSize)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(mac, sum) == 1
}

// New returns a hash.Hash computing the CMAC checksum.
func New(c cipher.Block) (hash.Hash, error) {
	return NewWithTagSize(c, c.BlockSize())
}

// NewWithTagSize returns a hash.Hash computing the CMAC checksum with the
// given tag size. The tag size must between the 1 and the cipher's block size.
func NewWithTagSize(c cipher.Block, tagSize int) (hash.Hash, error) {
	blockSize := c.BlockSize()

	if tagSize <= 0 || tagSize > blockSize {
		return nil, errInvalidTagSize
	}

	var p int
	switch blockSize {
	default:
		return nil, errUnsupportedCipher
	case 8:
		p = p64
	case 16:
		p = p128
	case 32:
		p = p256
	case 64:
		p = p512
	case 128:
		p = p1024
	}

	m := &macFunc{
		cipher: c,
		k0:     make([]byte, blockSize),
		k1:     make([]byte, blockSize),
		buf:    make([]byte, blockSize),
	}
	m.tagSize = tagSize
	c.Encrypt(m.k0, m.k0)

	v := shift(m.k0, m.k0)
	m.k0[blockSize-1] ^= byte(subtle.ConstantTimeSelect(v, p, 0))

	v = shift(m.k1, m.k0)
	m.k1[blockSize-1] ^= byte(subtle.ConstantTimeSelect(v, p, 0))

	return m, nil
}

// The CMAC message auth. function
type macFunc struct {
	cipher  cipher.Block
	k0, k1  []byte
	buf     []byte
	off     int
	tagSize int
}

func (h *macFunc) Size() int { return h.tagSize }

func (h *macFunc) BlockSize() int { return h.cipher.BlockSize() }

func (h *macFunc) Reset() {
	for i := range h.buf {
		h.buf[i] = 0
	}
	h.off = 0
}

func (h *macFunc) SetIV(iv []byte) {
	if len(iv) != len(h.buf) {
		panic("cmac: incorrect length IV")
	}
	copy(h.buf, iv)
	h.off = 0
}

func (h *macFunc) Write(msg []byte) (int, error) {
	bs := h.BlockSize()
	n := len(msg)

	if h.off > 0 {
		dif := bs - h.off
		if n > dif {
			subtle.XORBytes(h.buf[h.off:], h.buf[h.off:], msg[:dif])
			msg = msg[dif:]
			h.cipher.Encrypt(h.buf, h.buf)
			h.off = 0
		} else {
			subtle.XORBytes(h.buf[h.off:], h.buf[h.off:], msg)
			h.off += n
			return n, nil
		}
	}

	if length := len(msg); length > bs {
		nn := length & (^(bs - 1))
		if length == nn {
			nn -= bs
		}
		for i := 0; i < nn; i += bs {
			subtle.XORBytes(h.buf, h.buf, msg[i:i+bs])
			h.cipher.Encrypt(h.buf, h.buf)
		}
		msg = msg[nn:]
	}

	if length := len(msg); length > 0 {
		subtle.XORBytes(h.buf[h.off:], h.buf[h.off:], msg)
		h.off += length
	}

	return n, nil
}

func (h *macFunc) Sum(b []byte) []byte {
	var k []byte
	if h.off < h.cipher.BlockSize() {
		k = h.k1
	} else {
		k = h.k0
	}
	return h.sum(b, k)
}

func (h *macFunc) SumManuallyPadded(b []byte) []byte {
	return h.sum(b, h.k1)
}

func (h *macFunc) sum(b, k []byte) []byte {
	blockSize := h.cipher.BlockSize()

	// Don't change the buffer so the
	// caller can keep writing and suming.
	hashOut := make([]byte, blockSize)

	copy(hashOut, k)

	subtle.XORBytes(hashOut, hashOut, h.buf)
	if h.off < blockSize {
		hashOut[h.off] ^= 0x80
	}

	h.cipher.Encrypt(hashOut, hashOut)
	return append(b, hashOut[:h.tagSize]...)
}

func shift(dst, src []byte) int {
	var b, bit byte
	for i := len(src) - 1; i >= 0; i-- { // a range would be nice
		bit = src[i] >> 7
		dst[i] = src[i]<<1 | b
		b = bit
	}
	return int(b)
}
