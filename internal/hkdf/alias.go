// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf

import (
	"crypto/hkdf"
	"hash"
)

func Extract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	out, err := hkdf.Extract(h, secret, salt)
	if err != nil {
		panic(err.Error())
	}
	return out
}

func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) []byte {
	out, err := hkdf.Expand(h, pseudorandomKey, info, keyLen)
	if err != nil {
		panic(err.Error())
	}
	return out
}

func Key[H hash.Hash](h func() H, secret, salt []byte, info string, keyLen int) []byte {
	out, err := hkdf.Key(h, secret, salt, info, keyLen)
	if err != nil {
		panic(err.Error())
	}
	return out
}
