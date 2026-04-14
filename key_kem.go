// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/mlkem"
	"io"
)

type kemPrivateKeyGenerator func(rand io.Reader) (crypto.Decapsulator, error)
type kemPublicKeyGenerator func(encapsulationKey []byte) (crypto.Encapsulator, error)

func newMLKEMPrivateKey768(rand io.Reader) (crypto.Decapsulator, error) {
	seed := make([]byte, mlkem.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey768(seed)
}

func newMLKEMPublicKey768(encapsulationKey []byte) (crypto.Encapsulator, error) {
	return mlkem.NewEncapsulationKey768(encapsulationKey)
}

func newMLKEMPrivateKey1024(rand io.Reader) (crypto.Decapsulator, error) {
	seed := make([]byte, mlkem.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey1024(seed)
}

func newMLKEMPublicKey1024(encapsulationKey []byte) (crypto.Encapsulator, error) {
	return mlkem.NewEncapsulationKey1024(encapsulationKey)
}
