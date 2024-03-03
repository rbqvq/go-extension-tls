// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"

	"github.com/cloudflare/circl/hpke"
)

// The mandatory-to-implement HPKE cipher suite for use with the ECH extension.
var (
	dummyX25519PublicKey = []byte{
		143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
		81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
	}
	defaultHpkeSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
)

func hpkeAssembleSuite(kemId, kdfId, aeadId uint16) (hpke.Suite, error) {
	kem := hpke.KEM(kemId)
	if !kem.IsValid() {
		return hpke.Suite{}, errors.New("KEM is not supported")
	}
	kdf := hpke.KDF(kdfId)
	if !kdf.IsValid() {
		return hpke.Suite{}, errors.New("KDF is not supported")
	}
	aead := hpke.AEAD(aeadId)
	if !aead.IsValid() {
		return hpke.Suite{}, errors.New("AEAD is not supported")
	}
	return hpke.NewSuite(kem, kdf, aead), nil
}

// HpkeSymmetricCipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair. This
// is different from an HPKE ciphersuite, which represents a KEM/KDF/AEAD
// triple.
type hpkeSymmetricCipherSuite struct {
	KDF, AEAD uint16
}
