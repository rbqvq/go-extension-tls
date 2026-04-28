// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"io"

	"gitlab.com/go-extension/rand"
)

type ECHCipher struct {
	KEM  hpke.KEM
	KDF  hpke.KDF
	AEAD hpke.AEAD
}

// ECHDummyConfig represents an ECH dummy configuration.
type ECHDummyConfig struct {
	ConfigIds    []uint8
	CipherSuites []ECHCipher
	InnerLens    []uint16
}

func (config *ECHDummyConfig) configId() uint8 {
	if len(config.ConfigIds) <= 0 {
		return uint8(rand.Crypto.IntN(0xff + 1))
	}

	return config.ConfigIds[rand.Crypto.IntN(len(config.ConfigIds))]
}

func (config *ECHDummyConfig) cipherSuite() ECHCipher {
	if len(config.CipherSuites) <= 0 {
		return ECHCipher{KEM: hpke.DHKEM(ecdh.X25519()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM()}
	}

	return config.CipherSuites[rand.Crypto.IntN(len(config.CipherSuites))]
}

func (config *ECHDummyConfig) innerLen() uint16 {
	if len(config.InnerLens) <= 0 {
		return 128
	}

	return config.InnerLens[rand.Crypto.IntN(len(config.InnerLens))]
}

func generateAndUpdateOuterECHExtension(rand io.Reader, outer *clientHelloMsg, echConfig *ECHDummyConfig) error {
	if echConfig == nil {
		return nil
	}

	suite := echConfig.cipherSuite()

	var dummyPublicKey []byte
	switch suite.KEM {
	case hpke.DHKEM(ecdh.X25519()):
		dummyPublicKey = []byte{
			143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
			81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
		}
	default:
		return fmt.Errorf("tls: dummy ech: invalid kem %#x", suite.KEM)
	}

	var length uint16
	switch suite.AEAD {
	case hpke.AES128GCM(), hpke.AES256GCM(), hpke.ChaCha20Poly1305():
		length = echConfig.innerLen() + 16
	default:
		return fmt.Errorf("tls: dummy ech: invalid aead %#x", suite.AEAD.ID())
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(rand, payload); err != nil {
		return fmt.Errorf("tls: grease ech: %s", err)
	}

	echPK, err := suite.KEM.NewPublicKey(dummyPublicKey)
	if err != nil {
		return err
	}

	encapKey, _, err := hpke.NewSender(echPK, suite.KDF, suite.AEAD, nil)
	if err != nil {
		return err
	}

	outer.encryptedClientHello, err = generateOuterECHExt(echConfig.configId(), suite.KDF.ID(), suite.AEAD.ID(), encapKey, payload)
	if err != nil {
		return err
	}

	return nil
}
