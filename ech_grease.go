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
	Disabled     bool
	ConfigIds    []uint8
	CipherSuites []ECHCipher
	InnerLens    []uint16
}

func (config *ECHDummyConfig) pickConfigId() uint8 {
	if len(config.ConfigIds) <= 0 {
		return uint8(rand.Crypto.IntN(0xff + 1))
	}

	return config.ConfigIds[rand.Crypto.IntN(len(config.ConfigIds))]
}

func (config *ECHDummyConfig) pickCipherSuite() ECHCipher {
	if len(config.CipherSuites) <= 0 {
		return ECHCipher{KEM: hpke.DHKEM(ecdh.X25519()), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM()}
	}

	return config.CipherSuites[rand.Crypto.IntN(len(config.CipherSuites))]
}

func (config *ECHDummyConfig) pickInnerLen() uint16 {
	if len(config.InnerLens) <= 0 {
		return 128
	}

	return config.InnerLens[rand.Crypto.IntN(len(config.InnerLens))]
}

func generateAndUpdateOuterECHExtension(rand io.Reader, outer *clientHelloMsg, dummyConfig *ECHDummyConfig) error {
	if dummyConfig == nil {
		return nil
	}

	if dummyConfig.Disabled {
		return nil
	}

	id := dummyConfig.pickConfigId()
	suite := dummyConfig.pickCipherSuite()
	length := dummyConfig.pickInnerLen()

	dummyKey, err := suite.KEM.GenerateKey()
	if err != nil {
		return fmt.Errorf("tls: grease ech: %s", err)
	}
	dummyPublicKey := dummyKey.PublicKey().Bytes()

	var overhead uint16
	switch suite.AEAD {
	case hpke.AES128GCM(), hpke.AES256GCM(), hpke.ChaCha20Poly1305():
		overhead = 16
	default:
		return fmt.Errorf("tls: grease ech: invalid aead %#x", suite.AEAD.ID())
	}
	length += overhead

	payload := make([]byte, length)
	if _, err := io.ReadFull(rand, payload); err != nil {
		return fmt.Errorf("tls: grease ech: %s", err)
	}

	outer.encryptedClientHello, err = generateOuterECHExt(id, suite.KDF.ID(), suite.AEAD.ID(), dummyPublicKey, payload)
	if err != nil {
		return err
	}
	return nil
}
