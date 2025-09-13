package tls

import (
	"fmt"
	"io"

	"gitlab.com/go-extension/hpke"
	"gitlab.com/go-extension/rand"
)

var (
	dummyX25519PublicKey = []byte{
		143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
		81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
	}

	defaultHpkeSuite = ECHCipher{KEM: hpke.DHKEM_X25519_HKDF_SHA256, KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES_128_GCM}
)

type ECHCipher struct {
	KEM  uint16
	KDF  uint16
	AEAD uint16
}

// ECHDummyConfig represents an ECH dummy configuration.
type ECHDummyConfig struct {
	ConfigIds      []uint8
	CipherSuites   []ECHCipher
	HelloInnerLens []uint16 // Pre-encryption. If 0, will pick 128 (+16=144)
}

func (config *ECHDummyConfig) configId() uint8 {
	if len(config.ConfigIds) <= 0 {
		return uint8(rand.Crypto.IntN(0xff + 1))
	}

	return config.ConfigIds[rand.Crypto.IntN(len(config.ConfigIds))]
}

func (config *ECHDummyConfig) cipherSuite() ECHCipher {
	if len(config.CipherSuites) <= 0 {
		return defaultHpkeSuite
	}

	return config.CipherSuites[rand.Crypto.IntN(len(config.CipherSuites))]
}

func (config *ECHDummyConfig) helloInnerLen() uint16 {
	if len(config.HelloInnerLens) <= 0 {
		return 128
	}

	return config.HelloInnerLens[rand.Crypto.IntN(len(config.HelloInnerLens))]
}

func generateAndUpdateOuterECHExtension(rand io.Reader, outer *clientHelloMsg, ech *ECHDummyConfig) error {
	suite := ech.cipherSuite()

	var dummyPublicKey []byte
	switch suite.KEM {
	case hpke.DHKEM_X25519_HKDF_SHA256:
		dummyPublicKey = dummyX25519PublicKey
	default:
		return fmt.Errorf("tls: dummy ech: invalid kem %#x", suite.KEM)
	}

	var length uint16
	switch suite.AEAD {
	case hpke.AEAD_AES_128_GCM, hpke.AEAD_AES_256_GCM, hpke.AEAD_ChaCha20Poly1305:
		length = ech.helloInnerLen() + 16
	default:
		return fmt.Errorf("tls: dummy ech: invalid aead %#x", suite.AEAD)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(rand, payload); err != nil {
		return fmt.Errorf("tls: grease ech: %s", err)
	}

	echPK, err := hpke.ParseHPKEPublicKey(suite.KEM, dummyPublicKey)
	if err != nil {
		return err
	}

	encapKey, _, err := hpke.SetupSender(suite.KEM, suite.KDF, suite.AEAD, echPK, nil)
	if err != nil {
		return err
	}

	outer.encryptedClientHello, err = generateOuterECHExt(ech.configId(), suite.KDF, suite.AEAD, encapKey, payload)
	if err != nil {
		return err
	}

	return nil
}
