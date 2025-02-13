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

	defaultHpkeSuite = ECHCipher{KEM: KEM_X25519_HKDF_SHA256, KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES128GCM}
)

type KEM uint16

const (
	// RFC 9180, Section 7.2
	// KEM_X25519_HKDF_SHA256 is a KEM using X25519 Diffie-Hellman function
	// and HKDF with SHA-256.
	KEM_X25519_HKDF_SHA256 KEM = 0x20
)

type KDF uint16

const (
	// RFC 9180, Section 7.2
	// KDF_HKDF_SHA256 is a KDF using HKDF with SHA-256.
	KDF_HKDF_SHA256 KDF = 0x01
)

type AEAD uint16

const (
	// RFC 9180, Section 7.2

	// AEAD_AES128GCM is AES-128 block cipher in Galois Counter Mode (GCM).
	AEAD_AES128GCM AEAD = 0x01
	// AEAD_AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
	AEAD_AES256GCM AEAD = 0x02
	// AEAD_ChaCha20Poly1305 is ChaCha20 stream cipher and Poly1305 MAC.
	AEAD_ChaCha20Poly1305 AEAD = 0x03
)

type ECHCipher struct {
	KEM  KEM
	KDF  KDF
	AEAD AEAD
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
	case KEM_X25519_HKDF_SHA256:
		dummyPublicKey = dummyX25519PublicKey
	default:
		return fmt.Errorf("tls: dummy ech: invalid kem %#x", suite.KEM)
	}

	var length uint16
	switch suite.AEAD {
	case AEAD_AES128GCM, AEAD_AES256GCM, AEAD_ChaCha20Poly1305:
		length = ech.helloInnerLen() + 16
	default:
		return fmt.Errorf("tls: dummy ech: invalid aead %#x", suite.AEAD)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(rand, payload); err != nil {
		return fmt.Errorf("tls: grease ech: %s", err)
	}

	echPK, err := hpke.ParseHPKEPublicKey(uint16(suite.KEM), dummyPublicKey)
	if err != nil {
		return err
	}

	encapKey, _, err := hpke.SetupSender(uint16(suite.KEM), uint16(suite.KDF), uint16(suite.AEAD), echPK, nil)
	if err != nil {
		return err
	}

	outer.encryptedClientHello, err = generateOuterECHExt(ech.configId(), uint16(suite.KDF), uint16(suite.AEAD), encapKey, payload)
	if err != nil {
		return err
	}

	return nil
}
