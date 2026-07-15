// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "unsafe"

type kernelCryptoCipherType uint16

const (
	_TLS_CIPHER_AES_GCM_128              kernelCryptoCipherType = 51
	_TLS_CIPHER_AES_GCM_128_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_AES_GCM_128_KEY_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_AES_GCM_128_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_AES_GCM_128_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_AES_GCM_256              kernelCryptoCipherType = 52
	_TLS_CIPHER_AES_GCM_256_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_AES_GCM_256_KEY_SIZE     kernelCryptoCipherType = 32
	_TLS_CIPHER_AES_GCM_256_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_AES_GCM_256_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_AES_CCM_128              kernelCryptoCipherType = 53
	_TLS_CIPHER_AES_CCM_128_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_AES_CCM_128_KEY_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_AES_CCM_128_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_AES_CCM_128_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_CHACHA20_POLY1305              kernelCryptoCipherType = 54
	_TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE      kernelCryptoCipherType = 12
	_TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE     kernelCryptoCipherType = 32
	_TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE    kernelCryptoCipherType = 0
	_TLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_SM4_GCM              kernelCryptoCipherType = 55
	_TLS_CIPHER_SM4_GCM_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_SM4_GCM_KEY_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_SM4_GCM_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_SM4_GCM_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_SM4_CCM              kernelCryptoCipherType = 56
	_TLS_CIPHER_SM4_CCM_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_SM4_CCM_KEY_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_SM4_CCM_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_SM4_CCM_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_ARIA_GCM_128              kernelCryptoCipherType = 57
	_TLS_CIPHER_ARIA_GCM_128_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_ARIA_GCM_128_KEY_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_ARIA_GCM_128_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_ARIA_GCM_128_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_ARIA_GCM_128_REC_SEQ_SIZE kernelCryptoCipherType = 8

	_TLS_CIPHER_ARIA_GCM_256              kernelCryptoCipherType = 58
	_TLS_CIPHER_ARIA_GCM_256_IV_SIZE      kernelCryptoCipherType = 8
	_TLS_CIPHER_ARIA_GCM_256_KEY_SIZE     kernelCryptoCipherType = 32
	_TLS_CIPHER_ARIA_GCM_256_SALT_SIZE    kernelCryptoCipherType = 4
	_TLS_CIPHER_ARIA_GCM_256_TAG_SIZE     kernelCryptoCipherType = 16
	_TLS_CIPHER_ARIA_GCM_256_REC_SEQ_SIZE kernelCryptoCipherType = 8
)

type kernelCrypto interface {
	String() string
}

type kernelCryptoInfo struct {
	version     uint16
	cipher_type kernelCryptoCipherType
}

var _ kernelCrypto = (*kernelCryptoAES128GCM)(nil)

type kernelCryptoAES128GCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_AES_GCM_128_IV_SIZE]byte
	key     [_TLS_CIPHER_AES_GCM_128_KEY_SIZE]byte
	salt    [_TLS_CIPHER_AES_GCM_128_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoAES128GCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_AES_GCM_128
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoAES256GCM)(nil)

type kernelCryptoAES256GCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_AES_GCM_256_IV_SIZE]byte
	key     [_TLS_CIPHER_AES_GCM_256_KEY_SIZE]byte
	salt    [_TLS_CIPHER_AES_GCM_256_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoAES256GCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_AES_GCM_256
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoAES128CCM)(nil)

type kernelCryptoAES128CCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_AES_CCM_128_IV_SIZE]byte
	key     [_TLS_CIPHER_AES_CCM_128_KEY_SIZE]byte
	salt    [_TLS_CIPHER_AES_CCM_128_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoAES128CCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_AES_CCM_128
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoChacha20Poly1035)(nil)

type kernelCryptoChacha20Poly1035 struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE]byte
	key     [_TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE]byte
	salt    [_TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoChacha20Poly1035) String() string {
	crypto.cipher_type = _TLS_CIPHER_CHACHA20_POLY1305
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoSM4GCM)(nil)

type kernelCryptoSM4GCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_SM4_GCM_IV_SIZE]byte
	key     [_TLS_CIPHER_SM4_GCM_KEY_SIZE]byte
	salt    [_TLS_CIPHER_SM4_GCM_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoSM4GCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_SM4_GCM
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoSM4CCM)(nil)

type kernelCryptoSM4CCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_SM4_CCM_IV_SIZE]byte
	key     [_TLS_CIPHER_SM4_CCM_KEY_SIZE]byte
	salt    [_TLS_CIPHER_SM4_CCM_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoSM4CCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_SM4_CCM
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoARIA128GCM)(nil)

type kernelCryptoARIA128GCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_ARIA_GCM_128_IV_SIZE]byte
	key     [_TLS_CIPHER_ARIA_GCM_128_KEY_SIZE]byte
	salt    [_TLS_CIPHER_ARIA_GCM_128_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_ARIA_GCM_128_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoARIA128GCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_ARIA_GCM_128
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = (*kernelCryptoARIA256GCM)(nil)

type kernelCryptoARIA256GCM struct {
	kernelCryptoInfo
	iv      [_TLS_CIPHER_ARIA_GCM_256_IV_SIZE]byte
	key     [_TLS_CIPHER_ARIA_GCM_256_KEY_SIZE]byte
	salt    [_TLS_CIPHER_ARIA_GCM_256_SALT_SIZE]byte
	rec_seq [_TLS_CIPHER_ARIA_GCM_256_REC_SEQ_SIZE]byte
}

func (crypto *kernelCryptoARIA256GCM) String() string {
	crypto.cipher_type = _TLS_CIPHER_ARIA_GCM_256
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

func (hc *halfConn) kernelCipher(cipherSuite uint16, isRX bool) kernelCrypto {
	if !kernel.TLS {
		return nil
	}

	switch hc.version {
	case VersionTLS12:
		if isRX && !kernel.TLS_RX {
			return nil
		}

		if hc.limit < maxPlaintext && !kernel.TLS_TX_MAX_PAYLOAD {
			return nil
		}

	case VersionTLS13:
		if !kernel.TLS_Version13 {
			return nil
		}

		if isRX && !kernel.TLS_Version13_RX {
			return nil
		}

		if hc.limit < maxPlaintext+1 && !kernel.TLS_TX_MAX_PAYLOAD {
			return nil
		}
	default:
		return nil
	}

	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		crypto := new(kernelCryptoAES128GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		if !kernel.TLS_AES_256_GCM {
			return nil
		}

		crypto := new(kernelCryptoAES256GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_AES_128_CCM_SHA256, TLS_RSA_WITH_AES_128_CCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_SHA256:
		if !kernel.TLS_AES_128_CCM {
			return nil
		}

		crypto := new(kernelCryptoAES128CCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		if !kernel.TLS_CHACHA20_POLY1305 {
			return nil
		}

		crypto := new(kernelCryptoChacha20Poly1035)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv)
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_SM4_GCM_SM3:
		if !kernel.TLS_SM4 {
			return nil
		}

		crypto := new(kernelCryptoSM4GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_SM4_CCM_SM3:
		if !kernel.TLS_SM4 {
			return nil
		}

		crypto := new(kernelCryptoSM4CCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_RSA_WITH_ARIA_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
		if !kernel.TLS_ARIA_GCM {
			return nil
		}

		crypto := new(kernelCryptoARIA128GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	case TLS_RSA_WITH_ARIA_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
		if !kernel.TLS_ARIA_GCM {
			return nil
		}

		crypto := new(kernelCryptoARIA256GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		return crypto
	default:
		return nil
	}
}
