// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"unsafe"
)

type kernelCryptoCipherAlgorithm int32

const (
	_CRYPTO_AES_CBC           kernelCryptoCipherAlgorithm = 11 /* 128 bit blocksize -- the same as above */
	_CRYPTO_AES_NIST_GCM_16   kernelCryptoCipherAlgorithm = 25 /* 16 byte ICV */
	_CRYPTO_CHACHA20_POLY1305 kernelCryptoCipherAlgorithm = 41 /* combined AEAD cipher per RFC 8439 */
)

type kernelCryptoAuthAlgorithm int32

const (
	_CRYPTO_SHA1_HMAC     kernelCryptoAuthAlgorithm = 7
	_CRYPTO_SHA2_256_HMAC kernelCryptoAuthAlgorithm = 18
	_CRYPTO_SHA2_384_HMAC kernelCryptoAuthAlgorithm = 19
)

type kernelCrypto interface {
	String() string
}

var _ kernelCrypto = &kernelCryptoInfo{}

type kernelCryptoInfo struct {
	cipher_key       uintptr                     // const uint8_t *cipher_key
	iv               uintptr                     // const uint8_t *iv
	auth_key         uintptr                     // const uint8_t *auth_key
	cipher_algorithm kernelCryptoCipherAlgorithm // int cipher_algorithm (e.g., CRYPTO_AES_CBC)
	cipher_key_len   int32                       // int cipher_key_len
	iv_len           int32                       // int iv_len
	auth_algorithm   kernelCryptoAuthAlgorithm   // int auth_algorithm (e.g., CRYPTO_SHA2_256_HMAC)
	auth_key_len     int32                       // int auth_key_len
	flags            int32                       // int flags
	tls_vmajor       uint8                       // uint8_t tls_vmajor
	tls_vminor       uint8                       // uint8_t tls_vminor
	rec_seq          [8]byte                     // uint8_t rec_seq[8]
}

func (crypto *kernelCryptoInfo) setCipherKey(cipher_key []byte) {
	cipher_key_len := len(cipher_key)

	crypto.cipher_key_len = int32(cipher_key_len)
	crypto.cipher_key = uintptr(unsafe.Pointer(&cipher_key[0]))
}

func (crypto *kernelCryptoInfo) setIV(iv []byte) {
	iv_len := len(iv)

	crypto.iv_len = int32(iv_len)
	crypto.iv = uintptr(unsafe.Pointer(&iv[0]))
}

func (crypto *kernelCryptoInfo) setAuthKey(auth_key []byte) {
	auth_key_len := len(auth_key)

	crypto.auth_key_len = int32(auth_key_len)
	crypto.auth_key = uintptr(unsafe.Pointer(&auth_key[0]))
}

func (crypto *kernelCryptoInfo) String() string {
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

func (hc *halfConn) kernelCipher(cipherSuite uint16, isRX bool) kernelCrypto {
	if !kernel.TLS {
		return nil
	}

	switch hc.version {
	case VersionTLS10:
		if isRX {
			return nil
		}

	case VersionTLS11, VersionTLS12:
	case VersionTLS13:
		if isRX && !kernel.TLS_Version13_RX {
			return nil
		}

	default:
		return nil
	}

	crypto := new(kernelCryptoInfo)
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		crypto.cipher_algorithm = _CRYPTO_AES_NIST_GCM_16
		crypto.setCipherKey(hc.key)
		crypto.setIV(hc.iv)
	case TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		if !kernel.TLS_CHACHA20_POLY1305 {
			return nil
		}

		crypto.cipher_algorithm = _CRYPTO_CHACHA20_POLY1305
		crypto.setCipherKey(hc.key)
		crypto.setIV(hc.iv)
	case TLS_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		if !kernel.TLS_CBC {
			return nil
		}

		if hc.etm {
			return nil
		}

		if isRX && !kernel.TLS_Version11_12_CBC_RX {
			return nil
		}

		crypto.cipher_algorithm = _CRYPTO_AES_CBC
		crypto.auth_algorithm = _CRYPTO_SHA1_HMAC
		crypto.setCipherKey(hc.key)
		crypto.setIV(hc.iv)
		crypto.setAuthKey(hc.mac)
	case TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		if !kernel.TLS_CBC {
			return nil
		}

		if hc.etm {
			return nil
		}

		if isRX && !kernel.TLS_Version11_12_CBC_RX {
			return nil
		}

		crypto.cipher_algorithm = _CRYPTO_AES_CBC
		crypto.auth_algorithm = _CRYPTO_SHA2_256_HMAC
		crypto.setCipherKey(hc.key)
		crypto.setIV(hc.iv)
		crypto.setAuthKey(hc.mac)
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		if !kernel.TLS_CBC {
			return nil
		}

		if hc.etm {
			return nil
		}

		if isRX && !kernel.TLS_Version11_12_CBC_RX {
			return nil
		}

		crypto.cipher_algorithm = _CRYPTO_AES_CBC
		crypto.auth_algorithm = _CRYPTO_SHA2_384_HMAC
		crypto.setCipherKey(hc.key)
		crypto.setIV(hc.iv)
		crypto.setAuthKey(hc.mac)
	default:
		return nil
	}

	crypto.tls_vmajor = uint8(hc.version >> 8)
	crypto.tls_vminor = uint8(hc.version)
	crypto.rec_seq = hc.seq
	return crypto
}
