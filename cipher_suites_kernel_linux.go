// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "unsafe"

type kernelCrypto interface {
	String() string
}

type kernelCryptoInfo struct {
	version     uint16
	cipher_type uint16
}

var _ kernelCrypto = &kernelCryptoAES128GCM{}

type kernelCryptoAES128GCM struct {
	kernelCryptoInfo
	iv      [8]byte
	key     [16]byte
	salt    [4]byte
	rec_seq [8]byte
}

func (crypto *kernelCryptoAES128GCM) String() string {
	crypto.cipher_type = 51
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = &kernelCryptoAES256GCM{}

type kernelCryptoAES256GCM struct {
	kernelCryptoInfo
	iv      [8]byte
	key     [32]byte
	salt    [4]byte
	rec_seq [8]byte
}

func (crypto *kernelCryptoAES256GCM) String() string {
	crypto.cipher_type = 52
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = &kernelCryptoAES128CCM{}

type kernelCryptoAES128CCM struct {
	kernelCryptoInfo
	iv      [8]byte
	key     [16]byte
	salt    [4]byte
	rec_seq [8]byte
}

func (crypto *kernelCryptoAES128CCM) String() string {
	crypto.cipher_type = 53
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = &kernelCryptoChacha20Poly1035{}

type kernelCryptoChacha20Poly1035 struct {
	kernelCryptoInfo
	iv      [12]byte
	key     [32]byte
	salt    [0]byte
	rec_seq [8]byte
}

func (crypto *kernelCryptoChacha20Poly1035) String() string {
	crypto.cipher_type = 54
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = &kernelCryptoARIA128GCM{}

type kernelCryptoARIA128GCM struct {
	kernelCryptoInfo
	iv      [8]byte
	key     [16]byte
	salt    [4]byte
	rec_seq [8]byte
}

func (crypto *kernelCryptoARIA128GCM) String() string {
	crypto.cipher_type = 57
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

var _ kernelCrypto = &kernelCryptoARIA256GCM{}

type kernelCryptoARIA256GCM struct {
	kernelCryptoInfo
	iv      [8]byte
	key     [32]byte
	salt    [4]byte
	rec_seq [8]byte
}

func (crypto *kernelCryptoARIA256GCM) String() string {
	crypto.cipher_type = 58
	return string((*[unsafe.Sizeof(*crypto)]byte)(unsafe.Pointer(crypto))[:])
}

func (hc *halfConn) kernelCipher(cipherSuite uint16) (kc kernelCrypto) {
	if hc.version < VersionTLS12 {
		return
	}

	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		crypto := new(kernelCryptoAES128GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		kc = crypto
	case TLS_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		if !kernel.TLS_AESGCM256 {
			return
		}

		crypto := new(kernelCryptoAES256GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		kc = crypto
	case TLS_AES_128_CCM_SHA256, TLS_RSA_WITH_AES_128_CCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_SHA256:
		if !kernel.TLS_AESCCM128 {
			return
		}

		crypto := new(kernelCryptoAES128CCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		kc = crypto
	case TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		if !kernel.TLS_CHACHA20 {
			return
		}

		crypto := new(kernelCryptoChacha20Poly1035)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv)
		crypto.rec_seq = hc.seq

		kc = crypto
	case TLS_RSA_WITH_ARIA_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
		if !kernel.TLS_ARIAGCM {
			return
		}

		crypto := new(kernelCryptoARIA128GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		kc = crypto
	case TLS_RSA_WITH_ARIA_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
		if !kernel.TLS_ARIAGCM {
			return
		}

		crypto := new(kernelCryptoARIA256GCM)

		crypto.version = hc.version
		copy(crypto.key[:], hc.key)
		copy(crypto.iv[:], hc.iv[4:])
		copy(crypto.salt[:], hc.iv[:4])
		crypto.rec_seq = hc.seq

		kc = crypto
	default:
		return
	}

	hc.cipher = new(kernelCipher)
	return
}
