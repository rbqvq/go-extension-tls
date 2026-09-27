// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"slices"
)

// Defaults are collected in this file to allow distributions to more easily patch
// them to apply local policies.

// defaultCurvePreferences is the default set of supported key exchanges, as
// well as the preference order.
func defaultCurvePreferences() []CurveID {
	return []CurveID{
		X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
		X25519, CurveP256, CurveP384, CurveP521,
	}
}

// defaultSupportedSignatureAlgorithms returns the signature and hash algorithms that
// the code advertises and supports in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
func defaultSupportedSignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{
		MLDSA44,
		MLDSA65,
		MLDSA87,
		PSSWithSHA256,
		ECDSAWithP256AndSHA256,
		Ed25519,
		PSSWithSHA384,
		PSSWithSHA512,
		PKCS1WithSHA256,
		PKCS1WithSHA384,
		PKCS1WithSHA512,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
		PKCS1WithSHA1,
		ECDSAWithSHA1,
	}
}

// defaultSupportedSignatureAlgorithmsDC returns the signature and hash algorithms that
// the code advertises as supported in a TLS 1.3 ClientHello and in a TLS 1.3
// CertificateRequest. This excludes 'rsa_pss_rsae_' and 'rsa_pkc1s_' algorithms.
func defaultSupportedSignatureAlgorithmsDC() []SignatureScheme {
	return []SignatureScheme{
		ECDSAWithP256AndSHA256,
		Ed25519,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
	}
}

func defaultCertificateCompressionAlgorithms() []CertificateCompressionAlgorithm {
	return []CertificateCompressionAlgorithm{
		Zlib,
		Brotli,
		Zstd,
	}
}

func supportedCipherSuites(aesGCMPreferred bool) []uint16 {
	if aesGCMPreferred {
		return slices.Clone(cipherSuitesPreferenceOrder)
	} else {
		return slices.Clone(cipherSuitesPreferenceOrderNoAES)
	}
}

func defaultCipherSuites(aesGCMPreferred bool) []uint16 {
	cipherSuites := supportedCipherSuites(aesGCMPreferred)
	return slices.DeleteFunc(cipherSuites, func(c uint16) bool {
		return disabledCipherSuites[c] || extendedCipherSuites[c]
	})
}

var defaultCipherSuitesTLS13 = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_AES_128_CCM_SHA256,
	TLS_AES_128_CCM_8_SHA256,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_SM4_GCM_SM3,
	TLS_SM4_CCM_SM3,
}

var defaultCipherSuitesTLS13NoAES = []uint16{
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_AES_128_CCM_SHA256,
	TLS_AES_128_CCM_8_SHA256,
	TLS_SM4_GCM_SM3,
	TLS_SM4_CCM_SM3,
}

var defaultBehavior = &Behavior{
	MaxUselessRecords: maxUselessRecords,
}

var defaultInnerExtensions = []Extension{
	&ServerNameIndicationExtension{},
	&SCTExtension{},
	&EarlyDataExtension{},
	&QUICTransportParametersExtension{},
	&EncryptedClientHelloExtension{},

	&ECHOuterExtension{},

	&PreSharedKeyExtension{},
}

var defaultOuterExtensions = []Extension{
	&ServerNameIndicationExtension{},
	&SCTExtension{},
	&EarlyDataExtension{},
	&QUICTransportParametersExtension{},
	&EncryptedClientHelloExtension{},

	&StatusRequestExtension{},
	&SupportedGroupsExtension{},
	&SignatureAlgorithmsExtension{},
	&SignatureAlgorithmsCertExtension{},
	&ALPNExtension{},
	&SupportedVersionsExtension{},
	&CookieExtension{},
	&KeyShareExtension{},
	&PSKModesExtension{},

	&PreSharedKeyExtension{},
}

var defaultCompressedExtensions = []Extension{
	&StatusRequestExtension{},
	&SupportedGroupsExtension{},
	&SignatureAlgorithmsExtension{},
	&SignatureAlgorithmsCertExtension{},
	&ALPNExtension{},
	&SupportedVersionsExtension{},
	&CookieExtension{},
	&KeyShareExtension{},
	&PSKModesExtension{},
}

var defaultExtensions = []Extension{
	&ServerNameIndicationExtension{},
	&SupportedPointsExtension{},
	&SessionTicketExtension{},
	&RenegotiationInfoExtension{},
	&ExtendedMasterSecretExtension{},
	&SCTExtension{},
	&EarlyDataExtension{},
	&QUICTransportParametersExtension{},
	&EncryptedClientHelloExtension{},

	&StatusRequestExtension{},
	&SupportedGroupsExtension{},
	&SignatureAlgorithmsExtension{},
	&SignatureAlgorithmsCertExtension{},
	&ALPNExtension{},
	&SupportedVersionsExtension{},
	&CookieExtension{},
	&KeyShareExtension{},
	&PSKModesExtension{},

	&PreSharedKeyExtension{},
}

var defaultEncryptedClientHelloConfig = &ECHConfig{}
