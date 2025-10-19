// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "slices"

func fullCipherSuites(aesGCMPreferred bool) []uint16 {
	cipherSuites := supportedCipherSuites(aesGCMPreferred)
	return slices.DeleteFunc(cipherSuites, func(c uint16) bool {
		return disabledCipherSuites[c] ||
			rsaKexCiphers[c] ||
			tdesCiphers[c]
	})
}

func fullCurvePreferences() []CurveID {
	return []CurveID{X25519MLKEM768, X25519Kyber768Draft00, X25519, CurveP256, CurveP384, CurveP521, CurveSM2, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192}
}

var fullInnerExtensions = []Extension{
	&ServerNameIndicationExtension{},
	&SCTExtension{},
	&EarlyDataExtension{},
	&QUICTransportParametersExtension{},
	&EncryptedClientHelloExtension{},

	&ECHOuterExtension{},

	&PreSharedKeyExtension{},
}

var fullOuterExtensions = []Extension{
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
	&ALPSExtension{},
	&CompressedCertificateExtension{},
	&DelegatedCredentialsExtension{},
	&RecordSizeLimitExtension{},

	&PaddingExtension{},
	&PreSharedKeyExtension{},
}

var fullCompressedExtensions = []Extension{
	&StatusRequestExtension{},
	&SupportedGroupsExtension{},
	&SignatureAlgorithmsExtension{},
	&SignatureAlgorithmsCertExtension{},
	&ALPNExtension{},
	&SupportedVersionsExtension{},
	&CookieExtension{},
	&KeyShareExtension{},
	&PSKModesExtension{},
	&ALPSExtension{},
	&CompressedCertificateExtension{},
	&DelegatedCredentialsExtension{},
	&RecordSizeLimitExtension{},
}

var fullExtensions = []Extension{
	&ServerNameIndicationExtension{},
	&SupportedPointsExtension{},
	&SessionTicketExtension{},
	&RenegotiationInfoExtension{},
	&ExtendedMasterSecretExtension{},
	&EncryptThenMacExtension{},
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
	&ALPSExtension{},
	&CompressedCertificateExtension{},
	&DelegatedCredentialsExtension{},
	&RecordSizeLimitExtension{},

	&PaddingExtension{},
	&PreSharedKeyExtension{},
}

var fullEncryptedClientHelloConfig = &ECHConfig{
	InnerExtensions:      fullInnerExtensions,
	OuterExtensions:      fullOuterExtensions,
	CompressedExtensions: fullCompressedExtensions,
}
