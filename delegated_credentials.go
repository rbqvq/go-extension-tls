// Copyright 2025 The Go Authors and Cloudflare, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// In the absence of an application profile standard specifying otherwise,
	// the maximum validity period is set to 7 days.
	maxDelegatetdCredentialLifetime  = time.Duration(7 * 24 * time.Hour)
	maxDelegatetdCredentialPublicKey = (1 << 24) - 1
	maxDelegatetdCredentialSignature = (1 << 16) - 1
)

var oidExtensionDelegatedCredential = []int{1, 3, 6, 1, 4, 1, 44363, 44}

// isValidForDelegation returns true if a certificate can be used for Delegated
// Credentials.
func isValidForDelegation(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	// The certificate must contains the digitalSignature KeyUsage.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's marked as non-critical (See Section 4.2 of RFC 5280).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidExtensionDelegatedCredential) {
			return !extension.Critical
		}
	}
	return false
}

// Credential stores the public components of a Delegated Credential.
type Credential struct {
	// The amount of time for which the credential is valid. Specifically, the
	// the credential expires 'validTime' seconds after the 'notBefore' of the
	// delegation certificate. The delegator shall not issue Delegated
	// Credentials that are valid for more than 7 days from the current time.
	ValidTime time.Duration
	// The signature scheme associated with the credential public key.
	// This is expected to be the same as the CertificateVerify.algorithm
	// sent by the client or server.
	CertVerifyAlgorithm SignatureScheme
	// The credential's public key.
	PublicKey crypto.PublicKey
}

// DelegatedCredential stores a Delegated Credential with the credential and its
// signature.
type DelegatedCredential struct {
	// The serialized form of the Delegated Credential.
	Raw []byte

	// Cred stores the public components of a Delegated Credential.
	Credential Credential

	// The signature scheme associated with the credential public key.
	// This is expected to be the same as the CertificateVerify.algorithm
	// sent by the client or server.
	Algorithm SignatureScheme

	// The Credential's delegation: a signature that binds the credential to
	// the end-entity certificate's public key.
	Signature []byte

	// PrivateKey is the private key used to derive the public key of
	// contained in DC. PrivateKey must implement crypto.Signer.
	PrivateKey crypto.PrivateKey
}

func (delegatedCredential *DelegatedCredential) marshal() ([]byte, error) {
	if delegatedCredential.Raw != nil {
		return delegatedCredential.Raw, nil
	}

	publicKey, err := x509.MarshalPKIXPublicKey(delegatedCredential.Credential.PublicKey)
	if err != nil {
		return nil, err
	}

	if len(publicKey) > maxDelegatetdCredentialPublicKey {
		return nil, errors.New("tls: credential public key length exceeds 2^24-1 limit")
	}

	var b cryptobyte.Builder
	b.AddUint32(uint32(delegatedCredential.Credential.ValidTime / time.Second))
	b.AddUint16(uint16(delegatedCredential.Credential.CertVerifyAlgorithm))
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(publicKey)
	})
	b.AddUint16(uint16(delegatedCredential.Algorithm))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(delegatedCredential.Signature)
	})

	delegatedCredential.Raw, err = b.Bytes()
	return delegatedCredential.Raw, err
}

func (delegatedCredential *DelegatedCredential) marshalWithoutSignature() ([]byte, error) {
	signatureLen := 2 // uint16 length prefix
	signatureLen += len(delegatedCredential.Signature)

	credential, err := delegatedCredential.marshal()
	if err != nil {
		return nil, err
	}
	return credential[:len(credential)-signatureLen], nil
}

func (delegatedCredential *DelegatedCredential) Bytes() ([]byte, error) {
	return delegatedCredential.marshal()
}

func parseDelegatedCredential(data []byte) (delegatedCredential DelegatedCredential, err error) {
	delegatedCredential.Raw = data

	var validTime uint32
	var certVerifyAlgorithm uint16
	var publicKey []byte
	var algorithm uint16

	s := cryptobyte.String(data)
	if !s.ReadUint32(&validTime) ||
		!s.ReadUint16(&certVerifyAlgorithm) ||
		!readUint24LengthPrefixed(&s, &publicKey) ||
		!s.ReadUint16(&algorithm) ||
		!readUint16LengthPrefixed(&s, &delegatedCredential.Signature) ||
		!s.Empty() {
		return DelegatedCredential{}, errors.New("tls: malformed delegated credential")
	}

	delegatedCredential.Credential.PublicKey, err = x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return DelegatedCredential{}, err
	}

	delegatedCredential.Credential.ValidTime = time.Duration(validTime) * time.Second
	delegatedCredential.Credential.CertVerifyAlgorithm = SignatureScheme(certVerifyAlgorithm)
	delegatedCredential.Algorithm = SignatureScheme(algorithm)
	return
}

// SupportedDelegatedCredentialAlgorithms returns the signature and hash algorithms that
// the code advertises as supported in a TLS 1.3 ClientHello and in a TLS 1.3
// CertificateRequest. This excludes 'rsa_pss_rsae_' and 'rsa_pkc1s_' algorithms.
func SupportedDelegatedCredentialAlgorithms() []SignatureScheme {
	return defaultSupportedSignatureAlgorithmsDC()
}

// SignatureAlgorithms returns supported signature algorithms by public key of leaf certificate.
func (cert *Certificate) SignatureAlgorithms(version uint16) ([]SignatureScheme, error) {
	x509Cert, err := cert.leaf()
	if err != nil {
		return nil, err
	}

	supportedAlgs := signatureSchemesForPublicKey(version, x509Cert.PublicKey)
	if version >= VersionTLS13 {
		supportedAlgs = slices.DeleteFunc(supportedAlgs, func(sigAlg SignatureScheme) bool {
			// TLS 1.3 removed support for PKCS#1 v1.5 and SHA-1 signatures.
			return isDisabledSignatureAlgorithm(version, sigAlg, false)
		})
	}
	if cert.SupportedSignatureAlgorithms != nil {
		supportedAlgs = slices.DeleteFunc(supportedAlgs, func(sigAlg SignatureScheme) bool {
			return !isSupportedSignatureAlgorithm(sigAlg, cert.SupportedSignatureAlgorithms)
		})
	}
	return supportedAlgs, nil
}

// NewDelegatedCredential creates a new Delegated Credential for delegation.
func (cert *Certificate) NewDelegatedCredential(isClient bool, notAfter time.Time, algorithm, certVerifyAlgorithm SignatureScheme) (DelegatedCredential, error) {
	fail := func(err error) (DelegatedCredential, error) { return DelegatedCredential{}, err }

	x509Cert, err := cert.leaf()
	if err != nil {
		return fail(err)
	}

	if notAfter.Before(x509Cert.NotBefore) {
		return fail(errors.New("tls: delegated credential lifetime before the certificate lifetime"))
	}
	if notAfter.After(x509Cert.NotAfter) {
		return fail(errors.New("tls: delegated credential lifetime exceeds the certificate lifetime"))
	}

	validTime := notAfter.Sub(x509Cert.NotBefore).Truncate(time.Second)
	if validTime <= 0 {
		return fail(errors.New("tls: delegated credential lifetime before the certificate lifetime"))
	}

	if !isValidForDelegation(x509Cert) {
		return fail(errors.New("tls: certificate not authorized for delegation"))
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fail(fmt.Errorf("tls: certificate private key (%T) does not implement crypto.Signer",
			cert.PrivateKey))
	}

	if !isSupportedSignatureAlgorithm(algorithm, signatureSchemesForPublicKey(VersionTLS13, x509Cert.PublicKey)) {
		return fail(errors.New("tls: delegated credential used with invalid signature algorithm"))
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(algorithm)
	if err != nil {
		return fail(err)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return fail(errors.New("tls: delegated credential used with invalid signature algorithm"))
	}

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	switch certVerifyAlgorithm {
	case ECDSAWithP256AndSHA256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fail(err)
		}
		privateKey = key
		publicKey = key.Public()
	case ECDSAWithP384AndSHA384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return fail(err)
		}
		privateKey = key
		publicKey = key.Public()
	case ECDSAWithP521AndSHA512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return fail(err)
		}
		privateKey = key
		publicKey = key.Public()
	case Ed25519:
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("tls: unsupported certVerifyAlgorithm for delegated credential: %s", certVerifyAlgorithm))
	}

	delegatedCredential := DelegatedCredential{
		Credential: Credential{
			ValidTime:           validTime,
			CertVerifyAlgorithm: certVerifyAlgorithm,
			PublicKey:           publicKey,
		},
		Algorithm:  algorithm,
		PrivateKey: privateKey,
	}

	credential, err := delegatedCredential.marshalWithoutSignature()
	if err != nil {
		return fail(err)
	}

	context := serverCredentialSignatureContext
	if isClient {
		context = clientCredentialSignatureContext
	}
	signed := signedCredential(sigHash, context, x509Cert.Raw, credential)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	signature, err := signer.Sign(rand.Reader, signed, signOpts)
	if err != nil {
		return fail(err)
	}
	if len(signature) > maxDelegatetdCredentialSignature {
		return fail(errors.New("tls: delegated credential signature is too large, try anther signature algorithm"))
	}
	delegatedCredential.Signature = signature

	// reset raw because we called marshalWithoutSignature
	delegatedCredential.Raw = nil

	return delegatedCredential, nil
}

// LoadDelegatedCredentialKeyPair reads and parses a public/private key pair from a pair of
// files. The files must contain PEM encoded data.
func (cert *Certificate) LoadDelegatedCredentialKeyPair(cerdentialFile, keyFile string) (DelegatedCredential, error) {
	dcPEMBlock, err := os.ReadFile(cerdentialFile)
	if err != nil {
		return DelegatedCredential{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return DelegatedCredential{}, err
	}
	return cert.DelegatedCredentialKeyPair(dcPEMBlock, keyPEMBlock)
}

// DelegatedCredentialKeyPair parses a public/private key pair from a pair of
// PEM encoded data.
func (cert *Certificate) DelegatedCredentialKeyPair(dcPEMBlock, keyPEMBlock []byte) (DelegatedCredential, error) {
	fail := func(err error) (DelegatedCredential, error) { return DelegatedCredential{}, err }

	var dcBlock *pem.Block
	var skippedBlockTypes []string
	for {
		dcBlock, dcPEMBlock = pem.Decode(dcPEMBlock)
		if dcBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in certificate input"))
			}
			if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
				return fail(errors.New("tls: failed to find delegated credential PEM data in delegated credential input, but did find a private key; PEM inputs may have been switched"))
			}
			return fail(fmt.Errorf("tls: failed to find \"DELEGATED CREDENTIAL\" PEM block in delegated credential input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if dcBlock.Type == "DELEGATED CREDENTIAL" {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, dcBlock.Type)
	}

	delegatedCredential, err := parseDelegatedCredential(dcBlock.Bytes)
	if err != nil {
		return fail(err)
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "DELEGATED CREDENTIAL" {
				return fail(errors.New("tls: found a delegated credential rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	delegatedCredential.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}

	x509Cert, err := cert.leaf()
	if err != nil {
		return fail(err)
	}

	if !isSupportedSignatureAlgorithm(delegatedCredential.Algorithm, signatureSchemesForPublicKey(VersionTLS13, x509Cert.PublicKey)) {
		return fail(errors.New("tls: delegated credential used with invalid signature algorithm"))
	}

	switch pub := delegatedCredential.Credential.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := delegatedCredential.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := delegatedCredential.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := delegatedCredential.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("tls: private key does not match public key"))
		}
	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}

	return delegatedCredential, nil
}
