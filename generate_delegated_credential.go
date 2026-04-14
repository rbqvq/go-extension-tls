// Copyright 2025 The Go Authors and Cloudflare, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// Generate a delegated credential with the given signature scheme, signed with
// the given x.509 key pair. Outputs to 'dc.cred' and 'dckey.pem' and will
// overwrite existing files.

// Example usage:
// generate_delegated_credential -cert-path cert.pem -key-path key.pem -signature-scheme Ed25519 -duration 24h

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"gitlab.com/go-extension/tls"
)

var (
	validFor         = flag.Duration("duration", 5*24*time.Hour, "Duration that credential is valid for")
	signatureScheme  = flag.String("signature", "", "The signature scheme used by the delegated credential")
	certVerifyScheme = flag.String("cert-verify", "", "The signature scheme used by the certificate verify message")
	certPath         = flag.String("cert-path", "./cert.pem", "Path to signing cert")
	keyPath          = flag.String("key-path", "./key.pem", "Path to signing key")
	isClient         = flag.Bool("client", false, "Create a client Delegated Credential")
)

var SigStringMap = map[string]tls.SignatureScheme{
	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	"ECDSAWithP256AndSHA256": tls.ECDSAWithP256AndSHA256,
	"ECDSAWithP384AndSHA384": tls.ECDSAWithP384AndSHA384,
	"ECDSAWithP521AndSHA512": tls.ECDSAWithP521AndSHA512,

	// EdDSA algorithms.
	"Ed25519": tls.Ed25519,
}

func main() {
	flag.Parse()
	sigAlgo := SigStringMap[*signatureScheme]
	certVerifyAlgo := SigStringMap[*certVerifyScheme]

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("Failed to load certificate and key: %v", err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	delegatedCredential, err := cert.NewDelegatedCredential(*isClient, time.Now().Add(*validFor), sigAlgo, certVerifyAlgo)
	if err != nil {
		log.Fatalf("Failed to create a delegated credential: %v\n", err)
	}

	credentialOut, err := os.Create("delegated_credential.pem")
	if err != nil {
		log.Fatalf("Failed to open delegated_credential.pem for writing: %v", err)
	}
	dcBytes, err := delegatedCredential.Bytes()
	if err != nil {
		log.Fatalf("Failed to marshal delegated credential: %v\n", err)
	}
	if err := pem.Encode(credentialOut, &pem.Block{Type: "DELEGATED CREDENTIAL", Bytes: dcBytes}); err != nil {
		log.Fatalf("Failed to write data to delegated_key.pem: %v\n", err)
	}
	if err := credentialOut.Close(); err != nil {
		log.Fatalf("Error closing delegated_credential.pem: %v", err)
	}
	log.Print("wrote delegated_credential.pem\n")

	keyOut, err := os.OpenFile("delegated_key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open delegated_key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(delegatedCredential.PrivateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to delegated_key.pem: %v\n", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing delegated_key.pem: %v\n", err)
	}
	log.Print("wrote delegated_key.pem\n")

	fmt.Println("Success")
}
