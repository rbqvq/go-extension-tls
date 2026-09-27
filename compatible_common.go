// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/tls"

	"gitlab.com/go-extension/utils"
)

// Convert exported ConnectionState fields.
func (cs ConnectionState) Compatible() tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
		ECHAccepted:                 cs.ECHAccepted,
		HelloRetryRequest:           cs.HelloRetryRequest,
		LocalCertificate:            cs.LocalCertificate,
	}
}

// Convert all ConnectionState fields by reflect (unsafe).
func (cs ConnectionState) FullCompatible() (tlsState tls.ConnectionState) {
	utils.Convert(&cs, &tlsState)
	return
}

// Convert exported ConnectionState fields.
func ToConnectionState(tlsState tls.ConnectionState) ConnectionState {
	return ConnectionState{
		Version:                     tlsState.Version,
		HandshakeComplete:           tlsState.HandshakeComplete,
		DidResume:                   tlsState.DidResume,
		CipherSuite:                 tlsState.CipherSuite,
		NegotiatedProtocol:          tlsState.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  tlsState.NegotiatedProtocolIsMutual,
		ServerName:                  tlsState.ServerName,
		PeerCertificates:            tlsState.PeerCertificates,
		VerifiedChains:              tlsState.VerifiedChains,
		SignedCertificateTimestamps: tlsState.SignedCertificateTimestamps,
		OCSPResponse:                tlsState.OCSPResponse,
		TLSUnique:                   tlsState.TLSUnique,
		ECHAccepted:                 tlsState.ECHAccepted,
		HelloRetryRequest:           tlsState.HelloRetryRequest,
		LocalCertificate:            tlsState.LocalCertificate,
		ekm:                         tlsState.ExportKeyingMaterial,
	}
}

// Convert all ConnectionState fields by reflect (unsafe).
func FullToConnectionState(tlsState tls.ConnectionState) (cs ConnectionState) {
	utils.Convert(&tlsState, &cs)
	return
}
