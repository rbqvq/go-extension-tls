package tls

import (
	"crypto/tls"

	"gitlab.com/go-extension/utils"
)

// Convert exported fields only
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
	}
}

// Unsafe convert using reflect
func (cs ConnectionState) FullCompatible() (tlsState tls.ConnectionState) {
	utils.Convert(&cs, &tlsState)
	return
}

// Convert exported fields only
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
		ekm:                         tlsState.ExportKeyingMaterial,
	}
}

// Unsafe convert using reflect
func FullToConnectionState(tlsState tls.ConnectionState) (cs ConnectionState) {
	utils.Convert(&tlsState, &cs)
	return
}
