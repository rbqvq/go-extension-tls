// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"time"
)

type clientHandshakeStateTLS13 struct {
	c           *Conn
	ctx         context.Context
	serverHello *serverHelloMsg
	hello       *clientHelloMsg
	helloInner  *clientHelloMsg
	ecdheKey    *ecdh.PrivateKey

	session     *SessionState
	earlySecret []byte
	binderKey   []byte

	alpsReq                  bool
	certReq                  *certificateRequestMsgTLS13
	usingPSK                 bool
	earlyData                bool
	sentDummyCCS             bool
	suite                    *cipherSuiteTLS13
	certCompressionAlgorithm CertCompressionAlgorithm
	transcript               hash.Hash
	transcriptInner          hash.Hash
	masterSecret             []byte
	handshakeSecret          []byte // client_handshake_traffic_secret_0
	trafficSecret            []byte // client_application_traffic_secret_0

	extensions []Extension
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.ecdheKey, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakeState.Load() != handshake0RTT && c.handshakes > 0 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.ecdheKey == nil || len(hs.hello.keyShares) < 1 {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()

	if err := transcriptMsg(hs.hello, hs.transcript); err != nil {
		return err
	}

	// When offering ECH, we don't know whether ECH was accepted or rejected
	// until we get the server's response. Compute the transcript of both the
	// inner and outer handshake until we know.
	if c.ech.offered {
		hs.transcriptInner = hs.suite.hash.New()
		helloInnerMarshalled, err := hs.helloInner.marshal()
		if err != nil {
			return fmt.Errorf("tls: ech: helloInner.marshal(): %w", err)
		}
		hs.transcriptInner.Write(helloInnerMarshalled)
	}

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	// Check for ECH acceptance confirmation.
	if c.ech.offered {
		echAcceptConfTranscript := cloneHash(hs.transcriptInner, hs.suite.hash)
		if echAcceptConfTranscript == nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: internal error: failed to clone hash")
		}

		sh, err := hs.serverHello.marshal()
		if err != nil {
			return fmt.Errorf("tls: ech: hs.serverHello.marshal(): %w", err)
		}
		echAcceptConfTranscript.Write(sh[:30])
		echAcceptConfTranscript.Write(zeros[:8])
		echAcceptConfTranscript.Write(sh[38:])
		echAcceptConf := hs.suite.expandLabel(
			hs.suite.extract(hs.helloInner.random, nil),
			echAcceptConfLabel,
			echAcceptConfTranscript.Sum(nil),
			8)

		if subtle.ConstantTimeCompare(hs.serverHello.random[24:], echAcceptConf) == 1 {
			c.ech.accepted = true
			hs.hello = hs.helloInner
			hs.transcript = hs.transcriptInner
		}
	}

	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

	// Resolve the server name now that ECH acceptance has been determined.
	//
	// NOTE(cjpatton): Currently the client sends the same ALPN extension in the
	// ClientHelloInner and ClientHelloOuter. If that changes, then we'll need
	// to resolve ALPN here as well.
	c.serverName = hs.hello.serverName

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.sendClientParameters(); err != nil {
		return err
	}
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if err := hs.abortIfRequired(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}
	if err := c.setup(); err != nil {
		return err
	}
	if err := hs.sendClientData(); err != nil {
		return err
	}
	c.handshakeState.Store(handshakeCompleted)
	return nil
}

// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		c.sendAlert(alertMissingExtension)
		return errors.New("tls: server selected TLS 1.3 using the legacy version field")
	}

	if hs.serverHello.supportedVersion != VersionTLS13 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid version after a HelloRetryRequest")
	}

	if hs.serverHello.vers != VersionTLS12 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an incorrect legacy version")
	}

	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.extendedMasterSecret ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3")
	}

	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not echo the legacy session ID")
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported compression format")
	}

	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.c.quic != nil {
		return nil
	}
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	return hs.c.writeChangeCipherRecord()
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. (The idea is that the server might offload transcript
	// storage to the client in the cookie.) See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

	// Determine which ClientHello message was consumed by the server. If ECH
	// was offered, this may be the ClientHelloInner or ClientHelloOuter.
	hello := hs.hello
	isInner := false
	if c.ech.offered {
		chHash = hs.transcriptInner.Sum(nil)
		hs.transcriptInner.Reset()
		hs.transcriptInner.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		hs.transcriptInner.Write(chHash)

		// Check for ECH acceptance confirmation.
		serverHelloMarshalled, err := hs.serverHello.marshal()
		if err != nil {
			return fmt.Errorf("tls: serverHello.marshal(): %w", err)
		}
		if hs.serverHello.ech != nil {
			if len(hs.serverHello.ech) != 8 {
				c.sendAlert(alertDecodeError)
				return errors.New("tls: ech: hrr: malformed acceptance signal")
			}

			echAcceptConfHRRTranscript := cloneHash(hs.transcriptInner, hs.suite.hash)
			if echAcceptConfHRRTranscript == nil {
				c.sendAlert(alertInternalError)
				return errors.New("tls: internal error: failed to clone hash")
			}

			echAcceptConfHRR := echEncodeAcceptConfHelloRetryRequest(serverHelloMarshalled)
			echAcceptConfHRRTranscript.Write(echAcceptConfHRR)
			echAcceptConfHRRSignal := hs.suite.expandLabel(
				hs.suite.extract(hs.helloInner.random, nil),
				echAcceptConfHRRLabel,
				echAcceptConfHRRTranscript.Sum(nil),
				8)

			if subtle.ConstantTimeCompare(hs.serverHello.ech, echAcceptConfHRRSignal) == 1 {
				hello = hs.helloInner
				isInner = true
			}
		}

		hs.transcriptInner.Write(serverHelloMarshalled)
	}

	// The only HelloRetryRequest extensions we support are key_share and
	// cookie, and clients must abort the handshake if the HRR would not result
	// in any change in the ClientHello.
	if hs.serverHello.selectedGroup == 0 && hs.serverHello.cookie == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an unnecessary HelloRetryRequest message")
	}

	if hs.serverHello.cookie != nil {
		hello.cookie = hs.serverHello.cookie
	}

	if hs.serverHello.serverShare.group != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received malformed key_share extension")
	}

	// If the server sent a key_share extension selecting a group, ensure it's
	// a group we advertised but did not send a key share for, and send a key
	// share for it this time.
	if curveID := hs.serverHello.selectedGroup; curveID != 0 {
		curveOK := false
		for _, id := range hello.supportedCurves {
			if id == curveID {
				curveOK = true
				break
			}
		}
		if !curveOK {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported group")
		}
		if sentID, _ := curveIDForCurve(hs.ecdheKey.Curve()); sentID == curveID {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server sent an unnecessary HelloRetryRequest key_share")
		}
		if _, ok := curveForCurveID(curveID); !ok {
			c.sendAlert(alertInternalError)
			return errors.New("tls: CurvePreferences includes unsupported curve")
		}
		key, err := generateECDHEKey(c.config.rand(), curveID)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.ecdheKey = key
		hello.keyShares = []keyShare{{group: curveID, data: key.PublicKey().Bytes()}}
	}

	hello.raw = nil
	if hello.earlyData {
		hello.earlyData = false

		c.earlyNotify.L.Lock()
		c.earlyDataEOF = true
		c.earlyNotify.L.Unlock()

		if c.quic != nil {
			c.quicRejectedEarlyData()
		}
		c.out.cipher = nil
	}

	if len(hello.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			return c.sendAlert(alertInternalError)
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			ticketAge := c.config.time().Sub(time.Unix(int64(hs.session.createdAt), 0))
			hello.pskIdentities[0].obfuscatedTicketAge = uint32(ticketAge/time.Millisecond) + hs.session.ageAdd

			transcript := hs.suite.hash.New()
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			if err := transcriptMsg(hs.serverHello, transcript); err != nil {
				return err
			}
			helloBytes, err := hello.marshalWithoutBinders()
			if err != nil {
				return err
			}
			transcript.Write(helloBytes)
			pskBinders := [][]byte{hs.suite.finishedHash(hs.binderKey, transcript)}
			if err := hello.updateBinders(pskBinders); err != nil {
				return err
			}
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hello.pskIdentities = nil
			hello.pskBinders = nil
		}
	}

	if isInner {
		hs.helloInner = hello
		helloInnerMarshalled, err := hs.helloInner.marshal()
		if err != nil {
			return fmt.Errorf("tls: ech: helloInner.marshal(): %w", err)
		}
		hs.transcriptInner.Write(helloInnerMarshalled)
		if err := c.echUpdateClientHelloOuter(hs.hello, hs.helloInner, nil); err != nil {
			return err
		}
	} else {
		hs.hello = hello
	}

	hs.hello.automaticPadding(c.config.MinClientHelloSize)

	if _, err := hs.c.writeHandshakeRecord(hs.hello, nil); err != nil {
		return err
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	helloMarshalled, err := hs.hello.marshal()
	if err != nil {
		return fmt.Errorf("tls: hello.marshal(): %w", err)
	}
	hs.transcript.Write(helloMarshalled)
	return nil
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not send a key share")
	}
	if sentID, _ := curveIDForCurve(hs.ecdheKey.Curve()); hs.serverHello.serverShare.group != sentID {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	// Per the rules of draft-ietf-tls-esni-13, Section 6.1, the server is not
	// permitted to resume a connection connection in the outer handshake. If
	// ECH is rejected and the client-facing server replies with a
	// "pre_shared_key" extension in its ServerHello, then the client MUST abort
	// the handshake with an "illegal_parameter" alert.
	if c.ech.offered && !c.ech.accepted {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: ech: client-facing server offered PSK after ECH rejection")
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK and cipher suite pair")
	}

	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.peerCertificates
	c.activeCertHandles = hs.session.activeCertHandles
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c

	peerKey, err := hs.ecdheKey.Curve().NewPublicKey(hs.serverHello.serverShare.data)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}
	sharedKey, err := hs.ecdheKey.ECDH(peerKey)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}

	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		earlySecret = hs.suite.extract(nil, nil)
	}

	handshakeSecret := hs.suite.extract(sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	hs.handshakeSecret = hs.suite.deriveSecret(handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, hs.handshakeSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
	}

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, hs.handshakeSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(handshakeSecret, "derived", nil))

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}

	if err := checkALPN(hs.hello.alpnProtocols, encryptedExtensions.alpnProtocol, c.quic != nil); err != nil {
		// RFC 8446 specifies that no_application_protocol is sent by servers, but
		// does not specify how clients handle the selection of an incompatible protocol.
		// RFC 9001 Section 8.1 specifies that QUIC clients send no_application_protocol
		// in this case. Always sending no_application_protocol seems reasonable.
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	c.clientProtocol = encryptedExtensions.alpnProtocol

	if encryptedExtensions.alps {
		hs.alpsReq = true
		if encryptedExtensions.alpnProtocol == "" {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent application settings without ALPN")
		}

		c.serverProtocolSetting = encryptedExtensions.alpnSetting
	}
	if c.quic != nil {
		if encryptedExtensions.quicTransportParameters == nil {
			// RFC 9001 Section 8.2.
			c.sendAlert(alertMissingExtension)
			return errors.New("tls: server did not send a quic_transport_parameters extension")
		}
		c.quicSetTransportParameters(encryptedExtensions.quicTransportParameters)
	} else {
		if encryptedExtensions.quicTransportParameters != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent an unexpected quic_transport_parameters extension")
		}
	}

	if !hs.hello.earlyData && encryptedExtensions.earlyData {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent an unexpected early_data extension")
	}
	if hs.hello.earlyData && !encryptedExtensions.earlyData && c.quic != nil {
		c.quicRejectedEarlyData()
	}
	if encryptedExtensions.earlyData {
		if hs.session.cipherSuite != c.cipherSuite {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong cipher suite")
		}
		if hs.session.alpnProtocol != c.clientProtocol {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong ALPN")
		}
		if !bytes.Equal(hs.session.alpnServerSetting, c.serverProtocolSetting) {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong ALPS")
		}
		hs.earlyData = true
	}
	if !hs.earlyData {
		c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, hs.handshakeSecret)
	}
	if c.ech.offered && len(encryptedExtensions.ech) > 0 {
		if !c.ech.accepted {
			// If the server rejects ECH, then it may send retry configurations.
			// If present, we must check them for syntactic correctness and
			// abort if they are not correct.
			c.ech.retryConfigs = encryptedExtensions.ech
			if _, err = UnmarshalECHConfigs(c.ech.retryConfigs); err != nil {
				c.sendAlert(alertDecodeError)
				return fmt.Errorf("tls: ech: failed to parse retry configs: %s", err)
			}
		} else {
			// Retry configs must not be sent in the inner handshake.
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: ech: got retry configs after ECH acceptance")
		}
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		hs.certReq = certReq

		msg, err = c.readHandshake(hs.transcript)
		if err != nil {
			return err
		}
	}

	var certMsg *certificateMsgTLS13
	switch msg := msg.(type) {
	case *certificateMsgTLS13:
		certMsg = msg
	case *compressedCertificateMsg:
		hs.certCompressionAlgorithm = CertCompressionAlgorithm(msg.algorithm)
		if !c.config.supportsCertCompression(hs.certCompressionAlgorithm) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported algorithm")
		}
		certMsg, err = msg.decompress()
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	default:
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(msg, msg)
	}

	if len(certMsg.certificate.Certificate) == 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received empty certificates message")
	}

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple

	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	// certificateVerifyMsg is included in the transcript, but not until
	// after we verify the handshake signature, since the state before
	// this message was sent is used.
	msg, err = c.readHandshake(nil)
	if err != nil {
		return err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms()) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	if err := transcriptMsg(certVerify, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	if err := transcriptMsg(finished, hs.transcript); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientParameters() error {
	c := hs.c

	if hs.earlyData || !hs.alpsReq {
		return nil
	}

	var clientProtocolSetting []byte
	var ok bool
	if c.config.GetProtoSetting != nil {
		clientProtocolSetting, ok = c.config.GetProtoSetting(c.clientProtocol, c.serverProtocolSetting)
	} else {
		// Check if the ALPN selected by the server exists in the client's list.
		clientProtocolSetting, ok = c.config.NextProtoSettings[c.clientProtocol]
	}

	if !ok {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected ALPN doesn't match a client ALPS")
	}

	encryptedExtensions := new(encryptedExtensionsMsg)
	encryptedExtensions.alpnSetting = clientProtocolSetting
	encryptedExtensions.extensions = hs.extensions

	if _, err := hs.c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil {
		return err
	}

	c.clientProtocolSetting = clientProtocolSetting
	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:    hs.certReq.certificateAuthorities,
		SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
		Version:          c.vers,
		ctx:              hs.ctx,
	})
	if err != nil {
		return err
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0

	var msg handshakeMessage = certMsg
	if hs.certCompressionAlgorithm != 0 {
		var err error
		msg, err = certMsg.compress(hs.certCompressionAlgorithm)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	if _, err := hs.c.writeHandshakeRecord(msg, hs.transcript); err != nil {
		return err
	}

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true

	certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

	if hs.earlyData {
		c.earlyNotify.L.Lock()
		c.earlyDataEOF = true
		c.earlyNotify.L.Unlock()

		if _, err := hs.c.writeHandshakeRecord(&endOfEarlyDataMsg{}, nil); err != nil {
			return err
		}

		c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, hs.handshakeSecret)
	}

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil {
		return err
	}

	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret)

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
	}

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelApplication, hs.suite.id, hs.trafficSecret)
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientData() error {
	c := hs.c
	defer c.earlyData.Reset()

	if c.earlyData.Len() == 0 {
		return nil
	}

	if !hs.earlyData {
		_, err := c.writeRecordLocked(recordTypeApplicationData, c.earlyData.Bytes())
		return err
	}

	if c.earlyData.Len() <= int(c.maxEarlyData) {
		return nil
	}

	_, err := c.writeRecordLocked(recordTypeApplicationData, c.earlyData.Bytes()[c.maxEarlyData:])
	return err
}

func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received new session ticket from a client")
	}

	if c.handshakeState.Load() == handshake0RTT {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(&endOfEarlyDataMsg{}, msg)
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: received a session ticket with invalid lifetime")
	}

	// RFC 9001, Section 4.6.1
	if c.quic != nil && msg.maxEarlyData != 0 && msg.maxEarlyData != quicMaxEarlyData {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid early data for QUIC connection")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert(alertInternalError)
	}

	psk := cipherSuite.expandLabel(c.resumptionSecret, "resumption",
		msg.nonce, cipherSuite.hash.Size())

	session, err := c.sessionState()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	session.secret = psk
	session.useBy = uint64(c.config.time().Add(lifetime).Unix())
	session.ageAdd = msg.ageAdd
	session.MaxEarlyData = msg.maxEarlyData
	cs := &ClientSessionState{ticket: msg.label, session: session}

	if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
		c.config.ClientSessionCache.Put(cacheKey, cs)
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) abortIfRequired() error {
	c := hs.c
	if c.ech.offered && !c.ech.accepted {
		// If ECH was rejected, then abort the handshake.
		c.sendAlert(alertECHRequired)
		return errors.New("tls: ech: rejected")
	}
	return nil
}
