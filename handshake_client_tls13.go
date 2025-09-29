// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"slices"
	"time"

	"golang.org/x/crypto/hkdf"
)

type clientHandshakeStateTLS13 struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	keyShareKeys []*keySharePrivateKeys

	session     *SessionState
	earlySecret []byte
	binderKey   []byte

	alpsReq                  bool
	certReq                  *certificateRequestMsgTLS13
	usingPSK                 bool
	earlyData                bool
	sentDummyCCS             bool
	certCompressionAlgorithm CertCompressionAlgorithm
	suite                    *cipherSuiteTLS13
	transcript               hash.Hash
	masterSecret             []byte
	handshakeSecret          []byte // client_handshake_traffic_secret_0
	trafficSecret            []byte // client_application_traffic_secret_0

	echContext *echClientContext

	extensions []Extension
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.keyShareKeys, and,
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
	if len(hs.keyShareKeys) < 1 ||
		slices.ContainsFunc(hs.keyShareKeys, func(keyShareKeys *keySharePrivateKeys) bool { return keyShareKeys == nil }) ||
		len(hs.hello.keyShares) == 0 {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()

	if err := transcriptMsg(hs.hello, hs.transcript); err != nil {
		return err
	}

	if hs.echContext != nil {
		hs.echContext.innerTranscript = hs.suite.hash.New()
		if err := transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript); err != nil {
			return err
		}
	}

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	if hs.echContext != nil {
		confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
		confTranscript.Write(hs.serverHello.original[:30])
		confTranscript.Write(make([]byte, 8))
		confTranscript.Write(hs.serverHello.original[38:])
		acceptConfirmation := hs.suite.expandLabel(
			hkdf.Extract(hs.suite.hash.New, hs.echContext.innerHello.random, nil),
			"ech accept confirmation",
			confTranscript.Sum(nil),
			8,
		)
		if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.random[len(hs.serverHello.random)-8:]) == 1 {
			hs.hello = hs.echContext.innerHello
			c.serverName = c.config.ServerName
			hs.transcript = hs.echContext.innerTranscript
			c.echAccepted = true

			if hs.serverHello.encryptedClientHello != nil {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected encrypted client hello extension in server hello despite ECH being accepted")
			}

			if hs.hello.serverName == "" && hs.serverHello.serverNameAck {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected server_name extension in server hello")
			}

			hs.extensions = hs.echContext.innerHello.extensionList
			for _, extension := range hs.serverHello.extensions {
				switch extension := extension.(type) {
				case nil:
				case *UnimplementedExtension:
					for _, ext := range hs.extensions {
						if ext == nil {
							continue
						}

						if ext.ExtensionId() != extension.ExtensionId() {
							continue
						}

						ext.NegotiatedVersion(c.vers)

						ok, err := ext.Unmarshal(typeServerHello, true, extension.Data, c.extensionState)
						if !ok {
							return c.sendAlert(alertDecodeError)
						}
						if err != nil {
							c.sendAlert(alertIllegalParameter)
							return err
						}
						break
					}
				}
			}
		} else {
			hs.echContext.echRejected = true
		}
	}

	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

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
	if _, err := c.flush(); err != nil {
		return err
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		c.sendAlert(alertECHRequired)
		return &ECHRejectionError{hs.echContext.retryConfigs}
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
		c.sendAlert(alertDecodeError)
		return errors.New("tls: server sent non-zero legacy TLS compression method")
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

	var isInnerHello bool
	hello := hs.hello
	if hs.echContext != nil {
		chHash = hs.echContext.innerTranscript.Sum(nil)
		hs.echContext.innerTranscript.Reset()
		hs.echContext.innerTranscript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		hs.echContext.innerTranscript.Write(chHash)

		if hs.serverHello.encryptedClientHello != nil {
			if len(hs.serverHello.encryptedClientHello) != 8 {
				hs.c.sendAlert(alertDecodeError)
				return errors.New("tls: malformed encrypted client hello extension")
			}

			confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
			hrrHello := make([]byte, len(hs.serverHello.original))
			copy(hrrHello, hs.serverHello.original)
			hrrHello = bytes.Replace(hrrHello, hs.serverHello.encryptedClientHello, make([]byte, 8), 1)
			confTranscript.Write(hrrHello)
			acceptConfirmation := hs.suite.expandLabel(
				hkdf.Extract(hs.suite.hash.New, hs.echContext.innerHello.random, nil),
				"hrr ech accept confirmation",
				confTranscript.Sum(nil),
				8,
			)
			if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.encryptedClientHello) == 1 {
				hello = hs.echContext.innerHello
				c.serverName = c.config.ServerName
				isInnerHello = true
				c.echAccepted = true

				hs.extensions = hs.echContext.innerHello.extensionList
				for _, extension := range hs.serverHello.extensions {
					switch extension := extension.(type) {
					case nil:
					case *UnimplementedExtension:
						for _, ext := range hs.extensions {
							if ext == nil {
								continue
							}

							if ext.ExtensionId() != extension.ExtensionId() {
								continue
							}

							ext.NegotiatedVersion(c.vers)

							ok, err := ext.Unmarshal(typeServerHello, true, extension.Data, c.extensionState)
							if !ok {
								return c.sendAlert(alertDecodeError)
							}
							if err != nil {
								c.sendAlert(alertIllegalParameter)
								return err
							}
							break
						}
					}
				}
			}
		}

		if err := transcriptMsg(hs.serverHello, hs.echContext.innerTranscript); err != nil {
			return err
		}
	} else if hs.serverHello.encryptedClientHello != nil {
		// Unsolicited ECH extension should be rejected
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: unexpected encrypted client hello extension in serverHello")
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
		if !slices.Contains(hello.supportedCurves, curveID) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported group")
		}
		if slices.ContainsFunc(hs.hello.keyShares, func(ks keyShare) bool {
			return ks.group == curveID
		}) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server sent an unnecessary HelloRetryRequest key_share")
		}
		switch curveID {
		case X25519MLKEM768:
			key, err := generateECDHEKey(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			x25519EphemeralKey := key.PublicKey().Bytes()

			mlkem, err := generateMLKEM768Key(c.config.rand())
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			mlkemEncapsulationKey := mlkem.EncapsulationKey().Bytes()

			hs.keyShareKeys = []*keySharePrivateKeys{{curveID: curveID, ecdhe: key, mlkem: mlkem}}
			hello.keyShares = []keyShare{{group: curveID, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)}}
		case X25519Kyber768Draft00:
			key, err := generateECDHEKey(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			x25519EphemeralKey := key.PublicKey().Bytes()

			mlkem, err := generateMLKEM768Key(c.config.rand())
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			mlkemEncapsulationKey := mlkem.EncapsulationKey().Bytes()

			hs.keyShareKeys = []*keySharePrivateKeys{{curveID: curveID, ecdhe: key, mlkem: mlkem}}
			hello.keyShares = []keyShare{{group: curveID, data: append(x25519EphemeralKey, mlkemEncapsulationKey...)}}
		case X25519, CurveP256, CurveP384, CurveP521:
			key, err := generateECDHEKey(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			hs.keyShareKeys = []*keySharePrivateKeys{{curveID: curveID, ecdhe: key}}
			hello.keyShares = []keyShare{{group: curveID, data: key.PublicKey().Bytes()}}
		case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
			key, err := generateFFDHEKey(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			hs.keyShareKeys = []*keySharePrivateKeys{{curveID: curveID, ffdhe: key}}
			hello.keyShares = []keyShare{{group: curveID, data: key.PublicKey().Bytes()}}
		default:
			if IsGREASE(curveID) {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: server selected grease group")
			}

			c.sendAlert(alertInternalError)
			return errors.New("tls: CurvePreferences includes unsupported curve")
		}
	}

	if hello.earlyData {
		hello.earlyData = false

		if c.quic == nil {
			c.earlyNotify.L.Lock()
			c.earlyDataEOF = true
			c.earlyNotify.L.Unlock()
		} else {
			c.quicRejectedEarlyData()
		}
		c.out.cipher = nil
	}

	echConf := c.config.echConfig()
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

			setupInnerClientHelloCompress(echConf, hs.hello, hello)
			c.config.updateClientHelloPadding(hello, true)

			if err := computeAndUpdatePSK(hello, hs.binderKey, transcript, hs.suite.finishedHash); err != nil {
				return err
			}
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hello.pskIdentities = nil
			hello.pskBinders = nil
			setupInnerClientHelloCompress(echConf, hs.hello, hello)
			c.config.updateClientHelloPadding(hello, true)
		}
	} else {
		setupInnerClientHelloCompress(echConf, hs.hello, hello)
		c.config.updateClientHelloPadding(hello, true)
	}

	if isInnerHello {
		// Any extensions which have changed in hello, but are mirrored in the
		// outer hello and compressed, need to be copied to the outer hello, so
		// they can be properly decompressed by the server.
		hs.hello.pskBinders = hello.pskBinders
		hs.echContext.innerHello = hello
		if err := transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript); err != nil {
			return err
		}

		if err := c.config.computeAndUpdateOuterECHExtension(hs.hello, hs.echContext.innerHello, hs.echContext, false); err != nil {
			return err
		}
	} else {
		hs.hello = hello
	}

	if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
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

	extensions := hs.hello.extensionList
	for _, extension := range serverHello.extensions {
		switch extension := extension.(type) {
		case nil:
		case *UnimplementedExtension:
			for _, ext := range extensions {
				if ext == nil {
					continue
				}

				if ext.ExtensionId() != extension.ExtensionId() {
					continue
				}

				ext.NegotiatedVersion(c.vers)

				ok, err := ext.Unmarshal(typeServerHello, false, extension.Data, c.extensionState)
				if !ok {
					return c.sendAlert(alertDecodeError)
				}
				if err != nil {
					c.sendAlert(alertIllegalParameter)
					return err
				}
				break
			}
		}
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	c.didHRR = true
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
	if !slices.ContainsFunc(hs.keyShareKeys, func(keyShareKeys *keySharePrivateKeys) bool {
		if keyShareKeys.curveID != hs.serverHello.serverShare.group {
			return false
		}

		hs.keyShareKeys = []*keySharePrivateKeys{keyShareKeys}
		return true
	}) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
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
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c
	keyShareKeys := hs.keyShareKeys[0]

	var sharedKey []byte
	switch hs.serverHello.serverShare.group {
	case X25519MLKEM768:
		if keyShareKeys.mlkem == nil || keyShareKeys.ecdhe == nil {
			return c.sendAlert(alertInternalError)
		}

		if len(hs.serverHello.serverShare.data) != mlkem.CiphertextSize768+x25519PublicKeySize {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server X25519MLKEM768 key share")
		}

		peerData := hs.serverHello.serverShare.data[mlkem.CiphertextSize768:]
		peerKey, err := keyShareKeys.ecdhe.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}

		sharedKey, err = keyShareKeys.ecdhe.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}

		ciphertext := hs.serverHello.serverShare.data[:mlkem.CiphertextSize768]
		mlkemShared, err := keyShareKeys.mlkem.Decapsulate(ciphertext)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519MLKEM768 server key share")
		}
		sharedKey = append(mlkemShared, sharedKey...)
	case X25519Kyber768Draft00:
		if keyShareKeys.mlkem == nil || keyShareKeys.ecdhe == nil {
			return c.sendAlert(alertInternalError)
		}

		if len(hs.serverHello.serverShare.data) != x25519PublicKeySize+mlkem.CiphertextSize768 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server X25519Kyber768Draft00 key share")
		}

		peerData := hs.serverHello.serverShare.data[:x25519PublicKeySize]
		peerKey, err := keyShareKeys.ecdhe.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}

		sharedKey, err = keyShareKeys.ecdhe.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}

		ciphertext := hs.serverHello.serverShare.data[x25519PublicKeySize:]
		mlkemShared, err := keyShareKeys.mlkem.Decapsulate(ciphertext)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519Kyber768Draft00 server key share")
		}
		kyberShared := kyberSharedSecret(mlkemShared, ciphertext)
		sharedKey = append(sharedKey, kyberShared...)
	case X25519, CurveP256, CurveP384, CurveP521:
		if keyShareKeys.ecdhe == nil {
			return c.sendAlert(alertInternalError)
		}

		peerData := hs.serverHello.serverShare.data
		peerKey, err := keyShareKeys.ecdhe.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}

		sharedKey, err = keyShareKeys.ecdhe.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}
	case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
		if keyShareKeys.ffdhe == nil {
			return c.sendAlert(alertInternalError)
		}

		peerData := hs.serverHello.serverShare.data
		peerKey, err := keyShareKeys.ffdhe.Group().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}

		sharedKey, err = keyShareKeys.ffdhe.FFDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}
	default:
		if IsGREASE(hs.serverHello.serverShare.group) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected grease group")
		}

		c.sendAlert(alertInternalError)
		return errors.New("tls: CurvePreferences includes unsupported curve")
	}
	c.curveID = hs.serverHello.serverShare.group

	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		earlySecret = hs.suite.extract(nil, nil)
	}

	handshakeSecret := hs.suite.extract(sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	clientSecret := hs.suite.deriveSecret(handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	if c.quic != nil {
		c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret)
	}
	serverSecret := hs.suite.deriveSecret(handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)

	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, clientSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
	}

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	hs.handshakeSecret = clientSecret
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

	for _, extension := range encryptedExtensions.extensions {
		switch extension := extension.(type) {
		case nil:
		case *UnimplementedExtension:
			for _, ext := range hs.extensions {
				if ext == nil {
					continue
				}

				if ext.ExtensionId() != extension.ExtensionId() {
					continue
				}

				ok, err := ext.Unmarshal(typeEncryptedExtensions, c.echAccepted, extension.Data, c.extensionState)
				if !ok {
					return c.sendAlert(alertDecodeError)
				}
				if err != nil {
					c.sendAlert(alertIllegalParameter)
					return err
				}
				break
			}
		}
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
	if c.quic == nil && !hs.earlyData {
		c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, hs.handshakeSecret)
	}
	if hs.echContext != nil {
		if hs.echContext.echRejected {
			hs.echContext.retryConfigs = encryptedExtensions.echRetryConfigs
		} else if encryptedExtensions.echRetryConfigs != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent encrypted client hello retry configs after accepting encrypted client hello")
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) verifyServerDelegatedCredential(delegatedCredential *DelegatedCredential) error {
	c := hs.c

	cert := c.peerCertificates[0]
	if !isValidForDelegation(cert) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server certificate not authorized for delegation")
	}

	now := c.config.time()
	notAfter := cert.NotBefore.Add(delegatedCredential.Credential.ValidTime)
	if notAfter.After(cert.NotAfter) {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("tls: invalid server delegated credential, credential time %s is after %s", notAfter.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	if now.After(notAfter) {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("tls: server delegated credential is expired, current time %s is after %s", now.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}

	lifetime := notAfter.Sub(now)
	if lifetime > maxDelegatetdCredentialLifetime {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("tls: invalid server delegated credential lifetime, current time %s is more than 7-day before %s", now.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(delegatedCredential.Algorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return c.sendAlert(alertInternalError)
	}
	credential, err := delegatedCredential.marshalWithoutSignature()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	signed := signedCredential(sigHash, serverCredentialSignatureContext, cert.Raw, credential)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey,
		sigHash, signed, delegatedCredential.Signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid delegated credential signature by the server certificate: " + err.Error())
	}

	c.verifiedDC = delegatedCredential
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

	publicKey := c.peerCertificates[0].PublicKey
	supportedSignatureAlgorithms := slices.DeleteFunc(slices.Clone(hs.hello.supportedSignatureAlgorithms), func(s SignatureScheme) bool { return isDisabledSignatureAlgorithm(VersionTLS13, s, false) })
	publicKeySignatureAlgorithms := signatureSchemesForPublicKey(c.vers, publicKey)
	if len(certMsg.delegatedCredential) != 0 {
		if len(hs.hello.supportedSignatureAlgorithmsDC) <= 0 {
			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: server sent an unexpected delegated credential extension")
		}

		delegatedCredential, err := parseDelegatedCredential(certMsg.delegatedCredential)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return err
		}

		if !isSupportedSignatureAlgorithm(delegatedCredential.Algorithm, supportedSignatureAlgorithms) ||
			!isSupportedSignatureAlgorithm(delegatedCredential.Algorithm, publicKeySignatureAlgorithms) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: certificate used with invalid signature algorithm")
		}

		if !isSupportedSignatureAlgorithm(delegatedCredential.Credential.CertVerifyAlgorithm, signatureSchemesForPublicKeyDC(delegatedCredential.Credential.PublicKey)) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: delegated credential used with invalid signature algorithm")
		}

		if err := hs.verifyServerDelegatedCredential(&delegatedCredential); err != nil {
			return err
		}

		publicKey = c.verifiedDC.Credential.PublicKey
		supportedSignatureAlgorithms = slices.DeleteFunc(slices.Clone(hs.hello.supportedSignatureAlgorithmsDC), func(s SignatureScheme) bool { return isDisabledSignatureAlgorithm(VersionTLS13, s, false) })
		publicKeySignatureAlgorithms = []SignatureScheme{c.verifiedDC.Credential.CertVerifyAlgorithm}
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
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) ||
		!isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, publicKeySignatureAlgorithms) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate or delegated credential used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return c.sendAlert(alertInternalError)
	}
	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, publicKey,
		sigHash, signed, certVerify.signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	c.peerSigAlg = certVerify.signatureAlgorithm

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

	if hs.echContext != nil && hs.echContext.echRejected {
		if _, err := hs.c.writeHandshakeRecord(&encryptedExtensionsMsg{}, hs.transcript); err != nil {
			return err
		}
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

func (hs *clientHandshakeStateTLS13) pickDelegatedCredential(cert *Certificate) *DelegatedCredential {
	if len(cert.Certificate) == 0 {
		return nil
	}

	for _, delegatedCredential := range cert.DelegatedCredentials {
		if !isSupportedSignatureAlgorithm(delegatedCredential.Algorithm, hs.certReq.supportedSignatureAlgorithms) {
			continue
		}

		if !isSupportedSignatureAlgorithm(delegatedCredential.Credential.CertVerifyAlgorithm, hs.certReq.supportedSignatureAlgorithmsDC) {
			continue
		}

		_, ok := delegatedCredential.PrivateKey.(crypto.Signer)
		if !ok {
			continue
		}

		return &delegatedCredential
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		if _, err := hs.c.writeHandshakeRecord(&certificateMsgTLS13{}, hs.transcript); err != nil {
			return err
		}
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:      hs.certReq.certificateAuthorities,
		SignatureSchemes:   hs.certReq.supportedSignatureAlgorithms,
		SignatureSchemesDC: hs.certReq.supportedSignatureAlgorithmsDC,
		Version:            c.vers,
		ctx:                hs.ctx,
	})
	if err != nil {
		return err
	}

	var delegatedCredential []byte
	dc := hs.pickDelegatedCredential(cert)
	if dc != nil {
		delegatedCredential, err = dc.marshal()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0
	certMsg.delegatedCredential = delegatedCredential

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

	var privateKey crypto.PrivateKey
	if dc != nil {
		certVerifyMsg.signatureAlgorithm = dc.Credential.CertVerifyAlgorithm
		privateKey = dc.PrivateKey
	} else {
		certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
		if err != nil {
			// getClientCertificate returned a certificate incompatible with the
			// CertificateRequestInfo supported signature algorithms.
			c.sendAlert(alertHandshakeFailure)
			return err
		}
		privateKey = cert.PrivateKey
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
	sig, err := privateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
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

	if c.quic == nil && hs.earlyData {
		c.earlyNotify.L.Lock()
		c.earlyDataEOF = true
		c.earlyNotify.L.Unlock()

		if _, err := hs.c.writeHandshakeRecord(&endOfEarlyDataMsg{}, hs.transcript); err != nil {
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

	c.out.Lock()
	defer c.out.Unlock()

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

	if len(msg.label) == 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received a session ticket with empty opaque ticket label")
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

	session := c.sessionState()
	session.secret = psk
	session.useBy = uint64(c.config.time().Add(lifetime).Unix())
	session.ageAdd = msg.ageAdd
	session.maxEarlyData = msg.maxEarlyData
	session.ticket = msg.label
	if c.quic != nil && c.quic.enableSessionEvents {
		c.quicStoreSession(session)
		return nil
	}
	cs := &ClientSessionState{session: session}
	if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
		c.config.ClientSessionCache.Put(cacheKey, cs)
	}

	return nil
}
