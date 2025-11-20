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
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"sort"
	"time"

	ehash "gitlab.com/go-extension/hash"
	"gitlab.com/go-extension/hpke"
	"golang.org/x/crypto/hkdf"
)

// maxClientPSKIdentities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const maxClientPSKIdentities = 5

type echServerContext struct {
	hpkeContext *hpke.Recipient
	configID    uint8
	ciphersuite echCipher
	transcript  hash.Hash
	// inner indicates that the initial client_hello we recieved contained an
	// encrypted_client_hello extension that indicated it was an "inner" hello.
	// We don't do any additional processing of the hello in this case, so all
	// fields above are unset.
	inner bool
}

type serverHandshakeStateTLS13 struct {
	c                               *Conn
	ctx                             context.Context
	clientHello                     *clientHelloMsg
	hello                           *serverHelloMsg
	sentDummyCCS                    bool
	usingPSK                        bool
	usingALPS                       bool
	earlyData                       bool
	suite                           *cipherSuiteTLS13
	certReq                         *certificateRequestMsgTLS13
	certificateCompressionAlgorithm CertificateCompressionAlgorithm
	cert                            *Certificate
	delegatedCredential             *DelegatedCredential
	sigAlg                          SignatureScheme
	clientHandshakeSecret           []byte
	earlySecret                     []byte
	sharedKey                       []byte
	handshakeSecret                 []byte
	masterSecret                    []byte
	trafficSecret                   []byte // client_application_traffic_secret_0
	transcript                      hash.Hash
	clientFinished                  []byte
	sendTicketOnCompleted           bool
	echContext                      *echServerContext

	maxRecvLimit uint16
	maxSentLimit uint16

	extensions []Extension
}

func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
	if err := hs.processClientHello(); err != nil {
		return err
	}
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	if err := hs.pickCertificate(); err != nil {
		return err
	}
	c.buffering = true
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	// Note that at this point we could start sending application data without
	// waiting for the client's second flight, but the application might not
	// expect the lack of replay protection of the ClientHello parameters.
	if _, err := c.flush(); err != nil {
		return err
	}

	switch {
	case !hs.earlyData:
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
	case c.quic != nil:
		if err := hs.doEarlyHandshake(); err != nil {
			return err
		}
	default:
		// early handshake in handleEndOfEarlyData
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)

	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	hs.hello.supportedVersion = c.vers
	hs.hello.extensions = hs.extensions

	if len(hs.clientHello.supportedVersions) == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client used the legacy version field to negotiate TLS 1.3")
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if c.vers < c.config.maxSupportedVersion(roleServer) {
				c.sendAlert(alertInappropriateFallback)
				return errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: TLS 1.3 client supports illegal compression methods")
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	if hs.clientHello.earlyData {
		if len(hs.clientHello.pskIdentities) == 0 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: early_data without pre_shared_key")
		}

		if c.quic == nil {
			c.handshakeState.Store(handshakeEarly)
		}
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone

	configCipherSuites := c.config.supportedCipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))

	var preferenceOrder []uint16
	switch {
	case c.config.PreferCipherSuites:
		preferenceOrder = c.config.CipherSuites
	case !hasAESGCMHardwareSupport, !isAESGCMPreferred(hs.clientHello.cipherSuites):
		preferenceOrder = defaultCipherSuitesTLS13NoAES
	default:
		preferenceOrder = defaultCipherSuitesTLS13
	}

	for _, suiteID := range preferenceOrder {
		if IsGREASE(suiteID) {
			continue
		}

		if slices.Contains(configCipherSuites, suiteID) {
			preferenceList = append(preferenceList, suiteID)
		}
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(hs.clientHello.cipherSuites, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return fmt.Errorf("tls: no cipher suite supported by both client and server; client offered: %x",
			hs.clientHello.cipherSuites)
	}
	c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	hs.transcript = hs.suite.hash.New()

	// First, if a post-quantum key exchange is available, use one. See
	// draft-ietf-tls-key-share-prediction-01, Section 4 for why this must be
	// first.
	//
	// Second, if the client sent a key share for a group we support, use that,
	// to avoid a HelloRetryRequest round-trip.
	//
	// Finally, pick in our fixed preference order.
	preferredGroups := c.config.curvePreferences(c.vers)
	preferredGroups = slices.DeleteFunc(preferredGroups, func(group CurveID) bool {
		return IsGREASE(group) || !slices.Contains(hs.clientHello.supportedCurves, group)
	})
	if len(preferredGroups) == 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no key exchanges supported by both client and server")
	}
	hasKeyShare := func(group CurveID) bool {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == group {
				return true
			}
		}
		return false
	}
	sort.SliceStable(preferredGroups, func(i, j int) bool {
		return hasKeyShare(preferredGroups[i]) && !hasKeyShare(preferredGroups[j])
	})
	sort.SliceStable(preferredGroups, func(i, j int) bool {
		return isPQKeyExchange(preferredGroups[i]) && !isPQKeyExchange(preferredGroups[j])
	})
	selectedGroup := preferredGroups[0]

	var clientKeyShare *keyShare
	for _, ks := range hs.clientHello.keyShares {
		if ks.group == selectedGroup {
			clientKeyShare = &ks
			break
		}
	}
	if clientKeyShare == nil {
		ks, err := hs.doHelloRetryRequest(selectedGroup)
		if err != nil {
			return err
		}
		clientKeyShare = ks
	}
	c.curveID = selectedGroup

	switch selectedGroup {
	case MLKEM768:
		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		hs.sharedKey, hs.hello.serverShare.data = k.Encapsulate()
	case MLKEM1024:
		k, err := mlkem.NewEncapsulationKey1024(clientKeyShare.data)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		hs.sharedKey, hs.hello.serverShare.data = k.Encapsulate()
	case X25519MLKEM768:
		if len(clientKeyShare.data) != mlkem.EncapsulationKeySize768+x25519PublicKeySize {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		key, err := generateECDHEKey(c.config.rand(), X25519)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data[mlkem.EncapsulationKeySize768:]
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[:mlkem.EncapsulationKeySize768])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		// draft-kwiatkowski-tls-ecdhe-mlkem-02, Section 3.1.3: "For
		// X25519MLKEM768, the shared secret is the concatenation of the ML-KEM
		// shared secret and the X25519 shared secret. The shared secret is 64
		// bytes (32 bytes for each part)."
		hs.sharedKey = append(mlkemSharedSecret, hs.sharedKey...)
		// draft-kwiatkowski-tls-ecdhe-mlkem-02, Section 3.1.2: "When the
		// X25519MLKEM768 group is negotiated, the server's key exchange value
		// is the concatenation of an ML-KEM ciphertext returned from
		// encapsulation to the client's encapsulation key, and the server's
		// ephemeral X25519 share."
		hs.hello.serverShare.data = append(ciphertext, hs.hello.serverShare.data...)
	case CurveP256MLKEM768:
		if len(clientKeyShare.data) != p256PublicKeySize+mlkem.EncapsulationKeySize768 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		key, err := generateECDHEKey(c.config.rand(), CurveP256)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data[:p256PublicKeySize]
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[p256PublicKeySize:])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		hs.sharedKey = append(hs.sharedKey, mlkemSharedSecret...)
		hs.hello.serverShare.data = append(hs.hello.serverShare.data, ciphertext...)
	case CurveP384MLKEM1024:
		if len(clientKeyShare.data) != p384PublicKeySize+mlkem.EncapsulationKeySize1024 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		key, err := generateECDHEKey(c.config.rand(), CurveP384)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data[:p384PublicKeySize]
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		k, err := mlkem.NewEncapsulationKey1024(clientKeyShare.data[p384PublicKeySize:])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		hs.sharedKey = append(hs.sharedKey, mlkemSharedSecret...)
		hs.hello.serverShare.data = append(hs.hello.serverShare.data, ciphertext...)
	case CurveSM2MLKEM768:
		if len(clientKeyShare.data) != sm2PublicKeySize+mlkem.EncapsulationKeySize768 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		key, err := generateECDHEKeySM2(c.config.rand(), CurveSM2)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data[:sm2PublicKeySize]
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[sm2PublicKeySize:])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		hs.sharedKey = append(hs.sharedKey, mlkemSharedSecret...)
		hs.hello.serverShare.data = append(hs.hello.serverShare.data, ciphertext...)
	case X25519Kyber768Draft00, CurveP256Kyber768Draft00:
		publicKeySize := publicKeySizeForHybrid(selectedGroup)
		if len(clientKeyShare.data) != publicKeySize+mlkem.EncapsulationKeySize768 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		key, err := generateECDHEKey(c.config.rand(), curveForHybrid(selectedGroup))
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data[:publicKeySize]
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[publicKeySize:])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		kyberSharedSecret := kyberSharedSecret(mlkemSharedSecret, ciphertext)
		hs.sharedKey = append(hs.sharedKey, kyberSharedSecret...)
		hs.hello.serverShare.data = append(hs.hello.serverShare.data, ciphertext...)
	case X25519, CurveP256, CurveP384, CurveP521:
		key, err := generateECDHEKey(c.config.rand(), selectedGroup)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
	case CurveSM2:
		key, err := generateECDHEKeySM2(c.config.rand(), selectedGroup)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data
		peerKey, err := key.Curve().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.ECDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
	case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
		key, err := generateFFDHEKey(c.config.rand(), selectedGroup)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}

		peerData := clientKeyShare.data
		peerKey, err := key.Group().NewPublicKey(peerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}

		hs.sharedKey, err = key.FFDH(peerKey)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid client key share")
		}
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: CurvePreferences includes unsupported curve")
	}

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols, c.quic != nil)
	if err != nil {
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	c.clientProtocol = selectedProto

	protoSetting, ok := c.config.negotiateALPS(selectedProto, hs.clientHello.alpsProtocols)
	if ok {
		hs.usingALPS = true
		c.serverProtocolSetting = protoSetting
	}

	if c.quic != nil {
		// RFC 9001 Section 4.2: Clients MUST NOT offer TLS versions older than 1.3.
		for _, v := range hs.clientHello.supportedVersions {
			if v < VersionTLS13 {
				c.sendAlert(alertProtocolVersion)
				return errors.New("tls: client offered TLS version older than TLS 1.3")
			}
		}
		// RFC 9001 Section 8.2.
		if hs.clientHello.quicTransportParameters == nil {
			c.sendAlert(alertMissingExtension)
			return errors.New("tls: client did not send a quic_transport_parameters extension")
		}
		c.quicSetTransportParameters(hs.clientHello.quicTransportParameters)
	} else {
		if hs.clientHello.quicTransportParameters != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: client sent an unexpected quic_transport_parameters extension")
		}
	}

	hs.maxRecvLimit = maxPlaintext + 1
	hs.maxSentLimit = maxPlaintext + 1
	if hs.clientHello.limitSupported {
		if hs.clientHello.recordSizeLimit < 64 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: client sent an invalid record size limit")
		}

		if c.config.MaxRecordSize != 0 {
			if c.config.MaxRecordSize < 64 {
				c.sendAlert(alertInternalError)
				return errors.New("tls: MaxRecordSize must greater than 64")
			}

			hs.maxSentLimit = min(hs.maxSentLimit, hs.clientHello.recordSizeLimit)
			hs.maxRecvLimit = min(hs.maxRecvLimit, c.config.MaxRecordSize)
		}
	}

CertificateCompressionAlgorithmSelection:
	for _, preferredAlgorithm := range c.config.certificateCompressionPreferences() {
		for _, algorithm := range hs.clientHello.supportedCertificateCompressionAlgorithms {
			if algorithm == preferredAlgorithm {
				hs.certificateCompressionAlgorithm = algorithm
				break CertificateCompressionAlgorithmSelection
			}
		}
	}

	c.serverName = hs.clientHello.serverName
	return nil
}

func (hs *serverHandshakeStateTLS13) checkForResumption() error {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid or missing PSK binders")
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil
	}

	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}

		var sessionState *SessionState
		if c.config.UnwrapSession != nil {
			var err error
			sessionState, err = c.config.UnwrapSession(identity.label, c.connectionStateLocked())
			if err != nil {
				return err
			}
			if sessionState == nil {
				continue
			}
		} else {
			plaintext := c.config.decryptTicket(identity.label, c.ticketKeys)
			if plaintext == nil {
				continue
			}
			var err error
			sessionState, err = ParseSessionState(plaintext)
			if err != nil {
				continue
			}
		}

		if sessionState.version != VersionTLS13 {
			continue
		}

		serverAge := c.config.time().Sub(time.Unix(int64(sessionState.createdAt), 0))
		if serverAge > maxSessionTicketLifetime {
			continue
		}

		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.peerCertificates) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}
		if sessionHasClientCerts && c.config.time().After(sessionState.peerCertificates[0].NotAfter) {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth >= VerifyClientCertIfGiven &&
			len(sessionState.verifiedChains) == 0 {
			continue
		}
		if sessionState.verifiedDC != nil && !sessionHasClientCerts {
			continue
		}
		if sessionState.verifiedDC != nil && c.config.time().After(sessionState.peerCertificates[0].NotBefore.Add(sessionState.verifiedDC.Credential.ValidTime)) {
			continue
		}

		if c.quic != nil && c.quic.enableSessionEvents {
			if err := c.quicResumeSession(sessionState); err != nil {
				return err
			}
		}

		hs.earlySecret = hs.suite.extract(sessionState.secret, nil)
		binderKey := hs.suite.deriveSecret(hs.earlySecret, resumptionBinderLabel, nil)
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: internal error: failed to clone hash")
		}
		clientHelloBytes, err := hs.clientHello.marshalWithoutBinders()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		transcript.Write(clientHelloBytes)
		pskBinder := hs.suite.finishedHash(binderKey, transcript)
		if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
			c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid PSK binder")
		}

		c.didResume = true
		c.peerCertificates = sessionState.peerCertificates
		c.ocspResponse = sessionState.ocspResponse
		c.scts = sessionState.scts
		c.verifiedChains = sessionState.verifiedChains

		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		hs.usingPSK = true

		if !hs.clientHello.earlyData || i != 0 {
			return nil
		}

		if sessionState.maxEarlyData <= 0 {
			return nil
		}

		if !c.config.AllowEarlyData {
			return nil
		}

		clientAge := time.Duration(identity.obfuscatedTicketAge-sessionState.ageAdd) * time.Millisecond
		if ageDiff := clientAge - serverAge; ageDiff > maxSessionTicketSkewAllowance || ageDiff < -maxSessionTicketSkewAllowance {
			return nil
		}

		if sessionState.cipherSuite != hs.suite.id || sessionState.alpnProtocol != c.clientProtocol || !bytes.Equal(c.serverProtocolSetting, sessionState.alpnServerSetting) {
			return nil
		}

		hs.earlyData = true
		hs.usingALPS = false
		c.clientProtocolSetting = sessionState.alpnClientSetting

		transcript = hs.suite.hash.New()
		if err := transcriptMsg(hs.clientHello, transcript); err != nil {
			return err
		}
		earlyTrafficSecret := hs.suite.deriveSecret(hs.earlySecret, clientEarlyTrafficLabel, transcript)
		if c.quic == nil {
			c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelEarly, earlyTrafficSecret, maxPlaintext+1)
		} else {
			c.quicSetReadSecret(QUICEncryptionLevelEarly, hs.suite.id, earlyTrafficSecret)
		}
		err = c.config.writeKeyLog(keyLogLabelClientEarly, hs.clientHello.random, earlyTrafficSecret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		if c.quic == nil {
			c.initServerEarlyData(hs, sessionState.maxEarlyData)
		}
		return nil
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) doFullHandshake() error {
	c := hs.c

	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, hs.clientHandshakeSecret, hs.maxRecvLimit)

	if err := hs.readClientEarlyData(); err != nil {
		return err
	}
	if err := hs.readClientParameters(); err != nil {
		return err
	}
	if err := hs.readClientCertificate(); err != nil {
		return err
	}
	if err := hs.readClientFinished(); err != nil {
		return err
	}
	if err := c.setup(); err != nil {
		return err
	}

	c.handshakeState.Store(handshakeCompleted)
	return nil
}

func (hs *serverHandshakeStateTLS13) doEarlyHandshake() error {
	c := hs.c

	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, hs.clientHandshakeSecret, hs.maxRecvLimit)

	if err := hs.readClientFinished(); err != nil {
		return err
	}
	if err := c.setup(); err != nil {
		return err
	}

	c.handshakeState.Store(handshakeCompleted)
	return nil
}

// cloneHash uses the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
// interfaces implemented by standard library hashes to clone the state of in
// to a new instance of h. It returns nil if the operation fails.
func cloneHash(in hash.Hash, h ehash.Hasher) hash.Hash {
	// Recreate the interface to avoid importing encoding.
	type binaryMarshaler interface {
		MarshalBinary() (data []byte, err error)
		UnmarshalBinary(data []byte) error
	}
	marshaler, ok := in.(binaryMarshaler)
	if !ok {
		return nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil
	}
	out := h.New()
	unmarshaler, ok := out.(binaryMarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil
	}
	return out
}

func (hs *serverHandshakeStateTLS13) pickDelegatedCredential() bool {
	for _, delegatedCredential := range hs.cert.DelegatedCredentials {
		if !isSupportedSignatureAlgorithm(delegatedCredential.Algorithm, hs.clientHello.supportedSignatureAlgorithms) {
			continue
		}

		if !isSupportedSignatureAlgorithm(delegatedCredential.Credential.CertVerifyAlgorithm, hs.clientHello.supportedSignatureAlgorithmsDC) {
			continue
		}

		_, ok := delegatedCredential.PrivateKey.(crypto.Signer)
		if !ok {
			continue
		}

		hs.delegatedCredential = &delegatedCredential
		hs.sigAlg = delegatedCredential.Credential.CertVerifyAlgorithm
		return true
	}

	return false
}

func (hs *serverHandshakeStateTLS13) pickCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert(alertMissingExtension)
	}

	certificate, err := c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			c.sendAlert(alertUnrecognizedName)
		} else {
			c.sendAlert(alertInternalError)
		}
		return err
	}
	hs.cert = certificate

	if hs.pickDelegatedCredential() {
		return nil
	}

	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.c.quic != nil {
		return nil
	}
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	return hs.c.writeChangeCipherRecord()
}

func (hs *serverHandshakeStateTLS13) doHelloRetryRequest(selectedGroup CurveID) (*keyShare, error) {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return nil, err
	}
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)

	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom,
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
		extensions:        hs.hello.extensions,
	}

	if hs.echContext != nil {
		// Compute the acceptance message.
		helloRetryRequest.encryptedClientHello = make([]byte, 8)
		confTranscript := cloneHash(hs.transcript, hs.suite.hash)
		if err := transcriptMsg(helloRetryRequest, confTranscript); err != nil {
			return nil, err
		}
		acceptConfirmation := hs.suite.expandLabel(
			hkdf.Extract(hs.suite.hash.New, hs.clientHello.random, nil),
			"hrr ech accept confirmation",
			confTranscript.Sum(nil),
			8,
		)
		helloRetryRequest.encryptedClientHello = acceptConfirmation
	}

	if _, err := hs.c.writeHandshakeRecord(helloRetryRequest, hs.transcript); err != nil {
		return nil, err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return nil, err
	}

	// clientHelloMsg is not included in the transcript.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}

	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	if hs.echContext != nil {
		if len(clientHello.encryptedClientHello) == 0 {
			c.sendAlert(alertMissingExtension)
			return nil, errors.New("tls: second client hello missing encrypted client hello extension")
		}

		echType, echCiphersuite, configID, encap, payload, err := parseECHExt(clientHello.encryptedClientHello)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return nil, errors.New("tls: client sent invalid encrypted client hello extension")
		}

		if echType == outerECHExt && hs.echContext.inner || echType == innerECHExt && !hs.echContext.inner {
			c.sendAlert(alertDecodeError)
			return nil, errors.New("tls: unexpected switch in encrypted client hello extension type")
		}

		if echType == outerECHExt {
			if echCiphersuite != hs.echContext.ciphersuite || configID != hs.echContext.configID || len(encap) != 0 {
				c.sendAlert(alertIllegalParameter)
				return nil, errors.New("tls: second client hello encrypted client hello extension does not match")
			}

			encodedInner, err := decryptECHPayload(hs.echContext.hpkeContext, clientHello.original, payload)
			if err != nil {
				c.sendAlert(alertDecryptError)
				return nil, errors.New("tls: failed to decrypt second client hello encrypted client hello extension payload")
			}

			echInner, err := decodeInnerClientHello(clientHello, encodedInner)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return nil, errors.New("tls: client sent invalid encrypted client hello extension")
			}

			clientHello = echInner
		}
	}

	for _, extension := range clientHello.extensionList {
		switch extension := extension.(type) {
		case nil:
		case *UnimplementedExtension:
			for _, ext := range hs.extensions {
				if ext == nil {
					continue
				}

				if ext.ExtensionId() != extension.Id {
					continue
				}

				ok, err := ext.Unmarshal(typeClientHello, hs.echContext != nil, extension.Data, c.extensionState)
				if !ok {
					return nil, c.sendAlert(alertDecodeError)
				}
				if err != nil {
					c.sendAlert(alertIllegalParameter)
					return nil, err
				}
				break
			}
		}
	}

	if len(clientHello.keyShares) != 1 {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client didn't send one key share in second ClientHello")
	}
	ks := &clientHello.keyShares[0]

	if ks.group != selectedGroup {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client sent unexpected key share in second ClientHello")
	}

	if clientHello.earlyData {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client indicated early data in second ClientHello")
	}
	c.earlyData.done = true

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("tls: client illegally modified second ClientHello")
	}

	c.didHRR = true
	hs.clientHello = clientHello
	return ks, nil
}

// illegalClientHelloChange reports whether the two ClientHello messages are
// different, with the exception of the changes allowed before and after a
// HelloRetryRequest. See RFC 8446, Section 4.1.2.
func illegalClientHelloChange(ch, ch1 *clientHelloMsg) bool {
	if len(ch.supportedVersions) != len(ch1.supportedVersions) ||
		len(ch.cipherSuites) != len(ch1.cipherSuites) ||
		len(ch.supportedCurves) != len(ch1.supportedCurves) ||
		len(ch.supportedSignatureAlgorithms) != len(ch1.supportedSignatureAlgorithms) ||
		len(ch.supportedSignatureAlgorithmsCert) != len(ch1.supportedSignatureAlgorithmsCert) ||
		len(ch.supportedSignatureAlgorithmsDC) != len(ch1.supportedSignatureAlgorithmsDC) ||
		len(ch.alpnProtocols) != len(ch1.alpnProtocols) {
		return true
	}
	for i := range ch.supportedVersions {
		if ch.supportedVersions[i] != ch1.supportedVersions[i] {
			return true
		}
	}
	for i := range ch.cipherSuites {
		if ch.cipherSuites[i] != ch1.cipherSuites[i] {
			return true
		}
	}
	for i := range ch.supportedCurves {
		if ch.supportedCurves[i] != ch1.supportedCurves[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithms {
		if ch.supportedSignatureAlgorithms[i] != ch1.supportedSignatureAlgorithms[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsCert {
		if ch.supportedSignatureAlgorithmsCert[i] != ch1.supportedSignatureAlgorithmsCert[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsDC {
		if ch.supportedSignatureAlgorithmsDC[i] != ch1.supportedSignatureAlgorithmsDC[i] {
			return true
		}
	}
	for i := range ch.alpnProtocols {
		if ch.alpnProtocols[i] != ch1.alpnProtocols[i] {
			return true
		}
	}
	return ch.vers != ch1.vers ||
		!bytes.Equal(ch.random, ch1.random) ||
		!bytes.Equal(ch.sessionId, ch1.sessionId) ||
		!bytes.Equal(ch.compressionMethods, ch1.compressionMethods) ||
		ch.serverName != ch1.serverName ||
		ch.ocspStapling != ch1.ocspStapling ||
		!bytes.Equal(ch.supportedPoints, ch1.supportedPoints) ||
		ch.ticketSupported != ch1.ticketSupported ||
		!bytes.Equal(ch.sessionTicket, ch1.sessionTicket) ||
		ch.limitSupported != ch1.limitSupported ||
		ch.recordSizeLimit != ch1.recordSizeLimit ||
		ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported ||
		!bytes.Equal(ch.secureRenegotiation, ch1.secureRenegotiation) ||
		ch.scts != ch1.scts ||
		!bytes.Equal(ch.cookie, ch1.cookie) ||
		!bytes.Equal(ch.pskModes, ch1.pskModes)
}

func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c

	if hs.echContext != nil {
		copy(hs.hello.random[32-8:], make([]byte, 8))
		echTranscript := cloneHash(hs.transcript, hs.suite.hash)
		echTranscript.Write(hs.clientHello.original)
		if err := transcriptMsg(hs.hello, echTranscript); err != nil {
			return err
		}
		// compute the acceptance message
		acceptConfirmation := hs.suite.expandLabel(
			hkdf.Extract(hs.suite.hash.New, hs.clientHello.random, nil),
			"ech accept confirmation",
			echTranscript.Sum(nil),
			8,
		)
		copy(hs.hello.random[32-8:], acceptConfirmation)
	}

	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return err
	}

	if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = hs.suite.extract(nil, nil)
	}
	hs.handshakeSecret = hs.suite.extract(hs.sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	clientSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	hs.clientHandshakeSecret = clientSecret
	serverSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret, hs.maxSentLimit)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, clientSecret)
	}

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)
	encryptedExtensions.extensions = hs.extensions
	encryptedExtensions.alpnProtocol = c.clientProtocol
	if hs.usingALPS {
		encryptedExtensions.alps = true
		encryptedExtensions.alpnSetting = c.serverProtocolSetting
	}
	encryptedExtensions.earlyData = hs.earlyData
	if c.quic != nil {
		p, err := c.quicGetTransportParameters()
		if err != nil {
			return err
		}
		encryptedExtensions.quicTransportParameters = p
	}

	if !hs.c.didResume && hs.clientHello.serverName != "" {
		encryptedExtensions.serverNameAck = true
	}

	// If client sent ECH extension, but we didn't accept it,
	// send retry configs, if available.
	echKeys := hs.c.config.EncryptedClientHelloKeys
	if hs.c.config.GetEncryptedClientHelloKeys != nil {
		echKeys, err = hs.c.config.GetEncryptedClientHelloKeys(clientHelloInfo(hs.ctx, c, hs.clientHello))
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}
	if len(echKeys) > 0 && len(hs.clientHello.encryptedClientHello) > 0 && hs.echContext == nil {
		encryptedExtensions.echRetryConfigs, err = buildRetryConfigList(echKeys)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	if hs.clientHello.limitSupported && c.config.MaxRecordSize != 0 {
		encryptedExtensions.limitSupported = true
		encryptedExtensions.recordSizeLimit = hs.maxRecvLimit
	}

	if _, err := hs.c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil {
		return err
	}

	return nil
}

// negotiateALPS picks a shared ALPS protocol that both sides support in server
// preference order. If ALPS is not configured or the peer doesn't support it,
// it returns nil and false.
func (config *Config) negotiateALPS(selectedProto string, clientProtos []string) ([]byte, bool) {
	if selectedProto == "" || len(clientProtos) == 0 || len(config.NextProtoSettings) == 0 {
		return nil, false
	}

	if !slices.Contains(clientProtos, selectedProto) {
		return nil, false
	}

	protoSetting, ok := config.NextProtoSettings[selectedProto]
	return protoSetting, ok
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if hs.requestClientCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true

		supportedSignatureAlgorithms := slices.DeleteFunc(c.config.signatureAlgorithmsPreferences(c.vers), func(s SignatureScheme) bool { return isDisabledSignatureAlgorithm(VersionTLS13, s, false) })
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms

		supportedSignatureAlgorithmsCert := slices.DeleteFunc(c.config.signatureAlgorithmsCertPreferences(), func(s SignatureScheme) bool { return isDisabledSignatureAlgorithm(0, s, true) })
		certReq.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithmsCert

		supportedSignatureAlgorithmsDC := slices.DeleteFunc(c.config.delegatedCredentialPreferences(), func(s SignatureScheme) bool { return isDisabledSignatureAlgorithm(VersionTLS13, s, false) })
		certReq.supportedSignatureAlgorithmsDC = supportedSignatureAlgorithmsDC

		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		hs.certReq = certReq
		if _, err := hs.c.writeHandshakeRecord(certReq, hs.transcript); err != nil {
			return err
		}
	}

	var err error
	var delegatedCredential []byte
	privateKey := hs.cert.PrivateKey
	if hs.delegatedCredential != nil {
		delegatedCredential, err = hs.delegatedCredential.marshal()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		privateKey = hs.delegatedCredential.PrivateKey
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
	certMsg.delegatedCredential = delegatedCredential

	var msg handshakeMessage = certMsg
	if hs.certificateCompressionAlgorithm != 0 {
		msg, err = certMsg.compress(hs.certificateCompressionAlgorithm)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	if _, err := hs.c.writeHandshakeRecord(msg, hs.transcript); err != nil {
		return err
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := privateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := privateKey.(crypto.Signer).Public()
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
			c.sendAlert(alertHandshakeFailure)
		} else {
			c.sendAlert(alertInternalError)
		}
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))

	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret, hs.maxSentLimit)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			// TODO: Handle this in setTrafficSecret?
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelApplication, hs.suite.id, serverSecret)
	}

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	// If we did not request client certificates and encrypted extensions, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() && !hs.usingALPS {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled {
		return false
	}

	// QUIC tickets are sent by QUICConn.SendSessionTicket, not automatically.
	if hs.c.quic != nil {
		return false
	}

	// Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
	return slices.Contains(hs.clientHello.pskModes, pskModeDHE)
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	if hs.earlyData && c.quic == nil {
		err := transcriptMsg(&endOfEarlyDataMsg{}, hs.transcript)
		if err != nil {
			return err
		}
	}

	hs.clientFinished = hs.suite.finishedHash(hs.clientHandshakeSecret, hs.transcript)
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	if err := transcriptMsg(finishedMsg, hs.transcript); err != nil {
		return err
	}

	c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
		resumptionLabel, hs.transcript)

	if !hs.shouldSendSessionTickets() {
		return nil
	}

	behavior := c.config.behavior()
	if behavior.SendTicketOnCompleted {
		hs.sendTicketOnCompleted = true
		return nil
	}
	return c.sendSessionTicket(c.config.maxEarlyData(), nil)
}

func (c *Conn) sendSessionTicket(maxEarlyData uint32, extra [][]byte) error {
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil {
		return errors.New("tls: internal error: unknown cipher suite")
	}
	// ticket_nonce, which must be unique per connection, is always left at
	// zero because we only ever send one ticket per connection.
	psk := suite.expandLabel(c.resumptionSecret, "resumption",
		nil, suite.hash.Size())

	m := new(newSessionTicketMsgTLS13)

	state := c.sessionState()
	state.secret = psk
	state.maxEarlyData = maxEarlyData
	state.Extra = extra

	// ticket_age_add is a random 32-bit value. See RFC 8446, section 4.6.1
	ageAdd := make([]byte, 4)
	if _, err := c.config.rand().Read(ageAdd); err != nil {
		return err
	}
	state.ageAdd = binary.LittleEndian.Uint32(ageAdd)

	if c.config.WrapSession != nil {
		var err error
		m.label, err = c.config.WrapSession(c.connectionStateLocked(), state)
		if err != nil {
			return err
		}
	} else {
		stateBytes, err := state.Bytes()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		m.label, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
		if err != nil {
			return err
		}
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)
	m.ageAdd = state.ageAdd

	// ticket_nonce, which must be unique per connection, is always left at
	// zero because we only ever send one ticket per connection.
	m.nonce = nil

	m.maxEarlyData = maxEarlyData

	if _, err := c.writeHandshakeRecord(m, nil); err != nil {
		return err
	}

	return nil
}

func (c *Conn) handleEndOfEarlyData() error {
	if c.handshakeState.Load() != handshakeEarly {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if c.earlyData.done {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}
	c.earlyData.done = true

	c.handshakeErr = c.earlyData.Handshake()
	return c.handshakeErr
}

func (hs *serverHandshakeStateTLS13) readClientEarlyData() error {
	c := hs.c

	if c.quic != nil {
		return nil
	}

	if !hs.clientHello.earlyData {
		return nil
	}

	for c.hand.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return err
		}
	}

	c.earlyData.done = true
	return nil
}

func (hs *serverHandshakeStateTLS13) readClientParameters() error {
	c := hs.c

	if !hs.usingALPS {
		return nil
	}

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
				if ext.ExtensionId() != extension.Id {
					continue
				}

				ok, err := ext.Unmarshal(typeEncryptedExtensions, hs.echContext != nil, extension.Data, c.extensionState)
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

	if !encryptedExtensions.alps {
		return c.sendAlert(alertMissingExtension)
	}

	c.clientProtocolSetting = encryptedExtensions.alpnSetting

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}
	return nil
}

func (hs *serverHandshakeStateTLS13) verifyClientDelegatedCredential(delegatedCredential *DelegatedCredential) error {
	c := hs.c

	cert := c.peerCertificates[0]
	if !isValidForDelegation(cert) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client certificate not authorized for delegation")
	}

	now := c.config.time()
	notAfter := cert.NotBefore.Add(delegatedCredential.Credential.ValidTime)
	if notAfter.After(cert.NotAfter) {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("tls: invalid client delegated credential, credential time %s is after %s", notAfter.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	if now.After(notAfter) {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("tls: client delegated credential is expired, current time %s is after %s", now.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}

	lifetime := notAfter.Sub(now)
	if lifetime > maxDelegatetdCredentialLifetime {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("tls: invalid client delegated credential lifetime, current time %s is more than 7-day before %s", now.Format(time.RFC3339), notAfter.Format(time.RFC3339))
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
	signed := signedCredential(sigHash, clientCredentialSignatureContext, cert.Raw, credential)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey,
		sigHash, signed, delegatedCredential.Signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid delegated credential signature by the client certificate: " + err.Error())
	}

	c.verifiedDC = delegatedCredential
	return nil
}

func (hs *serverHandshakeStateTLS13) readClientCertificate() error {
	c := hs.c

	if !hs.requestClientCert() {
		// Make sure the connection is still being verified whether or not
		// the server requested a client certificate.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// If we requested a client certificate, then the client must send a
	// certificate message. If it's empty, no CertificateVerify is sent.

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	var certMsg *certificateMsgTLS13
	switch msg := msg.(type) {
	case *certificateMsgTLS13:
		certMsg = msg
	case *compressedCertificateMsg:
		if !c.config.supportsCertificateCompression(msg.algorithm) {
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
		return unexpectedMessageError(certMsg, msg)
	}

	if err := c.processCertsFromClient(certMsg.certificate); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if len(certMsg.certificate.Certificate) != 0 {
		publicKey := c.peerCertificates[0].PublicKey
		supportedSignatureAlgorithms := hs.certReq.supportedSignatureAlgorithms
		publicKeySignatureAlgorithms := signatureSchemesForPublicKey(c.vers, publicKey)
		if len(certMsg.delegatedCredential) != 0 {
			if len(hs.certReq.supportedSignatureAlgorithmsDC) <= 0 {
				c.sendAlert(alertUnexpectedMessage)
				return errors.New("tls: client sent an unexpected delegated credential extension")
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

			if err := hs.verifyClientDelegatedCredential(&delegatedCredential); err != nil {
				return err
			}

			publicKey = c.verifiedDC.Credential.PublicKey
			supportedSignatureAlgorithms = hs.certReq.supportedSignatureAlgorithmsDC
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
			return errors.New("tls: client certificate or delegated credential used with invalid signature algorithm")
		}
		sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
		if err != nil {
			return c.sendAlert(alertInternalError)
		}
		if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
			return c.sendAlert(alertInternalError)
		}
		signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
		if err := verifyHandshakeSignature(sigType, publicKey,
			sigHash, signed, certVerify.signature); err != nil {
			c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid signature by the client certificate: " + err.Error())
		}
		c.peerSigAlg = certVerify.signatureAlgorithm

		if err := transcriptMsg(certVerify, hs.transcript); err != nil {
			return err
		}
	}

	// If we waited until the client certificates to send session tickets, we
	// are ready to do it now.
	if err := hs.sendSessionTickets(); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientFinished() error {
	c := hs.c

	// finishedMsg is not included in the transcript.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid client finished hash")
	}

	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret, hs.maxSentLimit)

	if hs.sendTicketOnCompleted {
		err := c.sendSessionTicket(c.config.maxEarlyData(), nil)
		if err != nil {
			return err
		}
	}

	return nil
}
