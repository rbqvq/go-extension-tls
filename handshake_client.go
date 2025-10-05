// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"gitlab.com/go-extension/hpke"
)

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *SessionState // the session being resumed
	ticket       []byte        // a fresh ticket received during this handshake
	extensions   []Extension
}

func (c *Conn) makeClientHelloExtensions(hello *clientHelloMsg, extensions []Extension) error {
	config := c.config
	hello.extensionList = make([]Extension, 0, len(extensions))

	grease_extensions_ids := make([]uint16, 0)
	for _, extension := range extensions {
		if extension == nil {
			continue
		}

		extension = extension.Clone()
		switch extension := extension.(type) {
		case *GREASEExtension:
			switch len(grease_extensions_ids) {
			case 0:
				extension.Id = config.GREASE()
			case 1:
				extension.Id = config.GREASE()
				if extension.Id == grease_extensions_ids[0] {
					extension.Id ^= 0x1010
				}

				extension.Data = []byte{0}
			default:
				return errors.New("at most 2 grease extensions are supported")
			}
			grease_extensions_ids = append(grease_extensions_ids, extension.Id)

			hello.extensionList = append(hello.extensionList, extension)
		default:
			hello.extensionList = append(hello.extensionList, extension)
		}
	}

	config.shuffleExtensions(hello)
	return nil
}

func (c *Conn) makeClientHello() (*clientHelloMsg, []*keySharePrivateKeys, *echClientContext, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions(roleClient)
	if len(supportedVersions) == 0 {
		return nil, nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}

	versions := slices.DeleteFunc(slices.Clone(supportedVersions), IsGREASE)
	slices.SortFunc(versions, func(a, b uint16) int { return int(b) - int(a) })
	maxVersion := versions[0]
	minVersion := versions[len(versions)-1]

	hello := &clientHelloMsg{
		vers:                         maxVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		encryptThenMAC:               config.EncryptThenMAC,
		extendedMasterSecret:         true,
		limitSupported:               true,
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	var maxRecvLimit uint16 = maxPlaintext
	if maxVersion >= VersionTLS13 {
		hello.supportedCertificateCompressionAlgorithms = config.certificateCompressionPreferences()

		for alpn := range config.NextProtoSettings {
			hello.alpsProtocols = append(hello.alpsProtocols, alpn)
		}

		maxRecvLimit += 1
	}

	if config.MaxRecordSize != 0 {
		if config.MaxRecordSize < 64 {
			return nil, nil, nil, errors.New("tls: MaxRecordSize must greater than 64")
		}

		maxRecvLimit = min(maxRecvLimit, config.MaxRecordSize)
	}
	hello.recordSizeLimit = maxRecvLimit

	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if hello.vers > VersionTLS12 {
		hello.vers = VersionTLS12
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	configCipherSuites := config.supportedCipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	var preferenceOrder []uint16
	switch {
	case config.PreferCipherSuites:
		preferenceOrder = config.CipherSuites
	case hasAESGCMHardwareSupport:
		preferenceOrder = cipherSuitesPreferenceOrder
	default:
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}

CipherSuiteLoop:
	for _, suiteId := range preferenceOrder {
		if IsGREASE(suiteId) {
			hello.cipherSuites = append(hello.cipherSuites, config.GREASE())
			continue
		}

		suite := mutualCipherSuite(configCipherSuites, suiteId)
		suite13 := mutualCipherSuiteTLS13(configCipherSuites, suiteId)
		switch {
		case suite != nil:
			if minVersion > VersionTLS12 {
				continue
			}

			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			if maxVersion < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				continue CipherSuiteLoop
			}
		case suite13 != nil:
			if maxVersion < VersionTLS13 {
				continue CipherSuiteLoop
			}
		default:
			continue CipherSuiteLoop
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	if len(hello.cipherSuites) == 0 {
		return nil, nil, nil, errors.New("tls: not vaild cipher suite provided")
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if c.quic == nil {
		hello.sessionId = make([]byte, 32)
		if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
			return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if maxVersion >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = config.signatureAlgorithmsPreferences(minVersion)
		hello.supportedSignatureAlgorithmsCert = config.signatureAlgorithmsCertPreferences()

		if maxVersion >= VersionTLS13 {
			hello.supportedSignatureAlgorithmsDC = config.delegatedCredentialPreferences()
		}
	}

	grease_groups_ids := make([]CurveID, 0)
	for _, curveID := range config.curvePreferences(maxVersion) {
		if IsGREASE(curveID) {
			curveID = CurveID(config.GREASE())
			grease_groups_ids = append(grease_groups_ids, curveID)
		}

		hello.supportedCurves = append(hello.supportedCurves, curveID)
	}

	var keyShareKeys []*keySharePrivateKeys
	var keyStorage keyStorage
	for _, curveID := range config.keySharePreferences(maxVersion) {
		switch curveID {
		case X25519MLKEM768:
			ecdhe, err := keyStorage.generateECDHEKey(config, X25519)
			if err != nil {
				return nil, nil, nil, err
			}
			x25519EphemeralKey := ecdhe.PublicKey().Bytes()

			mlkem, err := keyStorage.generateMLKEM768(config)
			if err != nil {
				return nil, nil, nil, err
			}
			mlkemEncapsulationKey := mlkem.EncapsulationKey().Bytes()

			keyShareKeys = append(keyShareKeys, &keySharePrivateKeys{curveID: X25519MLKEM768, ecdhe: ecdhe, mlkem: mlkem})
			hello.keyShares = append(hello.keyShares, keyShare{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)})
		case X25519Kyber768Draft00: // Draft of X25519MLKEM768
			ecdhe, err := keyStorage.generateECDHEKey(config, X25519)
			if err != nil {
				return nil, nil, nil, err
			}
			x25519EphemeralKey := ecdhe.PublicKey().Bytes()

			mlkem, err := keyStorage.generateMLKEM768(config)
			if err != nil {
				return nil, nil, nil, err
			}
			mlkemEncapsulationKey := mlkem.EncapsulationKey().Bytes()

			keyShareKeys = append(keyShareKeys, &keySharePrivateKeys{curveID: X25519Kyber768Draft00, ecdhe: ecdhe, mlkem: mlkem})
			hello.keyShares = append(hello.keyShares, keyShare{group: X25519Kyber768Draft00, data: append(x25519EphemeralKey, mlkemEncapsulationKey...)})
		case X25519, CurveP256, CurveP384, CurveP521:
			ecdhe, err := keyStorage.generateECDHEKey(config, curveID)
			if err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys = append(keyShareKeys, &keySharePrivateKeys{curveID: curveID, ecdhe: ecdhe})
			hello.keyShares = append(hello.keyShares, keyShare{group: curveID, data: ecdhe.PublicKey().Bytes()})
		case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
			ffdhe, err := keyStorage.generateFFDHEKey(config, curveID)
			if err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys = append(keyShareKeys, &keySharePrivateKeys{curveID: curveID, ffdhe: ffdhe})
			hello.keyShares = append(hello.keyShares, keyShare{group: curveID, data: ffdhe.PublicKey().Bytes()})
		default:
			if IsGREASE(curveID) {
				if len(grease_groups_ids) <= 0 {
					continue
				}
				curveID = grease_groups_ids[0]
				grease_groups_ids = grease_groups_ids[1:]

				hello.keyShares = append(hello.keyShares, keyShare{group: curveID, data: []byte{0}})
				continue
			}

			return nil, nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		}
	}

	if c.quic != nil {
		p, err := c.quicGetTransportParameters()
		if err != nil {
			return nil, nil, nil, err
		}
		if p == nil {
			p = []byte{}
		}
		hello.quicTransportParameters = p
	}

	echConf := config.echConfig()
	if echConf.Disabled {
		if err := c.makeClientHelloExtensions(hello, config.extensions()); err != nil {
			return nil, nil, nil, err
		}
		return hello, keyShareKeys, nil, nil
	}

	var ech *echClientContext
	if config.EncryptedClientHelloConfigList == nil {
		if err := generateAndUpdateOuterECHExtension(c.config.rand(), hello, echConf); err != nil {
			return nil, nil, nil, err
		}
		if err := c.makeClientHelloExtensions(hello, config.extensions()); err != nil {
			return nil, nil, nil, err
		}
	} else {
		innerExtensions := echConf.innerExtensions()
		if minVersion <= VersionTLS12 && !hasExtension[*SupportedVersionsExtension](innerExtensions) {
			return nil, nil, nil, errors.New("tls: MinVersion must be >= VersionTLS13 or InnerExtension must be have *SupportedVersionsExtension if EncryptedClientHelloConfigList is populated")
		}
		if maxVersion <= VersionTLS12 {
			return nil, nil, nil, errors.New("tls: MaxVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		echConfigs, err := parseECHConfigList(c.config.EncryptedClientHelloConfigList)
		if err != nil {
			return nil, nil, nil, err
		}
		echConfig := pickECHConfig(echConfigs)
		if echConfig == nil {
			return nil, nil, nil, errors.New("tls: EncryptedClientHelloConfigList contains no valid configs")
		}
		ech = &echClientContext{config: echConfig, innerHello: hello.clone()}
		ech.innerHello.encryptedClientHello = []byte{1} // indicate inner hello
		// We need to explicitly set these 1.2 fields to nil, as we do not
		// marshal them when encoding the inner hello, otherwise transcripts
		// will later mismatch.
		ech.innerHello.supportedPoints = nil
		ech.innerHello.ticketSupported = false
		ech.innerHello.secureRenegotiationSupported = false
		ech.innerHello.encryptThenMAC = false
		ech.innerHello.extendedMasterSecret = false

		ech.innerHello.cipherSuites = slices.DeleteFunc(ech.innerHello.cipherSuites, func(suite uint16) bool { return !IsGREASE(suite) && cipherSuiteTLS13ByID(suite) == nil })
		ech.innerHello.supportedVersions = slices.DeleteFunc(ech.innerHello.supportedVersions, func(v uint16) bool { return !IsGREASE(v) && v < VersionTLS13 })

		echPK, err := hpke.ParseHPKEPublicKey(ech.config.KemID, ech.config.PublicKey)
		if err != nil {
			return nil, nil, nil, err
		}
		suite, err := pickECHCipherSuite(ech.config.SymmetricCipherSuite)
		if err != nil {
			return nil, nil, nil, err
		}
		ech.kdfID, ech.aeadID = suite.KDFID, suite.AEADID
		info := append([]byte("tls ech\x00"), ech.config.raw...)
		ech.encapsulatedKey, ech.hpkeContext, err = hpke.SetupSender(ech.config.KemID, suite.KDFID, suite.AEADID, echPK, info)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := c.makeClientHelloExtensions(hello, echConf.outerExtensions()); err != nil {
			return nil, nil, nil, err
		}
		if err := c.makeClientHelloExtensions(ech.innerHello, innerExtensions); err != nil {
			return nil, nil, nil, err
		}
	}

	return hello, keyShareKeys, ech, nil
}

type echClientContext struct {
	config          *echConfig
	hpkeContext     *hpke.Sender
	encapsulatedKey []byte
	innerHello      *clientHelloMsg
	innerTranscript hash.Hash
	kdfID           uint16
	aeadID          uint16
	echRejected     bool
	retryConfigs    []byte
}

func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false
	c.curveID = 0

	hello, keyShareKeys, ech, err := c.makeClientHello()
	if err != nil {
		return err
	}

	session, earlySecret, binderKey, err := c.loadSession(hello, ech)
	if err != nil {
		return err
	}
	if session == nil {
		hello := hello
		if ech != nil {
			setupInnerClientHelloCompress(c.config.echConfig(), hello, ech.innerHello)
			hello = ech.innerHello
		}

		c.config.updateClientHelloPadding(hello, false)
	} else {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}
		}()
	}

	if ech != nil {
		// Any extensions which have changed in hello, but are mirrored in the
		// outer hello and compressed, need to be copied to the outer hello, so
		// they can be properly decompressed by the server.
		hello.pskBinders = ech.innerHello.pskBinders
		// Overwrite the server name in the outer hello with the public facing
		// name.
		hello.serverName = string(ech.config.PublicName)
		// Generate a new random for the outer hello.
		hello.random = make([]byte, 32)
		_, err = io.ReadFull(c.config.rand(), hello.random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}

		// NOTE: we don't do PSK GREASE, in line with boringssl, it's meant to
		// work around _possibly_ broken middleboxes, but there is little-to-no
		// evidence that this is actually a problem.

		if err := c.config.computeAndUpdateOuterECHExtension(hello, ech.innerHello, ech, true); err != nil {
			return err
		}
	}

	c.serverName = hello.serverName

	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	handshakeFn := func() error {
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

		if err := c.pickTLSVersion(serverHello); err != nil {
			return err
		}

		extensions := hello.extensionList
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

		// If we are negotiating a protocol version that's lower than what we
		// support, check for the server downgrade canaries.
		// See RFC 8446, Section 4.1.3.
		maxVers := c.config.maxSupportedVersion(roleClient)
		tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
		tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
		if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
			maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
		}

		if c.vers == VersionTLS13 {
			hs := &clientHandshakeStateTLS13{
				c:            c,
				ctx:          ctx,
				serverHello:  serverHello,
				hello:        hello,
				keyShareKeys: keyShareKeys,
				session:      session,
				earlySecret:  earlySecret,
				binderKey:    binderKey,
				echContext:   ech,
				sentDummyCCS: hello.earlyData,
				extensions:   extensions,
			}
			return hs.handshake()
		}

		hs := &clientHandshakeState{
			c:           c,
			ctx:         ctx,
			serverHello: serverHello,
			hello:       hello,
			session:     session,
			extensions:  extensions,
		}
		return hs.handshake()
	}

	if hello.earlyData {
		hello := hello
		if ech != nil {
			hello = ech.innerHello
		}

		if c.quic == nil {
			c.vers = VersionTLS13
			c.in.version = VersionTLS13
			c.out.version = VersionTLS13

			if err := c.writeChangeCipherRecord(); err != nil {
				return err
			}
		}

		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		transcript := suite.hash.New()
		if err := transcriptMsg(hello, transcript); err != nil {
			return err
		}

		earlyTrafficSecret := suite.deriveSecret(earlySecret, clientEarlyTrafficLabel, transcript)
		if c.quic == nil {
			c.out.setTrafficSecret(suite, QUICEncryptionLevelEarly, earlyTrafficSecret, maxPlaintext+1)
		} else {
			c.quicSetWriteSecret(QUICEncryptionLevelEarly, suite.id, earlyTrafficSecret)
		}

		err = c.config.writeKeyLog(keyLogLabelClientEarly, hello.random, earlyTrafficSecret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		if c.quic == nil {
			c.handshakeState.Store(handshake0RTT)

			go func() {
				c.handshakeErr = handshakeFn()

				c.earlyNotify.L.Lock()
				c.earlyNotify.Broadcast()
				c.earlyNotify.L.Unlock()
			}()

			return nil
		}
	}

	return handshakeFn()
}

func (c *Conn) loadSession(outer *clientHelloMsg, ech *echClientContext) (
	session *SessionState, earlySecret, binderKey []byte, err error) {
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil, nil, nil, nil
	}

	hello := outer
	hello.ticketSupported = true

	if ech != nil {
		hello = ech.innerHello
	}

	if c.config.maxSupportedVersion(c.isClient) >= VersionTLS13 {
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return nil, nil, nil, nil
	}

	// Try to resume a previously negotiated TLS session, if available.
	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil, nil, nil, nil
	}
	cs, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || cs == nil {
		return nil, nil, nil, nil
	}
	session = cs.session

	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.version {
			versOk = true
			break
		}
	}
	if !versOk {
		return nil, nil, nil, nil
	}

	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	if c.config.time().After(session.peerCertificates[0].NotAfter) {
		// Expired certificate, delete the entry.
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return nil, nil, nil, nil
	}
	// Check that the cached server delegated credential is not expired
	if session.verifiedDC != nil && c.config.time().After(session.peerCertificates[0].NotBefore.Add(session.verifiedDC.Credential.ValidTime)) {
		// Expired delegated credential, delete the entry.
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return nil, nil, nil, nil
	}
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return nil, nil, nil, nil
		}
		if err := session.peerCertificates[0].VerifyHostname(c.config.ServerName); err != nil {
			return nil, nil, nil, nil
		}
	}

	if session.version != VersionTLS13 {
		// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
		// are still offering it.
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return nil, nil, nil, nil
		}

		hello.sessionTicket = session.ticket
		c.config.updateClientHelloPadding(hello, false)
		return
	}

	// Check that the session ticket is not expired.
	if c.config.time().After(time.Unix(int64(session.useBy), 0)) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return nil, nil, nil, nil
	}

	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return nil, nil, nil, nil
	}
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return nil, nil, nil, nil
	}

	if c.quic != nil && c.quic.enableSessionEvents {
		c.quicResumeSession(session)
	}

	if c.config.AllowEarlyData && session.maxEarlyData > 0 {
		// For 0-RTT, the cipher suite has to match exactly, and we need to be
		// offering the same ALPN.
		if mutualCipherSuiteTLS13(hello.cipherSuites, session.cipherSuite) != nil {
			if session.alpnProtocol == "" {
				hello.earlyData = true
			} else {
				if slices.Contains(hello.alpnProtocols, session.alpnProtocol) {
					hello.earlyData = true
				}
			}
		}
	}

	if c.quic == nil && hello.earlyData {
		c.earlyNotify = sync.NewCond(&sync.Mutex{})
		c.maxEarlyData = session.maxEarlyData
	}

	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	ticketAge := c.config.time().Sub(time.Unix(int64(session.createdAt), 0))
	identity := pskIdentity{
		label:               session.ticket,
		obfuscatedTicketAge: uint32(ticketAge/time.Millisecond) + session.ageAdd,
	}
	hello.pskIdentities = []pskIdentity{identity}
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}

	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	earlySecret = cipherSuite.extract(session.secret, nil)
	binderKey = cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)
	transcript := cipherSuite.hash.New()

	setupInnerClientHelloCompress(c.config.echConfig(), outer, hello)
	c.config.updateClientHelloPadding(hello, false)

	if err := computeAndUpdatePSK(hello, binderKey, transcript, cipherSuite.finishedHash); err != nil {
		return nil, nil, nil, err
	}

	return
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	if c.handshakeState.CompareAndSwap(handshake0RTT, handshakeRunning) {
		c.earlyNotify.L.Lock()
		c.earlyDataEOF = true
		c.earlyNotify.L.Unlock()

		c.out.cipher = nil
	}

	// If we did not load a session (hs.session == nil), but we did set a
	// session ID in the transmitted client hello (hs.hello.sessionId != nil),
	// it means we tried to negotiate TLS 1.3 and sent a random session ID as a
	// compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// Since we're now handshaking for TLS 1.2, if the server echoed the
	// transmitted ID back to us, we know mischief is afoot: the session ID
	// was random and can't possibly be recognized by the server.
	if hs.session == nil && hs.hello.sessionId != nil && bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server echoed TLS 1.3 compatibility session ID in TLS 1.2")
	}

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	if err := transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err := transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}
	if err := c.setup(); err != nil {
		return err
	}
	if err := hs.saveSessionTicket(); err != nil {
		return err
	}
	if err := hs.sendClientData(); err != nil {
		return err
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.handshakeState.Store(handshakeCompleted)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	msg, err = c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}

		c.ocspResponse = cs.response

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return err
		}
		if keyAgreement, ok := keyAgreement.(*ecdheKeyAgreement); ok {
			c.curveID = keyAgreement.curveID
			c.peerSigAlg = keyAgreement.signatureAlgorithm
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true

		cri := certificateRequestInfoFromMsg(hs.ctx, c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		if _, err := hs.c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
			return err
		}
	}

	if hs.serverHello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.hello.random, hs.serverHello.random)
	}
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(alertHandshakeFailure)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		if _, err := hs.c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	var maxRecvLimit, maxSentLimit uint16 = maxPlaintext, maxPlaintext
	if hs.serverHello.limitSupported {
		maxRecvLimit = hs.hello.recordSizeLimit
		maxSentLimit = hs.serverHello.recordSizeLimit
	}
	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash, serverKey, serverIV, serverMAC, hs.serverHello.encryptThenMAC, maxRecvLimit)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash, clientKey, clientIV, clientMAC, hs.serverHello.encryptThenMAC, maxSentLimit)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	supportsPointFormat := false
	offeredNonCompressedFormat := false
	for _, format := range hs.serverHello.supportedPoints {
		if format == pointFormatUncompressed {
			supportsPointFormat = true
		} else {
			offeredNonCompressedFormat = true
		}
	}
	if !supportsPointFormat && offeredNonCompressedFormat {
		return false, errors.New("tls: server offered only incompatible point formats")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	if hs.serverHello.limitSupported {
		if hs.serverHello.recordSizeLimit < 64 || hs.serverHello.recordSizeLimit > maxPlaintext {
			c.sendAlert(alertIllegalParameter)
			return false, errors.New("tls: server sent an invalid record size limit")
		}
	}

	if err := checkALPN(hs.hello.alpnProtocols, hs.serverHello.alpnProtocol, false); err != nil {
		c.sendAlert(alertUnsupportedExtension)
		return false, err
	}
	c.clientProtocol = hs.serverHello.alpnProtocol

	c.scts = hs.serverHello.scts

	if !hs.hello.encryptThenMAC && hs.serverHello.encryptThenMAC {
		c.sendAlert(alertIllegalParameter)
		return false, errors.New("tls: server sent unexpected encrypt-then-mac")
	}

	if c.handshakes > 0 && c.in.etm && !hs.serverHello.encryptThenMAC {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server want to disable encrypt-then-mac in renegotiation")
	}

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.version != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// RFC 7627, Section 5.3
	if hs.session.extMasterSecret != hs.serverHello.extendedMasterSecret {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different EMS extension")
	}

	// Restore master secret and certificates from previous state
	hs.masterSecret = hs.session.secret
	c.extMasterSecret = hs.session.extMasterSecret
	c.peerCertificates = hs.session.peerCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	// Let the ServerHello SCTs override the session SCTs from the original
	// connection, if any are provided.
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}
	c.curveID = hs.session.curveID

	return true, nil
}

// checkALPN ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the ClientHello.
func checkALPN(clientProtos []string, serverProto string, quic bool) error {
	if serverProto == "" {
		if quic && len(clientProtos) > 0 {
			// RFC 9001, Section 8.1
			return errors.New("tls: server did not select an ALPN protocol")
		}
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("tls: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("tls: server selected unadvertised ALPN protocol")
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}

	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}
	c := hs.c

	if !hs.hello.ticketSupported {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent unrequested session ticket")
	}

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}

	hs.ticket = sessionTicketMsg.ticket
	return nil
}

func (hs *clientHandshakeState) saveSessionTicket() error {
	if hs.ticket == nil {
		return nil
	}
	c := hs.c

	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil
	}

	session := c.sessionState()
	session.secret = hs.masterSecret
	session.ticket = hs.ticket

	cs := &ClientSessionState{session: session}
	c.config.ClientSessionCache.Put(cacheKey, cs)
	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

func (hs *clientHandshakeState) sendClientData() error {
	c := hs.c
	defer c.earlyData.Reset()

	if c.earlyData.Len() == 0 {
		return nil
	}

	c.out.Lock()
	defer c.out.Unlock()
	_, err := c.writeRecordLocked(recordTypeApplicationData, c.earlyData.Bytes())
	return err
}

// defaultMaxRSAKeySize is the maximum RSA key size in bits that we are willing
// to verify the signatures of during a TLS handshake.
const defaultMaxRSAKeySize = 8192

func checkKeySize(n int) (max int, ok bool) {
	return defaultMaxRSAKeySize, n <= defaultMaxRSAKeySize
}

// verifyServerCertificate parses and verifies the provided chain, setting
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := globalCertCache.newCert(asn1Data)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		if cert.PublicKeyAlgorithm == x509.RSA {
			n := cert.PublicKey.(*rsa.PublicKey).N.BitLen()
			if max, ok := checkKeySize(n); !ok {
				c.sendAlert(alertBadCertificate)
				return fmt.Errorf("tls: server sent certificate containing RSA key larger than %d bits", max)
			}
		}
		certs[i] = cert
	}

	echRejected := c.config.EncryptedClientHelloConfigList != nil && !c.echAccepted
	if echRejected {
		if c.config.EncryptedClientHelloRejectionVerify != nil {
			if err := c.config.EncryptedClientHelloRejectionVerify(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		} else {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.serverName,
				Intermediates: x509.NewCertPool(),
			}

			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			var err error
			c.verifiedChains, err = certs[0].Verify(opts)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
			}
		}
	} else if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		var err error
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil && !echRejected {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil && !echRejected {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

// certificateRequestInfoFromMsg generates a CertificateRequestInfo from a TLS
// <= 1.2 CertificateRequest, making an effort to fill in missing information.
func certificateRequestInfoFromMsg(ctx context.Context, vers uint16, certReq *certificateRequestMsg) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
		Version:       vers,
		ctx:           ctx,
	}

	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	if !certReq.hasSignatureAlgorithm {
		// Prior to TLS 1.2, signature schemes did not exist. In this case we
		// make up a list based on the acceptable certificate types, to help
		// GetClientCertificate and SupportsCertificate select the right certificate.
		// The hash part of the SignatureScheme is a lie here, because
		// TLS 1.0 and 1.1 always use MD5+SHA1 for RSA and SHA1 for ECDSA.
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case rsaAvail:
			cri.SignatureSchemes = []SignatureScheme{
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
			}
		}
		return cri
	}

	// Filter the signature schemes based on the certificate types.
	// See RFC 5246, Section 7.4.4 (where it calls this "somewhat complicated").
	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		sigType, _, err := typeAndHashFromSignatureScheme(sigScheme)
		if err != nil {
			continue
		}
		switch sigType {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func (c *Conn) clientSessionCacheKey() string {
	if len(c.config.ServerName) > 0 {
		return c.config.ServerName
	}
	if c.conn != nil {
		return c.conn.RemoteAddr().String()
	}
	return ""
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

func computeAndUpdatePSK(m *clientHelloMsg, binderKey []byte, transcript hash.Hash, finishedHash func([]byte, hash.Hash) []byte) error {
	helloBytes, err := m.marshalWithoutBinders()
	if err != nil {
		return err
	}
	transcript.Write(helloBytes)
	pskBinders := [][]byte{finishedHash(binderKey, transcript)}
	return m.updateBinders(pskBinders)
}
