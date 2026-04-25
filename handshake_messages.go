// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gitlab.com/go-extension/rand"
	"golang.org/x/crypto/cryptobyte"
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// addUint64 appends a big-endian, 64-bit value to the cryptobyte.Builder.
func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// readUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint64(s *cryptobyte.String, out *uint64) bool {
	var hi, lo uint32
	if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) {
		return false
	}
	*out = uint64(hi)<<32 | uint64(lo)
	return true
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type clientHelloMsg struct {
	original                                  []byte
	vers                                      uint16
	random                                    []byte
	sessionId                                 []byte
	cipherSuites                              []uint16
	compressionMethods                        []uint8
	serverName                                string
	ocspStapling                              bool
	supportedCurves                           []CurveID
	supportedPoints                           []uint8
	ticketSupported                           bool
	sessionTicket                             []uint8
	limitSupported                            bool
	recordSizeLimit                           uint16
	supportedCertificateCompressionAlgorithms []CertificateCompressionAlgorithm
	supportedSignatureAlgorithms              []SignatureScheme
	supportedSignatureAlgorithmsCert          []SignatureScheme
	supportedSignatureAlgorithmsDC            []SignatureScheme
	secureRenegotiationSupported              bool
	secureRenegotiation                       []byte
	encryptThenMAC                            bool
	extendedMasterSecret                      bool
	alpnProtocols                             []string
	alpsProtocols                             []string
	scts                                      bool
	supportedVersions                         []uint16
	cookie                                    []byte
	keyShares                                 []keyShare
	earlyData                                 bool
	pskModes                                  []uint8
	pskIdentities                             []pskIdentity
	pskBinders                                [][]byte
	quicTransportParameters                   []byte
	encryptedClientHello                      []byte
	// extensions are only populated on the server-side of a handshake
	extensions []uint16

	echOuterExts   []uint16
	compressedList []Extension
	extensionList  []Extension
}

func (m *clientHelloMsg) echInner() bool {
	return bytes.Equal(m.encryptedClientHello, []byte{1})
}

func (m *clientHelloMsg) echOuterExtensions(compressed []Extension) []uint16 {
	// Note that any extension that can be compressed during ECH must be
	// contiguous. If any additional extensions are to be compressed they must
	// be added to the following block, so that they can be properly
	// decompressed on the other side.
	var echOuterExts []uint16

	for _, extension := range compressed {
		switch extension.(type) {
		case nil:
		case *ServerNameIndicationExtension:
			if len(m.serverName) > 0 {
				echOuterExts = append(echOuterExts, extensionServerName)
			}
		case *SupportedPointsExtension:
			if len(m.supportedPoints) > 0 {
				echOuterExts = append(echOuterExts, extensionSupportedPoints)
			}
		case *SessionTicketExtension:
			if m.ticketSupported {
				echOuterExts = append(echOuterExts, extensionSessionTicket)
			}
		case *RenegotiationInfoExtension:
			if m.secureRenegotiationSupported {
				echOuterExts = append(echOuterExts, extensionRenegotiationInfo)
			}
		case *EncryptThenMacExtension:
			if m.encryptThenMAC {
				echOuterExts = append(echOuterExts, extensionEncryptThenMAC)
			}
		case *ExtendedMasterSecretExtension:
			if m.extendedMasterSecret {
				echOuterExts = append(echOuterExts, extensionExtendedMasterSecret)
			}
		case *SCTExtension:
			if m.scts {
				echOuterExts = append(echOuterExts, extensionSCT)
			}
		case *EarlyDataExtension:
			if m.earlyData {
				echOuterExts = append(echOuterExts, extensionEarlyData)
			}
		case *QUICTransportParametersExtension:
			if m.quicTransportParameters != nil {
				echOuterExts = append(echOuterExts, extensionQUICTransportParameters)
			}
		case *EncryptedClientHelloExtension:
		case *StatusRequestExtension:
			if m.ocspStapling {
				echOuterExts = append(echOuterExts, extensionStatusRequest)
			}
		case *SupportedGroupsExtension:
			if len(m.supportedCurves) > 0 {
				echOuterExts = append(echOuterExts, extensionSupportedCurves)
			}
		case *SignatureAlgorithmsExtension:
			if len(m.supportedSignatureAlgorithms) > 0 {
				echOuterExts = append(echOuterExts, extensionSignatureAlgorithms)
			}
		case *SignatureAlgorithmsCertExtension:
			if len(m.supportedSignatureAlgorithmsCert) > 0 {
				echOuterExts = append(echOuterExts, extensionSignatureAlgorithmsCert)
			}
		case *DelegatedCredentialsExtension:
			if len(m.supportedSignatureAlgorithmsDC) > 0 {
				echOuterExts = append(echOuterExts, extensionDelegatedCredentials)
			}
		case *ALPNExtension:
			if len(m.alpnProtocols) > 0 {
				echOuterExts = append(echOuterExts, extensionALPN)
			}
		case *LegacyALPSExtension:
			if len(m.alpsProtocols) > 0 {
				echOuterExts = append(echOuterExts, extensionLegacyALPS)
			}
		case *ALPSExtension:
			if len(m.alpsProtocols) > 0 {
				echOuterExts = append(echOuterExts, extensionALPS)
			}
		case *SupportedVersionsExtension:
			if len(m.supportedVersions) > 0 {
				echOuterExts = append(echOuterExts, extensionSupportedVersions)
			}
		case *CompressedCertificateExtension:
			if len(m.supportedCertificateCompressionAlgorithms) > 0 {
				echOuterExts = append(echOuterExts, extensionCompressCertificate)
			}
		case *RecordSizeLimitExtension:
			if m.limitSupported {
				echOuterExts = append(echOuterExts, extensionRecordSizeLimit)
			}
		case *CookieExtension:
			if len(m.cookie) > 0 {
				echOuterExts = append(echOuterExts, extensionCookie)
			}
		case *KeyShareExtension:
			if len(m.keyShares) > 0 {
				echOuterExts = append(echOuterExts, extensionKeyShare)
			}
		case *PSKModesExtension:
			if len(m.pskModes) > 0 {
				echOuterExts = append(echOuterExts, extensionPSKModes)
			}
		case *ECHOuterExtension:
		case *PreSharedKeyExtension:
			if len(m.pskIdentities) > 0 {
				echOuterExts = append(echOuterExts, extensionPreSharedKey)
			}
		default:
			if extension.Negotiate(typeClientHello, false) {
				echOuterExts = append(echOuterExts, extension.ExtensionId())
			}
		}
	}

	return echOuterExts
}

func (m *clientHelloMsg) marshalMsg(echInner bool) ([]byte, error) {
	var exts cryptobyte.Builder
	for _, extension := range m.extensionList {
		if extension == nil {
			continue
		}

		if echInner && slices.Contains(m.echOuterExts, extension.ExtensionId()) {
			continue
		}

		switch extension.(type) {
		case *ServerNameIndicationExtension:
			if len(m.serverName) > 0 {
				// RFC 6066, Section 3
				exts.AddUint16(extensionServerName)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddUint8(0) // name_type = host_name
						exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes([]byte(m.serverName))
						})
					})
				})
			}
		case *SupportedPointsExtension:
			if len(m.supportedPoints) > 0 {
				// RFC 4492, Section 5.1.2
				exts.AddUint16(extensionSupportedPoints)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.supportedPoints)
					})
				})
			}
		case *SessionTicketExtension:
			if m.ticketSupported {
				// RFC 5077, Section 3.2
				exts.AddUint16(extensionSessionTicket)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.sessionTicket)
				})
			}
		case *RenegotiationInfoExtension:
			if m.secureRenegotiationSupported {
				// RFC 5746, Section 3.2
				exts.AddUint16(extensionRenegotiationInfo)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.secureRenegotiation)
					})
				})
			}
		case *EncryptThenMacExtension:
			if m.encryptThenMAC {
				// RFC 7366
				exts.AddUint16(extensionEncryptThenMAC)
				exts.AddUint16(0) // empty extension_data
			}
		case *ExtendedMasterSecretExtension:
			if m.extendedMasterSecret {
				// RFC 7627
				exts.AddUint16(extensionExtendedMasterSecret)
				exts.AddUint16(0) // empty extension_data
			}
		case *SCTExtension:
			if m.scts {
				// RFC 6962, Section 3.3.1
				exts.AddUint16(extensionSCT)
				exts.AddUint16(0) // empty extension_data
			}
		case *EarlyDataExtension:
			if m.earlyData {
				// RFC 8446, Section 4.2.10
				exts.AddUint16(extensionEarlyData)
				exts.AddUint16(0) // empty extension_data
			}
		case *QUICTransportParametersExtension:
			if m.quicTransportParameters != nil { // marshal zero-length parameters when present
				// RFC 9001, Section 8.2
				exts.AddUint16(extensionQUICTransportParameters)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.quicTransportParameters)
				})
			}
		case *EncryptedClientHelloExtension:
			if len(m.encryptedClientHello) > 0 {
				exts.AddUint16(extensionEncryptedClientHello)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.encryptedClientHello)
				})
			}
		case *StatusRequestExtension:
			if m.ocspStapling {
				// RFC 4366, Section 3.6
				exts.AddUint16(extensionStatusRequest)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8(1)  // status_type = ocsp
					exts.AddUint16(0) // empty responder_id_list
					exts.AddUint16(0) // empty request_extensions
				})
			}
		case *SupportedGroupsExtension:
			if len(m.supportedCurves) > 0 {
				// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
				exts.AddUint16(extensionSupportedCurves)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, curve := range m.supportedCurves {
							exts.AddUint16(uint16(curve))
						}
					})
				})
			}
		case *SignatureAlgorithmsExtension:
			if len(m.supportedSignatureAlgorithms) > 0 {
				// RFC 5246, Section 7.4.1.4.1
				exts.AddUint16(extensionSignatureAlgorithms)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithms {
							exts.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
		case *SignatureAlgorithmsCertExtension:
			if len(m.supportedSignatureAlgorithmsCert) > 0 {
				// RFC 8446, Section 4.2.3
				exts.AddUint16(extensionSignatureAlgorithmsCert)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
							exts.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
		case *DelegatedCredentialsExtension:
			if len(m.supportedSignatureAlgorithmsDC) > 0 {
				// RFC 9345, Section 4.1.1
				exts.AddUint16(extensionDelegatedCredentials)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithmsDC {
							exts.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
		case *ALPNExtension:
			if len(m.alpnProtocols) > 0 {
				// RFC 7301, Section 3.1
				exts.AddUint16(extensionALPN)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, proto := range m.alpnProtocols {
							exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes([]byte(proto))
							})
						}
					})
				})
			}
		case *LegacyALPSExtension:
			if len(m.alpsProtocols) > 0 {
				exts.AddUint16(extensionLegacyALPS)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, proto := range m.alpsProtocols {
							exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes([]byte(proto))
							})
						}
					})
				})
			}
		case *ALPSExtension:
			if len(m.alpsProtocols) > 0 {
				exts.AddUint16(extensionALPS)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, proto := range m.alpsProtocols {
							exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes([]byte(proto))
							})
						}
					})
				})
			}
		case *SupportedVersionsExtension:
			if len(m.supportedVersions) > 0 {
				// RFC 8446, Section 4.2.1
				exts.AddUint16(extensionSupportedVersions)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, vers := range m.supportedVersions {
							exts.AddUint16(vers)
						}
					})
				})
			}
		case *CompressedCertificateExtension:
			if len(m.supportedCertificateCompressionAlgorithms) > 0 {
				exts.AddUint16(extensionCompressCertificate)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, algorithm := range m.supportedCertificateCompressionAlgorithms {
							exts.AddUint16(uint16(algorithm))
						}
					})
				})
			}
		case *RecordSizeLimitExtension:
			if m.limitSupported {
				// RFC 8449, Section 4
				exts.AddUint16(extensionRecordSizeLimit)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16(m.recordSizeLimit)
				})
			}
		case *CookieExtension:
			if len(m.cookie) > 0 {
				// RFC 8446, Section 4.2.2
				exts.AddUint16(extensionCookie)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.cookie)
					})
				})
			}
		case *KeyShareExtension:
			if len(m.keyShares) > 0 {
				// RFC 8446, Section 4.2.8
				exts.AddUint16(extensionKeyShare)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, ks := range m.keyShares {
							exts.AddUint16(uint16(ks.group))
							exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes(ks.data)
							})
						}
					})
				})
			}
		case *PSKModesExtension:
			if len(m.pskModes) > 0 {
				// RFC 8446, Section 4.2.9
				exts.AddUint16(extensionPSKModes)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.pskModes)
					})
				})
			}
		case *ECHOuterExtension:
			if echInner {
				if len(m.echOuterExts) > 0 {
					exts.AddUint16(extensionECHOuterExtensions)
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
							for _, e := range m.echOuterExts {
								exts.AddUint16(e)
							}
						})
					})
				}
			}
		case *PreSharedKeyExtension:
			if len(m.pskIdentities) > 0 { // pre_shared_key must be the last extension
				// RFC 8446, Section 4.2.11
				exts.AddUint16(extensionPreSharedKey)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, psk := range m.pskIdentities {
							exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes(psk.label)
							})
							exts.AddUint32(psk.obfuscatedTicketAge)
						}
					})
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, binder := range m.pskBinders {
							exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes(binder)
							})
						}
					})
				})
			}
		default:
			if extension.Negotiate(typeClientHello, echInner) {
				exts.AddUint16(extension.ExtensionId())
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					extension.Marshal(typeClientHello, echInner, exts)
				})
			}
		}
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if !echInner {
				b.AddBytes(m.sessionId)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressionMethods)
		})

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *clientHelloMsg) marshal() ([]byte, error) {
	return m.marshalMsg(false)
}

func (m *clientHelloMsg) getUnpaddedLength() int {
	var length int
	length += 1
	length += 3
	length += 2

	length += 32

	length += 1
	length += len(m.sessionId)

	length += 2
	length += len(m.cipherSuites) * 2

	length += 1
	length += len(m.compressionMethods)

	{
		var extLength int
		for _, extension := range m.extensionList {
			switch extension.(type) {
			case nil:
			case *ServerNameIndicationExtension:
				if len(m.serverName) > 0 {
					extLength += 4
					// RFC 6066, Section 3
					extLength += 2
					extLength += 1
					extLength += 2
					extLength += len(m.serverName)
				}
			case *StatusRequestExtension:
				if m.ocspStapling {
					extLength += 4
					// RFC 4366, Section 3.6
					extLength += 1
					extLength += 2
					extLength += 2
				}
			case *SupportedGroupsExtension:
				if len(m.supportedCurves) > 0 {
					extLength += 4
					// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
					extLength += 2
					extLength += len(m.supportedCurves) * 2
				}
			case *SupportedPointsExtension:
				if len(m.supportedPoints) > 0 {
					extLength += 4
					// RFC 4492, Section 5.1.2
					extLength += 1
					extLength += len(m.supportedPoints)
				}
			case *SessionTicketExtension:
				if m.ticketSupported {
					extLength += 4
					// RFC 5077, Section 3.2
					extLength += len(m.sessionTicket)
				}
			case *SignatureAlgorithmsExtension:
				if len(m.supportedSignatureAlgorithms) > 0 {
					extLength += 4
					// RFC 5246, Section 7.4.1.4.1
					extLength += 2
					extLength += len(m.supportedSignatureAlgorithms) * 2
				}
			case *SignatureAlgorithmsCertExtension:
				if len(m.supportedSignatureAlgorithmsCert) > 0 {
					extLength += 4
					// RFC 8446, Section 4.2.3
					extLength += 2
					extLength += len(m.supportedSignatureAlgorithmsCert) * 2
				}
			case *DelegatedCredentialsExtension:
				if len(m.supportedSignatureAlgorithmsDC) > 0 {
					extLength += 4
					// RFC 9345, Section 4.1.1
					extLength += 2
					extLength += len(m.supportedSignatureAlgorithmsCert) * 2
				}
			case *RenegotiationInfoExtension:
				if m.secureRenegotiationSupported {
					extLength += 4
					// RFC 5746, Section 3.2
					extLength += 1
					extLength += len(m.secureRenegotiation)
				}
			case *EncryptThenMacExtension:
				if m.encryptThenMAC {
					// RFC 7366
					extLength += 4
				}
			case *ExtendedMasterSecretExtension:
				if m.extendedMasterSecret {
					extLength += 4
				}
				// RFC 7627
			case *ALPNExtension:
				if len(m.alpnProtocols) > 0 {
					extLength += 4
					// RFC 7301, Section 3.1
					extLength += 2
					for _, proto := range m.alpnProtocols {
						extLength += 1
						extLength += len(proto)
					}
				}
			case *LegacyALPSExtension, *ALPSExtension:
				if len(m.alpsProtocols) > 0 {
					extLength += 4

					extLength += 2
					for _, proto := range m.alpsProtocols {
						extLength += 1
						extLength += len(proto)
					}
				}
			case *SCTExtension:
				if m.scts {
					extLength += 4
					// RFC 6962, Section 3.3.1
				}
			case *SupportedVersionsExtension:
				if len(m.supportedVersions) > 0 {
					extLength += 4
					// RFC 8446, Section 4.2.1
					extLength += 1
					extLength += len(m.supportedVersions) * 2
				}
			case *CompressedCertificateExtension:
				if len(m.supportedCertificateCompressionAlgorithms) > 0 {
					extLength += 4

					extLength += 1
					extLength += len(m.supportedCertificateCompressionAlgorithms) * 2
				}
			case *RecordSizeLimitExtension:
				if m.limitSupported {
					extLength += 4
					// RFC 8449, Section 4
					extLength += 2
				}
			case *CookieExtension:
				if len(m.cookie) > 0 {
					extLength += 4
					// RFC 8446, Section 4.2.2
					extLength += 2
					extLength += len(m.cookie)
				}
			case *KeyShareExtension:
				if len(m.keyShares) > 0 {
					extLength += 4
					// RFC 8446, Section 4.2.8
					extLength += 2
					for _, ks := range m.keyShares {
						extLength += 2
						extLength += 2
						extLength += len(ks.data)
					}
				}
			case *EarlyDataExtension:
				if m.earlyData {
					extLength += 4
					// RFC 8446, Section 4.2.10
				}
			case *PSKModesExtension:
				if len(m.pskModes) > 0 {
					extLength += 4
					// RFC 8446, Section 4.2.9
					extLength += 1
					extLength += len(m.pskModes)
				}
			case *EncryptedClientHelloExtension:
				if len(m.encryptedClientHello) > 0 {
					extLength += 4
					extLength += len(m.encryptedClientHello)
				}
			case *ECHOuterExtension:
			case *QUICTransportParametersExtension:
				if m.quicTransportParameters != nil { // marshal zero-length parameters when present
					extLength += 4
					// RFC 9001, Section 8.2
					extLength += len(m.quicTransportParameters)
				}
			case *PreSharedKeyExtension:
				if len(m.pskIdentities) > 0 { // pre_shared_key must be the last extension
					extLength += 4
					// RFC 8446, Section 4.2.11
					extLength += 2
					for _, psk := range m.pskIdentities {
						extLength += 2
						extLength += len(psk.label)
						extLength += 4
					}

					extLength += 2
					for _, binder := range m.pskBinders {
						extLength += 1
						extLength += len(binder)
					}
				}
			case *PaddingExtension:
			default:
				extLength += 4
				extLength += extension.Len(typeClientHello, false)
			}
		}

		if extLength > 0 {
			length += 2
			length += extLength
		}
	}

	return length
}

func (m *clientHelloMsg) updatePaddingExtension(length uint16, ok bool) {
	if !ok {
		m.extensionList = slices.DeleteFunc(m.extensionList, func(extension Extension) bool {
			_, ok := extension.(*PaddingExtension)
			return ok
		})
		return
	}

	var seenPadding bool
	for i, extension := range m.extensionList {
		switch extension := extension.(type) {
		case *PaddingExtension:
			if seenPadding {
				m.extensionList[i] = nil
			} else {
				seenPadding = true
				extension.Length = length
			}
		}
	}

	m.extensionList = slices.DeleteFunc(m.extensionList, func(extension Extension) bool {
		return extension == nil
	})
}

// Shuffle extensions to avoid fingerprinting -- introduced in Chrome 106
func (m *clientHelloMsg) shuffleExtensions() {
	// shuffleCheck checks:
	// - if the m.extensions[i] is a ECHOuter extension, then it should not be shuffled
	// - if the m.extensions[i] is a GREASE extension, then it should not be shuffled
	// - if the m.extensions[i] is a padding/pre_shared_key extension, then it should be the
	//  last extension in the list and should not be shuffled
	var shuffleCheck = func(i int) bool {
		switch m.extensionList[i].(type) {
		case *ECHOuterExtension, *GREASEExtension, *PaddingExtension, *PreSharedKeyExtension:
			return false
		default:
			return true
		}
	}

	// Shuffle other extensions
	rand.Crypto.Shuffle(len(m.extensionList), func(i, j int) {
		if !shuffleCheck(i) || !shuffleCheck(j) {
			return
		}

		m.extensionList[i], m.extensionList[j] = m.extensionList[j], m.extensionList[i]
	})
}

// marshalWithoutBinders returns the ClientHello through the
// PreSharedKeyExtension.identities field, according to RFC 8446, Section
// 4.2.11.2. Note that m.pskBinders must be set to slices of the correct length.
func (m *clientHelloMsg) marshalWithoutBinders() ([]byte, error) {
	var bindersLen int

	if len(m.pskIdentities) > 0 {
		for _, extension := range m.extensionList {
			if _, ok := extension.(*PreSharedKeyExtension); ok {
				bindersLen += 2
				for _, binder := range m.pskBinders {
					bindersLen += 1
					bindersLen += len(binder)
				}
			}
		}
	}

	var fullMessage []byte
	if m.original != nil {
		fullMessage = m.original
	} else {
		var err error
		fullMessage, err = m.marshal()
		if err != nil {
			return nil, err
		}
	}
	return fullMessage[:len(fullMessage)-bindersLen], nil
}

// updateBinders updates the m.pskBinders field. The supplied binders must have
// the same length as the current m.pskBinders.
func (m *clientHelloMsg) updateBinders(pskBinders [][]byte) error {
	if len(pskBinders) != len(m.pskBinders) {
		return errors.New("tls: internal error: pskBinders length mismatch")
	}
	for i := range m.pskBinders {
		if len(pskBinders[i]) != len(m.pskBinders[i]) {
			return errors.New("tls: internal error: pskBinders length mismatch")
		}
	}
	m.pskBinders = pskBinders

	return nil
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	m.secureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
		m.cipherSuites = append(m.cipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true
		m.extensions = append(m.extensions, extension)

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}
			m.extensionList = append(m.extensionList, &ServerNameIndicationExtension{})
		case extensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.ocspStapling = statusType == statusTypeOCSP
			m.extensionList = append(m.extensionList, &StatusRequestExtension{})
		case extensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.supportedCurves = append(m.supportedCurves, CurveID(curve))
			}
			m.extensionList = append(m.extensionList, &SupportedGroupsExtension{})
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return false
			}
			m.extensionList = append(m.extensionList, &SupportedPointsExtension{})
		case extensionSessionTicket:
			// RFC 5077, Section 3.2
			m.ticketSupported = true
			extData.ReadBytes(&m.sessionTicket, len(extData))
			m.extensionList = append(m.extensionList, &SessionTicketExtension{})
		case extensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
			m.extensionList = append(m.extensionList, &SignatureAlgorithmsExtension{})
		case extensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsCert = append(
					m.supportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
			}
			m.extensionList = append(m.extensionList, &SignatureAlgorithmsCertExtension{})
		case extensionDelegatedCredentials:
			// RFC 9345, Section 4.1.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsDC = append(
					m.supportedSignatureAlgorithmsDC, SignatureScheme(sigAndAlg))
			}
			m.extensionList = append(m.extensionList, &DelegatedCredentialsExtension{})
		case extensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
			m.extensionList = append(m.extensionList, &RenegotiationInfoExtension{})
		case extensionEncryptThenMAC:
			// RFC 7366
			m.encryptThenMAC = true
			m.extensionList = append(m.extensionList, &EncryptThenMacExtension{})
		case extensionExtendedMasterSecret:
			// RFC 7627
			m.extendedMasterSecret = true
			m.extensionList = append(m.extensionList, &ExtendedMasterSecretExtension{})
		case extensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(proto))
			}
			m.extensionList = append(m.extensionList, &ALPNExtension{})
		case extensionLegacyALPS:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpsProtocols = append(m.alpsProtocols, string(proto))
			}
			m.extensionList = append(m.extensionList, &LegacyALPSExtension{})
		case extensionALPS:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpsProtocols = append(m.alpsProtocols, string(proto))
			}
			m.extensionList = append(m.extensionList, &ALPSExtension{})
		case extensionSCT:
			// RFC 6962, Section 3.3.1
			m.scts = true
			m.extensionList = append(m.extensionList, &SCTExtension{})
		case extensionCompressCertificate:
			var compressionList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&compressionList) || compressionList.Empty() {
				return false
			}
			for !compressionList.Empty() {
				var compression uint16
				if !compressionList.ReadUint16(&compression) {
					return false
				}
				m.supportedCertificateCompressionAlgorithms = append(m.supportedCertificateCompressionAlgorithms, CertificateCompressionAlgorithm(compression))
			}
			m.extensionList = append(m.extensionList, &CompressedCertificateExtension{})
		case extensionRecordSizeLimit:
			// RFC 8449, Section 4
			m.limitSupported = true
			if !extData.ReadUint16(&m.recordSizeLimit) {
				return false
			}
			m.extensionList = append(m.extensionList, &RecordSizeLimitExtension{})
		case extensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return false
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return false
				}
				m.supportedVersions = append(m.supportedVersions, vers)
			}
			m.extensionList = append(m.extensionList, &SupportedVersionsExtension{})
		case extensionCookie:
			// RFC 8446, Section 4.2.2
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
			m.extensionList = append(m.extensionList, &CookieExtension{})
		case extensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return false
			}
			for !clientShares.Empty() {
				var ks keyShare
				if !clientShares.ReadUint16((*uint16)(&ks.group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.data) ||
					len(ks.data) == 0 {
					return false
				}
				m.keyShares = append(m.keyShares, ks)
			}
			m.extensionList = append(m.extensionList, &KeyShareExtension{})
		case extensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.earlyData = true
			m.extensionList = append(m.extensionList, &EarlyDataExtension{})
		case extensionPSKModes:
			// RFC 8446, Section 4.2.9
			if !readUint8LengthPrefixed(&extData, &m.pskModes) {
				return false
			}
			m.extensionList = append(m.extensionList, &PSKModesExtension{})
		case extensionQUICTransportParameters:
			m.quicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.quicTransportParameters) {
				return false
			}
			m.extensionList = append(m.extensionList, &QUICTransportParametersExtension{})
		case extensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if !extensions.Empty() {
				return false // pre_shared_key must be the last extension
			}
			var identities cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
				return false
			}
			for !identities.Empty() {
				var psk pskIdentity
				if !readUint16LengthPrefixed(&identities, &psk.label) ||
					!identities.ReadUint32(&psk.obfuscatedTicketAge) ||
					len(psk.label) == 0 {
					return false
				}
				m.pskIdentities = append(m.pskIdentities, psk)
			}
			var binders cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
				return false
			}
			for !binders.Empty() {
				var binder []byte
				if !readUint8LengthPrefixed(&binders, &binder) ||
					len(binder) == 0 {
					return false
				}
				m.pskBinders = append(m.pskBinders, binder)
			}
			m.extensionList = append(m.extensionList, &PreSharedKeyExtension{})
		case extensionEncryptedClientHello:
			if !extData.ReadBytes(&m.encryptedClientHello, len(extData)) {
				return false
			}
			m.extensionList = append(m.extensionList, &EncryptedClientHelloExtension{})
		case extensionECHOuterExtensions:
			m.extensionList = append(m.extensionList, &ECHOuterExtension{})
		case extensionPadding:
			ext := &PaddingExtension{}
			if ok, _ := ext.Unmarshal(typeClientHello, false, extData, nil); !ok {
				return false
			}
			m.extensionList = append(m.extensionList, ext)
			continue
		default:
			var ext Extension

			switch {
			case IsGREASE(extension):
				ext = &GREASEExtension{Id: extension}
			default:
				ext = &UnimplementedExtension{Id: extension}
			}

			if ok, _ := ext.Unmarshal(typeClientHello, false, extData, nil); !ok {
				return false
			}

			m.extensionList = append(m.extensionList, ext)
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *clientHelloMsg) originalBytes() []byte {
	return m.original
}

func (m *clientHelloMsg) clone() *clientHelloMsg {
	return &clientHelloMsg{
		original:           slices.Clone(m.original),
		vers:               m.vers,
		random:             slices.Clone(m.random),
		sessionId:          slices.Clone(m.sessionId),
		cipherSuites:       slices.Clone(m.cipherSuites),
		compressionMethods: slices.Clone(m.compressionMethods),
		serverName:         m.serverName,
		ocspStapling:       m.ocspStapling,
		supportedCurves:    slices.Clone(m.supportedCurves),
		supportedPoints:    slices.Clone(m.supportedPoints),
		ticketSupported:    m.ticketSupported,
		sessionTicket:      slices.Clone(m.sessionTicket),
		limitSupported:     m.limitSupported,
		recordSizeLimit:    m.recordSizeLimit,
		supportedCertificateCompressionAlgorithms: slices.Clone(m.supportedCertificateCompressionAlgorithms),
		supportedSignatureAlgorithms:              slices.Clone(m.supportedSignatureAlgorithms),
		supportedSignatureAlgorithmsCert:          slices.Clone(m.supportedSignatureAlgorithmsCert),
		secureRenegotiationSupported:              m.secureRenegotiationSupported,
		secureRenegotiation:                       slices.Clone(m.secureRenegotiation),
		encryptThenMAC:                            m.encryptThenMAC,
		extendedMasterSecret:                      m.extendedMasterSecret,
		alpnProtocols:                             slices.Clone(m.alpnProtocols),
		alpsProtocols:                             slices.Clone(m.alpsProtocols),
		scts:                                      m.scts,
		supportedVersions:                         slices.Clone(m.supportedVersions),
		cookie:                                    slices.Clone(m.cookie),
		keyShares:                                 slices.Clone(m.keyShares),
		earlyData:                                 m.earlyData,
		pskModes:                                  slices.Clone(m.pskModes),
		pskIdentities:                             slices.Clone(m.pskIdentities),
		pskBinders:                                slices.Clone(m.pskBinders),
		quicTransportParameters:                   slices.Clone(m.quicTransportParameters),
		encryptedClientHello:                      slices.Clone(m.encryptedClientHello),
		extensions:                                slices.Clone(m.extensions),
		echOuterExts:                              slices.Clone(m.echOuterExts),
		compressedList:                            slices.Clone(m.compressedList),
		extensionList:                             slices.Clone(m.extensionList),
	}
}

type serverHelloMsg struct {
	original                     []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	ocspStapling                 bool
	ticketSupported              bool
	limitSupported               bool
	recordSizeLimit              uint16
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	encryptThenMAC               bool
	extendedMasterSecret         bool
	alpnProtocol                 string
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16
	supportedPoints              []uint8
	encryptedClientHello         []byte
	serverNameAck                bool

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup CurveID

	extensions []Extension
}

func (m *serverHelloMsg) marshal() ([]byte, error) {
	var exts cryptobyte.Builder

	for _, extension := range m.extensions {
		switch extension.(type) {
		case nil:
		case *StatusRequestExtension:
			if m.ocspStapling {
				exts.AddUint16(extensionStatusRequest)
				exts.AddUint16(0) // empty extension_data
			}
		case *SessionTicketExtension:
			if m.ticketSupported {
				exts.AddUint16(extensionSessionTicket)
				exts.AddUint16(0) // empty extension_data
			}
		case *RenegotiationInfoExtension:
			if m.secureRenegotiationSupported {
				exts.AddUint16(extensionRenegotiationInfo)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.secureRenegotiation)
					})
				})
			}
		case *EncryptThenMacExtension:
			if m.encryptThenMAC {
				exts.AddUint16(extensionEncryptThenMAC)
				exts.AddUint16(0) // empty extension_data
			}
		case *ExtendedMasterSecretExtension:
			if m.extendedMasterSecret {
				exts.AddUint16(extensionExtendedMasterSecret)
				exts.AddUint16(0) // empty extension_data
			}
		case *ALPNExtension:
			if len(m.alpnProtocol) > 0 {
				exts.AddUint16(extensionALPN)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes([]byte(m.alpnProtocol))
						})
					})
				})
			}
		case *SCTExtension:
			if len(m.scts) > 0 {
				exts.AddUint16(extensionSCT)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, sct := range m.scts {
							exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
								exts.AddBytes(sct)
							})
						}
					})
				})
			}
		case *SupportedVersionsExtension:
			if m.supportedVersion != 0 {
				exts.AddUint16(extensionSupportedVersions)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16(m.supportedVersion)
				})
			}
		case *KeyShareExtension:
			if m.serverShare.group != 0 {
				exts.AddUint16(extensionKeyShare)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16(uint16(m.serverShare.group))
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.serverShare.data)
					})
				})
			}

			if m.selectedGroup != 0 {
				exts.AddUint16(extensionKeyShare)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16(uint16(m.selectedGroup))
				})
			}
		case *PreSharedKeyExtension:
			if m.selectedIdentityPresent {
				exts.AddUint16(extensionPreSharedKey)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16(m.selectedIdentity)
				})
			}
		case *RecordSizeLimitExtension:
			if m.limitSupported {
				// RFC 8449, Section 4
				exts.AddUint16(extensionRecordSizeLimit)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16(m.recordSizeLimit)
				})
			}
		case *CookieExtension:
			if len(m.cookie) > 0 {
				exts.AddUint16(extensionCookie)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.cookie)
					})
				})
			}
		case *SupportedPointsExtension:
			if len(m.supportedPoints) > 0 {
				exts.AddUint16(extensionSupportedPoints)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(m.supportedPoints)
					})
				})
			}
		case *EncryptedClientHelloExtension:
			if len(m.encryptedClientHello) > 0 {
				exts.AddUint16(extensionEncryptedClientHello)
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.encryptedClientHello)
				})
			}
		case *ServerNameIndicationExtension:
			if m.serverNameAck {
				exts.AddUint16(extensionServerName)
				exts.AddUint16(0)
			}
		default:
			if extension.Negotiate(typeServerHello, false) {
				exts.AddUint16(extension.ExtensionId())
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					extension.Marshal(typeServerHello, false, exts)
				})
			}
		}
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16(m.cipherSuite)
		b.AddUint8(m.compressionMethod)

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case extensionStatusRequest:
			m.ocspStapling = true
			m.extensions = append(m.extensions, &StatusRequestExtension{})
		case extensionSessionTicket:
			m.ticketSupported = true
			m.extensions = append(m.extensions, &SessionTicketExtension{})
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
			m.extensions = append(m.extensions, &RenegotiationInfoExtension{})
		case extensionEncryptThenMAC:
			// RFC 7366
			m.encryptThenMAC = true
			m.extensions = append(m.extensions, &EncryptThenMacExtension{})
		case extensionExtendedMasterSecret:
			m.extendedMasterSecret = true
			m.extensions = append(m.extensions, &ExtendedMasterSecretExtension{})
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
			m.extensions = append(m.extensions, &ALPNExtension{})
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return false
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return false
				}
				m.scts = append(m.scts, sct)
			}
			m.extensions = append(m.extensions, &SCTExtension{})
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.supportedVersion) {
				return false
			}
			m.extensions = append(m.extensions, &SupportedVersionsExtension{})
		case extensionRecordSizeLimit:
			// RFC 8449, Section 4
			m.limitSupported = true
			if !extData.ReadUint16(&m.recordSizeLimit) {
				return false
			}
			m.extensions = append(m.extensions, &RecordSizeLimitExtension{})
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
			m.extensions = append(m.extensions, &CookieExtension{})
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.selectedGroup)) {
					return false
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.serverShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.serverShare.data) {
					return false
				}
			}
			m.extensions = append(m.extensions, &KeyShareExtension{})
		case extensionPreSharedKey:
			m.selectedIdentityPresent = true
			if !extData.ReadUint16(&m.selectedIdentity) {
				return false
			}
			m.extensions = append(m.extensions, &PreSharedKeyExtension{})
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return false
			}
			m.extensions = append(m.extensions, &SupportedPointsExtension{})
		case extensionEncryptedClientHello: // encrypted_client_hello
			m.encryptedClientHello = make([]byte, len(extData))
			if !extData.CopyBytes(m.encryptedClientHello) {
				return false
			}
			m.extensions = append(m.extensions, &EncryptedClientHelloExtension{})
		case extensionServerName:
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
			m.extensions = append(m.extensions, &ServerNameIndicationExtension{})
		default:
			var ext Extension

			switch {
			case IsGREASE(extension):
				ext = &GREASEExtension{Id: extension}
			default:
				ext = &UnimplementedExtension{Id: extension}
			}

			if ok, _ := ext.Unmarshal(typeServerHello, false, extData, nil); !ok {
				return false
			}

			m.extensions = append(m.extensions, ext)
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *serverHelloMsg) originalBytes() []byte {
	return m.original
}

type encryptedExtensionsMsg struct {
	alpnProtocol            string
	alps                    bool
	alpnSetting             []byte
	quicTransportParameters []byte
	earlyData               bool
	echRetryConfigs         []byte
	limitSupported          bool
	recordSizeLimit         uint16
	serverNameAck           bool

	extensions []Extension
}

func (m *encryptedExtensionsMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, extension := range m.extensions {
				switch extension.(type) {
				case nil:
				case *ALPNExtension:
					if len(m.alpnProtocol) > 0 {
						b.AddUint16(extensionALPN)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
									b.AddBytes([]byte(m.alpnProtocol))
								})
							})
						})
					}
				case *LegacyALPSExtension:
					if m.alps {
						b.AddUint16(extensionLegacyALPS)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.alpnSetting))
						})
					}
				case *ALPSExtension:
					if m.alps {
						b.AddUint16(extensionALPS)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.alpnSetting))
						})
					}
				case *QUICTransportParametersExtension:
					if m.quicTransportParameters != nil { // marshal zero-length parameters when present
						// draft-ietf-quic-tls-32, Section 8.2
						b.AddUint16(extensionQUICTransportParameters)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(m.quicTransportParameters)
						})
					}
				case *EarlyDataExtension:
					if m.earlyData {
						// RFC 8446, Section 4.2.10
						b.AddUint16(extensionEarlyData)
						b.AddUint16(0) // empty extension_data
					}
				case *EncryptedClientHelloExtension:
					if len(m.echRetryConfigs) > 0 {
						b.AddUint16(extensionEncryptedClientHello)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(m.echRetryConfigs)
						})
					}
				case *RecordSizeLimitExtension:
					if m.limitSupported {
						// RFC 8449, Section 4
						b.AddUint16(extensionRecordSizeLimit)
						b.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddUint16(m.recordSizeLimit)
						})
					}
				case *ServerNameIndicationExtension:
					if m.serverNameAck {
						b.AddUint16(extensionServerName)
						b.AddUint16(0) // empty extension_data
					}
				default:
					if extension.Negotiate(typeEncryptedExtensions, false) {
						b.AddUint16(extension.ExtensionId())
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							extension.Marshal(typeEncryptedExtensions, false, b)
						})
					}
				}
			}
		})
	})

	return b.Bytes()
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) bool {
	*m = encryptedExtensionsMsg{}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
			m.extensions = append(m.extensions, &ALPNExtension{})
		case extensionLegacyALPS:
			m.alps = true
			m.alpnSetting = extData
			m.extensions = append(m.extensions, &LegacyALPSExtension{})
			continue
		case extensionALPS:
			m.alps = true
			m.alpnSetting = extData
			m.extensions = append(m.extensions, &ALPSExtension{})
			continue
		case extensionQUICTransportParameters:
			m.quicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.quicTransportParameters) {
				return false
			}
			m.extensions = append(m.extensions, &QUICTransportParametersExtension{})
		case extensionEarlyData:
			m.earlyData = true
			m.extensions = append(m.extensions, &EarlyDataExtension{})
		case extensionEncryptedClientHello:
			m.echRetryConfigs = make([]byte, len(extData))
			if !extData.CopyBytes(m.echRetryConfigs) {
				return false
			}
			m.extensions = append(m.extensions, &EncryptedClientHelloExtension{})
		case extensionRecordSizeLimit:
			// RFC 8449, Section 4
			m.limitSupported = true
			if !extData.ReadUint16(&m.recordSizeLimit) {
				return false
			}
			m.extensions = append(m.extensions, &RecordSizeLimitExtension{})
		case extensionServerName:
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
			m.extensions = append(m.extensions, &ServerNameIndicationExtension{})
		default:
			var ext Extension

			switch {
			case IsGREASE(extension):
				ext = &GREASEExtension{Id: extension}
			default:
				ext = &UnimplementedExtension{Id: extension}
			}

			if ok, _ := ext.Unmarshal(typeEncryptedExtensions, false, extData, nil); !ok {
				return false
			}

			m.extensions = append(m.extensions, ext)
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type endOfEarlyDataMsg struct{}

func (m *endOfEarlyDataMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeEndOfEarlyData)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {})

	return b.Bytes()
}

func (m *endOfEarlyDataMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	return s.Empty()
}

type keyUpdateMsg struct {
	updateRequested bool
}

func (m *keyUpdateMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeKeyUpdate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		if m.updateRequested {
			b.AddUint8(1)
		} else {
			b.AddUint8(0)
		}
	})

	return b.Bytes()
}

func (m *keyUpdateMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var updateRequested uint8
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8(&updateRequested) || !s.Empty() {
		return false
	}
	switch updateRequested {
	case 0:
		m.updateRequested = false
	case 1:
		m.updateRequested = true
	default:
		return false
	}
	return true
}

type newSessionTicketMsgTLS13 struct {
	lifetime     uint32
	ageAdd       uint32
	nonce        []byte
	label        []byte
	maxEarlyData uint32
}

func (m *newSessionTicketMsgTLS13) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeNewSessionTicket)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32(m.lifetime)
		b.AddUint32(m.ageAdd)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.nonce)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.label)
		})

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.maxEarlyData > 0 {
				b.AddUint16(extensionEarlyData)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint32(m.maxEarlyData)
				})
			}
		})
	})

	return b.Bytes()
}

func (m *newSessionTicketMsgTLS13) unmarshal(data []byte) bool {
	*m = newSessionTicketMsgTLS13{}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint32(&m.lifetime) ||
		!s.ReadUint32(&m.ageAdd) ||
		!readUint8LengthPrefixed(&s, &m.nonce) ||
		!readUint16LengthPrefixed(&s, &m.label) ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionEarlyData:
			if !extData.ReadUint32(&m.maxEarlyData) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateRequestMsgTLS13 struct {
	ocspStapling                              bool
	scts                                      bool
	supportedCertificateCompressionAlgorithms []CertificateCompressionAlgorithm
	supportedSignatureAlgorithms              []SignatureScheme
	supportedSignatureAlgorithmsCert          []SignatureScheme
	supportedSignatureAlgorithmsDC            []SignatureScheme
	certificateAuthorities                    [][]byte
}

func (m *certificateRequestMsgTLS13) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateRequest)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		// certificate_request_context (SHALL be zero length unless used for
		// post-handshake authentication)
		b.AddUint8(0)

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.ocspStapling {
				b.AddUint16(extensionStatusRequest)
				b.AddUint16(0) // empty extension_data
			}
			if m.scts {
				// RFC 8446, Section 4.4.2.1 makes no mention of
				// signed_certificate_timestamp in CertificateRequest, but
				// "Extensions in the Certificate message from the client MUST
				// correspond to extensions in the CertificateRequest message
				// from the server." and it appears in the table in Section 4.2.
				b.AddUint16(extensionSCT)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.supportedCertificateCompressionAlgorithms) > 0 {
				b.AddUint16(extensionCompressCertificate)
				b.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						for _, algorithm := range m.supportedCertificateCompressionAlgorithms {
							exts.AddUint16(uint16(algorithm))
						}
					})
				})
			}
			if len(m.supportedSignatureAlgorithms) > 0 {
				b.AddUint16(extensionSignatureAlgorithms)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithms {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.supportedSignatureAlgorithmsCert) > 0 {
				b.AddUint16(extensionSignatureAlgorithmsCert)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.supportedSignatureAlgorithmsDC) > 0 {
				b.AddUint16(extensionDelegatedCredentials)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithmsDC {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.certificateAuthorities) > 0 {
				b.AddUint16(extensionCertificateAuthorities)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, ca := range m.certificateAuthorities {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(ca)
							})
						}
					})
				})
			}
		})
	})

	return b.Bytes()
}

func (m *certificateRequestMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateRequestMsgTLS13{}
	s := cryptobyte.String(data)

	var context, extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionStatusRequest:
			m.ocspStapling = true
		case extensionSCT:
			m.scts = true
		case extensionCompressCertificate:
			var compressionList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&compressionList) || compressionList.Empty() {
				return false
			}
			for !compressionList.Empty() {
				var compression uint16
				if !compressionList.ReadUint16(&compression) {
					return false
				}
				m.supportedCertificateCompressionAlgorithms = append(m.supportedCertificateCompressionAlgorithms, CertificateCompressionAlgorithm(compression))
			}
		case extensionSignatureAlgorithms:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
		case extensionSignatureAlgorithmsCert:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsCert = append(
					m.supportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
			}
		case extensionDelegatedCredentials:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsDC = append(
					m.supportedSignatureAlgorithmsDC, SignatureScheme(sigAndAlg))
			}
		case extensionCertificateAuthorities:
			var auths cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
				return false
			}
			for !auths.Empty() {
				var ca []byte
				if !readUint16LengthPrefixed(&auths, &ca) || len(ca) == 0 {
					return false
				}
				m.certificateAuthorities = append(m.certificateAuthorities, ca)
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateMsg struct {
	certificates [][]byte
}

func (m *certificateMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, certificate := range m.certificates {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(certificate)
				})
			}
		})
	})

	return b.Bytes()
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	*m = certificateMsg{certificates: make([][]byte, 0)}
	s := cryptobyte.String(data)

	var certificates cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint24LengthPrefixed(&certificates) {
		return false
	}

	for !certificates.Empty() {
		var certificate []byte
		if !readUint24LengthPrefixed(&certificates, &certificate) {
			return false
		}
		m.certificates = append(m.certificates, certificate)
	}

	return true
}

type certificateMsgTLS13 struct {
	certificate         Certificate
	ocspStapling        bool
	scts                bool
	delegatedCredential []byte
}

func (m *certificateMsgTLS13) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context

		certificate := m.certificate
		if !m.ocspStapling {
			certificate.OCSPStaple = nil
		}
		if !m.scts {
			certificate.SignedCertificateTimestamps = nil
		}
		marshalCertificate(b, certificate, m.delegatedCredential)
	})

	return b.Bytes()
}

func marshalCertificate(b *cryptobyte.Builder, certificate Certificate, delegatedCredential []byte) {
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for i, cert := range certificate.Certificate {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(cert)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if i > 0 {
					// This library only supports OCSP, SCT and Delegated Credentials for leaf certificates.
					// Delegated Credentials are only supported on the leaf/end-entity certificate.
					return
				}
				if certificate.OCSPStaple != nil {
					b.AddUint16(extensionStatusRequest)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(statusTypeOCSP)
						b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(certificate.OCSPStaple)
						})
					})
				}
				if certificate.SignedCertificateTimestamps != nil {
					b.AddUint16(extensionSCT)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, sct := range certificate.SignedCertificateTimestamps {
								b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
									b.AddBytes(sct)
								})
							}
						})
					})
				}
				if delegatedCredential != nil {
					b.AddUint16(extensionDelegatedCredentials)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(delegatedCredential)
					})
				}
			})
		}
	})
}

func (m *certificateMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateMsgTLS13{}
	s := cryptobyte.String(data)

	var context cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!unmarshalCertificate(&s, &m.certificate, &m.delegatedCredential) ||
		!s.Empty() {
		return false
	}

	m.scts = m.certificate.SignedCertificateTimestamps != nil
	m.ocspStapling = m.certificate.OCSPStaple != nil

	return true
}

func unmarshalCertificate(s *cryptobyte.String, certificate *Certificate, delegatedCredential *[]byte) bool {
	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) {
		return false
	}
	for !certList.Empty() {
		var cert []byte
		var extensions cryptobyte.String
		if !readUint24LengthPrefixed(&certList, &cert) ||
			!certList.ReadUint16LengthPrefixed(&extensions) {
			return false
		}
		certificate.Certificate = append(certificate.Certificate, cert)
		for !extensions.Empty() {
			var extension uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&extension) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				return false
			}
			if len(certificate.Certificate) > 1 {
				// This library only supports OCSP and SCT for leaf certificates.
				continue
			}

			switch extension {
			case extensionStatusRequest:
				var statusType uint8
				if !extData.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
					!readUint24LengthPrefixed(&extData, &certificate.OCSPStaple) ||
					len(certificate.OCSPStaple) == 0 {
					return false
				}
			case extensionSCT:
				var sctList cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
					return false
				}
				for !sctList.Empty() {
					var sct []byte
					if !readUint16LengthPrefixed(&sctList, &sct) ||
						len(sct) == 0 {
						return false
					}
					certificate.SignedCertificateTimestamps = append(
						certificate.SignedCertificateTimestamps, sct)
				}
			case extensionDelegatedCredentials:
				if extData.Empty() || !extData.ReadBytes(delegatedCredential, len(extData)) {
					return false
				}
			default:
				// Ignore unknown extensions.
				continue
			}

			if !extData.Empty() {
				return false
			}
		}
	}
	return true
}

type compressedCertificateMsg struct {
	algorithm                    CertificateCompressionAlgorithm
	uncompressedLength           uint32 // uint24
	compressedCertificateMessage []byte
}

func (m *compressedCertificateMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCompressedCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(uint16(m.algorithm))
		b.AddUint24(m.uncompressedLength)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressedCertificateMessage)
		})
	})

	return b.Bytes()
}

func (m *compressedCertificateMsg) unmarshal(data []byte) bool {
	*m = compressedCertificateMsg{}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16((*uint16)(&m.algorithm)) ||
		!s.ReadUint24(&m.uncompressedLength) ||
		!readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}
	return true
}

type serverKeyExchangeMsg struct {
	key []byte
}

func (m *serverKeyExchangeMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeServerKeyExchange)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.key)
	})

	return b.Bytes()
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	*m = serverKeyExchangeMsg{}
	s := cryptobyte.String(data)

	if !s.Skip(1) { // message type
		return false
	}
	return readUint24LengthPrefixed(&s, &m.key) && s.Empty()
}

type certificateStatusMsg struct {
	response []byte
}

func (m *certificateStatusMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateStatus)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(statusTypeOCSP)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.response)
		})
	})

	return b.Bytes()
}

func (m *certificateStatusMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var statusType uint8
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
		!readUint24LengthPrefixed(&s, &m.response) ||
		len(m.response) == 0 || !s.Empty() {
		return false
	}
	return true
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeServerHelloDone)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {})

	return b.Bytes()
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	return s.Empty()
}

type clientKeyExchangeMsg struct {
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeClientKeyExchange)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.ciphertext)
	})

	return b.Bytes()
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(1) { // message type
		return false
	}
	return readUint24LengthPrefixed(&s, &m.ciphertext) && s.Empty()
}

type finishedMsg struct {
	verifyData []byte
}

func (m *finishedMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	return b.Bytes()
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}

type certificateRequestMsg struct {
	// hasSignatureAlgorithm indicates whether this message includes a list of
	// supported signature algorithms. This change was introduced with TLS 1.2.
	hasSignatureAlgorithm bool

	certificateTypes             []byte
	supportedSignatureAlgorithms []SignatureScheme
	certificateAuthorities       [][]byte
}

func (m *certificateRequestMsg) marshal() ([]byte, error) {
	// See RFC 4346, Section 7.4.4.
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateRequest)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.certificateTypes)
		})

		if m.hasSignatureAlgorithm {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, sigAlgo := range m.supportedSignatureAlgorithms {
					b.AddUint16(uint16(sigAlgo))
				}
			})
		}

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ca := range m.certificateAuthorities {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(ca)
				})
			}
		})
	})

	return b.Bytes()
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}

	if !readUint8LengthPrefixed(&s, &m.certificateTypes) {
		return false
	}

	if m.hasSignatureAlgorithm {
		var sigAlgoList cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&sigAlgoList) || sigAlgoList.Empty() {
			return false
		}

		for !sigAlgoList.Empty() {
			var sigAlgo uint16
			if !sigAlgoList.ReadUint16(&sigAlgo) {
				return false
			}
			m.supportedSignatureAlgorithms = append(m.supportedSignatureAlgorithms, SignatureScheme(sigAlgo))
		}
	}

	var caList cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&caList) {
		return false
	}

	m.certificateAuthorities = nil
	for !caList.Empty() {
		var ca []byte
		if !readUint16LengthPrefixed(&caList, &ca) {
			return false
		}
		m.certificateAuthorities = append(m.certificateAuthorities, ca)
	}
	return s.Empty()
}

type certificateVerifyMsg struct {
	hasSignatureAlgorithm bool // format change introduced in TLS 1.2
	signatureAlgorithm    SignatureScheme
	signature             []byte
}

func (m *certificateVerifyMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateVerify)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		if m.hasSignatureAlgorithm {
			b.AddUint16(uint16(m.signatureAlgorithm))
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.signature)
		})
	})

	return b.Bytes()
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	if m.hasSignatureAlgorithm {
		if !s.ReadUint16((*uint16)(&m.signatureAlgorithm)) {
			return false
		}
	}
	return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
}

type newSessionTicketMsg struct {
	lifetime uint32
	ticket   []byte
}

func (m *newSessionTicketMsg) marshal() ([]byte, error) {
	// See RFC 5077, Section 3.3.
	var b cryptobyte.Builder
	b.AddUint8(typeNewSessionTicket)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32(m.lifetime)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.ticket)
		})
	})

	return b.Bytes()
}

func (m *newSessionTicketMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}

	if !s.ReadUint32(&m.lifetime) {
		return false
	}
	return readUint16LengthPrefixed(&s, &m.ticket) && s.Empty()
}

type helloRequestMsg struct {
}

func (*helloRequestMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeHelloRequest)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {})

	return b.Bytes()
}

func (*helloRequestMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	return s.Empty()
}

type transcriptHash interface {
	Write([]byte) (int, error)
}

// transcriptMsg is a helper used to hash messages which are not hashed when
// they are read from, or written to, the wire. This is typically the case for
// messages which are either not sent, or need to be hashed out of order from
// when they are read/written.
//
// For most messages, the message is marshalled using their marshal method,
// since their wire representation is idempotent. For clientHelloMsg and
// serverHelloMsg, we store the original wire representation of the message and
// use that for hashing, since unmarshal/marshal are not idempotent due to
// extension ordering and other malleable fields, which may cause differences
// between what was received and what we marshal.
func transcriptMsg(msg handshakeMessage, h transcriptHash) error {
	if msgWithOrig, ok := msg.(handshakeMessageWithOriginalBytes); ok {
		if orig := msgWithOrig.originalBytes(); orig != nil {
			h.Write(msgWithOrig.originalBytes())
			return nil
		}
	}

	data, err := msg.marshal()
	if err != nil {
		return err
	}
	h.Write(data)
	return nil
}
