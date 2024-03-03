// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "golang.org/x/crypto/cryptobyte"

// TLS Extension
type Extension interface {
	// TLS extension id
	ExtensionId() uint16
	// It will be called after protocol negotiation
	NegotiatedVersion(vers uint16)
	// Return true if this extension needs to be negotiated.
	// It will call the Marshal function to generate the message.
	//
	// Note: this option is only valid for servers
	Negotiate(messageType uint8) bool

	Len(messageType uint8) int
	Marshal(messageType uint8, b *cryptobyte.Builder)
	Unmarshal(messageType uint8, b cryptobyte.String) bool

	// Clone returns a shallow clone of extension. It is safe to clone an
	// extension that is being used concurrently by a TLS client or server.
	Clone() Extension
}

var (
	defaultExtensions = []Extension{
		&ServerNameIndicationExtension{},
		&StatusRequestExtension{},
		&SupportedGroupsExtension{},
		&SupportedPointsExtension{},
		&SessionTicketExtension{},
		&SignatureAlgorithmsExtension{},
		&SignatureAlgorithmsCertExtension{},
		&RenegotiationInfoExtension{},
		&ExtendedMasterSecretExtension{},
		&ALPNExtension{},
		&ALPSExtension{},
		&SCTExtension{},
		&SupportedVersionsExtension{},
		&CompressedCertificateExtension{},
		&CookieExtension{},
		&KeyShareExtension{},
		&EarlyExtension{},
		&PSKModesExtension{},
		&EncryptedClientHelloExtension{},
		&QUICTransportParametersExtension{},
		&PreSharedKeyExtension{},
	}
)

var _ Extension = &implementedExtension{}

type implementedExtension struct{}

func (*implementedExtension) ExtensionId() uint16 {
	return 0
}

func (*implementedExtension) NegotiatedVersion(vers uint16) {}

func (*implementedExtension) Negotiate(messageType uint8) bool {
	return false
}

func (*implementedExtension) Marshal(messageType uint8, b *cryptobyte.Builder) {}

func (*implementedExtension) Len(messageType uint8) int {
	return 0
}

func (*implementedExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	return true
}

func (*implementedExtension) Clone() Extension {
	return &implementedExtension{}
}

type ServerNameIndicationExtension struct{ implementedExtension }

func (*ServerNameIndicationExtension) ExtensionId() uint16 {
	return extensionServerName
}

func (*ServerNameIndicationExtension) Clone() Extension {
	return &ServerNameIndicationExtension{}
}

type StatusRequestExtension struct{ implementedExtension }

func (*StatusRequestExtension) ExtensionId() uint16 {
	return extensionStatusRequest
}

func (*StatusRequestExtension) Clone() Extension {
	return &StatusRequestExtension{}
}

type SupportedGroupsExtension struct{ implementedExtension }

func (*SupportedGroupsExtension) ExtensionId() uint16 {
	return extensionSupportedCurves
}

func (*SupportedGroupsExtension) Clone() Extension {
	return &SupportedGroupsExtension{}
}

type SupportedPointsExtension struct{ implementedExtension }

func (*SupportedPointsExtension) ExtensionId() uint16 {
	return extensionSupportedPoints
}

func (*SupportedPointsExtension) Clone() Extension {
	return &SupportedPointsExtension{}
}

type SessionTicketExtension struct{ implementedExtension }

func (*SessionTicketExtension) ExtensionId() uint16 {
	return extensionSessionTicket
}

func (*SessionTicketExtension) Clone() Extension {
	return &SessionTicketExtension{}
}

type SignatureAlgorithmsExtension struct{ implementedExtension }

func (*SignatureAlgorithmsExtension) ExtensionId() uint16 {
	return extensionSignatureAlgorithms
}

func (*SignatureAlgorithmsExtension) Clone() Extension {
	return &SignatureAlgorithmsExtension{}
}

type SignatureAlgorithmsCertExtension struct{ implementedExtension }

func (*SignatureAlgorithmsCertExtension) ExtensionId() uint16 {
	return extensionSignatureAlgorithmsCert
}

func (*SignatureAlgorithmsCertExtension) Clone() Extension {
	return &SignatureAlgorithmsCertExtension{}
}

type RenegotiationInfoExtension struct{ implementedExtension }

func (*RenegotiationInfoExtension) ExtensionId() uint16 {
	return extensionRenegotiationInfo
}

func (*RenegotiationInfoExtension) Clone() Extension {
	return &RenegotiationInfoExtension{}
}

type ExtendedMasterSecretExtension struct{ implementedExtension }

func (*ExtendedMasterSecretExtension) ExtensionId() uint16 {
	return extensionExtendedMasterSecret
}

func (*ExtendedMasterSecretExtension) Clone() Extension {
	return &ExtendedMasterSecretExtension{}
}

type ALPNExtension struct{ implementedExtension }

func (*ALPNExtension) ExtensionId() uint16 {
	return extensionALPN
}

func (*ALPNExtension) Clone() Extension {
	return &ALPNExtension{}
}

type ALPSExtension struct{ implementedExtension }

func (*ALPSExtension) ExtensionId() uint16 {
	return extensionALPS
}

func (*ALPSExtension) Clone() Extension {
	return &ALPSExtension{}
}

type SCTExtension struct{ implementedExtension }

func (*SCTExtension) ExtensionId() uint16 {
	return extensionSCT
}

func (*SCTExtension) Clone() Extension {
	return &SCTExtension{}
}

type SupportedVersionsExtension struct{ implementedExtension }

func (*SupportedVersionsExtension) ExtensionId() uint16 {
	return extensionSupportedVersions
}

func (*SupportedVersionsExtension) Clone() Extension {
	return &SupportedVersionsExtension{}
}

type CompressedCertificateExtension struct{ implementedExtension }

func (*CompressedCertificateExtension) ExtensionId() uint16 {
	return extensionCompressCert
}

func (*CompressedCertificateExtension) Clone() Extension {
	return &CompressedCertificateExtension{}
}

type CookieExtension struct{ implementedExtension }

func (*CookieExtension) ExtensionId() uint16 {
	return extensionCookie
}

func (*CookieExtension) Clone() Extension {
	return &CookieExtension{}
}

type KeyShareExtension struct{ implementedExtension }

func (*KeyShareExtension) ExtensionId() uint16 {
	return extensionKeyShare
}

func (*KeyShareExtension) Clone() Extension {
	return &KeyShareExtension{}
}

type EarlyExtension struct{ implementedExtension }

func (*EarlyExtension) ExtensionId() uint16 {
	return extensionEarlyData
}

func (*EarlyExtension) Clone() Extension {
	return &EarlyExtension{}
}

type PSKModesExtension struct{ implementedExtension }

func (*PSKModesExtension) ExtensionId() uint16 {
	return extensionPSKModes
}

func (*PSKModesExtension) Clone() Extension {
	return &PSKModesExtension{}
}

type EncryptedClientHelloExtension struct{ implementedExtension }

func (*EncryptedClientHelloExtension) ExtensionId() uint16 {
	return extensionECH
}

func (*EncryptedClientHelloExtension) Clone() Extension {
	return &EncryptedClientHelloExtension{}
}

type QUICTransportParametersExtension struct{ implementedExtension }

func (*QUICTransportParametersExtension) ExtensionId() uint16 {
	return extensionQUICTransportParameters
}

func (*QUICTransportParametersExtension) Clone() Extension {
	return &QUICTransportParametersExtension{}
}

type PreSharedKeyExtension struct{ implementedExtension }

func (*PreSharedKeyExtension) ExtensionId() uint16 {
	return extensionPreSharedKey
}

func (*PreSharedKeyExtension) Clone() Extension {
	return &PreSharedKeyExtension{}
}

var _ Extension = &PaddingExtension{}

type PaddingExtension struct {
	Length uint16
}

func (*PaddingExtension) ExtensionId() uint16 {
	return extensionPadding
}

func (*PaddingExtension) NegotiatedVersion(vers uint16) {}

func (*PaddingExtension) Negotiate(messageType uint8) bool {
	return false
}

func (extension *PaddingExtension) Marshal(messageType uint8, b *cryptobyte.Builder) {
	b.AddBytes(make([]byte, extension.Length))
}

func (extension *PaddingExtension) Len(messageType uint8) int {
	return int(extension.Length)
}

func (extension *PaddingExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	extension.Length = uint16(len(b))
	return true
}

func (extension *PaddingExtension) Clone() Extension {
	return &PaddingExtension{Length: extension.Length}
}

var _ Extension = &UnimplementedExtension{}

type UnimplementedExtension struct {
	Id   uint16
	Data cryptobyte.String
}

func (extension *UnimplementedExtension) ExtensionId() uint16 {
	return extension.Id
}

func (*UnimplementedExtension) NegotiatedVersion(vers uint16) {}

func (*UnimplementedExtension) Negotiate(messageType uint8) bool {
	return false
}

func (extension *UnimplementedExtension) Marshal(messageType uint8, b *cryptobyte.Builder) {
	b.AddBytes(extension.Data)
}

func (extension *UnimplementedExtension) Len(messageType uint8) int {
	return len(extension.Data)
}

func (extension *UnimplementedExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	extension.Data = b
	return true
}
func (extension *UnimplementedExtension) Clone() Extension {
	return &UnimplementedExtension{Id: extension.Id, Data: extension.Data}
}
