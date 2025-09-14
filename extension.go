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
	Negotiate(messageType uint8, encryptedClientHello bool) bool

	Len(messageType uint8, encryptedClientHello bool) int
	Marshal(messageType uint8, encryptedClientHello bool, b *cryptobyte.Builder)
	Unmarshal(messageType uint8, encryptedClientHello bool, b cryptobyte.String) bool

	// Clone returns a shallow clone of extension. It is safe to clone an
	// extension that is being used concurrently by a TLS client or server.
	Clone() Extension
}

var (
	defaultExtensions = []Extension{
		&ServerNameIndicationExtension{},
		&SupportedPointsExtension{},
		&SessionTicketExtension{},
		&RenegotiationInfoExtension{},
		&ExtendedMasterSecretExtension{},
		&SCTExtension{},
		&EarlyDataExtension{},
		&QUICTransportParametersExtension{},
		&EncryptedClientHelloExtension{},
		&StatusRequestExtension{},
		&SupportedGroupsExtension{},
		&SignatureAlgorithmsExtension{},
		&SignatureAlgorithmsCertExtension{},
		&ALPNExtension{},
		&SupportedVersionsExtension{},
		&CookieExtension{},
		&KeyShareExtension{},
		&PSKModesExtension{},
		&ECHOuterExtension{},
		&PreSharedKeyExtension{},
	}
)

var _ Extension = &implementedExtension{}

type implementedExtension struct{}

func (*implementedExtension) ExtensionId() uint16 {
	return 0
}

func (*implementedExtension) NegotiatedVersion(vers uint16) {}

func (*implementedExtension) Negotiate(messageType uint8, encryptedClientHello bool) bool {
	return false
}

func (*implementedExtension) Marshal(messageType uint8, encryptedClientHello bool, b *cryptobyte.Builder) {
}

func (*implementedExtension) Len(messageType uint8, encryptedClientHello bool) int {
	return 0
}

func (*implementedExtension) Unmarshal(messageType uint8, encryptedClientHello bool, b cryptobyte.String) bool {
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

type LegacyALPSExtension struct{ implementedExtension }

func (*LegacyALPSExtension) ExtensionId() uint16 {
	return extensionLegacyALPS
}

func (*LegacyALPSExtension) Clone() Extension {
	return &LegacyALPSExtension{}
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
	return extensionCompressCertificate
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

type EarlyDataExtension struct{ implementedExtension }

func (*EarlyDataExtension) ExtensionId() uint16 {
	return extensionEarlyData
}

func (*EarlyDataExtension) Clone() Extension {
	return &EarlyDataExtension{}
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
	return extensionEncryptedClientHello
}

func (*EncryptedClientHelloExtension) Clone() Extension {
	return &EncryptedClientHelloExtension{}
}

type ECHOuterExtension struct{ implementedExtension }

func (*ECHOuterExtension) ExtensionId() uint16 {
	return extensionECHOuterExtensions
}

func (*ECHOuterExtension) Clone() Extension {
	return &ECHOuterExtension{}
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

func (*PaddingExtension) Negotiate(messageType uint8, encryptedClientHello bool) bool {
	return messageType == typeClientHello
}

func (extension *PaddingExtension) Marshal(messageType uint8, encryptedClientHello bool, b *cryptobyte.Builder) {
	if messageType == typeClientHello {
		b.AddBytes(make([]byte, extension.Length))
	}
}

func (extension *PaddingExtension) Len(messageType uint8, encryptedClientHello bool) int {
	if messageType == typeClientHello {
		return int(extension.Length)
	}

	return 0
}

func (extension *PaddingExtension) Unmarshal(messageType uint8, encryptedClientHello bool, b cryptobyte.String) bool {
	length := len(b)
	extension.Length = uint16(length)
	return b.Skip(length)
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

func (*UnimplementedExtension) Negotiate(messageType uint8, encryptedClientHello bool) bool {
	return false
}

func (extension *UnimplementedExtension) Marshal(messageType uint8, encryptedClientHello bool, b *cryptobyte.Builder) {
	b.AddBytes(extension.Data)
}

func (extension *UnimplementedExtension) Len(messageType uint8, encryptedClientHello bool) int {
	return len(extension.Data)
}

func (extension *UnimplementedExtension) Unmarshal(messageType uint8, encryptedClientHello bool, b cryptobyte.String) bool {
	return b.CopyBytes(extension.Data)
}
func (extension *UnimplementedExtension) Clone() Extension {
	return &UnimplementedExtension{Id: extension.Id, Data: extension.Data}
}
