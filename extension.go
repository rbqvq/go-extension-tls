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
		&ALPNExtension{},
		&ALPSExtension{},
		&SCTExtension{},
		&SupportedVersionsExtension{},
		&CompressedCertificateExtension{},
		&CookieExtension{},
		&KeyShareExtension{},
		&EarlyExtension{},
		&PSKModesExtension{},
		&PreSharedKeyExtension{},
	}

	empty = make([]byte, 512)
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

func (*implementedExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	return false
}

func (*implementedExtension) Clone() Extension {
	return &implementedExtension{}
}

type ServerNameIndicationExtension struct{ implementedExtension }

func (*ServerNameIndicationExtension) Clone() Extension {
	return &ServerNameIndicationExtension{}
}

type StatusRequestExtension struct{ implementedExtension }

func (*StatusRequestExtension) Clone() Extension {
	return &StatusRequestExtension{}
}

type SupportedGroupsExtension struct{ implementedExtension }

func (*SupportedGroupsExtension) Clone() Extension {
	return &SupportedGroupsExtension{}
}

type SupportedPointsExtension struct{ implementedExtension }

func (*SupportedPointsExtension) Clone() Extension {
	return &SupportedPointsExtension{}
}

type SessionTicketExtension struct{ implementedExtension }

func (*SessionTicketExtension) Clone() Extension {
	return &SessionTicketExtension{}
}

type SignatureAlgorithmsExtension struct{ implementedExtension }

func (*SignatureAlgorithmsExtension) Clone() Extension {
	return &SignatureAlgorithmsExtension{}
}

type SignatureAlgorithmsCertExtension struct{ implementedExtension }

func (*SignatureAlgorithmsCertExtension) Clone() Extension {
	return &SignatureAlgorithmsCertExtension{}
}

type RenegotiationInfoExtension struct{ implementedExtension }

func (*RenegotiationInfoExtension) Clone() Extension {
	return &RenegotiationInfoExtension{}
}

type ALPNExtension struct{ implementedExtension }

func (*ALPNExtension) Clone() Extension {
	return &ALPNExtension{}
}

type ALPSExtension struct{ implementedExtension }

func (*ALPSExtension) Clone() Extension {
	return &ALPSExtension{}
}

type SCTExtension struct{ implementedExtension }

func (*SCTExtension) Clone() Extension {
	return &SCTExtension{}
}

type SupportedVersionsExtension struct{ implementedExtension }

func (*SupportedVersionsExtension) Clone() Extension {
	return &SupportedVersionsExtension{}
}

type CompressedCertificateExtension struct{ implementedExtension }

func (*CompressedCertificateExtension) Clone() Extension {
	return &CompressedCertificateExtension{}
}

type CookieExtension struct{ implementedExtension }

func (*CookieExtension) Clone() Extension {
	return &CookieExtension{}
}

type KeyShareExtension struct{ implementedExtension }

func (*KeyShareExtension) Clone() Extension {
	return &KeyShareExtension{}
}

type EarlyExtension struct{ implementedExtension }

func (*EarlyExtension) Clone() Extension {
	return &EarlyExtension{}
}

type PSKModesExtension struct{ implementedExtension }

func (*PSKModesExtension) Clone() Extension {
	return &PSKModesExtension{}
}

type PreSharedKeyExtension struct{ implementedExtension }

func (*PreSharedKeyExtension) Clone() Extension {
	return &PreSharedKeyExtension{}
}

var _ Extension = &PaddingExtension{}

var extensionPadding uint16 = 21

type PaddingExtension struct {
	Len uint16
}

func (*PaddingExtension) ExtensionId() uint16 {
	return extensionPadding
}

func (*PaddingExtension) NegotiatedVersion(vers uint16) {}

func (*PaddingExtension) Negotiate(messageType uint8) bool {
	return false
}

func (extension *PaddingExtension) Marshal(messageType uint8, b *cryptobyte.Builder) {
	var written uint16 = 0

	for written < extension.Len {
		size := extension.Len - written
		if size > 512 {
			size = 512
		}

		b.AddBytes(empty[:size])
		written += size
	}
}

func (extension *PaddingExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	extension.Len = uint16(len(b))
	return true
}

func (extension *PaddingExtension) Clone() Extension {
	return &PaddingExtension{Len: extension.Len}
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

func (extension *UnimplementedExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	extension.Data = b
	return true
}
func (extension *UnimplementedExtension) Clone() Extension {
	return &UnimplementedExtension{Id: extension.Id, Data: extension.Data}
}
