// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "golang.org/x/crypto/cryptobyte"

// TLS Extension
type Extension interface {
	// TLS extension id
	ExtensionId() uint16
	// Return true if this extension needs to be negotiated.
	// It will call the Marshal function to generate the message.
	//
	// Note: this option is only valid for servers
	Negotiate() bool

	Marshal(*cryptobyte.Builder)
	Unmarshal(cryptobyte.String) bool

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

func (*implementedExtension) Negotiate() bool {
	return false
}

func (*implementedExtension) Marshal(*cryptobyte.Builder) {}

func (*implementedExtension) Unmarshal(cryptobyte.String) bool {
	return false
}

func (*implementedExtension) Clone() Extension {
	return &implementedExtension{}
}

type ServerNameIndicationExtension struct{ implementedExtension }
type StatusRequestExtension struct{ implementedExtension }
type SupportedGroupsExtension struct{ implementedExtension }
type SupportedPointsExtension struct{ implementedExtension }
type SessionTicketExtension struct{ implementedExtension }
type SignatureAlgorithmsExtension struct{ implementedExtension }
type SignatureAlgorithmsCertExtension struct{ implementedExtension }
type RenegotiationInfoExtension struct{ implementedExtension }
type ALPNExtension struct{ implementedExtension }
type SCTExtension struct{ implementedExtension }
type SupportedVersionsExtension struct{ implementedExtension }
type CompressedCertificateExtension struct{ implementedExtension }
type CookieExtension struct{ implementedExtension }
type KeyShareExtension struct{ implementedExtension }
type EarlyExtension struct{ implementedExtension }
type PSKModesExtension struct{ implementedExtension }
type PreSharedKeyExtension struct{ implementedExtension }

var _ Extension = &PaddingExtension{}

var extensionPadding uint16 = 21

type PaddingExtension struct {
	Len uint16
}

func (*PaddingExtension) ExtensionId() uint16 {
	return extensionPadding
}

func (*PaddingExtension) Negotiate() bool {
	return false
}

func (extension *PaddingExtension) Marshal(b *cryptobyte.Builder) {
	var written uint16 = 0

	for written < extension.Len {
		size := extension.Len - written
		if size > 512 {
			size = 512
		}

		b.AddBytes(empty[:size])
		written += size
	}
	return
}

func (extension *PaddingExtension) Unmarshal(b cryptobyte.String) bool {
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

func (*UnimplementedExtension) Negotiate() bool {
	return false
}

func (extension *UnimplementedExtension) Marshal(b *cryptobyte.Builder) {
	b.AddBytes(extension.Data)
}

func (extension *UnimplementedExtension) Unmarshal(b cryptobyte.String) bool {
	extension.Data = b
	return true
}
func (extension *UnimplementedExtension) Clone() Extension {
	return &UnimplementedExtension{Id: extension.Id, Data: extension.Data}
}
