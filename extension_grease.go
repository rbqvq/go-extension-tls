package tls

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

var _ Extension = &GREASEExtension{}

type GREASEExtension struct {
	Id   uint16
	Data cryptobyte.String
}

func (extension *GREASEExtension) ExtensionId() uint16 {
	return extension.Id
}

func (*GREASEExtension) NegotiatedVersion(vers uint16) {}

func (*GREASEExtension) Negotiate(messageType uint8, encryptedClientHello bool) bool {
	return messageType == typeClientHello
}
func (extension *GREASEExtension) Marshal(messageType uint8, encryptedClientHello bool, b *cryptobyte.Builder) {
	if messageType == typeClientHello {
		b.AddBytes(extension.Data)
	}
}

func (extension *GREASEExtension) Len(messageType uint8, encryptedClientHello bool) int {
	if messageType == typeClientHello {
		return len(extension.Data)
	}

	return 0
}

func (extension *GREASEExtension) Unmarshal(messageType uint8, encryptedClientHello bool, b cryptobyte.String) bool {
	return b.CopyBytes(extension.Data)
}

func (extension *GREASEExtension) Clone() Extension {
	return &GREASEExtension{Id: extension.Id, Data: extension.Data}
}

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

func (c *Conn) GREASE() uint16 {
	grease_bytes := make([]byte, 2)
	// GREASE value is back from deterministic to random.

	_, err := io.ReadFull(c.config.rand(), grease_bytes)
	if err != nil {
		return GREASE_PLACEHOLDER
	}

	ret := binary.LittleEndian.Uint16(grease_bytes)
	/* This generates a random value of the form 0x?A?A, where ? can be any hex digit */
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	return ret
}

func IsGREASE(v uint16) bool {
	// GREASE (Generate Random Extensions And Sustain Extensibility) is a mechanism used by
	// browsers like Chrome to ensure TLS implementations correctly ignore unknown values.
	// GREASE values follow a specific pattern: 0x?A?A, where ? can be any hex digit.
	// These values should be ignored when processing supported TLS versions.
	return v&0x0F0F == 0x0A0A && v&0xff == v>>8
}
