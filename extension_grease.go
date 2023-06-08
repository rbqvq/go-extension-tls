// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

func (*GREASEExtension) Negotiate(messageType uint8) bool {
	return false
}
func (extension *GREASEExtension) Marshal(messageType uint8, b *cryptobyte.Builder) {
	b.AddBytes(extension.Data)
}

func (extension *GREASEExtension) Len(messageType uint8) int {
	return len(extension.Data)
}

func (extension *GREASEExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	extension.Data = b
	return true
}

func (extension *GREASEExtension) Clone() Extension {
	return &GREASEExtension{Id: extension.Id, Data: extension.Data}
}

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

// will panic if ssl_grease_last_index[index] is out of bounds.
func (c *Conn) GREASE() uint16 {
	grease_bytes := make([]byte, 2)
	// GREASE value is back from deterministic to random.

	_, err := io.ReadFull(c.config.rand(), grease_bytes)
	if err != nil {
		return GREASE_PLACEHOLDER
	}

	ret := binary.LittleEndian.Uint16(grease_bytes)
	/* This generates a random value of the form 0xωaωa, for all 0 ≤ ω < 16. */
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	return ret
}

func IsGREASE(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}
