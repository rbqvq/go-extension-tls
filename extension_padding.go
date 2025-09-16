// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "golang.org/x/crypto/cryptobyte"

type PaddingRequest struct {
	UnpaddedLength    int
	HelloInner        bool
	HelloRetryRequest bool
	QUIC              bool
}

var _ Extension = &PaddingExtension{}

type PaddingExtension struct {
	Length uint16
}

func (*PaddingExtension) ExtensionId() uint16 {
	return extensionPadding
}

func (*PaddingExtension) NegotiatedVersion(vers uint16) {}

func (*PaddingExtension) Negotiate(messageType uint8, echInner bool) bool {
	return messageType == typeClientHello
}

func (extension *PaddingExtension) Marshal(messageType uint8, echInner bool, b *cryptobyte.Builder) {
	if messageType == typeClientHello {
		b.AddBytes(make([]byte, extension.Length))
	}
}

func (extension *PaddingExtension) Len(messageType uint8, echInner bool) int {
	if messageType == typeClientHello {
		return int(extension.Length)
	}

	return 0
}

func (extension *PaddingExtension) Unmarshal(messageType uint8, echAccepted bool, b cryptobyte.String, _ *ExtensionState) (bool, error) {
	length := len(b)
	extension.Length = uint16(length)
	return b.Skip(length), nil
}

func (extension *PaddingExtension) Clone() Extension {
	return &PaddingExtension{Length: extension.Length}
}
