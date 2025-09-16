// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"reflect"
	"slices"

	"gitlab.com/go-extension/rand"
)

type ECHConfig struct {
	// If disabled is true, ECH will be disabled.
	Disabled bool

	// Dummy are the parameters used by the client when it
	// offers the dummy ECH extension.
	Dummy *ECHDummyConfig

	// InnerLens will padding to one of HelloLens.
	// If not set, the padding will be 128 for dummy and the default padding for non-dummy.
	InnerLens []uint16 // Pre-encryption. If 0, will pick 128 (+16=144)

	// InnerExtensions defines extensions to ClientHelloInner.
	InnerExtensions []Extension

	// OuterExtensions defines extensions to ClientHelloOuter.
	OuterExtensions []Extension

	// CompressedExtensions defines extensions for extract from outer.
	CompressedExtensions []Extension
}

func (config *ECHConfig) innerLen() uint16 {
	if len(config.InnerLens) <= 0 {
		return 128
	}

	return config.InnerLens[rand.Crypto.IntN(len(config.InnerLens))]
}

func (config *ECHConfig) innerExtensions() []Extension {
	if config.InnerExtensions != nil {
		return config.InnerExtensions
	}

	return defaultInnerExtensions
}

func (config *ECHConfig) outerExtensions() []Extension {
	if config.OuterExtensions != nil {
		return config.OuterExtensions
	}

	return defaultOuterExtensions
}

func (config *ECHConfig) compressedExtensions() []Extension {
	if config.CompressedExtensions != nil {
		return config.CompressedExtensions
	}

	return defaultCompressedExtensions
}

func setupInnerClientHelloCompress(config *ECHConfig, outer, inner *clientHelloMsg) {
	echInner := bytes.Equal(inner.encryptedClientHello, []byte{1})
	if !echInner {
		return
	}

	// Any extensions which have changed in hello, but are mirrored in the
	// outer hello and compressed, need to be copied to the outer hello, so
	// they can be properly decompressed by the server.
	outer.keyShares = inner.keyShares // HRR
	outer.pskModes = inner.pskModes
	outer.earlyData = inner.earlyData
	outer.pskIdentities = inner.pskIdentities
	outer.pskBinders = inner.pskBinders

	if inner.compressedList != nil {
		inner.echOuterExts = outer.echOuterExtensions(inner.compressedList)
		return
	}

	compressed := slices.Clone(config.compressedExtensions())

	extensionsList := make([]Extension, 0, len(inner.extensionList)+len(compressed))
	compressedList := make([]Extension, 0, len(compressed))
	for _, extension := range inner.extensionList {
		extensionsList = append(extensionsList, extension)

		if _, ok := extension.(*ECHOuterExtension); !ok {
			continue
		}

		for _, ext := range outer.extensionList {
			if ext == nil {
				continue
			}

			for i, extension := range compressed {
				if extension == nil {
					continue
				}

				if _, ok := extension.(*ECHOuterExtension); ok {
					continue
				}

				if reflect.TypeOf(ext) != reflect.TypeOf(extension) {
					continue
				}

				extensionsList = append(extensionsList, ext)
				compressedList = append(compressedList, ext)
				compressed = slices.Delete(compressed, i, i+1)
				break
			}

			if len(compressed) <= 0 {
				break
			}
		}
	}

	inner.extensionList = extensionsList
	inner.compressedList = compressedList
	inner.echOuterExts = outer.echOuterExtensions(compressedList)
}
