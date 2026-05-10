// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
	"reflect"
	"slices"

	"gitlab.com/go-extension/tls/internal/byteorder"
)

type ECHConfig struct {
	// If disabled is true, ECH will be disabled.
	Disabled bool

	// Dummy are the parameters used by the client when it
	// offers the dummy ECH extension.
	Dummy *ECHDummyConfig

	// KeepCipherSuites controls whether to keep non-TLS 1.3 cipher suites
	// in ClientHelloInner.
	KeepCipherSuites bool

	// InnerExtensions defines extensions to ClientHelloInner.
	InnerExtensions []Extension

	// OuterExtensions defines extensions to ClientHelloOuter.
	OuterExtensions []Extension

	// CompressedExtensions defines extensions for extract from outer.
	CompressedExtensions []Extension
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

func generateOuterPSK(rand io.Reader, outer, inner *clientHelloMsg) error {
	hasOuterPSK := func(ext Extension) bool {
		_, ok := ext.(*PreSharedKeyExtension)
		return ok
	}
	if inner.pskIdentities == nil || inner.pskBinders == nil || !slices.ContainsFunc(outer.extensionList, hasOuterPSK) {
		outer.pskIdentities = nil
		outer.pskBinders = nil
		return nil
	}

	outer.pskIdentities = make([]pskIdentity, len(inner.pskIdentities))
	for i := range outer.pskIdentities {
		outer.pskIdentities[i].label = make([]byte, len(inner.pskIdentities[i].label))
		if _, err := io.ReadFull(rand, outer.pskIdentities[i].label); err != nil {
			return err
		}

		var obfuscatedTicketAge [4]byte
		if _, err := rand.Read(obfuscatedTicketAge[:]); err != nil {
			return err
		}
		outer.pskIdentities[i].obfuscatedTicketAge = byteorder.BEUint32(obfuscatedTicketAge[:])
	}

	outer.pskBinders = make([][]byte, len(inner.pskBinders))
	for i := range outer.pskBinders {
		outer.pskBinders[i] = make([]byte, len(inner.pskBinders[i]))
		if _, err := io.ReadFull(rand, outer.pskBinders[i]); err != nil {
			return err
		}
	}

	return nil
}

func (config *Config) setupInnerClientHelloCompress(outer, inner *clientHelloMsg) error {
	if !inner.echInner() {
		return nil
	}

	// Any extensions which have changed in hello, but are mirrored in the
	// outer hello and compressed, need to be copied to the outer hello, so
	// they can be properly decompressed by the server
	outer.keyShares = inner.keyShares // HRR
	outer.pskModes = inner.pskModes
	outer.earlyData = inner.earlyData
	if err := generateOuterPSK(config.rand(), outer, inner); err != nil {
		return err
	}

	if inner.compressedList != nil {
		inner.echOuterExts = outer.echOuterExtensions(inner.compressedList)
		return nil
	}

	compressed := slices.Clone(config.echConfig().compressedExtensions())

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
				switch extension.(type) {
				case nil,
					*EncryptedClientHelloExtension,
					*ECHOuterExtension,
					*PaddingExtension:
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
	return nil
}
