// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"github.com/cloudflare/circl/hpke"
	"gitlab.com/go-extension/rand"
)

// ECHDummyConfig represents an ECH dummy configuration.
type ECHDummyConfig struct {
	ConfigIds      []uint8
	CipherSuites   []hpke.Suite
	HelloInnerLens []uint16 // Pre-encryption. If 0, will pick 128(+16=144)
}

func (config *ECHDummyConfig) configId() uint8 {
	if len(config.ConfigIds) <= 0 {
		return uint8(rand.Crypto.IntN(0xff + 1))
	}

	return config.ConfigIds[rand.Crypto.IntN(len(config.ConfigIds))]
}

func (config *ECHDummyConfig) cipherSuite() hpke.Suite {
	if len(config.CipherSuites) <= 0 {
		return defaultHpkeSuite
	}

	return config.CipherSuites[rand.Crypto.IntN(len(config.CipherSuites))]
}

func (config *ECHDummyConfig) helloInnerLen() uint16 {
	if len(config.HelloInnerLens) <= 0 {
		return 128
	}

	return config.HelloInnerLens[rand.Crypto.IntN(len(config.HelloInnerLens))]
}
