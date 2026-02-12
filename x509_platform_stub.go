// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(darwin || windows)

package tls

import (
	"crypto/x509"
)

func isPlatformVerifier(_ *x509.CertPool) bool {
	return false
}

func isRootOnlyVerifyAllowed(_ *x509.CertPool) bool {
	return true
}
