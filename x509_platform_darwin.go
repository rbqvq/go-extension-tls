// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/x509"
)

func isRootOnlyVerifyAllowed(certPool *x509.CertPool) bool {
	// If not using platformVerifier, allow it.
	if !isPlatformVerifier(certPool) {
		return true
	}

	// If using systemPool with platformVerifier, deny it.
	if certPool == nil {
		return false
	}

	// If no certificates in certPool, deny it.
	// Otherwise, allow it.
	return len(certPool.Subjects()) != 0
}
