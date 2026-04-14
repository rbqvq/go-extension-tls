// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || windows

package tls

import (
	"crypto/x509"
	"reflect"
)

var systemCertPoolOverride bool

func systemCertPool() *x509.CertPool {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return nil
	}
	return systemPool
}

func isSystemCertPool(certPool *x509.CertPool) bool {
	systemPool := reflect.ValueOf(certPool).Elem().FieldByName("systemPool")
	if systemPool.Kind() == reflect.Bool {
		return systemPool.Bool()
	}

	return true
}

func isPlatformVerifier(certPool *x509.CertPool) bool {
	if certPool != nil {
		return isSystemCertPool(certPool)
	}

	// If systemCertPool already override.
	if systemCertPoolOverride {
		return false
	}

	systemCertPool := systemCertPool()
	if systemCertPool == nil || isSystemCertPool(systemCertPool) {
		return true
	}

	// systemCertPool override.
	systemCertPoolOverride = true
	return false
}
