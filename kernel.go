// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
)

type kernelCipher struct{}

type warppedConn struct {
	io.ReadWriter
}
