// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || freebsd

package tls

import (
	"io"
)

type wrappedConn struct {
	io.ReadWriter
}

func (c *halfConn) useKernel() {
	c.cipher = new(kernelCipher)
}

func ioCopy(dst io.Writer, src io.Reader) (int64, error) {
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}

	return io.Copy(dst, src)
}
