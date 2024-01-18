// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
)

type kernelCipher struct{}

type wrappedConn struct {
	io.ReadWriter
}

func (c *Conn) KernelTX() bool {
	return c.out.usingKernel()
}

func (c *Conn) KernelRX() bool {
	return c.in.usingKernel()
}