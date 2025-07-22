// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
)

type wrappedConn struct {
	io.ReadWriter
}

type resetup func() error

var nopResetup = func() error {
	return nil
}

type kernelCipher struct{}

func (c *halfConn) useKernel() {
	c.cipher = new(kernelCipher)
}

func (c *halfConn) usingKernel() (ok bool) {
	_, ok = c.cipher.(*kernelCipher)
	return
}

func (c *Conn) KernelTX() bool {
	c.out.Lock()
	defer c.out.Unlock()

	return c.out.usingKernel()
}

func (c *Conn) KernelRX() bool {
	c.in.Lock()
	defer c.in.Unlock()

	return c.in.usingKernel()
}
