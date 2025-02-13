// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !freebsd

package tls

const kernelOverhead = 0

func (c *Conn) setup() error {
	return nil
}

func (c *Conn) readKernelRecord(handshakeState uint32) (typ recordType, data []byte, err error) {
	panic("not implement")
}

func (c *Conn) writeKernelRecord(typ recordType, data []byte) (n int, err error) {
	panic("not implement")
}
