// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"
)

type platform struct{}

const (
	_TCP_TXTLS_ENABLE = 39 /* TLS framing and encryption for transmit */
	_TCP_TXTLS_MODE   = 40 /* Transmit TLS mode */
	_TCP_RXTLS_ENABLE = 41 /* TLS framing and encryption for receive */
	_TCP_RXTLS_MODE   = 42 /* Receive TLS mode */

	_TLS_SET_RECORD_TYPE = 1
	_TLS_GET_RECORD      = 2

	_TCP_TLS_MODE_NONE  = 0
	_TCP_TLS_MODE_SW    = 1
	_TCP_TLS_MODE_IFNET = 2
	_TCP_TLS_MODE_TOE   = 3
)

// tls_get_record
type kernelGetRecord struct {
	RecordType    uint8  // uint8_t  tls_type;
	VersionMajor  uint8  // uint8_t  tls_vmajor;
	VersionMinjor uint8  // uint8_t  tls_vminor;
	Length        uint16 // uint16_t tls_length;
}

var (
	kernelRecvCmsgSpace  = unix.CmsgSpace(int(unsafe.Sizeof(&kernelGetRecord{})))
	kernelRecvCmsgLen    = unix.CmsgLen(int(unsafe.Sizeof(&kernelGetRecord{})))
	kernelSendCmsgSpace  = unix.CmsgSpace(1)
	kernelSendCmsgLen    = unix.CmsgLen(1)
	kernelCmsgDataOffset = unix.CmsgLen(0)
)

type kernelInfo struct {
	TLS     bool
	TLS_CBC bool

	TLS_Version13_RX        bool
	TLS_Version11_12_CBC_RX bool

	TLS_CHACHA20_POLY1305 bool
}

var kernel kernelInfo

func init() {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return
	}

	kernelVersion, err := parseVersion(strings.Trim(string(uname.Release[:]), "\x00"))
	if err != nil {
		return
	}
	kernelVersion.Pre = nil
	kernelVersion.Build = nil

	switch {
	case kernelVersion.GTE(semver.Version{Major: 14}):
		kernel.TLS_Version11_12_CBC_RX = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 13, Minor: 2}):
		kernel.TLS_Version13_RX = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 13, Minor: 1}):
		kernel.TLS_CHACHA20_POLY1305 = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 13}):
	default:
		return
	}

	ret, err := unix.Sysctl("kern.ipc.tls.enable")
	if err != nil {
		return
	}
	kernel.TLS = ret == "\x01"

	ret, err = unix.Sysctl("kern.ipc.tls.cbc_enable")
	if err != nil {
		return
	}
	kernel.TLS_CBC = ret == "\x01"
}

func (c *Conn) setup() error {
	c.out.Lock()
	defer c.out.Unlock()

	if c.quic != nil {
		return nil
	}

	if !c.config.KernelTX && !c.config.KernelRX {
		return nil
	}

	if !kernel.TLS {
		return nil
	}

	if c.in.usingKernel() || c.out.usingKernel() {
		return errors.New("tls: internal error: kernel does not support renegotiation")
	}

	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			return nil
		}

		var err error
		c.rawConn, err = conn.SyscallConn()
		if err != nil {
			return nil
		}
	}

	var in, out kernelCrypto
	if c.config.KernelRX {
		in = c.in.kernelCipher(c.cipherSuite, true)
	}
	if c.config.KernelTX {
		out = c.out.kernelCipher(c.cipherSuite, false)
	}

	if in == nil && out == nil {
		return nil
	}

	c.rawConn.Control(func(fd uintptr) {
		c.setupRX(fd, in)
		c.setupTX(fd, out)
	})
	return nil
}

func (c *Conn) setupRX(fd uintptr, crypto kernelCrypto) {
	if crypto == nil {
		return
	}

	err := syscall.SetsockoptString(int(fd), unix.IPPROTO_TCP, _TCP_RXTLS_ENABLE, crypto.String())
	if err != nil {
		return
	}
	c.in.useKernel()
}

func (c *Conn) resetupRX() error {
	if !c.in.usingKernel() {
		return nil
	}

	return errors.New("tls: internal error: kernel does not support rekey")
}

func (c *Conn) setupTX(fd uintptr, crypto kernelCrypto) {
	if crypto == nil {
		return
	}

	err := syscall.SetsockoptString(int(fd), unix.IPPROTO_TCP, _TCP_TXTLS_ENABLE, crypto.String())
	if err != nil {
		return
	}
	c.out.useKernel()
}

func (c *Conn) resetupTX() (resetup, error) {
	if !c.out.usingKernel() {
		return nopResetup, nil
	}

	return nil, errors.New("tls: internal error: kernel does not support rekey")
}

func (c *Conn) readKernelRecord(handshakeState uint32) (recordType, []byte, error) {
	if handshakeState != handshakeCompleted {
		c.sendAlertLocked(alertInternalError)
		return 0, nil, c.in.setErrorLocked(errors.New("tls: internal error: set kernelCipher before handshake completed"))
	}

	if c.rawInput.Len() < maxPlaintext {
		c.rawInput.Grow(maxPlaintext - c.rawInput.Len())
	}

	data := c.rawInput.Bytes()[:maxPlaintext]

	// cmsg for record type
	buffer := make([]byte, kernelRecvCmsgSpace)
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&buffer[0]))
	cmsg.SetLen(kernelRecvCmsgLen)

	var iov unix.Iovec
	iov.Base = &data[0]
	iov.SetLen(len(data))

	var msg unix.Msghdr
	msg.Control = &buffer[0]
	msg.Controllen = cmsg.Len
	msg.Iov = &iov
	msg.Iovlen = 1

	var n int
	var err error
	er := c.rawConn.Read(func(fd uintptr) bool {
		n, err = recvmsg(int(fd), &msg, 0)
		return err != unix.EAGAIN
	})
	if er != nil {
		c.sendAlert(alertInternalError)
		return 0, nil, c.in.setErrorLocked(er)
	}

	switch err {
	case nil:
	case syscall.EINVAL:
		return 0, nil, c.in.setErrorLocked(c.sendAlert(alertProtocolVersion))
	case syscall.EMSGSIZE:
		return 0, nil, c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	case syscall.EBADMSG:
		return 0, nil, c.in.setErrorLocked(c.sendAlert(alertBadRecordMAC))
	default:
		c.sendAlert(alertInternalError)
		return 0, nil, c.in.setErrorLocked(err)
	}

	if n <= 0 {
		return 0, nil, c.in.setErrorLocked(io.EOF)
	}

	if cmsg.Level == unix.IPPROTO_TCP && cmsg.Type == _TLS_GET_RECORD {
		hdr := (*kernelGetRecord)(unsafe.Pointer(&buffer[kernelCmsgDataOffset]))
		return recordType(hdr.RecordType), data[:n], nil
	}

	return recordTypeApplicationData, data[:n], nil
}

func (c *Conn) writeKernelRecord(typ recordType, data []byte) (int, error) {
	if typ == recordTypeApplicationData {
		return c.write(data)
	}

	// cmsg for record type
	buffer := make([]byte, kernelSendCmsgSpace)
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&buffer[0]))
	cmsg.SetLen(kernelSendCmsgLen)
	buffer[kernelCmsgDataOffset] = byte(typ)
	cmsg.Level = unix.IPPROTO_TCP
	cmsg.Type = _TLS_SET_RECORD_TYPE

	var iov unix.Iovec
	iov.Base = &data[0]
	iov.SetLen(len(data))

	var msg unix.Msghdr
	msg.Control = &buffer[0]
	msg.Controllen = cmsg.Len
	msg.Iov = &iov
	msg.Iovlen = 1

	var n int
	var err error
	ew := c.rawConn.Write(func(fd uintptr) bool {
		n, err = sendmsg(int(fd), &msg, 0)
		return err != unix.EAGAIN
	})
	if ew != nil {
		return 0, ew
	}
	return n, err
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	// interlock with Close below
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if !c.out.usingKernel() {
		c.out.Unlock()
		n, err := io.Copy(&wrappedConn{c}, r)
		c.out.Lock()
		return n, err
	}

	if err := c.out.err; err != nil {
		return 0, err
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	return io.Copy(c.conn, r)
}

// FreeBSD does not implement WriteTo.
// Record type are discarded on read calls instead of returning an error like on Linux.
// This can cause control and data messages to be mixed up.

//go:linkname recvmsg golang.org/x/sys/unix.recvmsg
func recvmsg(fd int, msg *unix.Msghdr, flags int) (n int, err error)

//go:linkname sendmsg golang.org/x/sys/unix.sendmsg
func sendmsg(fd int, msg *unix.Msghdr, flags int) (n int, err error)
