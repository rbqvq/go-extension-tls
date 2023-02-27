// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"
)

const (
	TLS_TX               = 1
	TLS_RX               = 2
	TLS_TX_ZEROCOPY_RO   = 3 // TX zerocopy (only sendfile now)
	TLS_RX_EXPECT_NO_PAD = 4 // Attempt opportunistic zero-copy, TLS 1.3 only

	TLS_SET_RECORD_TYPE = 1
	TLS_GET_RECORD_TYPE = 2

	kernelOverhead = 16
)

type kernelInfo struct {
	TLS_TX, TLS_RX bool

	TLS_Version13   bool
	TLS_TX_ZEROCOPY bool
	TLS_RX_NOPAD    bool

	TLS_AESGCM256, TLS_AESCCM128, TLS_CHACHA20 bool
	TLS_ARIAGCM                                bool
}

var kernel kernelInfo

func init() {
	// when kernel tls module enabled, /sys/module/tls is available
	if _, err := os.Stat("/sys/module/tls"); err != nil {
		return
	}

	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return
	}

	kernelVersion, err := semver.Parse(strings.Trim(string(uname.Release[:]), "\x00"))
	if err != nil {
		return
	}
	kernelVersion.Pre = nil
	kernelVersion.Build = nil

	if kernelVersion.GTE(semver.MustParse("4.13.0")) {
		kernel.TLS_TX = true
	}

	if kernelVersion.GTE(semver.MustParse("4.17.0")) {
		kernel.TLS_RX = true
	}

	if kernelVersion.GTE(semver.MustParse("5.1.0")) {
		kernel.TLS_AESGCM256 = true
		kernel.TLS_Version13 = true
	}

	if kernelVersion.GTE(semver.MustParse("5.2.0")) {
		kernel.TLS_AESCCM128 = true
	}

	if kernelVersion.GTE(semver.MustParse("5.11.0")) {
		kernel.TLS_CHACHA20 = true
	}

	if kernelVersion.GTE(semver.MustParse("5.16.0")) {
		// SM4_GCM, SM4_CCM (not supported)
	}

	if kernelVersion.GTE(semver.MustParse("5.19.0")) {
		kernel.TLS_CHACHA20 = true
	}

	if kernelVersion.Major > 5 {
		kernel.TLS_RX_NOPAD = true
	}

	if kernelVersion.GTE(semver.MustParse("6.1.0")) {
		kernel.TLS_ARIAGCM = true
	}
}

func (c *Conn) setup(cipherSuite uint16) error {
	if !kernel.TLS_TX || (!c.config.KernelTX && !c.config.KernelRX) {
		return nil
	}

	var rwc syscall.RawConn
	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			return nil
		}

		var err error
		rwc, err = conn.SyscallConn()
		if err != nil {
			return nil
		}
	}

	var in, out kernelCrypto
	switch c.vers {
	case VersionTLS12:
		if kernel.TLS_RX && c.config.KernelRX {
			in = c.in.kernelCipher(cipherSuite)
		}

		if c.config.KernelTX {
			out = c.out.kernelCipher(cipherSuite)
		}
	case VersionTLS13:
		if !kernel.TLS_Version13 {
			return nil
		}

		if kernel.TLS_RX && c.config.KernelRX {
			in = c.in.kernelCipher(cipherSuite)
		}

		if c.config.KernelTX {
			out = c.out.kernelCipher(cipherSuite)
		}
	default:
		return nil
	}

	if in == nil && out == nil {
		return nil
	}

	var err, er error
	err = rwc.Control(func(fd uintptr) {
		er = syscall.SetsockoptString(int(fd), unix.SOL_TCP, unix.TCP_ULP, "tls")
		if er != nil {
			return
		}

		if in != nil {
			er = syscall.SetsockoptString(int(fd), unix.SOL_TLS, TLS_RX, in.String())
			if er != nil {
				return
			}

			if kernel.TLS_RX_NOPAD {
				er = syscall.SetsockoptInt(int(fd), unix.SOL_TLS, TLS_RX_EXPECT_NO_PAD, 1)
				if er != nil {
					return
				}
			}
		}

		if out != nil {
			er = syscall.SetsockoptString(int(fd), unix.SOL_TLS, TLS_TX, out.String())
			if er != nil {
				return
			}

			if kernel.TLS_TX_ZEROCOPY {
				er = syscall.SetsockoptInt(int(fd), unix.SOL_TLS, TLS_TX_ZEROCOPY_RO, 1)
				if er != nil {
					return
				}
			}
		}
	})
	if er != nil {
		return er
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) readKernelRecord(handshakeState uint32) (typ recordType, data []byte, err error) {
	if handshakeState != handshakeCompleted {
		c.sendAlertLocked(alertInternalError)
		err = c.in.setErrorLocked(errors.New("tls: internal error: set kTLSCipher before handshake completed"))
		return
	}

	var rwc syscall.RawConn
	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			err = errors.New("unsupported conn types")
			return
		}

		rwc, err = conn.SyscallConn()
		if err != nil {
			return
		}
	}

	if c.rawInput.Len() < maxPlaintext {
		c.rawInput.Grow(maxPlaintext - c.rawInput.Len())
	}

	var n int
	data = c.rawInput.Bytes()[:maxPlaintext]

	// cmsg for record type
	buffer := make([]byte, unix.CmsgSpace(1))
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&buffer[0]))
	cmsg.SetLen(unix.CmsgLen(1))

	var iov unix.Iovec
	iov.Base = &data[0]
	iov.SetLen(len(data))

	var msg unix.Msghdr
	msg.Control = &buffer[0]
	msg.Controllen = cmsg.Len
	msg.Iov = &iov
	msg.Iovlen = 1

	er := rwc.Read(func(fd uintptr) bool {
		flags := 0

		n, err = recvmsg(fd, &msg, flags)
		if err == unix.EAGAIN {
			// data is not ready, goroutine will be parked
			return false
		}

		// n should not be zero when err == nil
		if err == nil && n == 0 {
			err = io.EOF
		}
		return true
	})
	if er != nil {
		err = er
	}

	if err != nil {
		return
	}

	if n <= 0 {
		data = nil
		return
	}

	if cmsg.Level != unix.SOL_TLS {
		err = fmt.Errorf("unsupported cmsg level: %d", cmsg.Level)
		return
	}

	if cmsg.Type != TLS_GET_RECORD_TYPE {
		err = fmt.Errorf("unsupported cmsg type: %d", cmsg.Type)
		return
	}

	typ = recordType(buffer[unix.SizeofCmsghdr])
	data = data[:n]
	return
}

func (c *Conn) writeKernelRecord(typ recordType, data []byte) (n int, err error) {
	if typ == recordTypeApplicationData {
		return c.write(data)
	}

	var rwc syscall.RawConn
	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			err = errors.New("unsupported conn types")
			return
		}

		rwc, err = conn.SyscallConn()
		if err != nil {
			return
		}
	}

	// cmsg for record type
	buffer := make([]byte, unix.CmsgSpace(1))
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&buffer[0]))
	cmsg.SetLen(unix.CmsgLen(1))
	buffer[unix.SizeofCmsghdr] = byte(typ)
	cmsg.Level = unix.SOL_TLS
	cmsg.Type = TLS_SET_RECORD_TYPE

	var iov unix.Iovec
	iov.Base = &data[0]
	iov.SetLen(len(data))

	var msg unix.Msghdr
	msg.Control = &buffer[0]
	msg.Controllen = cmsg.Len
	msg.Iov = &iov
	msg.Iovlen = 1

	ew := rwc.Write(func(fd uintptr) bool {
		flags := 0

		n, err = sendmsg(fd, &msg, flags)
		return err != unix.EAGAIN
	})
	if ew != nil {
		err = ew
	}
	return
}

func (c *Conn) ReadFrom(r io.Reader) (n int64, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	if !c.out.usingKernel() {
		return io.Copy(&warppedConn{c}, r)
	}

	return io.Copy(c.conn, r)
}

func (c *Conn) WriteTo(w io.Writer) (n int64, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	if !c.in.usingKernel() {
		return io.Copy(w, &warppedConn{c})
	}

	return io.Copy(w, c.conn)
}

func recvmsg(fd uintptr, msg *unix.Msghdr, flags int) (n int, err error) {
	r0, _, e1 := unix.Syscall(unix.SYS_RECVMSG, fd, uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	err = errnoErr(e1)
	return
}

func sendmsg(fd uintptr, msg *unix.Msghdr, flags int) (n int, err error) {
	r0, _, e1 := unix.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	err = errnoErr(e1)
	return
}

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e unix.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return unix.EAGAIN
	case unix.EINVAL:
		return unix.EINVAL
	case unix.ENOENT:
		return unix.ENOENT
	}
	return e
}
