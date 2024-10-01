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
	"github.com/pmorjan/kmod"
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

	TLS_Version13_TX bool
	TLS_Version13_RX bool
	TLS_TX_ZEROCOPY  bool
	TLS_RX_NOPAD     bool

	TLS_AESGCM256, TLS_AESCCM128, TLS_CHACHA20 bool
	TLS_SM4, TLS_ARIAGCM                       bool
}

var kernel kernelInfo

func init() {
	// when kernel tls module enabled, /sys/module/tls is available
	if _, err := os.Stat("/sys/module/tls"); err != nil {
		// try modprobe
		func() {
			defer recover()
			kmod, err := kmod.New()
			if err != nil {
				return
			}

			kmod.Load("tls", "", 0)
		}()
	}

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

	switch {
	case kernelVersion.GTE(semver.MustParse("6.1.0")):
		kernel.TLS_ARIAGCM = true
		fallthrough
	case kernelVersion.Major > 5:
		kernel.TLS_Version13_RX = true
		kernel.TLS_RX_NOPAD = true
		fallthrough
	case kernelVersion.GTE(semver.MustParse("5.19.0")):
		kernel.TLS_TX_ZEROCOPY = true
		fallthrough
	// case kernelVersion.GTE(semver.MustParse("5.16.0")):
	// 	// SM4_GCM, SM4_CCM
	// 	fallthrough
	case kernelVersion.GTE(semver.MustParse("5.11.0")):
		kernel.TLS_CHACHA20 = true
		fallthrough
	case kernelVersion.GTE(semver.MustParse("5.2.0")):
		kernel.TLS_AESCCM128 = true
		fallthrough
	case kernelVersion.GTE(semver.MustParse("5.1.0")):
		kernel.TLS_AESGCM256 = true
		kernel.TLS_Version13_TX = true
		fallthrough
	case kernelVersion.GTE(semver.MustParse("4.17.0")):
		kernel.TLS_RX = true
		fallthrough
	case kernelVersion.GTE(semver.MustParse("4.13.0")):
		kernel.TLS_TX = true
	}
}

func (c *Conn) setup() error {
	if !kernel.TLS_TX || (!c.config.KernelTX && !c.config.KernelRX) {
		return nil
	}

	if c.quic != nil {
		return nil
	}

	var rawConn syscall.RawConn
	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			return nil
		}

		var err error
		rawConn, err = conn.SyscallConn()
		if err != nil {
			return nil
		}
	}

	var in, out kernelCrypto
	switch c.vers {
	case VersionTLS12:
		if kernel.TLS_RX && c.config.KernelRX {
			in = c.in.kernelCipher(c.cipherSuite)
		}

		if c.config.KernelTX {
			out = c.out.kernelCipher(c.cipherSuite)
		}
	case VersionTLS13:
		if !kernel.TLS_Version13_TX {
			return nil
		}

		if kernel.TLS_Version13_RX && c.config.KernelRX {
			in = c.in.kernelCipher(c.cipherSuite)
		}

		if c.config.KernelTX {
			out = c.out.kernelCipher(c.cipherSuite)
		}
	default:
		return nil
	}

	if in == nil && out == nil {
		return nil
	}

	var err error
	ec := rawConn.Control(func(fd uintptr) {
		err = syscall.SetsockoptString(int(fd), unix.SOL_TCP, unix.TCP_ULP, "tls")
		if err != nil {
			return
		}

		if in != nil {
			err = syscall.SetsockoptString(int(fd), unix.SOL_TLS, TLS_RX, in.String())
			if err != nil {
				return
			}

			if c.vers >= VersionTLS13 && kernel.TLS_RX_NOPAD {
				err = syscall.SetsockoptInt(int(fd), unix.SOL_TLS, TLS_RX_EXPECT_NO_PAD, 1)
				if err != nil {
					return
				}
			}
		}

		if out != nil {
			err = syscall.SetsockoptString(int(fd), unix.SOL_TLS, TLS_TX, out.String())
			if err != nil {
				return
			}

			if kernel.TLS_TX_ZEROCOPY {
				err = syscall.SetsockoptInt(int(fd), unix.SOL_TLS, TLS_TX_ZEROCOPY_RO, 1)
				if err != nil {
					return
				}
			}
		}
	})
	if ec != nil {
		return ec
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) readKernelRecord(handshakeState uint32) (recordType, []byte, error) {
	if handshakeState != handshakeCompleted {
		c.sendAlertLocked(alertInternalError)
		return 0, nil, c.in.setErrorLocked(errors.New("tls: internal error: set kernelCipher before handshake completed"))
	}

	var rawConn syscall.RawConn
	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			c.sendAlertLocked(alertInternalError)
			return 0, nil, c.in.setErrorLocked(fmt.Errorf("tls: internal error: set kernelCipher on invalid connection type, want: %T, have: %T", conn, c.conn))
		}

		var err error
		rawConn, err = conn.SyscallConn()
		if err != nil {
			return 0, nil, err
		}
	}

	if c.rawInput.Len() < maxPlaintext {
		c.rawInput.Grow(maxPlaintext - c.rawInput.Len())
	}

	data := c.rawInput.Bytes()[:maxPlaintext]

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

	var n int
	var err error
	er := rawConn.Read(func(fd uintptr) bool {
		n, err = recvmsg(int(fd), &msg, 0)
		return err != unix.EAGAIN
	})
	if er != nil {
		return 0, nil, er
	}
	if err != nil {
		return 0, nil, err
	}

	if n <= 0 {
		return 0, nil, io.EOF
	}

	if cmsg.Level != unix.SOL_TLS {
		c.sendAlertLocked(alertInternalError)
		return 0, nil, c.in.setErrorLocked(fmt.Errorf("tls: internal error: invalid kernel cmsg level: %d", cmsg.Level))
	}

	if cmsg.Type != TLS_GET_RECORD_TYPE {
		c.sendAlertLocked(alertInternalError)
		return 0, nil, c.in.setErrorLocked(fmt.Errorf("tls: internal error: invalid kernel cmsg type: %d", cmsg.Type))
	}

	typ := recordType(buffer[unix.SizeofCmsghdr])
	return typ, data[:n], nil
}

func (c *Conn) writeKernelRecord(typ recordType, data []byte) (int, error) {
	if typ == recordTypeApplicationData {
		return c.write(data)
	}

	var rawConn syscall.RawConn
	{
		conn, ok := c.conn.(*net.TCPConn)
		if !ok {
			c.sendAlertLocked(alertInternalError)
			return 0, c.out.setErrorLocked(fmt.Errorf("tls: internal error: set kernelCipher on invalid connection type, want: %T, have: %T", conn, c.conn))
		}

		var err error
		rawConn, err = conn.SyscallConn()
		if err != nil {
			return 0, err
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

	var n int
	var err error
	ew := rawConn.Write(func(fd uintptr) bool {
		n, err = sendmsg(int(fd), &msg, 0)
		return err != unix.EAGAIN
	})
	if ew != nil {
		return 0, ew
	}
	return n, err
}

func (c *Conn) ReadFrom(r io.Reader) (n int64, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	if !c.out.usingKernel() {
		return io.Copy(&wrappedConn{c}, r)
	}

	return io.Copy(c.conn, r)
}

func (c *Conn) WriteTo(w io.Writer) (n int64, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	if !c.in.usingKernel() {
		return io.Copy(w, &wrappedConn{c})
	}

	return io.Copy(w, c.conn)
}

//go:linkname recvmsg golang.org/x/sys/unix.recvmsg
func recvmsg(fd int, msg *unix.Msghdr, flags int) (n int, err error)

//go:linkname sendmsg golang.org/x/sys/unix.sendmsg
func sendmsg(fd int, msg *unix.Msghdr, flags int) (n int, err error)
