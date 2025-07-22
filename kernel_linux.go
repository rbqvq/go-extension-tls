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
)

type kernelInfo struct {
	TLS, TLS_RX                     bool
	TLS_Version13, TLS_Version13_RX bool

	TLS_TX_ZEROCOPY  bool
	TLS_RX_NOPADDING bool

	TLS_AES_256_GCM       bool
	TLS_AES_128_CCM       bool
	TLS_CHACHA20_POLY1305 bool
	TLS_SM4               bool
	TLS_ARIA_GCM          bool
}

var kernel kernelInfo

func init() {
	// when kernel tls module enabled, /sys/module/tls is available
	if _, err := os.Stat("/sys/module/tls"); err != nil {
		// try modprobe
		func() {
			defer func() {
				recover()
			}()

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
	case kernelVersion.GTE(semver.Version{Major: 6, Minor: 1}):
		kernel.TLS_ARIA_GCM = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 6}):
		kernel.TLS_Version13_RX = true
		kernel.TLS_RX_NOPADDING = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 5, Minor: 19}):
		kernel.TLS_TX_ZEROCOPY = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 5, Minor: 16}):
		kernel.TLS_SM4 = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 5, Minor: 11}):
		kernel.TLS_CHACHA20_POLY1305 = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 5, Minor: 2}):
		kernel.TLS_AES_128_CCM = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 5, Minor: 1}):
		kernel.TLS_AES_256_GCM = true
		kernel.TLS_Version13 = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 4, Minor: 17}):
		kernel.TLS_RX = true
		fallthrough
	case kernelVersion.GTE(semver.Version{Major: 4, Minor: 13}):
		kernel.TLS = true
	}
}

func (c *Conn) setup() error {
	if c.quic != nil {
		return nil
	}

	if !c.config.KernelTX && !c.config.KernelRX {
		return nil
	}

	if !kernel.TLS {
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
	if c.config.KernelRX {
		in = c.in.kernelCipher(c.cipherSuite, true)
	}
	if c.config.KernelTX {
		out = c.out.kernelCipher(c.cipherSuite, false)
	}

	if in == nil && out == nil {
		return nil
	}

	rawConn.Control(func(fd uintptr) {
		err := syscall.SetsockoptString(int(fd), unix.SOL_TCP, unix.TCP_ULP, "tls")
		if err != nil {
			return
		}

		c.setupRX(fd, in)
		c.setupTX(fd, out)
	})
	return nil
}

func (c *Conn) setupRX(fd uintptr, crypto kernelCrypto) {
	if crypto == nil {
		return
	}

	err := syscall.SetsockoptString(int(fd), unix.SOL_TLS, TLS_RX, crypto.String())
	if err != nil {
		return
	}
	c.in.useKernel()

	if c.config.KernelRXExpectNoPad && c.vers >= VersionTLS13 && kernel.TLS_RX_NOPADDING {
		syscall.SetsockoptInt(int(fd), unix.SOL_TLS, TLS_RX_EXPECT_NO_PAD, 1)
	}
}

func (c *Conn) setupTX(fd uintptr, crypto kernelCrypto) {
	if crypto == nil {
		return
	}

	err := syscall.SetsockoptString(int(fd), unix.SOL_TLS, TLS_TX, crypto.String())
	if err != nil {
		return
	}
	c.out.useKernel()

	if kernel.TLS_TX_ZEROCOPY {
		syscall.SetsockoptInt(int(fd), unix.SOL_TLS, TLS_TX_ZEROCOPY_RO, 1)
	}
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
	switch err {
	case nil:
	case syscall.EINVAL:
		return 0, nil, c.in.setErrorLocked(c.sendAlert(alertProtocolVersion))
	case syscall.EMSGSIZE:
		return 0, nil, c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	case syscall.EBADMSG:
		return 0, nil, c.in.setErrorLocked(c.sendAlert(alertBadRecordMAC))
	default:
		return 0, nil, err
	}

	if n <= 0 {
		return 0, nil, io.EOF
	}

	if cmsg.Level == unix.SOL_TLS && cmsg.Type == TLS_GET_RECORD_TYPE {
		typ := recordType(buffer[unix.CmsgLen(0)])
		return typ, data[:n], nil
	}

	return recordTypeApplicationData, data[:n], nil
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
	buffer[unix.CmsgLen(0)] = byte(typ)
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

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.in.Lock()
	defer c.in.Unlock()

	if !c.in.usingKernel() {
		c.in.Unlock()
		n, err := io.Copy(w, &wrappedConn{c})
		c.in.Lock()
		return n, err
	}

	if err := c.in.err; err != nil {
		return 0, err
	}

	var written int64

	if c.input.Len() > 0 {
		n, err := c.input.WriteTo(w)
		written += n

		if err != nil {
			return written, err
		}
	}

	for {
		n, err := io.Copy(w, c.conn)
		written += n
		switch {
		case errors.Is(err, syscall.EINVAL):
			err = nil

			// splice receive control msg will return -EINVAL
			// if receive bad protocol version, splice will blocking until conenction disconnect
			err := c.readRecord()
			if err != nil {
				return written, err
			}

			if c.input.Len() > 0 {
				n, err := c.input.WriteTo(w)
				written += n

				if err != nil {
					return written, err
				}
			}

			for c.hand.Len() > 0 {
				if err := c.handlePostHandshakeMessage(); err != nil {
					return written, err
				}
			}
		case errors.Is(err, syscall.EMSGSIZE):
			err = c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
		case errors.Is(err, syscall.EBADMSG):
			err = c.in.setErrorLocked(c.sendAlert(alertBadRecordMAC))
		}

		if err != nil {
			return written, err
		}
	}
}

//go:linkname recvmsg golang.org/x/sys/unix.recvmsg
func recvmsg(fd int, msg *unix.Msghdr, flags int) (n int, err error)

//go:linkname sendmsg golang.org/x/sys/unix.sendmsg
func sendmsg(fd int, msg *unix.Msghdr, flags int) (n int, err error)
