// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"
)

const (
	TCP_TXTLS_ENABLE = 39 /* TLS framing and encryption for transmit */
	TCP_TXTLS_MODE   = 40 /* Transmit TLS mode */
	TCP_RXTLS_ENABLE = 41 /* TLS framing and encryption for receive */
	TCP_RXTLS_MODE   = 42 /* Receive TLS mode */

	TLS_SET_RECORD_TYPE = 1
	TLS_GET_RECORD      = 2

	TCP_TLS_MODE_NONE  = 0
	TCP_TLS_MODE_SW    = 1
	TCP_TLS_MODE_IFNET = 2
	TCP_TLS_MODE_TOE   = 3
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
		c.setupRX(fd, in)
		c.setupTX(fd, out)
	})
	return nil
}

func (c *Conn) setupRX(fd uintptr, crypto kernelCrypto) {
	if crypto == nil {
		return
	}

	err := syscall.SetsockoptString(int(fd), unix.IPPROTO_TCP, TCP_RXTLS_ENABLE, crypto.String())
	if err != nil {
		return
	}
	c.in.useKernel()
}

func (c *Conn) setupTX(fd uintptr, crypto kernelCrypto) {
	if crypto == nil {
		return
	}

	err := syscall.SetsockoptString(int(fd), unix.IPPROTO_TCP, TCP_TXTLS_ENABLE, crypto.String())
	if err != nil {
		return
	}
	c.out.useKernel()
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

	if cmsg.Level == unix.IPPROTO_TCP && cmsg.Type == TLS_GET_RECORD {
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
	cmsg.Level = unix.IPPROTO_TCP
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

const (
	numbers  string = "0123456789"
	alphas          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"
	alphanum        = alphas + numbers
)

// Parse parses version string and returns a validated Version or error
// FreeBSD release version not contains patch
func parseVersion(s string) (semver.Version, error) {
	if len(s) == 0 {
		return semver.Version{}, errors.New("Version string empty")
	}

	// Split into major.(minor+pr+meta)
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return semver.Version{}, errors.New("No Major.Minor elements found")
	}

	// Major
	if !containsOnly(parts[0], numbers) {
		return semver.Version{}, fmt.Errorf("Invalid character(s) found in major number %q", parts[0])
	}
	if hasLeadingZeroes(parts[0]) {
		return semver.Version{}, fmt.Errorf("Major number must not contain leading zeroes %q", parts[0])
	}
	major, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return semver.Version{}, err
	}

	v := semver.Version{}
	v.Major = major

	var build, prerelease []string
	minorStr := parts[1]

	if buildIndex := strings.IndexRune(minorStr, '+'); buildIndex != -1 {
		build = strings.Split(minorStr[buildIndex+1:], ".")
		minorStr = minorStr[:buildIndex]
	}

	if preIndex := strings.IndexRune(minorStr, '-'); preIndex != -1 {
		prerelease = strings.Split(minorStr[preIndex+1:], ".")
		minorStr = minorStr[:preIndex]
	}

	if !containsOnly(minorStr, numbers) {
		return semver.Version{}, fmt.Errorf("Invalid character(s) found in minor number %q", minorStr)
	}
	if hasLeadingZeroes(minorStr) {
		return semver.Version{}, fmt.Errorf("Minor number must not contain leading zeroes %q", minorStr)
	}
	minor, err := strconv.ParseUint(minorStr, 10, 64)
	if err != nil {
		return semver.Version{}, err
	}

	v.Minor = minor

	// Prerelease
	for _, prstr := range prerelease {
		parsedPR, err := semver.NewPRVersion(prstr)
		if err != nil {
			return semver.Version{}, err
		}
		v.Pre = append(v.Pre, parsedPR)
	}

	// Build meta data
	for _, str := range build {
		if len(str) == 0 {
			return semver.Version{}, errors.New("Build meta data is empty")
		}
		if !containsOnly(str, alphanum) {
			return semver.Version{}, fmt.Errorf("Invalid character(s) found in build meta data %q", str)
		}
		v.Build = append(v.Build, str)
	}

	return v, nil
}

//go:linkname containsOnly github.com/blang/semver/v4.containsOnly
func containsOnly(s string, set string) bool

//go:linkname hasLeadingZeroes github.com/blang/semver/v4.hasLeadingZeroes
func hasLeadingZeroes(s string) bool
