// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

var earlyDataPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(nil)
	},
}

type earlyData struct {
	max  uint32       // maximum early data
	size atomic.Int64 // number of bytes of early data
	done bool         // endOfEarlyData was sent or received
	data *bytes.Buffer

	// For client only
	mutex             sync.Mutex
	handshakeDone     chan struct{}
	handshakeDoneOnce sync.Once

	// For server only
	handshakeState *serverHandshakeStateTLS13
}

/* Client */
func (early *earlyData) initClient(max uint32) {
	early.max = max
	early.data = earlyDataPool.Get().(*bytes.Buffer)
	early.handshakeDone = make(chan struct{})
}

func (early *earlyData) Lock() {
	early.mutex.Lock()
}

func (early *earlyData) Unlock() {
	early.mutex.Unlock()
}

func (early *earlyData) Check(n int) bool {
	if early.done {
		return false
	}

	return early.Add(n)
}

func (early *earlyData) Done() {
	early.mutex.Lock()
	defer early.mutex.Unlock()

	early.done = true
}

func (early *earlyData) Wait() {
	<-early.handshakeDone
}

func (early *earlyData) WaitLocked() {
	early.mutex.Unlock()
	defer early.mutex.Lock()

	<-early.handshakeDone
}

func (early *earlyData) Notify() {
	early.handshakeDoneOnce.Do(func() {
		close(early.handshakeDone)
	})
}

/* Server */
func (early *earlyData) initServer(hs *serverHandshakeStateTLS13, max uint32) {
	early.max = max
	early.handshakeState = hs
}

func (early *earlyData) Add(n int) bool {
	return early.size.Add(int64(n)) <= int64(early.max)
}

func (early *earlyData) Handshake() error {
	if hs := early.handshakeState; hs != nil {
		early.handshakeState = nil
		return hs.doEarlyHandshake()
	}
	return nil
}

/* Client and Server */
func (early *earlyData) Len() int {
	if data := early.data; data != nil {
		return data.Len()
	}
	return 0
}

func (early *earlyData) Read(p []byte) (int, error) {
	if data := early.data; data != nil {
		return data.Read(p)
	}
	return 0, io.ErrClosedPipe
}

func (early *earlyData) WriteTo(w io.Writer) (int64, error) {
	if data := early.data; data != nil {
		return data.WriteTo(w)
	}
	return 0, io.ErrClosedPipe
}

func (early *earlyData) Write(p []byte) (int, error) {
	if data := early.data; data != nil {
		return data.Write(p)
	}
	return 0, io.ErrClosedPipe
}

func (early *earlyData) Data() []byte {
	if data := early.data; data != nil {
		return data.Bytes()
	}
	return nil
}

func (early *earlyData) Reset() {
	data := early.data
	if data == nil {
		return
	}

	early.data = nil
	data.Reset()
	earlyDataPool.Put(data)
}

/* Conn */
func (c *Conn) initClientEarlyData(max uint32) {
	c.earlyData.initClient(max)
	c.vers = VersionTLS13
	c.in.version = VersionTLS13
	c.out.version = VersionTLS13
	c.handshakeState.Store(handshakeEarly)
}

func (c *Conn) initServerEarlyData(hs *serverHandshakeStateTLS13, max uint32) {
	c.earlyData.initServer(hs, max)
}

func (c *Conn) waitEarlyHandshake() error {
	if !c.isClient {
		return nil
	}

	c.earlyData.Wait() // wait handshake done

	if c.handshakeErr != nil {
		return c.handshakeErr
	}

	if c.handshakeState.Load() != handshakeCompleted {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
		return c.handshakeErr
	}

	return nil
}

func (c *Conn) writeClientEarlyData(b []byte) error {
	if c.earlyData.Check(len(b)) {
		c.earlyData.Write(b)
		return nil
	}

	c.earlyData.WaitLocked() // wait handshake done
	if c.handshakeErr != nil {
		return c.handshakeErr
	}

	if c.handshakeState.Load() != handshakeCompleted {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
		return c.handshakeErr
	}

	return nil
}

func (c *Conn) earlyCloseNotify() error {
	if !c.isClient {
		c.handshakeMutex.Lock()
		defer c.handshakeMutex.Unlock()

		if c.handshakeErr != nil {
			return errEarlyCloseWrite
		}

		return c.closeNotify()
	}

	c.earlyData.Lock()
	defer c.earlyData.Unlock()

	if c.earlyData.Check(0) {
		return c.closeNotify()
	}

	c.earlyData.WaitLocked() // wait handshake done
	if c.handshakeErr != nil {
		return errEarlyCloseWrite
	}

	if c.handshakeState.Load() != handshakeCompleted {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
		return errEarlyCloseWrite
	}

	return c.closeNotify()
}

func (c *Conn) rejectedEarlyData() {
	if c.quic != nil {
		c.quicRejectedEarlyData()
		return
	}

	c.earlyData.Lock()
	defer c.earlyData.Unlock()

	c.earlyData.max = 0
	c.earlyData.done = true
	c.out.cipher = nil
}

// ConfirmHandshake waits for the handshake to reach a point at which
// the connection is certainly not replayed. That is, after receiving
// the Client Finished.
//
// If ConfirmHandshake returns an error and until ConfirmHandshake
// returns, the 0-RTT data should not be trusted not to be replayed.
//
// This is only meaningful in TLS 1.3 when Allow0RTT is true and the
// client sent valid 0-RTT data. In any other case it's equivalent to
// calling Handshake.
func (c *Conn) ConfirmHandshake() error {
	if err := c.Handshake(); err != nil {
		return err
	}

	if c.isClient || c.vers < VersionTLS13 || c.handshakeState.Load() != handshakeEarly {
		return c.handshakeErr
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.handshakeState.Load() != handshakeEarly {
		return c.handshakeErr
	}

	c.in.Lock()
	defer c.in.Unlock()

	c.earlyData.data = earlyDataPool.Get().(*bytes.Buffer)
	handshakeFn := func() error {
		for c.handshakeState.Load() == handshakeEarly {
			if err := c.readRecord(); err != nil {
				return err
			}

			if c.input.Len() > 0 {
				c.input.WriteTo(&c.earlyData)
			}

			for c.hand.Len() > 0 {
				if err := c.handlePostHandshakeMessage(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := handshakeFn(); err != nil {
		c.earlyData.Reset()
		return err
	}

	return nil
}
