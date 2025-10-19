// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"errors"
	"fmt"
	"hash"
	"io"

	sm2ecdh "github.com/emmansun/gmsm/ecdh"
	"gitlab.com/go-extension/ffdh"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientEarlyTrafficLabel       = "c e traffic"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	earlyExporterLabel            = "e exp master"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		// Rather than calling BytesOrPanic, we explicitly handle this error, in
		// order to provide a reasonable error message. It should be basically
		// impossible for this to panic, and routing errors back through the
		// tree rooted in this function is quite painful. The labels are fixed
		// size, and the context is either a fixed-length computed hash, or
		// parsed from a field which has the same length limitation. As such, an
		// error here is likely to only be caused during development.
		//
		// NOTE: another reasonable approach here might be to return a
		// randomized slice if we encounter an error, which would break the
		// connection, but avoid panicking. This would perhaps be safer but
		// significantly more confusing to users.
		panic(fmt.Errorf("failed to construct HKDF label: %s", err))
	}
	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash.New, secret, hkdfLabelBytes).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

// extract implements HKDF-Extract with the cipher suite hash.
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := c.deriveSecret(masterSecret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := c.deriveSecret(expMasterSecret, label, nil)
		h := c.hash.New()
		h.Write(context)
		return c.expandLabel(secret, "exporter", h.Sum(nil), length), nil
	}
}

type keyStorage struct {
	ecdhe map[CurveID]*ecdh.PrivateKey
	ffdhe map[CurveID]*ffdh.PrivateKey

	mlkem *mlkem.DecapsulationKey768

	ecdheSM2 map[CurveID]*sm2ecdh.PrivateKey
}

func (ks *keyStorage) generateECDHEKey(c *Config, curveID CurveID) (*ecdh.PrivateKey, error) {
	if c.IndependentlyHybridKeyShare {
		return generateECDHEKey(c.rand(), curveID)
	}

	if ks.ecdhe == nil {
		ks.ecdhe = make(map[CurveID]*ecdh.PrivateKey)
	} else {
		ecdhe, ok := ks.ecdhe[curveID]
		if ok {
			return ecdhe, nil
		}
	}

	ecdhe, err := generateECDHEKey(c.rand(), curveID)
	if err != nil {
		return nil, err
	}

	ks.ecdhe[curveID] = ecdhe
	return ecdhe, nil
}

func (ks *keyStorage) generateFFDHEKey(c *Config, curveID CurveID) (*ffdh.PrivateKey, error) {
	if c.IndependentlyHybridKeyShare {
		return generateFFDHEKey(c.rand(), curveID)
	}

	if ks.ffdhe == nil {
		ks.ffdhe = make(map[CurveID]*ffdh.PrivateKey)
	} else {
		ffdhe, ok := ks.ffdhe[curveID]
		if ok {
			return ffdhe, nil
		}
	}

	ffdhe, err := generateFFDHEKey(c.rand(), curveID)
	if err != nil {
		return nil, err
	}

	ks.ffdhe[curveID] = ffdhe
	return ffdhe, nil
}

func (ks *keyStorage) generateMLKEM768(c *Config) (*mlkem.DecapsulationKey768, error) {
	if c.IndependentlyHybridKeyShare {
		return generateMLKEM768Key(c.rand())
	}

	if ks.mlkem != nil {
		return ks.mlkem, nil
	}

	mlkem, err := generateMLKEM768Key(c.rand())
	if err != nil {
		return nil, err
	}

	ks.mlkem = mlkem
	return mlkem, nil
}

func (ks *keyStorage) generateECDHEKeySM2(c *Config, curveID CurveID) (*sm2ecdh.PrivateKey, error) {
	if c.IndependentlyHybridKeyShare {
		return generateECDHEKeySM2(c.rand(), curveID)
	}

	if ks.ecdheSM2 == nil {
		ks.ecdheSM2 = make(map[CurveID]*sm2ecdh.PrivateKey)
	} else {
		ecdhe, ok := ks.ecdheSM2[curveID]
		if ok {
			return ecdhe, nil
		}
	}

	ecdhe, err := generateECDHEKeySM2(c.rand(), curveID)
	if err != nil {
		return nil, err
	}

	ks.ecdheSM2[curveID] = ecdhe
	return ecdhe, nil
}

type keySharePrivateKeys struct {
	curveID CurveID
	ecdhe   *ecdh.PrivateKey
	ffdhe   *ffdh.PrivateKey
	mlkem   *mlkem.DecapsulationKey768

	ecdheSM2 *sm2ecdh.PrivateKey
}

func kyberSharedSecret(mlkemSharedSecret, ciphertext []byte) []byte {
	// Package mlkem768 implements ML-KEM, which compared to Kyber removed a
	// final hashing step. Compute SHAKE-256(K || SHA3-256(c), 32) to match Kyber.
	// See https://words.filippo.io/mlkem768/#bonus-track-using-a-ml-kem-implementation-as-kyber-v3.
	h := sha3.NewShake256()
	h.Write(mlkemSharedSecret)
	ch := sha3.Sum256(ciphertext)
	h.Write(ch[:])
	out := make([]byte, 32)
	h.Read(out)
	return out
}

const x25519PublicKeySize = 32

// generateECDHEKey returns a PrivateKey that implements Diffie-Hellman
// according to RFC 8446, Section 4.2.8.2.
func generateECDHEKey(rand io.Reader, curveID CurveID) (*ecdh.PrivateKey, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	return curve.GenerateKey(rand)
}

func curveForCurveID(id CurveID) (ecdh.Curve, bool) {
	switch id {
	case X25519:
		return ecdh.X25519(), true
	case CurveP256:
		return ecdh.P256(), true
	case CurveP384:
		return ecdh.P384(), true
	case CurveP521:
		return ecdh.P521(), true
	default:
		return nil, false
	}
}

// generateFFDHEKey returns a PrivateKey that implements Diffie-Hellman
// according to RFC 7919.
func generateFFDHEKey(rand io.Reader, curveID CurveID) (*ffdh.PrivateKey, error) {
	group, ok := groupForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported ffdh group")
	}

	return group.GenerateKey(rand)
}

func groupForCurveID(id CurveID) (ffdh.Group, bool) {
	switch id {
	case FFDHE2048:
		return ffdh.FFDHE2048(), true
	case FFDHE3072:
		return ffdh.FFDHE3072(), true
	case FFDHE4096:
		return ffdh.FFDHE4096(), true
	case FFDHE6144:
		return ffdh.FFDHE6144(), true
	case FFDHE8192:
		return ffdh.FFDHE8192(), true
	default:
		return nil, false
	}
}

func generateMLKEM768Key(rand io.Reader) (*mlkem.DecapsulationKey768, error) {
	seed := make([]byte, mlkem.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey768(seed)
}

// generateECDHEKeySM2 returns a PrivateKey that implements Diffie-Hellman
// according to RFC 8998.
func generateECDHEKeySM2(rand io.Reader, curveID CurveID) (*sm2ecdh.PrivateKey, error) {
	curve, ok := sm2CurveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	return curve.GenerateKey(rand)
}

func sm2CurveForCurveID(id CurveID) (sm2ecdh.Curve, bool) {
	switch id {
	case CurveSM2:
		return sm2ecdh.P256(), true
	default:
		return nil, false
	}
}
