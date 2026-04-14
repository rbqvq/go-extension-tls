// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdh"
	"io"

	sm2ecdh "github.com/emmansun/gmsm/ecdh"
	"gitlab.com/go-extension/ffdh"
)

var defaultKeyGenerator keyGenerator = &keyGeneratorIndependent{}

type keyGenerator interface {
	GenerateKeyECDH(rand io.Reader, curveID CurveID, curve ecdh.Curve) (*ecdh.PrivateKey, error)
	GenerateKeyFFDH(rand io.Reader, curveID CurveID, group ffdh.Group) (*ffdh.PrivateKey, error)
	GenerateKeyKEM(rand io.Reader, curveID CurveID, f kemPrivateKeyGenerator) (crypto.Decapsulator, error)
	GenerateKeySM2(rand io.Reader, curveID CurveID, curve sm2ecdh.Curve) (*sm2ecdh.PrivateKey, error)
}

type keyGeneratorIndependent struct{}

func (keyGeneratorIndependent) GenerateKeyECDH(rand io.Reader, _ CurveID, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand)
}

func (keyGeneratorIndependent) GenerateKeyFFDH(rand io.Reader, _ CurveID, group ffdh.Group) (*ffdh.PrivateKey, error) {
	return group.GenerateKey(rand)
}

func (keyGeneratorIndependent) GenerateKeyKEM(rand io.Reader, _ CurveID, f kemPrivateKeyGenerator) (crypto.Decapsulator, error) {
	return f(rand)
}

func (keyGeneratorIndependent) GenerateKeySM2(rand io.Reader, _ CurveID, curve sm2ecdh.Curve) (*sm2ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand)
}

type keyGeneratorShared struct {
	ecdh map[CurveID]*ecdh.PrivateKey
	ffdh map[CurveID]*ffdh.PrivateKey
	kem  map[CurveID]crypto.Decapsulator
	sm2  map[CurveID]*sm2ecdh.PrivateKey
}

func newKeyGeneratorShared() keyGenerator {
	return &keyGeneratorShared{
		ecdh: make(map[CurveID]*ecdh.PrivateKey),
		ffdh: make(map[CurveID]*ffdh.PrivateKey),
		kem:  make(map[CurveID]crypto.Decapsulator),
		sm2:  make(map[CurveID]*sm2ecdh.PrivateKey),
	}
}

func (g *keyGeneratorShared) GenerateKeyECDH(rand io.Reader, curveID CurveID, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	priv, ok := g.ecdh[curveID]
	if ok {
		return priv, nil
	}

	priv, err := curve.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	g.ecdh[curveID] = priv
	return priv, nil
}

func (g *keyGeneratorShared) GenerateKeyFFDH(rand io.Reader, curveID CurveID, group ffdh.Group) (*ffdh.PrivateKey, error) {
	priv, ok := g.ffdh[curveID]
	if ok {
		return priv, nil
	}

	priv, err := group.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	g.ffdh[curveID] = priv
	return priv, nil
}

func (g *keyGeneratorShared) GenerateKeyKEM(rand io.Reader, curveID CurveID, f kemPrivateKeyGenerator) (crypto.Decapsulator, error) {
	priv, ok := g.kem[curveID]
	if ok {
		return priv, nil
	}

	priv, err := f(rand)
	if err != nil {
		return nil, err
	}

	g.kem[curveID] = priv
	return priv, nil
}

func (g *keyGeneratorShared) GenerateKeySM2(rand io.Reader, curveID CurveID, curve sm2ecdh.Curve) (*sm2ecdh.PrivateKey, error) {
	priv, ok := g.sm2[curveID]
	if ok {
		return priv, nil
	}

	priv, err := curve.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	g.sm2[curveID] = priv
	return priv, nil
}
