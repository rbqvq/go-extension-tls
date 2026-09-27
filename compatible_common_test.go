// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"testing"
)

func TestFullCompatible(t *testing.T) {
	e := errors.New("crypto/tls: TestFullCompatible")

	cs := &ConnectionState{
		ekm: func(label string, context []byte, length int) ([]byte, error) {
			return nil, e
		},
	}

	converted := cs.FullCompatible()
	_, err := converted.ExportKeyingMaterial("", nil, 0)
	if err != e {
		t.Errorf("bad compatible convert, want: %T, got: %T", e, err)
	}
}
