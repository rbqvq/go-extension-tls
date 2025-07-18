package tls

import (
	"errors"
	"testing"
)

func TestCompatible(t *testing.T) {
	e := errors.New("crypto/tls: TestCompatible")

	cs := &ConnectionState{
		ekm: func(label string, context []byte, length int) ([]byte, error) {
			return nil, e
		},
	}

	converted := cs.Compatible()
	_, err := converted.ExportKeyingMaterial("", nil, 0)
	if err != e {
		t.Errorf("bad compatible convert, want: %T, got: %T", e, err)
	}
}
