// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func (m *certificateMsgTLS13) compress(algorithm CertificateCompressionAlgorithm) (*compressedCertificateMsg, error) {
	compressed := bytes.NewBuffer(nil)

	var compresser io.WriteCloser
	switch algorithm {
	case Brotli:
		compresser = brotli.NewWriter(compressed)
	case Zlib:
		compresser, _ = zlib.NewWriterLevel(compressed, zlib.DefaultCompression)
	case Zstd:
		compresser, _ = zstd.NewWriter(compressed)
	default:
		return nil, errors.New("tls: CertificateCompressionPreferences includes unsupported compression algorithm")
	}

	certMsg, err := m.marshal()
	if err != nil {
		return nil, err
	}
	certMsg = certMsg[4:]

	compresser.Write(certMsg)
	compresser.Close()

	return &compressedCertificateMsg{
		algorithm:                    algorithm,
		uncompressedLength:           uint32(len(certMsg)),
		compressedCertificateMessage: compressed.Bytes(),
	}, nil
}

func (m *compressedCertificateMsg) decompress() (*certificateMsgTLS13, error) {
	if m.uncompressedLength+4 > maxHandshakeCertificateMsg {
		return nil, fmt.Errorf("tls: uncompressed certificate message of length %d bytes exceeds maximum of %d bytes", m.uncompressedLength, maxHandshakeCertificateMsg)
	}

	compressed := bytes.NewReader(m.compressedCertificateMessage)

	var decompressed io.Reader
	switch m.algorithm {
	case Brotli:
		decompressed = brotli.NewReader(compressed)

	case Zlib:
		rc, err := zlib.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to open zlib reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	case Zstd:
		rc, err := zstd.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to open zstd reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	default:
		return nil, fmt.Errorf("tls: unsupported certificate compression algorithm (%d)", m.algorithm)
	}

	rawMsg := make([]byte, m.uncompressedLength+4) // +4 for message type and uint24 length field
	rawMsg[0] = typeCertificate
	rawMsg[1] = uint8(m.uncompressedLength >> 16)
	rawMsg[2] = uint8(m.uncompressedLength >> 8)
	rawMsg[3] = uint8(m.uncompressedLength)

	_, err := io.ReadFull(decompressed, rawMsg[4:])
	if err != nil {
		return nil, fmt.Errorf("tls: failed to decompress certificate message: %w", err)
	}

	var tmp [1]byte
	n, err := decompressed.Read(tmp[:])
	if n > 0 || err != io.EOF {
		return nil, fmt.Errorf("tls: decompressed certificate message longer than %d bytes", m.uncompressedLength)
	}

	certMsg := new(certificateMsgTLS13)
	if !certMsg.unmarshal(rawMsg) {
		return nil, errors.New("tls: failed to decode decompressed certificate message")
	}
	return certMsg, nil
}
