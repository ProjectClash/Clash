// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package statefile

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/metacubex/gvisor/pkg/compressio"
)

const keySize = 32

const stateFileChunkSize = 1024 * 1024

const maxMetadataSize = 16 * 1024 * 1024

var magicHeader = []byte("\x67\x56\x69\x73\x6f\x72\x53\x46")

var ErrBadMagic = fmt.Errorf("bad magic header")

var ErrMetadataMissing = fmt.Errorf("missing metadata")

var ErrInvalidMetadataLength = fmt.Errorf("metadata length invalid, maximum size is %d", maxMetadataSize)

var ErrMetadataInvalid = fmt.Errorf("metadata invalid, can't start with _")

var ErrInvalidFlags = fmt.Errorf("flags set is invalid")

const (
	compressionKey = "compression"
)

type CompressionLevel string

const (
	CompressionLevelFlateBestSpeed = CompressionLevel("flate-best-speed")
	CompressionLevelNone = CompressionLevel("none")
	CompressionLevelDefault = CompressionLevelNone
)

func (c CompressionLevel) String() string {
	return string(c)
}

func (c CompressionLevel) ToMetadata() map[string]string {
	return map[string]string{compressionKey: string(c)}
}

func CompressionLevelFromString(val string) (CompressionLevel, error) {
	switch val {
	case string(CompressionLevelFlateBestSpeed):
		return CompressionLevelFlateBestSpeed, nil
	case string(CompressionLevelNone):
		return CompressionLevelNone, nil
	case "":
		return CompressionLevelDefault, nil
	default:
		return CompressionLevelNone, ErrInvalidFlags
	}
}

func CompressionLevelFromMetadata(metadata map[string]string) (CompressionLevel, error) {
	if val, ok := metadata[compressionKey]; ok {
		return CompressionLevelFromString(val)
	}
	compression := CompressionLevelDefault
	metadata[compressionKey] = string(compression)
	return compression, nil
}

func writeMetadataLen(w io.Writer, val uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	_, err := w.Write(buf[:])
	return err
}

func NewWriter(w io.Writer, key []byte, metadata map[string]string) (io.WriteCloser, error) {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	for k := range metadata {
		if strings.HasPrefix(k, "_") {
			return nil, ErrMetadataInvalid
		}
	}

	mw := w
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
		mw = io.MultiWriter(w, h)
	}

	if _, err := mw.Write(magicHeader); err != nil {
		return nil, err
	}

	metadata["_timestamp"] = time.Now().UTC().String()
	defer delete(metadata, "_timestamp")

	compression, err := CompressionLevelFromMetadata(metadata)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	if len(b) > maxMetadataSize {
		return nil, ErrInvalidMetadataLength
	}

	if err := writeMetadataLen(mw, uint64(len(b))); err != nil {
		return nil, err
	}
	if _, err := mw.Write(b); err != nil {
		return nil, err
	}
	if h != nil {
		cur := h.Sum(nil)
		for done := 0; done < len(cur); {
			n, err := mw.Write(cur[done:])
			done += n
			if err != nil {
				return nil, err
			}
		}
	}

	if compression == CompressionLevelFlateBestSpeed {
		return compressio.NewWriter(w, key, stateFileChunkSize, flate.BestSpeed)
	}

	return compressio.NewSimpleWriter(w, key, stateFileChunkSize), nil
}

func MetadataUnsafe(r io.Reader) (map[string]string, error) {
	return metadata(r, nil)
}

func readMetadataLen(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func metadata(r io.Reader, key []byte) (map[string]string, error) {
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
		r = io.TeeReader(r, h)
	}

	b := make([]byte, len(magicHeader))
	if _, err := r.Read(b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b, magicHeader) {
		return nil, ErrBadMagic
	}

	b, err := func() (b []byte, err error) {
		defer func() {
			if r := recover(); r != nil {
				b = nil
				err = fmt.Errorf("%v", r)
			}
		}()

		metadataLen, err := readMetadataLen(r)
		if err != nil {
			return nil, err
		}
		if metadataLen > maxMetadataSize {
			return nil, ErrInvalidMetadataLength
		}
		b = make([]byte, int(metadataLen))
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return b, nil
	}()
	if err != nil {
		return nil, err
	}

	if h != nil {
		cur := h.Sum(nil)
		buf := make([]byte, len(cur))
		if _, err := io.ReadFull(r, buf); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if !hmac.Equal(cur, buf) {
			return nil, compressio.ErrHashMismatch
		}
	}

	metadata := make(map[string]string)
	if err := json.Unmarshal(b, &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

func NewReader(r io.ReadCloser, key []byte) (io.ReadCloser, map[string]string, error) {
	metadata, err := metadata(r, key)
	if err != nil {
		return nil, nil, err
	}

	compression, err := CompressionLevelFromMetadata(metadata)
	if err != nil {
		return nil, nil, err
	}

	var cr io.ReadCloser

	switch compression {
	case CompressionLevelFlateBestSpeed:
		cr, err = compressio.NewReader(r, key)
	case CompressionLevelNone:
		cr = compressio.NewSimpleReader(r, key)
	default:
		return nil, nil, fmt.Errorf("metadata contains invalid compression flag value: %v", compression)
	}

	if err != nil {
		return nil, nil, err
	}

	return cr, metadata, nil
}
