// Copyright 2023 The gVisor Authors.
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

package compressio

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
)


type SimpleReader struct {
	source io.ReadCloser

	bin *bufio.Reader

	h hash.Hash

	chunkSize uint32

	done uint32

	prevHash [sha256.Size]byte

	scratch [sha256.Size]byte
}

var _ io.Reader = (*SimpleReader)(nil)

const (
	defaultBufSize = 256 * 1024
)

func NewSimpleReader(in io.ReadCloser, key []byte) *SimpleReader {
	bin := bufio.NewReaderSize(in, defaultBufSize)
	r := &SimpleReader{
		source: in,
		bin:    bin,
	}
	if len(key) > 0 {
		r.h = hmac.New(sha256.New, key)
	}
	return r
}

func (r *SimpleReader) Read(p []byte) (int, error) {
	if r.h == nil || len(p) == 0 {
		return r.bin.Read(p)
	}

	if r.done >= r.chunkSize {
		if _, err := io.ReadFull(r.bin, r.scratch[:4]); err != nil {
			return 0, err
		}

		r.chunkSize = binary.BigEndian.Uint32(r.scratch[:4])
		r.done = 0
		r.h.Reset()

		if r.chunkSize == 0 {
			return 0, io.ErrNoProgress
		}
	}

	toRead := uint32(len(p))
	if toRead > r.chunkSize-r.done {
		toRead = r.chunkSize - r.done
	}

	n, err := r.bin.Read(p[:toRead])
	if err != nil {
		if err == io.EOF {
			return n, io.ErrUnexpectedEOF
		}
		return n, err
	}

	_, _ = r.h.Write(p[:n])
	r.done += uint32(n)
	if r.done >= r.chunkSize {
		binary.BigEndian.PutUint32(r.scratch[:4], r.chunkSize)
		r.h.Write(r.scratch[:4])

		r.h.Write(r.prevHash[:])

		r.h.Sum(r.prevHash[0:0:sha256.Size])

		if _, err := io.ReadFull(r.bin, r.scratch[:]); err != nil {
			if err == io.EOF {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}

		if !hmac.Equal(r.scratch[:sha256.Size], r.prevHash[:sha256.Size]) {
			return n, ErrHashMismatch
		}

		r.done = 0
		r.chunkSize = 0
	}

	return n, nil
}

func (r *SimpleReader) Close() error {
	return r.source.Close()
}

type SimpleWriter struct {
	base io.Writer

	bufOut *bufio.Writer

	h hash.Hash

	chunkSize int

	done int

	prevHash [sha256.Size]byte

	buf []byte

	closed bool
}

var _ io.Writer = (*SimpleWriter)(nil)
var _ io.Closer = (*SimpleWriter)(nil)

func NewSimpleWriter(out io.Writer, key []byte, chunkSize uint32) *SimpleWriter {
	if len(key) == 0 {
		return &SimpleWriter{
			base:   out,
			bufOut: bufio.NewWriterSize(out, defaultBufSize),
		}
	}

	return &SimpleWriter{
		base:      out,
		h:         hmac.New(sha256.New, key),
		chunkSize: int(chunkSize),
		buf: make([]byte, 4+chunkSize+sha256.Size),
	}
}

func (w *SimpleWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}

	if w.bufOut != nil {
		return w.bufOut.Write(p)
	}

	total := 0
	for len(p) > 0 {
		if len(p) > w.chunkSize && w.done == 0 {
			n, err := w.directWrite(p)
			return total + n, err
		}

		n := copy(w.buf[4+w.done:4+w.chunkSize], p)

		w.done += n
		p = p[n:]
		total += n

		if w.done >= w.chunkSize {
			if err := w.flush(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (w *SimpleWriter) directWrite(p []byte) (int, error) {
	binary.BigEndian.PutUint32(w.buf[:4], uint32(len(p)))
	if _, err := w.base.Write(w.buf[:4]); err != nil {
		return 0, err
	}

	n, err := w.base.Write(p)
	if err != nil {
		return n, err
	}

	w.h.Reset()
	_, _ = w.h.Write(p)
	_, _ = w.h.Write(w.buf[:4])
	_, _ = w.h.Write(w.prevHash[:])
	w.h.Sum(w.prevHash[0:0:sha256.Size])
	_, err = w.base.Write(w.prevHash[:sha256.Size])
	return n, err
}

func (w *SimpleWriter) flush() error {
	if w.done <= 0 {
		return nil
	}

	binary.BigEndian.PutUint32(w.buf[:4], uint32(w.done))

	w.h.Reset()
	_, _ = w.h.Write(w.buf[4 : 4+w.done])
	_, _ = w.h.Write(w.buf[:4])
	_, _ = w.h.Write(w.prevHash[:])

	w.h.Sum(w.prevHash[0:0:sha256.Size])
	copy(w.buf[4+w.done:4+w.done+sha256.Size], w.prevHash[:sha256.Size])

	_, err := w.base.Write(w.buf[:4+w.done+sha256.Size])

	w.done = 0
	return err
}

func (w *SimpleWriter) Close() error {
	if w.closed {
		return io.ErrUnexpectedEOF
	}
	w.closed = true

	if w.bufOut != nil {
		if err := w.bufOut.Flush(); err != nil {
			return err
		}
	} else {
		if err := w.flush(); err != nil {
			return err
		}
	}

	if closer, ok := w.base.(io.Closer); ok {
		return closer.Close()
	}

	w.bufOut = nil
	w.base = nil
	w.buf = nil

	return nil
}
