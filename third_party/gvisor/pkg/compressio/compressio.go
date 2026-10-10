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

package compressio

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"runtime"

	"github.com/metacubex/gvisor/pkg/sync"
)

var bufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(nil)
	},
}

var chunkPool = sync.Pool{
	New: func() any {
		return new(chunk)
	},
}

type chunk struct {
	compressed *bytes.Buffer

	uncompressed *bytes.Buffer

	h hash.Hash

	lastSum []byte

	sum []byte
}

func newChunk(lastSum []byte, sum []byte, compressed *bytes.Buffer, uncompressed *bytes.Buffer) *chunk {
	c := chunkPool.Get().(*chunk)
	c.lastSum = lastSum
	c.sum = sum
	if compressed != nil {
		c.compressed = compressed
	} else {
		c.compressed = bufPool.Get().(*bytes.Buffer)
	}
	if uncompressed != nil {
		c.uncompressed = uncompressed
	} else {
		c.uncompressed = bufPool.Get().(*bytes.Buffer)
	}
	return c
}

type result struct {
	*chunk
	err error
}

type worker struct {
	hashPool *hashPool
	input    chan *chunk
	output   chan result

	scratch [4]byte
}

func (w *worker) work(compress bool, level int) {
	defer close(w.output)

	var h hash.Hash

	for c := range w.input {
		if h == nil && w.hashPool != nil {
			h = w.hashPool.getHash()
		}
		if compress {
			mw := io.Writer(c.compressed)
			if h != nil {
				mw = io.MultiWriter(mw, h)
			}

			fw, err := flate.NewWriter(mw, level)
			if err != nil {
				w.output <- result{c, err}
				continue
			}

			if _, err := io.CopyN(fw, c.uncompressed, int64(c.uncompressed.Len())); err != nil {
				w.output <- result{c, err}
				continue
			}
			if err := fw.Close(); err != nil {
				w.output <- result{c, err}
				continue
			}

			if h != nil {
				binary.BigEndian.PutUint32(w.scratch[:], uint32(c.compressed.Len()))
				h.Write(w.scratch[:4])
				c.h = h
				h = nil
			}
		} else {
			if h != nil {
				h.Write(c.compressed.Bytes())
				binary.BigEndian.PutUint32(w.scratch[:], uint32(c.compressed.Len()))
				h.Write(w.scratch[:4])
				io.CopyN(h, bytes.NewReader(c.lastSum), int64(len(c.lastSum)))

				sum := h.Sum(nil)
				h.Reset()
				if !hmac.Equal(c.sum, sum) {
					w.output <- result{c, ErrHashMismatch}
					continue
				}
			}

			fr := flate.NewReader(c.compressed)

			if _, err := io.Copy(c.uncompressed, fr); err != nil {
				w.output <- result{c, err}
				continue
			}
		}

		w.output <- result{c, nil}
	}
}

type hashPool struct {
	mu sync.Mutex

	key []byte

	hashes []hash.Hash
}

func (p *hashPool) getHash() hash.Hash {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.hashes) == 0 {
		return hmac.New(sha256.New, p.key)
	}

	h := p.hashes[len(p.hashes)-1]
	p.hashes = p.hashes[:len(p.hashes)-1]
	return h
}

func (p *hashPool) putHash(h hash.Hash) {
	h.Reset()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.hashes = append(p.hashes, h)
}

type pool struct {
	workers []worker

	chunkSize uint32

	mu sync.Mutex

	nextInput int

	nextOutput int

	buf *bytes.Buffer

	lastSum []byte

	hashPool *hashPool
}

func (p *pool) init(key []byte, workers int, compress bool, level int) {
	if len(key) > 0 {
		p.hashPool = &hashPool{key: key}
	}
	p.workers = make([]worker, workers)
	for i := 0; i < len(p.workers); i++ {
		p.workers[i] = worker{
			hashPool: p.hashPool,
			input:    make(chan *chunk, 1),
			output:   make(chan result, 1),
		}
		go p.workers[i].work(compress, level)
	}
	runtime.SetFinalizer(p, (*pool).stop)
}

func (p *pool) stop() {
	for i := 0; i < len(p.workers); i++ {
		close(p.workers[i].input)
	}
	if len(p.workers) != 0 {
		for p.nextOutput < p.nextInput {
			handleResult(<-p.workers[(p.nextOutput+1)%len(p.workers)].output, func(*chunk) error {
				return nil
			})
			p.nextOutput++
		}
	}
	p.workers = nil
	p.hashPool = nil
}

func handleResult(r result, callback func(*chunk) error) error {
	defer func() {
		r.chunk.compressed.Reset()
		bufPool.Put(r.chunk.compressed)
		chunkPool.Put(r.chunk)
	}()
	if r.err != nil {
		return r.err
	}
	return callback(r.chunk)
}

func (p *pool) schedule(c *chunk, callback func(*chunk) error) error {
	for {
		var (
			inputChan  chan *chunk
			outputChan chan result
		)
		if c != nil && len(p.workers) != 0 {
			inputChan = p.workers[(p.nextInput+1)%len(p.workers)].input
		}
		if callback != nil && p.nextOutput != p.nextInput && len(p.workers) != 0 {
			outputChan = p.workers[(p.nextOutput+1)%len(p.workers)].output
		}
		if inputChan == nil && outputChan == nil {
			return nil
		}

		select {
		case inputChan <- c:
			p.nextInput++
			return nil
		case r := <-outputChan:
			p.nextOutput++
			if err := handleResult(r, callback); err != nil {
				return err
			}
		}
	}
}

type Reader struct {
	pool

	in io.ReadCloser

	scratch [4]byte
}

var _ io.Reader = (*Reader)(nil)

func NewReader(in io.ReadCloser, key []byte) (*Reader, error) {
	r := &Reader{
		in: in,
	}

	r.init(key, 2*runtime.GOMAXPROCS(0), false, 0)

	if _, err := io.ReadFull(in, r.scratch[:4]); err != nil {
		return nil, err
	}
	r.chunkSize = binary.BigEndian.Uint32(r.scratch[:4])

	if r.hashPool != nil {
		h := r.hashPool.getHash()
		binary.BigEndian.PutUint32(r.scratch[:], r.chunkSize)
		h.Write(r.scratch[:4])
		r.lastSum = h.Sum(nil)
		r.hashPool.putHash(h)
		sum := make([]byte, len(r.lastSum))
		if _, err := io.ReadFull(r.in, sum); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if !hmac.Equal(r.lastSum, sum) {
			return nil, ErrHashMismatch
		}
	}

	return r, nil
}

var errNewBuffer = errors.New("buffer ready")

var ErrHashMismatch = errors.New("hash mismatch")

func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	done := 0

	var (
		pendingPre    = r.nextInput - r.nextOutput
		pendingInline = 0
	)

	callback := func(c *chunk) error {
		if pendingPre == 0 && pendingInline > 0 {
			pendingInline--
			done += c.uncompressed.Len()
			return nil
		}

		if pendingPre > 0 {
			pendingPre--
		}
		r.buf = c.uncompressed
		return errNewBuffer
	}

	for done < len(p) {
		if r.buf != nil {
			n, err := r.buf.Read(p[done:])
			done += n
			if err == io.EOF {
				r.buf.Reset()
				bufPool.Put(r.buf)
				r.buf = nil
			} else if err != nil {
				defer r.stop()
				return done, err
			}
			continue
		}

		if _, err := io.ReadFull(r.in, r.scratch[:4]); err != nil {
			if err := r.schedule(nil, callback); err == nil {
				defer r.stop()
				return done, io.EOF
			} else if err == errNewBuffer {
				continue
			} else {
				defer r.stop()
				return done, err
			}
		}
		l := binary.BigEndian.Uint32(r.scratch[:4])

		compressed := bufPool.Get().(*bytes.Buffer)
		if _, err := io.CopyN(compressed, r.in, int64(l)); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return done, err
		}

		var sum []byte
		if r.hashPool != nil {
			sum = make([]byte, len(r.lastSum))
			if _, err := io.ReadFull(r.in, sum); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return done, err
			}
		}

		var c *chunk
		start := done + ((pendingPre + pendingInline) * int(r.chunkSize))
		if len(p) >= start+int(r.chunkSize) && len(p) >= start+bytes.MinRead {
			c = newChunk(r.lastSum, sum, compressed, bytes.NewBuffer(p[start:start]))
			pendingInline++
		} else {
			c = newChunk(r.lastSum, sum, compressed, nil)
		}
		r.lastSum = sum
		if err := r.schedule(c, callback); err == errNewBuffer {
			r.schedule(c, nil)
		} else if err != nil {
			defer r.stop()
			return done, err
		}
	}

	for pendingInline > 0 {
		if err := r.schedule(nil, func(c *chunk) error {
			if err := callback(c); err != nil {
				return err
			}
			return errNewBuffer
		}); err != errNewBuffer {
			return done, err
		}
	}

	return done, nil
}

func (r *Reader) Close() error {
	return r.in.Close()
}

type Writer struct {
	pool

	out io.Writer

	closed bool

	scratch [4]byte
}

var _ io.Writer = (*Writer)(nil)

func NewWriter(out io.Writer, key []byte, chunkSize uint32, level int) (*Writer, error) {
	w := &Writer{
		pool: pool{
			chunkSize: chunkSize,
			buf:       bufPool.Get().(*bytes.Buffer),
		},
		out: out,
	}
	w.init(key, 1+runtime.GOMAXPROCS(0), true, level)

	binary.BigEndian.PutUint32(w.scratch[:], chunkSize)
	if _, err := w.out.Write(w.scratch[:4]); err != nil {
		return nil, err
	}

	if w.hashPool != nil {
		h := w.hashPool.getHash()
		binary.BigEndian.PutUint32(w.scratch[:], chunkSize)
		h.Write(w.scratch[:4])
		w.lastSum = h.Sum(nil)
		w.hashPool.putHash(h)
		if _, err := io.CopyN(w.out, bytes.NewReader(w.lastSum), int64(len(w.lastSum))); err != nil {
			return nil, err
		}
	}

	return w, nil
}

func (w *Writer) flush(c *chunk) error {
	l := uint32(c.compressed.Len())

	binary.BigEndian.PutUint32(w.scratch[:], l)
	if _, err := w.out.Write(w.scratch[:4]); err != nil {
		return err
	}

	if _, err := io.CopyN(w.out, c.compressed, int64(c.compressed.Len())); err != nil {
		return err
	}

	if w.hashPool != nil {
		io.CopyN(c.h, bytes.NewReader(w.lastSum), int64(len(w.lastSum)))
		sum := c.h.Sum(nil)
		w.hashPool.putHash(c.h)
		c.h = nil
		if _, err := io.CopyN(w.out, bytes.NewReader(sum), int64(len(sum))); err != nil {
			return err
		}
		w.lastSum = sum
	}

	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}

	var (
		pendingPre    = w.nextInput - w.nextOutput
		pendingInline = 0
	)
	callback := func(c *chunk) error {
		if pendingPre > 0 {
			pendingPre--
			err := w.flush(c)
			c.uncompressed.Reset()
			bufPool.Put(c.uncompressed)
			return err
		}
		if pendingInline > 0 {
			pendingInline--
			return w.flush(c)
		}
		panic("both pendingPre and pendingInline exhausted")
	}

	for done := 0; done < len(p); {
		inline := false
		if w.buf.Len() == 0 && len(p) >= done+int(w.chunkSize) && len(p) >= done+bytes.MinRead {
			bufPool.Put(w.buf)
			w.buf = bytes.NewBuffer(p[done : done+int(w.chunkSize)])
			done += int(w.chunkSize)
			pendingInline++
			inline = true
		}

		left := int(w.chunkSize) - w.buf.Len()
		if left == 0 {
			if err := w.schedule(newChunk(nil, nil, nil, w.buf), callback); err != nil {
				return done, err
			}
			if !inline {
				pendingPre++
			}
			w.buf = bufPool.Get().(*bytes.Buffer)
			continue
		}

		toWrite := len(p) - done
		if toWrite > left {
			toWrite = left
		}
		n, err := w.buf.Write(p[done : done+toWrite])
		done += n
		if err != nil {
			return done, err
		}
	}

	for pendingInline > 0 {
		if err := w.schedule(nil, func(c *chunk) error {
			if err := callback(c); err != nil {
				return err
			}
			return errNewBuffer
		}); err != errNewBuffer {
			return len(p), err
		}
	}

	return len(p), nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return io.ErrUnexpectedEOF
	}
	w.closed = true
	defer w.stop()

	if w.buf.Len() > 0 {
		if err := w.schedule(newChunk(nil, nil, nil, w.buf), w.flush); err != nil {
			return err
		}
	}

	if err := w.schedule(nil, w.flush); err != nil {
		return err
	}

	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
