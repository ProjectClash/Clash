// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package internal

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

const maxLineLength = 4096

var ErrLineTooLong = errors.New("header line too long")

func NewChunkedReader(r io.Reader) io.Reader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &chunkedReader{r: br}
}

type chunkedReader struct {
	r        *bufio.Reader
	n        uint64
	err      error
	buf      [2]byte
	checkEnd bool
	excess   int64
}

func (cr *chunkedReader) beginChunk() {
	var line []byte
	line, cr.err = readChunkLine(cr.r)
	if cr.err != nil {
		return
	}
	cr.excess += int64(len(line)) + 2
	line = trimTrailingWhitespace(line)
	line, cr.err = removeChunkExtension(line)
	if cr.err != nil {
		return
	}
	cr.n, cr.err = parseHexUint(line)
	if cr.err != nil {
		return
	}
	cr.excess -= 16 + (2 * int64(cr.n))
	if cr.excess < 0 {
		cr.excess = 0
	}
	if cr.excess > 16*1024 {
		cr.err = errors.New("chunked encoding contains too much non-data")
	}
	if cr.n == 0 {
		cr.err = io.EOF
	}
}

func (cr *chunkedReader) chunkHeaderAvailable() bool {
	n := cr.r.Buffered()
	if n > 0 {
		peek, _ := cr.r.Peek(n)
		return bytes.IndexByte(peek, '\n') >= 0
	}
	return false
}

func (cr *chunkedReader) Read(b []uint8) (n int, err error) {
	for cr.err == nil {
		if cr.checkEnd {
			if n > 0 && cr.r.Buffered() < 2 {
				break
			}
			if _, cr.err = io.ReadFull(cr.r, cr.buf[:2]); cr.err == nil {
				if string(cr.buf[:]) != "\r\n" {
					cr.err = errors.New("malformed chunked encoding")
					break
				}
			} else {
				if cr.err == io.EOF {
					cr.err = io.ErrUnexpectedEOF
				}
				break
			}
			cr.checkEnd = false
		}
		if cr.n == 0 {
			if n > 0 && !cr.chunkHeaderAvailable() {
				break
			}
			cr.beginChunk()
			continue
		}
		if len(b) == 0 {
			break
		}
		rbuf := b
		if uint64(len(rbuf)) > cr.n {
			rbuf = rbuf[:cr.n]
		}
		var n0 int
		n0, cr.err = cr.r.Read(rbuf)
		n += n0
		b = b[n0:]
		cr.n -= uint64(n0)
		if cr.n == 0 && cr.err == nil {
			cr.checkEnd = true
		} else if cr.err == io.EOF {
			cr.err = io.ErrUnexpectedEOF
		}
	}
	return n, cr.err
}

func readChunkLine(b *bufio.Reader) ([]byte, error) {
	p, err := b.ReadSlice('\n')
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		} else if err == bufio.ErrBufferFull {
			err = ErrLineTooLong
		}
		return nil, err
	}

	if idx := bytes.IndexByte(p, '\r'); idx == -1 {
		return nil, errors.New("chunked line ends with bare LF")
	} else if idx != len(p)-2 {
		return nil, errors.New("invalid CR in chunked line")
	}
	p = p[:len(p)-2]

	if len(p) >= maxLineLength {
		return nil, ErrLineTooLong
	}
	return p, nil
}

func trimTrailingWhitespace(b []byte) []byte {
	for len(b) > 0 && isOWS(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isOWS(b byte) bool {
	return b == ' ' || b == '\t'
}

var semi = []byte(";")

func removeChunkExtension(p []byte) ([]byte, error) {
	p, _, _ = bytes.Cut(p, semi)
	return p, nil
}

func NewChunkedWriter(w io.Writer) io.WriteCloser {
	return &chunkedWriter{w}
}

type chunkedWriter struct {
	Wire io.Writer
}

func (cw *chunkedWriter) Write(data []byte) (n int, err error) {

	if len(data) == 0 {
		return 0, nil
	}

	if _, err = fmt.Fprintf(cw.Wire, "%x\r\n", len(data)); err != nil {
		return 0, err
	}
	if n, err = cw.Wire.Write(data); err != nil {
		return
	}
	if n != len(data) {
		err = io.ErrShortWrite
		return
	}
	if _, err = io.WriteString(cw.Wire, "\r\n"); err != nil {
		return
	}
	if bw, ok := cw.Wire.(*FlushAfterChunkWriter); ok {
		err = bw.Flush()
	}
	return
}

func (cw *chunkedWriter) Close() error {
	_, err := io.WriteString(cw.Wire, "0\r\n")
	return err
}

type FlushAfterChunkWriter struct {
	*bufio.Writer
}

func parseHexUint(v []byte) (n uint64, err error) {
	if len(v) == 0 {
		return 0, errors.New("empty hex number for chunk length")
	}
	for i, b := range v {
		switch {
		case '0' <= b && b <= '9':
			b = b - '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, errors.New("invalid byte in chunk length")
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}
