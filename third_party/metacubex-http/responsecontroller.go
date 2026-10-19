// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

type ResponseController struct {
	rw ResponseWriter
}

func NewResponseController(rw ResponseWriter) *ResponseController {
	return &ResponseController{rw}
}

type rwUnwrapper interface {
	Unwrap() ResponseWriter
}

func (c *ResponseController) Flush() error {
	rw := c.rw
	for {
		switch t := rw.(type) {
		case interface{ FlushError() error }:
			return t.FlushError()
		case Flusher:
			t.Flush()
			return nil
		case rwUnwrapper:
			rw = t.Unwrap()
		default:
			return errNotSupported()
		}
	}
}

func (c *ResponseController) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := c.rw
	for {
		switch t := rw.(type) {
		case Hijacker:
			return t.Hijack()
		case rwUnwrapper:
			rw = t.Unwrap()
		default:
			return nil, nil, errNotSupported()
		}
	}
}

func (c *ResponseController) SetReadDeadline(deadline time.Time) error {
	rw := c.rw
	for {
		switch t := rw.(type) {
		case interface{ SetReadDeadline(time.Time) error }:
			return t.SetReadDeadline(deadline)
		case rwUnwrapper:
			rw = t.Unwrap()
		default:
			return errNotSupported()
		}
	}
}

func (c *ResponseController) SetWriteDeadline(deadline time.Time) error {
	rw := c.rw
	for {
		switch t := rw.(type) {
		case interface{ SetWriteDeadline(time.Time) error }:
			return t.SetWriteDeadline(deadline)
		case rwUnwrapper:
			rw = t.Unwrap()
		default:
			return errNotSupported()
		}
	}
}

func (c *ResponseController) EnableFullDuplex() error {
	rw := c.rw
	for {
		switch t := rw.(type) {
		case interface{ EnableFullDuplex() error }:
			return t.EnableFullDuplex()
		case rwUnwrapper:
			rw = t.Unwrap()
		default:
			return errNotSupported()
		}
	}
}

func errNotSupported() error {
	return fmt.Errorf("%w", ErrNotSupported)
}
