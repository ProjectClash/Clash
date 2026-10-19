// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import (
	"bufio"
	"errors"
	"github.com/metacubex/http"
	"io"
	"net"
	"net/textproto"
	"sync"
)

var (
	ErrPersistEOF = &http.ProtocolError{ErrorString: "persistent connection closed"}

	ErrClosed = &http.ProtocolError{ErrorString: "connection closed by user"}

	ErrPipeline = &http.ProtocolError{ErrorString: "pipeline error"}
)

var errClosed = errors.New("i/o operation on closed connection")

type ServerConn struct {
	mu              sync.Mutex
	c               net.Conn
	r               *bufio.Reader
	re, we          error
	lastbody        io.ReadCloser
	nread, nwritten int
	pipereq         map[*http.Request]uint

	pipe textproto.Pipeline
}

func NewServerConn(c net.Conn, r *bufio.Reader) *ServerConn {
	if r == nil {
		r = bufio.NewReader(c)
	}
	return &ServerConn{c: c, r: r, pipereq: make(map[*http.Request]uint)}
}

func (sc *ServerConn) Hijack() (net.Conn, *bufio.Reader) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	c := sc.c
	r := sc.r
	sc.c = nil
	sc.r = nil
	return c, r
}

func (sc *ServerConn) Close() error {
	c, _ := sc.Hijack()
	if c != nil {
		return c.Close()
	}
	return nil
}

func (sc *ServerConn) Read() (*http.Request, error) {
	var req *http.Request
	var err error

	id := sc.pipe.Next()
	sc.pipe.StartRequest(id)
	defer func() {
		sc.pipe.EndRequest(id)
		if req == nil {
			sc.pipe.StartResponse(id)
			sc.pipe.EndResponse(id)
		} else {
			sc.mu.Lock()
			sc.pipereq[req] = id
			sc.mu.Unlock()
		}
	}()

	sc.mu.Lock()
	if sc.we != nil {
		defer sc.mu.Unlock()
		return nil, sc.we
	}
	if sc.re != nil {
		defer sc.mu.Unlock()
		return nil, sc.re
	}
	if sc.r == nil {
		defer sc.mu.Unlock()
		return nil, errClosed
	}
	r := sc.r
	lastbody := sc.lastbody
	sc.lastbody = nil
	sc.mu.Unlock()

	if lastbody != nil {
		err = lastbody.Close()
		if err != nil {
			sc.mu.Lock()
			defer sc.mu.Unlock()
			sc.re = err
			return nil, err
		}
	}

	req, err = http.ReadRequest(r)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			sc.re = ErrPersistEOF
			return nil, sc.re
		} else {
			sc.re = err
			return req, err
		}
	}
	sc.lastbody = req.Body
	sc.nread++
	if req.Close {
		sc.re = ErrPersistEOF
		return req, sc.re
	}
	return req, err
}

func (sc *ServerConn) Pending() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.nread - sc.nwritten
}

func (sc *ServerConn) Write(req *http.Request, resp *http.Response) error {

	sc.mu.Lock()
	id, ok := sc.pipereq[req]
	delete(sc.pipereq, req)
	if !ok {
		sc.mu.Unlock()
		return ErrPipeline
	}
	sc.mu.Unlock()

	sc.pipe.StartResponse(id)
	defer sc.pipe.EndResponse(id)

	sc.mu.Lock()
	if sc.we != nil {
		defer sc.mu.Unlock()
		return sc.we
	}
	if sc.c == nil {
		defer sc.mu.Unlock()
		return ErrClosed
	}
	c := sc.c
	if sc.nread <= sc.nwritten {
		defer sc.mu.Unlock()
		return errors.New("persist server pipe count")
	}
	if resp.Close {
		sc.re = ErrPersistEOF
	}
	sc.mu.Unlock()

	err := resp.Write(c)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err != nil {
		sc.we = err
		return err
	}
	sc.nwritten++

	return nil
}

type ClientConn struct {
	mu              sync.Mutex
	c               net.Conn
	r               *bufio.Reader
	re, we          error
	lastbody        io.ReadCloser
	nread, nwritten int
	pipereq         map[*http.Request]uint

	pipe     textproto.Pipeline
	writeReq func(*http.Request, io.Writer) error
}

func NewClientConn(c net.Conn, r *bufio.Reader) *ClientConn {
	if r == nil {
		r = bufio.NewReader(c)
	}
	return &ClientConn{
		c:        c,
		r:        r,
		pipereq:  make(map[*http.Request]uint),
		writeReq: (*http.Request).Write,
	}
}

func NewProxyClientConn(c net.Conn, r *bufio.Reader) *ClientConn {
	cc := NewClientConn(c, r)
	cc.writeReq = (*http.Request).WriteProxy
	return cc
}

func (cc *ClientConn) Hijack() (c net.Conn, r *bufio.Reader) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	c = cc.c
	r = cc.r
	cc.c = nil
	cc.r = nil
	return
}

func (cc *ClientConn) Close() error {
	c, _ := cc.Hijack()
	if c != nil {
		return c.Close()
	}
	return nil
}

func (cc *ClientConn) Write(req *http.Request) error {
	var err error

	id := cc.pipe.Next()
	cc.pipe.StartRequest(id)
	defer func() {
		cc.pipe.EndRequest(id)
		if err != nil {
			cc.pipe.StartResponse(id)
			cc.pipe.EndResponse(id)
		} else {
			cc.mu.Lock()
			cc.pipereq[req] = id
			cc.mu.Unlock()
		}
	}()

	cc.mu.Lock()
	if cc.re != nil {
		defer cc.mu.Unlock()
		return cc.re
	}
	if cc.we != nil {
		defer cc.mu.Unlock()
		return cc.we
	}
	if cc.c == nil {
		defer cc.mu.Unlock()
		return errClosed
	}
	c := cc.c
	if req.Close {
		cc.we = ErrPersistEOF
	}
	cc.mu.Unlock()

	err = cc.writeReq(req, c)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if err != nil {
		cc.we = err
		return err
	}
	cc.nwritten++

	return nil
}

func (cc *ClientConn) Pending() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.nwritten - cc.nread
}

func (cc *ClientConn) Read(req *http.Request) (resp *http.Response, err error) {
	cc.mu.Lock()
	id, ok := cc.pipereq[req]
	delete(cc.pipereq, req)
	if !ok {
		cc.mu.Unlock()
		return nil, ErrPipeline
	}
	cc.mu.Unlock()

	cc.pipe.StartResponse(id)
	defer cc.pipe.EndResponse(id)

	cc.mu.Lock()
	if cc.re != nil {
		defer cc.mu.Unlock()
		return nil, cc.re
	}
	if cc.r == nil {
		defer cc.mu.Unlock()
		return nil, errClosed
	}
	r := cc.r
	lastbody := cc.lastbody
	cc.lastbody = nil
	cc.mu.Unlock()

	if lastbody != nil {
		err = lastbody.Close()
		if err != nil {
			cc.mu.Lock()
			defer cc.mu.Unlock()
			cc.re = err
			return nil, err
		}
	}

	resp, err = http.ReadResponse(r, req)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if err != nil {
		cc.re = err
		return resp, err
	}
	cc.lastbody = resp.Body

	cc.nread++

	if resp.Close {
		cc.re = ErrPersistEOF
		return resp, cc.re
	}
	return resp, err
}

func (cc *ClientConn) Do(req *http.Request) (*http.Response, error) {
	err := cc.Write(req)
	if err != nil {
		return nil, err
	}
	return cc.Read(req)
}
