// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"errors"
	"io"
	"sync"
)

type pipe struct {
	mu       sync.Mutex
	c        sync.Cond
	b        pipeBuffer
	unread   int
	err      error
	breakErr error
	donec    chan struct{}
	readFn   func()
}

type pipeBuffer interface {
	Len() int
	io.Writer
	io.Reader
}

func (p *pipe) setBuffer(b pipeBuffer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.breakErr != nil {
		return
	}
	p.b = b
}

func (p *pipe) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.b == nil {
		return p.unread
	}
	return p.b.Len()
}

func (p *pipe) Read(d []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	for {
		if p.breakErr != nil {
			return 0, p.breakErr
		}
		if p.b != nil && p.b.Len() > 0 {
			return p.b.Read(d)
		}
		if p.err != nil {
			if p.readFn != nil {
				p.readFn()
				p.readFn = nil
			}
			p.b = nil
			return 0, p.err
		}
		p.c.Wait()
	}
}

var (
	errClosedPipeWrite        = errors.New("write on closed buffer")
	errUninitializedPipeWrite = errors.New("write on uninitialized buffer")
)

func (p *pipe) Write(d []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	defer p.c.Signal()
	if p.err != nil || p.breakErr != nil {
		return 0, errClosedPipeWrite
	}
	if p.b == nil {
		return 0, errUninitializedPipeWrite
	}
	return p.b.Write(d)
}

func (p *pipe) CloseWithError(err error) { p.closeWithError(&p.err, err, nil) }

func (p *pipe) BreakWithError(err error) { p.closeWithError(&p.breakErr, err, nil) }

func (p *pipe) closeWithErrorAndCode(err error, fn func()) { p.closeWithError(&p.err, err, fn) }

func (p *pipe) closeWithError(dst *error, err error, fn func()) {
	if err == nil {
		panic("err must be non-nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	defer p.c.Signal()
	if *dst != nil {
		return
	}
	p.readFn = fn
	if dst == &p.breakErr {
		if p.b != nil {
			p.unread += p.b.Len()
		}
		p.b = nil
	}
	*dst = err
	p.closeDoneLocked()
}

func (p *pipe) closeDoneLocked() {
	if p.donec == nil {
		return
	}
	select {
	case <-p.donec:
	default:
		close(p.donec)
	}
}

func (p *pipe) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.breakErr != nil {
		return p.breakErr
	}
	return p.err
}

func (p *pipe) Done() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.donec == nil {
		p.donec = make(chan struct{})
		if p.err != nil || p.breakErr != nil {
			p.closeDoneLocked()
		}
	}
	return p.donec
}
