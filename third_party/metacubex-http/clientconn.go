// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"errors"
	"fmt"
	"github.com/metacubex/http/httptrace"
	"net"
	"net/url"
	"sync"
)

type ClientConn struct {
	cc genericClientConn

	stateHookMu      sync.Mutex
	userStateHook    func(*ClientConn)
	stateHookRunning bool
	lastAvailable    int
	lastInFlight     int
	lastClosed       bool
}

type newClientConner interface {
	NewClientConn(nc net.Conn, internalStateHook func()) (RoundTripper, error)
}

type genericClientConn interface {
	Close() error
	Err() error
	RoundTrip(req *Request) (*Response, error)
	Reserve() error
	Release()
	Available() int
	InFlight() int
}

func (t *Transport) NewClientConn(ctx context.Context, scheme, address string) (*ClientConn, error) {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)

	switch scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("net/http: invalid scheme %q", scheme)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if port == "" {
		port = schemePort(scheme)
	}

	var proxyURL *url.URL
	if t.Proxy != nil {
		req := &Request{
			ctx:    ctx,
			Method: "GET",
			URL: &url.URL{
				Scheme: scheme,
				Host:   host,
				Path:   "/",
			},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(Header),
			Body:       NoBody,
			Host:       host,
		}
		var err error
		proxyURL, err = t.Proxy(req)
		if err != nil {
			return nil, err
		}
	}

	cm := connectMethod{
		targetScheme: scheme,
		targetAddr:   net.JoinHostPort(host, port),
		proxyURL:     proxyURL,
	}

	cc := &ClientConn{}
	const isClientConn = true
	pconn, err := t.dialConn(ctx, cm, isClientConn, cc.maybeRunStateHook)
	if err != nil {
		return nil, err
	}

	cc.stateHookMu.Lock()
	defer cc.stateHookMu.Unlock()
	if pconn.alt != nil {
		gc, ok := pconn.alt.(genericClientConn)
		if !ok {
			return nil, errors.New("http: NewClientConn returned something that is not a ClientConn")
		}
		cc.cc = gc
		cc.lastAvailable = gc.Available()
	} else {
		pconn.availch = make(chan struct{}, 1)
		pconn.availch <- struct{}{}
		cc.cc = http1ClientConn{pconn}
		cc.lastAvailable = 1
	}
	return cc, nil
}

func (cc *ClientConn) Close() error {
	defer cc.maybeRunStateHook()
	return cc.cc.Close()
}

func (cc *ClientConn) Err() error {
	return cc.cc.Err()
}

func validateClientConnRequest(req *Request) error {
	if req.URL == nil {
		return errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		return errors.New("http: nil Request.Header")
	}
	if err := validateHeaders(req.Header); err != "" {
		return fmt.Errorf("http: invalid header %s", err)
	}
	if err := validateHeaders(req.Trailer); err != "" {
		return fmt.Errorf("http: invalid trailer %s", err)
	}
	if req.Method != "" && !validMethod(req.Method) {
		return fmt.Errorf("http: invalid method %q", req.Method)
	}
	if req.URL.Host == "" {
		return errors.New("http: no Host in request URL")
	}
	return nil
}

func (cc *ClientConn) RoundTrip(req *Request) (*Response, error) {
	defer cc.maybeRunStateHook()
	if err := validateClientConnRequest(req); err != nil {
		cc.Release()
		return nil, err
	}
	return cc.cc.RoundTrip(req)
}

func (cc *ClientConn) Available() int {
	return cc.cc.Available()
}

func (cc *ClientConn) InFlight() int {
	return cc.cc.InFlight()
}

func (cc *ClientConn) Reserve() error {
	defer cc.maybeRunStateHook()
	return cc.cc.Reserve()
}

func (cc *ClientConn) Release() {
	defer cc.maybeRunStateHook()
	cc.cc.Release()
}

func (cc *ClientConn) shouldRunStateHook(stopRunning bool) func(*ClientConn) {
	cc.stateHookMu.Lock()
	defer cc.stateHookMu.Unlock()
	if cc.cc == nil {
		return nil
	}
	if stopRunning {
		cc.stateHookRunning = false
	}
	if cc.userStateHook == nil {
		return nil
	}
	if cc.stateHookRunning {
		return nil
	}
	var (
		available = cc.Available()
		inFlight  = cc.InFlight()
		closed    = cc.Err() != nil
	)
	var hook func(*ClientConn)
	if available > cc.lastAvailable || inFlight < cc.lastInFlight || closed != cc.lastClosed {
		hook = cc.userStateHook
		cc.stateHookRunning = true
	}
	cc.lastAvailable = available
	cc.lastInFlight = inFlight
	cc.lastClosed = closed
	return hook
}

func (cc *ClientConn) maybeRunStateHook() {
	hook := cc.shouldRunStateHook(false)
	if hook == nil {
		return
	}
	hook(cc)
	hook = cc.shouldRunStateHook(true)
	if hook != nil {
		go func() {
			for hook != nil {
				hook(cc)
				hook = cc.shouldRunStateHook(true)
			}
		}()
	}
}

func (cc *ClientConn) SetStateHook(f func(*ClientConn)) {
	cc.stateHookMu.Lock()
	cc.userStateHook = f
	cc.stateHookMu.Unlock()
	cc.maybeRunStateHook()
}

type http1ClientConn struct {
	pconn *persistConn
}

func (cc http1ClientConn) RoundTrip(req *Request) (*Response, error) {
	ctx := req.Context()
	trace := httptrace.ContextClientTrace(ctx)

	ctx, cancel := context.WithCancelCause(req.Context())
	if req.Cancel != nil {
		go awaitLegacyCancel(ctx, cancel, req)
	}

	treq := &transportRequest{Request: req, trace: trace, ctx: ctx, cancel: cancel}
	resp, err := cc.pconn.roundTrip(treq)
	if err != nil {
		return nil, err
	}
	resp.Request = req
	return resp, nil
}

func (cc http1ClientConn) Close() error {
	cc.pconn.close(errors.New("ClientConn closed"))
	return nil
}

func (cc http1ClientConn) Err() error {
	select {
	case <-cc.pconn.closech:
		return cc.pconn.closed
	default:
		return nil
	}
}

func (cc http1ClientConn) Available() int {
	cc.pconn.mu.Lock()
	defer cc.pconn.mu.Unlock()
	if cc.pconn.closed != nil || cc.pconn.reserved || cc.pconn.inFlight {
		return 0
	}
	return 1
}

func (cc http1ClientConn) InFlight() int {
	cc.pconn.mu.Lock()
	defer cc.pconn.mu.Unlock()
	if cc.pconn.closed == nil && (cc.pconn.reserved || cc.pconn.inFlight) {
		return 1
	}
	return 0
}

func (cc http1ClientConn) Reserve() error {
	cc.pconn.mu.Lock()
	defer cc.pconn.mu.Unlock()
	if cc.pconn.closed != nil {
		return cc.pconn.closed
	}
	select {
	case <-cc.pconn.availch:
	default:
		return errors.New("connection is unavailable")
	}
	cc.pconn.reserved = true
	return nil
}

func (cc http1ClientConn) Release() {
	cc.pconn.mu.Lock()
	defer cc.pconn.mu.Unlock()
	if cc.pconn.reserved {
		select {
		case cc.pconn.availch <- struct{}{}:
		default:
			panic("cannot release reservation")
		}
		cc.pconn.reserved = false
	}
}
