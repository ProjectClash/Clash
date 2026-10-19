// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package http

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"container/list"
	"context"
	"errors"
	"fmt"
	"github.com/metacubex/tls"
	"golang.org/x/exp/maps"
	"io"
	"log"
	"net"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/http/internal/ascii"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http/httpproxy"
)

var DefaultTransport RoundTripper = &Transport{
	Proxy: ProxyFromEnvironment,
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}),
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

const DefaultMaxIdleConnsPerHost = 2

type Transport struct {
	idleMu       sync.Mutex
	closeIdle    bool
	idleConn     map[connectMethodKey][]*persistConn
	idleConnWait map[connectMethodKey]wantConnQueue
	idleLRU      connLRU

	reqMu       sync.Mutex
	reqCanceler map[*Request]context.CancelCauseFunc

	altMu    sync.Mutex
	altProto atomic.Value

	connsPerHostMu   sync.Mutex
	connsPerHost     map[connectMethodKey]int
	connsPerHostWait map[connectMethodKey]wantConnQueue
	dialsInProgress  wantConnQueue

	Proxy func(*Request) (*url.URL, error)

	OnProxyConnectResponse func(ctx context.Context, proxyURL *url.URL, connectReq *Request, connectRes *Response) error

	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	Dial func(network, addr string) (net.Conn, error)

	DialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	DialTLS func(network, addr string) (net.Conn, error)

	TLSClientConfig *tls.Config

	TLSHandshakeTimeout time.Duration

	DisableKeepAlives bool

	DisableCompression bool

	MaxIdleConns int

	MaxIdleConnsPerHost int

	MaxConnsPerHost int

	IdleConnTimeout time.Duration

	ResponseHeaderTimeout time.Duration

	ExpectContinueTimeout time.Duration

	TLSNextProto map[string]func(authority string, c TLSConn) RoundTripper

	ProxyConnectHeader Header

	GetProxyConnectHeader func(ctx context.Context, proxyURL *url.URL, target string) (Header, error)

	MaxResponseHeaderBytes int64

	WriteBufferSize int

	ReadBufferSize int

	nextProtoOnce      sync.Once
	h2transport        h2Transport
	tlsNextProtoWasNil bool

	ForceAttemptHTTP2 bool

	HTTP2 *HTTP2Config

	Protocols *Protocols
}

func (t *Transport) writeBufferSize() int {
	if t.WriteBufferSize > 0 {
		return t.WriteBufferSize
	}
	return 4 << 10
}

func (t *Transport) readBufferSize() int {
	if t.ReadBufferSize > 0 {
		return t.ReadBufferSize
	}
	return 4 << 10
}

func (t *Transport) maxHeaderResponseSize() int64 {
	if t.MaxResponseHeaderBytes > 0 {
		return t.MaxResponseHeaderBytes
	}
	return 10 << 20
}

func (t *Transport) Clone() *Transport {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	t2 := &Transport{
		Proxy:                  t.Proxy,
		OnProxyConnectResponse: t.OnProxyConnectResponse,
		DialContext:            t.DialContext,
		Dial:                   t.Dial,
		DialTLS:                t.DialTLS,
		DialTLSContext:         t.DialTLSContext,
		TLSHandshakeTimeout:    t.TLSHandshakeTimeout,
		DisableKeepAlives:      t.DisableKeepAlives,
		DisableCompression:     t.DisableCompression,
		MaxIdleConns:           t.MaxIdleConns,
		MaxIdleConnsPerHost:    t.MaxIdleConnsPerHost,
		MaxConnsPerHost:        t.MaxConnsPerHost,
		IdleConnTimeout:        t.IdleConnTimeout,
		ResponseHeaderTimeout:  t.ResponseHeaderTimeout,
		ExpectContinueTimeout:  t.ExpectContinueTimeout,
		ProxyConnectHeader:     t.ProxyConnectHeader.Clone(),
		GetProxyConnectHeader:  t.GetProxyConnectHeader,
		MaxResponseHeaderBytes: t.MaxResponseHeaderBytes,
		ForceAttemptHTTP2:      t.ForceAttemptHTTP2,
		WriteBufferSize:        t.WriteBufferSize,
		ReadBufferSize:         t.ReadBufferSize,
	}
	if t.TLSClientConfig != nil {
		t2.TLSClientConfig = t.TLSClientConfig.Clone()
	}
	if t.HTTP2 != nil {
		t2.HTTP2 = &HTTP2Config{}
		*t2.HTTP2 = *t.HTTP2
	}
	if t.Protocols != nil {
		t2.Protocols = &Protocols{}
		*t2.Protocols = *t.Protocols
	}
	if !t.tlsNextProtoWasNil {
		npm := maps.Clone(t.TLSNextProto)
		if npm == nil {
			npm = make(map[string]func(authority string, c TLSConn) RoundTripper)
		}
		t2.TLSNextProto = npm
	}
	return t2
}

type h2Transport interface {
	CloseIdleConnections()
}

func (t *Transport) hasCustomTLSDialer() bool {
	return t.DialTLS != nil || t.DialTLSContext != nil
}

func (t *Transport) onceSetNextProtoDefaults() {
	t.tlsNextProtoWasNil = (t.TLSNextProto == nil)

	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	if rv := reflect.ValueOf(altProto["https"]); rv.IsValid() && rv.Type().Kind() == reflect.Struct && rv.Type().NumField() == 1 {
		if v := rv.Field(0); v.CanInterface() {
			if h2i, ok := v.Interface().(h2Transport); ok {
				t.h2transport = h2i
				return
			}
		}
	}

	if _, ok := t.TLSNextProto["h2"]; ok {
		return
	}
	protocols := t.protocols()
	if !protocols.HTTP2() && !protocols.UnencryptedHTTP2() {
		return
	}
	if omitBundledHTTP2 {
		return
	}
	t2, err := http2configureTransports(t)
	if err != nil {
		log.Printf("Error enabling Transport HTTP/2 support: %v", err)
		return
	}
	t.h2transport = t2

	if limit1 := t.MaxResponseHeaderBytes; limit1 != 0 && t2.MaxHeaderListSize == 0 {
		const h2max = 1<<32 - 1
		if limit1 >= h2max {
			t2.MaxHeaderListSize = h2max
		} else {
			t2.MaxHeaderListSize = uint32(limit1)
		}
	}

	t.TLSClientConfig.NextProtos = adjustNextProtos(t.TLSClientConfig.NextProtos, protocols)
}

func (t *Transport) protocols() Protocols {
	if t.Protocols != nil {
		return *t.Protocols
	}
	var p Protocols
	p.SetHTTP1(true)
	switch {
	case t.TLSNextProto != nil:
		if t.TLSNextProto["h2"] != nil {
			p.SetHTTP2(true)
		}
	case !t.ForceAttemptHTTP2 && (t.TLSClientConfig != nil || t.Dial != nil || t.DialContext != nil || t.hasCustomTLSDialer()):
	default:
		p.SetHTTP2(true)
	}
	return p
}

func ProxyFromEnvironment(req *Request) (*url.URL, error) {
	return envProxyFunc()(req.URL)
}

func ProxyURL(fixedURL *url.URL) func(*Request) (*url.URL, error) {
	return func(*Request) (*url.URL, error) {
		return fixedURL, nil
	}
}

type transportRequest struct {
	*Request
	extra    Header
	trace    *httptrace.ClientTrace

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu  sync.Mutex
	err error
}

func (tr *transportRequest) extraHeaders() Header {
	if tr.extra == nil {
		tr.extra = make(Header)
	}
	return tr.extra
}

func (tr *transportRequest) setError(err error) {
	tr.mu.Lock()
	if tr.err == nil {
		tr.err = err
	}
	tr.mu.Unlock()
}

func (t *Transport) useRegisteredProtocol(req *Request) bool {
	if req.URL.Scheme == "https" && req.requiresHTTP1() {
		return false
	}
	return true
}

func (t *Transport) alternateRoundTripper(req *Request) RoundTripper {
	if !t.useRegisteredProtocol(req) {
		return nil
	}
	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	return altProto[req.URL.Scheme]
}

func validateHeaders(hdrs Header) string {
	for k, vv := range hdrs {
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Sprintf("field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return fmt.Sprintf("field value for %q", k)
			}
		}
	}
	return ""
}

func (t *Transport) roundTrip(req *Request) (_ *Response, err error) {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	ctx := req.Context()
	trace := httptrace.ContextClientTrace(ctx)

	if req.URL == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.Header")
	}
	scheme := req.URL.Scheme
	isHTTP := scheme == "http" || scheme == "https"
	if isHTTP {
		if err := validateHeaders(req.Header); err != "" {
			req.closeBody()
			return nil, fmt.Errorf("net/http: invalid header %s", err)
		}

		if err := validateHeaders(req.Trailer); err != "" {
			req.closeBody()
			return nil, fmt.Errorf("net/http: invalid trailer %s", err)
		}
	}

	origReq := req
	req = setupRewindBody(req)

	if altRT := t.alternateRoundTripper(req); altRT != nil {
		if resp, err := altRT.RoundTrip(req); err != ErrSkipAltProtocol {
			return resp, err
		}
		var err error
		req, err = rewindBody(req)
		if err != nil {
			return nil, err
		}
	}
	if !isHTTP {
		req.closeBody()
		return nil, badStringError("unsupported protocol scheme", scheme)
	}
	if req.Method != "" && !validMethod(req.Method) {
		req.closeBody()
		return nil, fmt.Errorf("net/http: invalid method %q", req.Method)
	}
	if req.URL.Host == "" {
		req.closeBody()
		return nil, errors.New("http: no Host in request URL")
	}

	ctx, cancel := context.WithCancelCause(req.Context())

	if origReq.Cancel != nil {
		go awaitLegacyCancel(ctx, cancel, origReq)
	}

	cancel = t.prepareTransportCancel(origReq, cancel)

	defer func() {
		if err != nil {
			cancel(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			req.closeBody()
			return nil, context.Cause(ctx)
		default:
		}

		treq := &transportRequest{Request: req, trace: trace, ctx: ctx, cancel: cancel}
		cm, err := t.connectMethodForRequest(treq)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		pconn, err := t.getConn(treq, cm)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		var resp *Response
		if pconn.alt != nil {
			resp, err = pconn.alt.RoundTrip(req)
		} else {
			resp, err = pconn.roundTrip(treq)
		}
		if err == nil {
			if pconn.alt != nil {
				cancel(errRequestDone)
			}
			resp.Request = origReq
			return resp, nil
		}

		if http2isNoCachedConnError(err) {
			if t.removeIdleConn(pconn) {
				t.decConnsPerHost(pconn.cacheKey)
			}
		} else if !pconn.shouldRetryRequest(req, err) {
			if e, ok := err.(nothingWrittenError); ok {
				err = e.error
			}
			if e, ok := err.(transportReadFromServerError); ok {
				err = e.err
			}
			if b, ok := req.Body.(*readTrackingBody); ok && !b.didClose.Load() {
				req.closeBody()
			}
			return nil, err
		}
		testHookRoundTripRetried()

		req, err = rewindBody(req)
		if err != nil {
			return nil, err
		}
	}
}

func awaitLegacyCancel(ctx context.Context, cancel context.CancelCauseFunc, req *Request) {
	select {
	case <-req.Cancel:
		cancel(errRequestCanceled)
	case <-ctx.Done():
	}
}

var errCannotRewind = errors.New("net/http: cannot rewind body after connection loss")

type readTrackingBody struct {
	io.ReadCloser
	didRead  bool
	didClose atomic.Bool
}

func (r *readTrackingBody) Read(data []byte) (int, error) {
	r.didRead = true
	return r.ReadCloser.Read(data)
}

func (r *readTrackingBody) Close() error {
	if !r.didClose.CompareAndSwap(false, true) {
		return nil
	}
	return r.ReadCloser.Close()
}

func setupRewindBody(req *Request) *Request {
	if req.Body == nil || req.Body == NoBody {
		return req
	}
	newReq := *req
	newReq.Body = &readTrackingBody{ReadCloser: req.Body}
	return &newReq
}

func rewindBody(req *Request) (rewound *Request, err error) {
	if req.Body == nil || req.Body == NoBody || (!req.Body.(*readTrackingBody).didRead && !req.Body.(*readTrackingBody).didClose.Load()) {
		return req, nil
	}
	if !req.Body.(*readTrackingBody).didClose.Load() {
		req.closeBody()
	}
	if req.GetBody == nil {
		return nil, errCannotRewind
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	newReq := *req
	newReq.Body = &readTrackingBody{ReadCloser: body}
	return &newReq, nil
}

func (pc *persistConn) shouldRetryRequest(req *Request, err error) bool {
	if http2isNoCachedConnError(err) {
		return true
	}
	if err == errMissingHost {
		return false
	}
	if !pc.isReused() {
		return false
	}
	if _, ok := err.(nothingWrittenError); ok {
		return req.outgoingLength() == 0 || req.GetBody != nil
	}
	if !req.isReplayable() {
		return false
	}
	if _, ok := err.(transportReadFromServerError); ok {
		return true
	}
	if err == errServerClosedIdle {
		return true
	}
	return false
}

var ErrSkipAltProtocol = errors.New("net/http: skip alternate protocol")

func (t *Transport) RegisterProtocol(scheme string, rt RoundTripper) {
	t.altMu.Lock()
	defer t.altMu.Unlock()
	oldMap, _ := t.altProto.Load().(map[string]RoundTripper)
	if _, exists := oldMap[scheme]; exists {
		panic("protocol " + scheme + " already registered")
	}
	newMap := maps.Clone(oldMap)
	if newMap == nil {
		newMap = make(map[string]RoundTripper)
	}
	newMap[scheme] = rt
	t.altProto.Store(newMap)
}

func (t *Transport) CloseIdleConnections() {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	t.idleMu.Lock()
	m := t.idleConn
	t.idleConn = nil
	t.closeIdle = true
	t.idleLRU = connLRU{}
	t.idleMu.Unlock()
	for _, conns := range m {
		for _, pconn := range conns {
			pconn.close(errCloseIdleConns)
		}
	}
	t.connsPerHostMu.Lock()
	t.dialsInProgress.all(func(w *wantConn) {
		if w.cancelCtx != nil && !w.waiting() {
			w.cancelCtx()
		}
	})
	t.connsPerHostMu.Unlock()
	if t2 := t.h2transport; t2 != nil {
		t2.CloseIdleConnections()
	}
}

func (t *Transport) prepareTransportCancel(req *Request, origCancel context.CancelCauseFunc) context.CancelCauseFunc {
	cancel := func(err error) {
		origCancel(err)
		t.reqMu.Lock()
		delete(t.reqCanceler, req)
		t.reqMu.Unlock()
	}
	t.reqMu.Lock()
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*Request]context.CancelCauseFunc)
	}
	t.reqCanceler[req] = cancel
	t.reqMu.Unlock()
	return cancel
}

func (t *Transport) CancelRequest(req *Request) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	t.reqMu.Unlock()
	if cancel != nil {
		cancel(errRequestCanceled)
	}
}


var (
	envProxyOnce      sync.Once
	envProxyFuncValue func(*url.URL) (*url.URL, error)
)

func envProxyFunc() func(*url.URL) (*url.URL, error) {
	envProxyOnce.Do(func() {
		envProxyFuncValue = httpproxy.FromEnvironment().ProxyFunc()
	})
	return envProxyFuncValue
}

func resetProxyConfig() {
	envProxyOnce = sync.Once{}
	envProxyFuncValue = nil
}

func (t *Transport) connectMethodForRequest(treq *transportRequest) (cm connectMethod, err error) {
	cm.targetScheme = treq.URL.Scheme
	cm.targetAddr = canonicalAddr(treq.URL)
	if t.Proxy != nil {
		cm.proxyURL, err = t.Proxy(treq.Request)
	}
	cm.onlyH1 = treq.requiresHTTP1()
	return cm, err
}

func (cm *connectMethod) proxyAuth() string {
	if cm.proxyURL == nil {
		return ""
	}
	if u := cm.proxyURL.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + basicAuth(username, password)
	}
	return ""
}

var (
	errKeepAlivesDisabled = errors.New("http: putIdleConn: keep alives disabled")
	errConnBroken         = errors.New("http: putIdleConn: connection is in bad state")
	errCloseIdle          = errors.New("http: putIdleConn: CloseIdleConnections was called")
	errTooManyIdle        = errors.New("http: putIdleConn: too many idle connections")
	errTooManyIdleHost    = errors.New("http: putIdleConn: too many idle connections for host")
	errCloseIdleConns     = errors.New("http: CloseIdleConnections called")
	errReadLoopExiting    = errors.New("http: persistConn.readLoop exiting")
	errIdleConnTimeout    = errors.New("http: idle connection timeout")

	errServerClosedIdle = errors.New("http: server closed idle connection")
)

type transportReadFromServerError struct {
	err error
}

func (e transportReadFromServerError) Unwrap() error { return e.err }

func (e transportReadFromServerError) Error() string {
	return fmt.Sprintf("net/http: Transport failed to read from server: %v", e.err)
}

func (t *Transport) putOrCloseIdleConn(pconn *persistConn) {
	if err := t.tryPutIdleConn(pconn); err != nil {
		pconn.close(err)
	}
}

func (t *Transport) maxIdleConnsPerHost() int {
	if v := t.MaxIdleConnsPerHost; v != 0 {
		return v
	}
	return DefaultMaxIdleConnsPerHost
}

func (t *Transport) tryPutIdleConn(pconn *persistConn) error {
	if t.DisableKeepAlives || t.MaxIdleConnsPerHost < 0 {
		return errKeepAlivesDisabled
	}
	if pconn.isBroken() {
		return errConnBroken
	}
	pconn.markReused()
	if pconn.isClientConn {
		defer pconn.internalStateHook()
		pconn.mu.Lock()
		defer pconn.mu.Unlock()
		if !pconn.inFlight {
			panic("pconn is not in flight")
		}
		pconn.inFlight = false
		select {
		case pconn.availch <- struct{}{}:
		default:
			panic("unable to make pconn available")
		}
		return nil
	}

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	if pconn.alt != nil && t.idleLRU.m[pconn] != nil {
		return nil
	}

	key := pconn.cacheKey
	if q, ok := t.idleConnWait[key]; ok {
		done := false
		if pconn.alt == nil {
			for q.len() > 0 {
				w := q.popFront()
				if w.tryDeliver(pconn, nil, time.Time{}) {
					done = true
					break
				}
			}
		} else {
			for q.len() > 0 {
				w := q.popFront()
				w.tryDeliver(pconn, nil, time.Time{})
			}
		}
		if q.len() == 0 {
			delete(t.idleConnWait, key)
		} else {
			t.idleConnWait[key] = q
		}
		if done {
			return nil
		}
	}

	if t.closeIdle {
		return errCloseIdle
	}
	if t.idleConn == nil {
		t.idleConn = make(map[connectMethodKey][]*persistConn)
	}
	idles := t.idleConn[key]
	if len(idles) >= t.maxIdleConnsPerHost() {
		return errTooManyIdleHost
	}
	for _, exist := range idles {
		if exist == pconn {
			log.Fatalf("dup idle pconn %p in freelist", pconn)
		}
	}
	t.idleConn[key] = append(idles, pconn)
	t.idleLRU.add(pconn)
	if t.MaxIdleConns != 0 && t.idleLRU.len() > t.MaxIdleConns {
		oldest := t.idleLRU.removeOldest()
		oldest.close(errTooManyIdle)
		t.removeIdleConnLocked(oldest)
	}

	if t.IdleConnTimeout > 0 && pconn.alt == nil {
		if pconn.idleTimer != nil {
			pconn.idleTimer.Reset(t.IdleConnTimeout)
		} else {
			pconn.idleTimer = time.AfterFunc(t.IdleConnTimeout, pconn.closeConnIfStillIdle)
		}
	}
	pconn.idleAt = time.Now()
	return nil
}

func (t *Transport) queueForIdleConn(w *wantConn) (delivered bool) {
	if t.DisableKeepAlives {
		return false
	}

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	t.closeIdle = false

	if w == nil {
		return false
	}

	var oldTime time.Time
	if t.IdleConnTimeout > 0 {
		oldTime = time.Now().Add(-t.IdleConnTimeout)
	}

	if list, ok := t.idleConn[w.key]; ok {
		stop := false
		delivered := false
		for len(list) > 0 && !stop {
			pconn := list[len(list)-1]

			tooOld := !oldTime.IsZero() && pconn.idleAt.Round(0).Before(oldTime)
			if tooOld {
				go pconn.closeConnIfStillIdle()
			}
			if pconn.isBroken() || tooOld {
				list = list[:len(list)-1]
				continue
			}
			delivered = w.tryDeliver(pconn, nil, pconn.idleAt)
			if delivered {
				if pconn.alt != nil {
				} else {
					t.idleLRU.remove(pconn)
					list = list[:len(list)-1]
				}
			}
			stop = true
		}
		if len(list) > 0 {
			t.idleConn[w.key] = list
		} else {
			delete(t.idleConn, w.key)
		}
		if stop {
			return delivered
		}
	}

	if t.idleConnWait == nil {
		t.idleConnWait = make(map[connectMethodKey]wantConnQueue)
	}
	q := t.idleConnWait[w.key]
	q.cleanFrontNotWaiting()
	q.pushBack(w)
	t.idleConnWait[w.key] = q
	return false
}

func (t *Transport) removeIdleConn(pconn *persistConn) bool {
	if pconn.isClientConn {
		return true
	}
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	return t.removeIdleConnLocked(pconn)
}

func (t *Transport) removeIdleConnLocked(pconn *persistConn) bool {
	if pconn.idleTimer != nil {
		pconn.idleTimer.Stop()
	}
	t.idleLRU.remove(pconn)
	key := pconn.cacheKey
	pconns := t.idleConn[key]
	var removed bool
	switch len(pconns) {
	case 0:
	case 1:
		if pconns[0] == pconn {
			delete(t.idleConn, key)
			removed = true
		}
	default:
		for i, v := range pconns {
			if v != pconn {
				continue
			}
			copy(pconns[i:], pconns[i+1:])
			t.idleConn[key] = pconns[:len(pconns)-1]
			removed = true
			break
		}
	}
	return removed
}

var zeroDialer net.Dialer

func (t *Transport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.DialContext != nil {
		c, err := t.DialContext(ctx, network, addr)
		if c == nil && err == nil {
			err = errors.New("net/http: Transport.DialContext hook returned (nil, nil)")
		}
		return c, err
	}
	if t.Dial != nil {
		c, err := t.Dial(network, addr)
		if c == nil && err == nil {
			err = errors.New("net/http: Transport.Dial hook returned (nil, nil)")
		}
		return c, err
	}
	return zeroDialer.DialContext(ctx, network, addr)
}

type wantConn struct {
	cm  connectMethod
	key connectMethodKey

	beforeDial func()
	afterDial  func()

	mu        sync.Mutex
	ctx       context.Context
	cancelCtx context.CancelFunc
	done      bool
	result    chan connOrError
}

type connOrError struct {
	pc     *persistConn
	err    error
	idleAt time.Time
}

func (w *wantConn) waiting() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	return !w.done
}

func (w *wantConn) getCtxForDial() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.ctx
}

func (w *wantConn) tryDeliver(pc *persistConn, err error, idleAt time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.done {
		return false
	}
	if (pc == nil) == (err == nil) {
		panic("net/http: internal error: misuse of tryDeliver")
	}
	w.ctx = nil
	w.done = true

	w.result <- connOrError{pc: pc, err: err, idleAt: idleAt}
	close(w.result)

	return true
}

func (w *wantConn) cancel(t *Transport) {
	w.mu.Lock()
	var pc *persistConn
	if w.done {
		if r, ok := <-w.result; ok {
			pc = r.pc
		}
	} else {
		close(w.result)
	}
	w.ctx = nil
	w.done = true
	w.mu.Unlock()

	if pc != nil && pc.alt == nil {
		t.putOrCloseIdleConn(pc)
	}
}

type wantConnQueue struct {
	head    []*wantConn
	headPos int
	tail    []*wantConn
}

func (q *wantConnQueue) len() int {
	return len(q.head) - q.headPos + len(q.tail)
}

func (q *wantConnQueue) pushBack(w *wantConn) {
	q.tail = append(q.tail, w)
}

func (q *wantConnQueue) popFront() *wantConn {
	if q.headPos >= len(q.head) {
		if len(q.tail) == 0 {
			return nil
		}
		q.head, q.headPos, q.tail = q.tail, 0, q.head[:0]
	}
	w := q.head[q.headPos]
	q.head[q.headPos] = nil
	q.headPos++
	return w
}

func (q *wantConnQueue) peekFront() *wantConn {
	if q.headPos < len(q.head) {
		return q.head[q.headPos]
	}
	if len(q.tail) > 0 {
		return q.tail[0]
	}
	return nil
}

func (q *wantConnQueue) cleanFrontNotWaiting() (cleaned bool) {
	for {
		w := q.peekFront()
		if w == nil || w.waiting() {
			return cleaned
		}
		q.popFront()
		cleaned = true
	}
}

func (q *wantConnQueue) cleanFrontCanceled() {
	for {
		w := q.peekFront()
		if w == nil || w.cancelCtx != nil {
			return
		}
		q.popFront()
	}
}

func (q *wantConnQueue) all(f func(*wantConn)) {
	for _, w := range q.head[q.headPos:] {
		f(w)
	}
	for _, w := range q.tail {
		f(w)
	}
}

func (t *Transport) customDialTLS(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if t.DialTLSContext != nil {
		conn, err = t.DialTLSContext(ctx, network, addr)
	} else {
		conn, err = t.DialTLS(network, addr)
	}
	if conn == nil && err == nil {
		err = errors.New("net/http: Transport.DialTLS or DialTLSContext returned (nil, nil)")
	}
	return
}

func (t *Transport) getConn(treq *transportRequest, cm connectMethod) (_ *persistConn, err error) {
	req := treq.Request
	trace := treq.trace
	ctx := req.Context()
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(cm.addr())
	}

	dialCtx, dialCancel := context.WithCancel(contextWithoutCancel(ctx))

	w := &wantConn{
		cm:         cm,
		key:        cm.key(),
		ctx:        dialCtx,
		cancelCtx:  dialCancel,
		result:     make(chan connOrError, 1),
		beforeDial: testHookPrePendingDial,
		afterDial:  testHookPostPendingDial,
	}
	defer func() {
		if err != nil {
			w.cancel(t)
		}
	}()

	if delivered := t.queueForIdleConn(w); !delivered {
		t.queueForDial(w)
	}

	select {
	case r := <-w.result:
		if r.pc != nil && r.pc.alt == nil && trace != nil && trace.GotConn != nil {
			info := httptrace.GotConnInfo{
				Conn:   r.pc.conn,
				Reused: r.pc.isReused(),
			}
			if !r.idleAt.IsZero() {
				info.WasIdle = true
				info.IdleTime = time.Since(r.idleAt)
			}
			trace.GotConn(info)
		}
		if r.err != nil {
			select {
			case <-treq.ctx.Done():
				err := context.Cause(treq.ctx)
				if err == errRequestCanceled {
					err = errRequestCanceledConn
				}
				return nil, err
			default:
			}
		}
		return r.pc, r.err
	case <-treq.ctx.Done():
		err := context.Cause(treq.ctx)
		if err == errRequestCanceled {
			err = errRequestCanceledConn
		}
		return nil, err
	}
}

func (t *Transport) queueForDial(w *wantConn) {
	w.beforeDial()

	t.connsPerHostMu.Lock()
	defer t.connsPerHostMu.Unlock()

	if t.MaxConnsPerHost <= 0 {
		t.startDialConnForLocked(w)
		return
	}

	if n := t.connsPerHost[w.key]; n < t.MaxConnsPerHost {
		if t.connsPerHost == nil {
			t.connsPerHost = make(map[connectMethodKey]int)
		}
		t.connsPerHost[w.key] = n + 1
		t.startDialConnForLocked(w)
		return
	}

	if t.connsPerHostWait == nil {
		t.connsPerHostWait = make(map[connectMethodKey]wantConnQueue)
	}
	q := t.connsPerHostWait[w.key]
	q.cleanFrontNotWaiting()
	q.pushBack(w)
	t.connsPerHostWait[w.key] = q
}

func (t *Transport) startDialConnForLocked(w *wantConn) {
	t.dialsInProgress.cleanFrontCanceled()
	t.dialsInProgress.pushBack(w)
	go func() {
		t.dialConnFor(w)
		t.connsPerHostMu.Lock()
		defer t.connsPerHostMu.Unlock()
		w.cancelCtx = nil
	}()
}

func (t *Transport) dialConnFor(w *wantConn) {
	defer w.afterDial()
	ctx := w.getCtxForDial()
	if ctx == nil {
		t.decConnsPerHost(w.key)
		return
	}

	const isClientConn = false
	pc, err := t.dialConn(ctx, w.cm, isClientConn, nil)
	delivered := w.tryDeliver(pc, err, time.Time{})
	if err == nil && (!delivered || pc.alt != nil) {
		t.putOrCloseIdleConn(pc)
	}
	if err != nil {
		t.decConnsPerHost(w.key)
	}
}

func (t *Transport) decConnsPerHost(key connectMethodKey) {
	if t.MaxConnsPerHost <= 0 {
		return
	}

	t.connsPerHostMu.Lock()
	defer t.connsPerHostMu.Unlock()
	n := t.connsPerHost[key]
	if n == 0 {
		panic("net/http: internal error: connCount underflow")
	}

	if q := t.connsPerHostWait[key]; q.len() > 0 {
		done := false
		for q.len() > 0 {
			w := q.popFront()
			if w.waiting() {
				t.startDialConnForLocked(w)
				done = true
				break
			}
		}
		if q.len() == 0 {
			delete(t.connsPerHostWait, key)
		} else {
			t.connsPerHostWait[key] = q
		}
		if done {
			return
		}
	}

	if n--; n == 0 {
		delete(t.connsPerHost, key)
	} else {
		t.connsPerHost[key] = n
	}
}

func (pconn *persistConn) addTLS(ctx context.Context, name string, trace *httptrace.ClientTrace) error {
	cfg := cloneTLSConfig(pconn.t.TLSClientConfig)
	if cfg.ServerName == "" {
		cfg.ServerName = name
	}
	if pconn.cacheKey.onlyH1 {
		cfg.NextProtos = nil
	}
	plainConn := pconn.conn
	tlsConn := tls.Client(plainConn, cfg)
	errc := make(chan error, 2)
	var timer *time.Timer
	if d := pconn.t.TLSHandshakeTimeout; d != 0 {
		timer = time.AfterFunc(d, func() {
			errc <- tlsHandshakeTimeoutError{}
		})
	}
	go func() {
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := tlsConn.HandshakeContext(ctx)
		if timer != nil {
			timer.Stop()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		plainConn.Close()
		if err == (tlsHandshakeTimeoutError{}) {
			<-errc
		}
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tls.ConnectionState{}, err)
		}
		return err
	}
	cs := tlsConn.ConnectionState()
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(cs, nil)
	}
	pconn.tlsState = &cs
	pconn.conn = tlsConn
	return nil
}

type erringRoundTripper interface {
	RoundTripErr() error
}

var testHookProxyConnectTimeout = context.WithTimeout

func (t *Transport) dialConn(ctx context.Context, cm connectMethod, isClientConn bool, internalStateHook func()) (pconn *persistConn, err error) {
	pconn = &persistConn{
		t:                 t,
		cacheKey:          cm.key(),
		reqch:             make(chan requestAndChan, 1),
		writech:           make(chan writeRequest, 1),
		closech:           make(chan struct{}),
		writeErrCh:        make(chan error, 1),
		writeLoopDone:     make(chan struct{}),
		isClientConn:      isClientConn,
		internalStateHook: internalStateHook,
	}
	trace := httptrace.ContextClientTrace(ctx)
	wrapErr := func(err error) error {
		if cm.proxyURL != nil {
			return &net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}
		}
		return err
	}
	if cm.scheme() == "https" && t.hasCustomTLSDialer() {
		var err error
		pconn.conn, err = t.customDialTLS(ctx, "tcp", cm.addr())
		if err != nil {
			return nil, wrapErr(err)
		}
		if tc, ok := pconn.conn.(TLSConn); ok {
			if trace != nil && trace.TLSHandshakeStart != nil {
				trace.TLSHandshakeStart()
			}
			if err := tc.HandshakeContext(ctx); err != nil {
				go pconn.conn.Close()
				if trace != nil && trace.TLSHandshakeDone != nil {
					trace.TLSHandshakeDone(tls.ConnectionState{}, err)
				}
				return nil, err
			}
			cs := tc.ConnectionState()
			if trace != nil && trace.TLSHandshakeDone != nil {
				trace.TLSHandshakeDone(cs, nil)
			}
			pconn.tlsState = &cs
		}
	} else {
		conn, err := t.dial(ctx, "tcp", cm.addr())
		if err != nil {
			return nil, wrapErr(err)
		}
		pconn.conn = conn
		if cm.scheme() == "https" {
			var firstTLSHost string
			if firstTLSHost, _, err = net.SplitHostPort(cm.addr()); err != nil {
				return nil, wrapErr(err)
			}
			if err = pconn.addTLS(ctx, firstTLSHost, trace); err != nil {
				return nil, wrapErr(err)
			}
		}
	}

	switch {
	case cm.proxyURL == nil:
	case cm.proxyURL.Scheme == "socks5" || cm.proxyURL.Scheme == "socks5h":
		conn := pconn.conn
		d := socksNewDialer("tcp", conn.RemoteAddr().String())
		if u := cm.proxyURL.User; u != nil {
			auth := &socksUsernamePassword{
				Username: u.Username(),
			}
			auth.Password, _ = u.Password()
			d.AuthMethods = []socksAuthMethod{
				socksAuthMethodNotRequired,
				socksAuthMethodUsernamePassword,
			}
			d.Authenticate = auth.Authenticate
		}
		if _, err := d.DialWithConn(ctx, conn, "tcp", cm.targetAddr); err != nil {
			conn.Close()
			return nil, err
		}
	case cm.targetScheme == "http":
		pconn.isProxy = true
		if pa := cm.proxyAuth(); pa != "" {
			pconn.mutateHeaderFunc = func(h Header) {
				h.Set("Proxy-Authorization", pa)
			}
		}
	case cm.targetScheme == "https":
		conn := pconn.conn
		var hdr Header
		if t.GetProxyConnectHeader != nil {
			var err error
			hdr, err = t.GetProxyConnectHeader(ctx, cm.proxyURL, cm.targetAddr)
			if err != nil {
				conn.Close()
				return nil, err
			}
		} else {
			hdr = t.ProxyConnectHeader
		}
		if hdr == nil {
			hdr = make(Header)
		}
		if pa := cm.proxyAuth(); pa != "" {
			hdr = hdr.Clone()
			hdr.Set("Proxy-Authorization", pa)
		}
		connectReq := &Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: cm.targetAddr},
			Host:   cm.targetAddr,
			Header: hdr,
		}

		connectCtx, cancel := testHookProxyConnectTimeout(ctx, 1*time.Minute)
		defer cancel()

		didReadResponse := make(chan struct{})
		var (
			resp *Response
			err  error
		)
		go func() {
			defer close(didReadResponse)
			err = connectReq.Write(conn)
			if err != nil {
				return
			}
			br := bufio.NewReader(&io.LimitedReader{R: conn, N: t.maxHeaderResponseSize()})
			resp, err = ReadResponse(br, connectReq)
		}()
		select {
		case <-connectCtx.Done():
			conn.Close()
			<-didReadResponse
			return nil, connectCtx.Err()
		case <-didReadResponse:
		}
		if err != nil {
			conn.Close()
			return nil, err
		}

		if t.OnProxyConnectResponse != nil {
			err = t.OnProxyConnectResponse(ctx, cm.proxyURL, connectReq, resp)
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		if resp.StatusCode != 200 {
			_, text, ok := strings.Cut(resp.Status, " ")
			conn.Close()
			if !ok {
				return nil, errors.New("unknown status code")
			}
			return nil, errors.New(text)
		}
	}

	if cm.proxyURL != nil && cm.targetScheme == "https" {
		if err := pconn.addTLS(ctx, cm.tlsHost(), trace); err != nil {
			return nil, err
		}
	}

	unencryptedHTTP2 := t.Protocols != nil &&
		t.Protocols.UnencryptedHTTP2() &&
		!t.Protocols.HTTP1()

	if isClientConn && (unencryptedHTTP2 || (pconn.tlsState != nil && pconn.tlsState.NegotiatedProtocol == "h2")) {
		altProto, _ := t.altProto.Load().(map[string]RoundTripper)
		h2, ok := altProto["https"].(newClientConner)
		if !ok {
			return nil, errors.New("http: HTTP/2 implementation does not support NewClientConn (update golang.org/x/net?)")
		}
		if ctx.Done() != nil {
			nc := pconn.conn
			stop := contextAfterFunc(ctx, func() {
				_ = nc.Close()
			})
			defer func() {
				if !stop() {
					err = ctx.Err()
				}
			}()
		}
		var alt RoundTripper
		alt, err = h2.NewClientConn(pconn.conn, internalStateHook)
		if err != nil {
			pconn.conn.Close()
			return nil, err
		}
		return &persistConn{t: t, cacheKey: pconn.cacheKey, alt: alt, isClientConn: true}, nil
	}

	if unencryptedHTTP2 {
		next, ok := t.TLSNextProto[nextProtoUnencryptedHTTP2]
		if !ok {
			return nil, errors.New("http: Transport does not support unencrypted HTTP/2")
		}
		alt := next(cm.targetAddr, unencryptedTLSConn(pconn.conn))
		if e, ok := alt.(erringRoundTripper); ok {
			return nil, e.RoundTripErr()
		}
		return &persistConn{t: t, cacheKey: pconn.cacheKey, alt: alt}, nil
	}

	if s := pconn.tlsState; s != nil && s.NegotiatedProtocolIsMutual && s.NegotiatedProtocol != "" {
		if next, ok := t.TLSNextProto[s.NegotiatedProtocol]; ok {
			alt := next(cm.targetAddr, pconn.conn.(TLSConn))
			if e, ok := alt.(erringRoundTripper); ok {
				return nil, e.RoundTripErr()
			}
			return &persistConn{t: t, cacheKey: pconn.cacheKey, alt: alt}, nil
		}
	}

	pconn.br = bufio.NewReaderSize(pconn, t.readBufferSize())
	pconn.bw = bufio.NewWriterSize(persistConnWriter{pconn}, t.writeBufferSize())

	go pconn.readLoop()
	go pconn.writeLoop()
	return pconn, nil
}

type persistConnWriter struct {
	pc *persistConn
}

func (w persistConnWriter) Write(p []byte) (n int, err error) {
	n, err = w.pc.conn.Write(p)
	w.pc.nwrite += int64(n)
	return
}

func (w persistConnWriter) ReadFrom(r io.Reader) (n int64, err error) {
	n, err = io.Copy(w.pc.conn, r)
	w.pc.nwrite += n
	return
}

var _ io.ReaderFrom = (*persistConnWriter)(nil)

type connectMethod struct {
	_            incomparable
	proxyURL     *url.URL
	targetScheme string
	targetAddr string
	onlyH1     bool
}

func (cm *connectMethod) key() connectMethodKey {
	proxyStr := ""
	targetAddr := cm.targetAddr
	if cm.proxyURL != nil {
		proxyStr = cm.proxyURL.String()
		if (cm.proxyURL.Scheme == "http" || cm.proxyURL.Scheme == "https") && cm.targetScheme == "http" {
			targetAddr = ""
		}
	}
	return connectMethodKey{
		proxy:  proxyStr,
		scheme: cm.targetScheme,
		addr:   targetAddr,
		onlyH1: cm.onlyH1,
	}
}

func (cm *connectMethod) scheme() string {
	if cm.proxyURL != nil {
		return cm.proxyURL.Scheme
	}
	return cm.targetScheme
}

func (cm *connectMethod) addr() string {
	if cm.proxyURL != nil {
		return canonicalAddr(cm.proxyURL)
	}
	return cm.targetAddr
}

func (cm *connectMethod) tlsHost() string {
	h := cm.targetAddr
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}
	return h
}

type connectMethodKey struct {
	proxy, scheme, addr string
	onlyH1              bool
}

func (k connectMethodKey) String() string {
	var h1 string
	if k.onlyH1 {
		h1 = ",h1"
	}
	return fmt.Sprintf("%s|%s%s|%s", k.proxy, k.scheme, h1, k.addr)
}

type persistConn struct {
	alt RoundTripper

	t            *Transport
	cacheKey     connectMethodKey
	conn         net.Conn
	tlsState     *tls.ConnectionState
	br           *bufio.Reader
	bw           *bufio.Writer
	nwrite       int64
	reqch        chan requestAndChan
	writech      chan writeRequest
	closech      chan struct{}
	availch      chan struct{}
	isProxy      bool
	sawEOF       bool
	isClientConn bool
	readLimit    int64
	writeErrCh chan error

	writeLoopDone chan struct{}

	idleAt    time.Time
	idleTimer *time.Timer

	mu                   sync.Mutex
	numExpectedResponses int
	closed               error
	canceledErr          error
	reused               bool
	reserved             bool
	inFlight             bool
	internalStateHook    func()

	mutateHeaderFunc func(Header)
}

func (pc *persistConn) maxHeaderResponseSize() int64 {
	return pc.t.maxHeaderResponseSize()
}

func (pc *persistConn) Read(p []byte) (n int, err error) {
	if pc.readLimit <= 0 {
		return 0, fmt.Errorf("read limit of %d bytes exhausted", pc.maxHeaderResponseSize())
	}
	if int64(len(p)) > pc.readLimit {
		p = p[:pc.readLimit]
	}
	n, err = pc.conn.Read(p)
	if err == io.EOF {
		pc.sawEOF = true
	}
	pc.readLimit -= int64(n)
	return
}

func (pc *persistConn) isBroken() bool {
	pc.mu.Lock()
	b := pc.closed != nil
	pc.mu.Unlock()
	return b
}

func (pc *persistConn) canceled() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.canceledErr
}

func (pc *persistConn) isReused() bool {
	pc.mu.Lock()
	r := pc.reused
	pc.mu.Unlock()
	return r
}

func (pc *persistConn) cancelRequest(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.canceledErr = err
	pc.closeLocked(errRequestCanceled)
}

func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

func (pc *persistConn) mapRoundTripError(req *transportRequest, startBytesWritten int64, err error) error {
	if err == nil {
		return nil
	}

	<-pc.writeLoopDone

	if cerr := pc.canceled(); cerr != nil {
		return cerr
	}

	req.mu.Lock()
	reqErr := req.err
	req.mu.Unlock()
	if reqErr != nil {
		return reqErr
	}

	if err == errServerClosedIdle {
		return err
	}

	if _, ok := err.(transportReadFromServerError); ok {
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return err
	}
	if pc.isBroken() {
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", err)
	}
	return err
}

var errCallerOwnsConn = errors.New("read loop ending; caller owns writable underlying conn")

func (pc *persistConn) readLoop() {
	closeErr := errReadLoopExiting
	defer func() {
		pc.close(closeErr)
		pc.t.removeIdleConn(pc)
		if pc.internalStateHook != nil {
			pc.internalStateHook()
		}
	}()

	tryPutIdleConn := func(treq *transportRequest) bool {
		trace := treq.trace
		if err := pc.t.tryPutIdleConn(pc); err != nil {
			closeErr = err
			if trace != nil && trace.PutIdleConn != nil && err != errKeepAlivesDisabled {
				trace.PutIdleConn(err)
			}
			return false
		}
		if trace != nil && trace.PutIdleConn != nil {
			trace.PutIdleConn(nil)
		}
		return true
	}

	eofc := make(chan struct{})
	defer close(eofc)

	testHookMu.Lock()
	testHookReadLoopBeforeNextRead := testHookReadLoopBeforeNextRead
	testHookMu.Unlock()

	alive := true
	for alive {
		pc.readLimit = pc.maxHeaderResponseSize()
		_, err := pc.br.Peek(1)

		pc.mu.Lock()
		if pc.numExpectedResponses == 0 {
			pc.readLoopPeekFailLocked(err)
			pc.mu.Unlock()
			return
		}
		pc.mu.Unlock()

		rc := <-pc.reqch
		trace := rc.treq.trace

		var resp *Response
		if err == nil {
			resp, err = pc.readResponse(rc, trace)
		} else {
			err = transportReadFromServerError{err}
			closeErr = err
		}

		if err != nil {
			if pc.readLimit <= 0 {
				err = fmt.Errorf("net/http: server response headers exceeded %d bytes; aborted", pc.maxHeaderResponseSize())
			}

			select {
			case rc.ch <- responseAndError{err: err}:
			case <-rc.callerGone:
				return
			}
			return
		}
		pc.readLimit = maxInt64

		pc.mu.Lock()
		pc.numExpectedResponses--
		pc.mu.Unlock()

		bodyWritable := resp.bodyIsWritable()
		hasBody := rc.treq.Request.Method != "HEAD" && resp.ContentLength != 0

		if resp.Close || rc.treq.Request.Close || resp.StatusCode <= 199 || bodyWritable {
			alive = false
		}

		if !hasBody || bodyWritable {
			alive = alive &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(rc.treq)

			if bodyWritable {
				closeErr = errCallerOwnsConn
			}

			select {
			case rc.ch <- responseAndError{res: resp}:
			case <-rc.callerGone:
				return
			}

			rc.treq.cancel(errRequestDone)

			testHookReadLoopBeforeNextRead()
			continue
		}

		waitForBodyRead := make(chan bool, 2)
		body := &bodyEOFSignal{
			body: resp.Body,
			earlyCloseFn: func() error {
				waitForBodyRead <- false
				<-eofc
				return nil

			},
			fn: func(err error) error {
				isEOF := err == io.EOF
				waitForBodyRead <- isEOF
				if isEOF {
					<-eofc
				} else if err != nil {
					if cerr := pc.canceled(); cerr != nil {
						return cerr
					}
				}
				return err
			},
		}

		resp.Body = body
		if rc.addedGzip && ascii.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			resp.Body = &gzipReader{body: body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}

		select {
		case rc.ch <- responseAndError{res: resp}:
		case <-rc.callerGone:
			return
		}

		select {
		case bodyEOF := <-waitForBodyRead:
			alive = alive &&
				bodyEOF &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(rc.treq)
			if bodyEOF {
				eofc <- struct{}{}
			}
		case <-rc.treq.ctx.Done():
			alive = false
			pc.cancelRequest(context.Cause(rc.treq.ctx))
		case <-pc.closech:
			alive = false
		}

		rc.treq.cancel(errRequestDone)
		testHookReadLoopBeforeNextRead()
	}
}

func (pc *persistConn) readLoopPeekFailLocked(peekErr error) {
	if pc.closed != nil {
		return
	}
	if n := pc.br.Buffered(); n > 0 {
		buf, _ := pc.br.Peek(n)
		if is408Message(buf) {
			pc.closeLocked(errServerClosedIdle)
			return
		} else {
			log.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", buf, peekErr)
		}
	}
	if peekErr == io.EOF {
		pc.closeLocked(errServerClosedIdle)
	} else {
		pc.closeLocked(fmt.Errorf("readLoopPeekFailLocked: %w", peekErr))
	}
}

func is408Message(buf []byte) bool {
	if len(buf) < len("HTTP/1.x 408") {
		return false
	}
	if string(buf[:7]) != "HTTP/1." {
		return false
	}
	return string(buf[8:12]) == " 408"
}

func (pc *persistConn) readResponse(rc requestAndChan, trace *httptrace.ClientTrace) (resp *Response, err error) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := pc.br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}

	continueCh := rc.continueCh
	for {
		resp, err = ReadResponse(pc.br, rc.treq.Request)
		if err != nil {
			return
		}
		resCode := resp.StatusCode
		if continueCh != nil && resCode == StatusContinue {
			if trace != nil && trace.Got100Continue != nil {
				trace.Got100Continue()
			}
			continueCh <- struct{}{}
			continueCh = nil
		}
		is1xx := 100 <= resCode && resCode <= 199
		is1xxNonTerminal := is1xx && resCode != StatusSwitchingProtocols
		if is1xxNonTerminal {
			if trace != nil && trace.Got1xxResponse != nil {
				if err := trace.Got1xxResponse(resCode, textproto.MIMEHeader(resp.Header)); err != nil {
					return nil, err
				}
				pc.readLimit = pc.maxHeaderResponseSize()
			}
			continue
		}
		break
	}
	if resp.isProtocolSwitch() {
		resp.Body = newReadWriteCloserBody(pc.br, pc.conn)
	}
	if continueCh != nil {
		if resp.Close || rc.treq.Request.Close {
			close(continueCh)
		} else {
			continueCh <- struct{}{}
		}
	}

	resp.TLS = pc.tlsState
	return
}

func (pc *persistConn) waitForContinue(continueCh <-chan struct{}) func() bool {
	if continueCh == nil {
		return nil
	}
	return func() bool {
		timer := time.NewTimer(pc.t.ExpectContinueTimeout)
		defer timer.Stop()

		select {
		case _, ok := <-continueCh:
			return ok
		case <-timer.C:
			return true
		case <-pc.closech:
			return false
		}
	}
}

func newReadWriteCloserBody(br *bufio.Reader, rwc io.ReadWriteCloser) io.ReadWriteCloser {
	body := &readWriteCloserBody{ReadWriteCloser: rwc}
	if br.Buffered() != 0 {
		body.br = br
	}
	return body
}

type readWriteCloserBody struct {
	_  incomparable
	br *bufio.Reader
	io.ReadWriteCloser
}

func (b *readWriteCloserBody) Read(p []byte) (n int, err error) {
	if b.br != nil {
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.ReadWriteCloser.Read(p)
}

func (b *readWriteCloserBody) CloseWrite() error {
	if cw, ok := b.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("CloseWrite: %w", ErrNotSupported)
}

type nothingWrittenError struct {
	error
}

func (nwe nothingWrittenError) Unwrap() error {
	return nwe.error
}

func (pc *persistConn) writeLoop() {
	defer close(pc.writeLoopDone)
	for {
		select {
		case wr := <-pc.writech:
			startBytesWritten := pc.nwrite
			err := wr.req.Request.write(pc.bw, pc.isProxy, wr.req.extra, pc.waitForContinue(wr.continueCh))
			if bre, ok := err.(requestBodyReadError); ok {
				err = bre.error
				wr.req.setError(err)
			}
			if err == nil {
				err = pc.bw.Flush()
			}
			if err != nil {
				if pc.nwrite == startBytesWritten {
					err = nothingWrittenError{err}
				}
			}
			pc.writeErrCh <- err
			wr.ch <- err
			if err != nil {
				pc.close(err)
				return
			}
		case <-pc.closech:
			return
		}
	}
}

var maxWriteWaitBeforeConnReuse = 50 * time.Millisecond

func (pc *persistConn) wroteRequest() bool {
	select {
	case err := <-pc.writeErrCh:
		return err == nil
	default:
		t := time.NewTimer(maxWriteWaitBeforeConnReuse)
		defer t.Stop()
		select {
		case err := <-pc.writeErrCh:
			return err == nil
		case <-t.C:
			return false
		}
	}
}

type responseAndError struct {
	_   incomparable
	res *Response
	err error
}

type requestAndChan struct {
	_    incomparable
	treq *transportRequest
	ch   chan responseAndError

	addedGzip bool

	continueCh chan<- struct{}

	callerGone <-chan struct{}
}

type writeRequest struct {
	req *transportRequest
	ch  chan<- error

	continueCh <-chan struct{}
}

type timeoutError struct {
	err string
}

func (e *timeoutError) Error() string     { return e.err }
func (e *timeoutError) Timeout() bool     { return true }
func (e *timeoutError) Temporary() bool   { return true }
func (e *timeoutError) Is(err error) bool { return err == context.DeadlineExceeded }

var errTimeout error = &timeoutError{"net/http: timeout awaiting response headers"}

var errRequestCanceled = http2errRequestCanceled
var errRequestCanceledConn = errors.New("net/http: request canceled while waiting for connection")

var errRequestDone = errors.New("net/http: request completed")

func nop() {}

var (
	testHookEnterRoundTrip   = nop
	testHookWaitResLoop      = nop
	testHookRoundTripRetried = nop
	testHookPrePendingDial   = nop
	testHookPostPendingDial  = nop

	testHookMu                     sync.Locker = fakeLocker{}
	testHookReadLoopBeforeNextRead             = nop
)

func (pc *persistConn) waitForAvailability(ctx context.Context) error {
	select {
	case <-pc.availch:
		return nil
	case <-pc.closech:
		return pc.closed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (pc *persistConn) roundTrip(req *transportRequest) (resp *Response, err error) {
	testHookEnterRoundTrip()

	pc.mu.Lock()
	if pc.isClientConn {
		if !pc.reserved {
			pc.mu.Unlock()
			if err := pc.waitForAvailability(req.ctx); err != nil {
				return nil, err
			}
			pc.mu.Lock()
		}
		pc.reserved = false
		pc.inFlight = true
	}
	pc.numExpectedResponses++
	headerFn := pc.mutateHeaderFunc
	pc.mu.Unlock()

	if headerFn != nil {
		headerFn(req.extraHeaders())
	}

	requestedGzip := false
	if !pc.t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		requestedGzip = true
		req.extraHeaders().Set("Accept-Encoding", "gzip")
	}

	var continueCh chan struct{}
	if req.ProtoAtLeast(1, 1) && req.Body != nil && req.expectsContinue() {
		continueCh = make(chan struct{}, 1)
	}

	if pc.t.DisableKeepAlives &&
		!req.wantsClose() &&
		!isProtocolSwitchHeader(req.Header) {
		req.extraHeaders().Set("Connection", "close")
	}

	gone := make(chan struct{})
	defer close(gone)

	const debugRoundTrip = false

	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh, continueCh}

	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		treq:       req,
		ch:         resc,
		addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	handleResponse := func(re responseAndError) (*Response, error) {
		if (re.res == nil) == (re.err == nil) {
			panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
		}
		if debugRoundTrip {
			req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
		}
		if re.err != nil {
			return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
		}
		return re.res, nil
	}

	var respHeaderTimer <-chan time.Time
	ctxDoneChan := req.ctx.Done()
	pcClosed := pc.closech
	for {
		testHookWaitResLoop()
		select {
		case err := <-writeErrCh:
			if debugRoundTrip {
				req.logf("writeErrCh recv: %T/%#v", err, err)
			}
			if err != nil {
				pc.close(fmt.Errorf("write error: %w", err))
				return nil, pc.mapRoundTripError(req, startBytesWritten, err)
			}
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				if debugRoundTrip {
					req.logf("starting timer for %v", d)
				}
				timer := time.NewTimer(d)
				defer timer.Stop()
				respHeaderTimer = timer.C
			}
		case <-pcClosed:
			select {
			case re := <-resc:
				return handleResponse(re)
			default:
			}
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			return handleResponse(re)
		case <-ctxDoneChan:
			select {
			case re := <-resc:
				return handleResponse(re)
			default:
			}
			pc.cancelRequest(context.Cause(req.ctx))
		}
	}
}

type tLogKey struct{}

func (tr *transportRequest) logf(format string, args ...any) {
	if logf, ok := tr.Request.Context().Value(tLogKey{}).(func(string, ...any)); ok {
		logf(time.Now().Format(time.RFC3339Nano)+": "+format, args...)
	}
}

func (pc *persistConn) markReused() {
	pc.mu.Lock()
	pc.reused = true
	pc.mu.Unlock()
}

func (pc *persistConn) close(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.closeLocked(err)
}

func (pc *persistConn) closeLocked(err error) {
	if err == nil {
		panic("nil error")
	}
	if pc.closed == nil {
		pc.closed = err
		pc.t.decConnsPerHost(pc.cacheKey)
		if pc.alt == nil {
			if err != errCallerOwnsConn {
				pc.conn.Close()
			}
			close(pc.closech)
		}
	}
	pc.mutateHeaderFunc = nil
}

func schemePort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	default:
		return ""
	}
}

func idnaASCIIFromURL(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	return addr
}

func canonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = schemePort(url.Scheme)
	}
	return net.JoinHostPort(idnaASCIIFromURL(url), port)
}

type bodyEOFSignal struct {
	body         io.ReadCloser
	mu           sync.Mutex
	closed       bool
	rerr         error
	fn           func(error) error
	earlyCloseFn func() error
}

var errReadOnClosedResBody = errors.New("http: read on closed response body")
var errConcurrentReadOnResBody = errors.New("http: concurrent read on response body")

func (es *bodyEOFSignal) Read(p []byte) (n int, err error) {
	es.mu.Lock()
	closed, rerr := es.closed, es.rerr
	es.mu.Unlock()
	if closed {
		return 0, errReadOnClosedResBody
	}
	if rerr != nil {
		return 0, rerr
	}

	n, err = es.body.Read(p)
	if err != nil {
		es.mu.Lock()
		defer es.mu.Unlock()
		if es.rerr == nil {
			es.rerr = err
		}
		err = es.condfn(err)
	}
	return
}

func (es *bodyEOFSignal) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.closed {
		return nil
	}
	es.closed = true
	if es.earlyCloseFn != nil && es.rerr != io.EOF {
		return es.earlyCloseFn()
	}
	err := es.body.Close()
	return es.condfn(err)
}

func (es *bodyEOFSignal) condfn(err error) error {
	if es.fn == nil {
		return err
	}
	err = es.fn(err)
	es.fn = nil
	return err
}

type gzipReader struct {
	_    incomparable
	body *bodyEOFSignal
	mu   sync.Mutex
	zr   *gzip.Reader
	zerr error
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
func (eofReader) ReadByte() (byte, error)  { return 0, io.EOF }

var gzipPool = sync.Pool{New: func() any { return new(gzip.Reader) }}

func gzipPoolGet(r io.Reader) (*gzip.Reader, error) {
	zr := gzipPool.Get().(*gzip.Reader)
	if err := zr.Reset(r); err != nil {
		gzipPoolPut(zr)
		return nil, err
	}
	return zr, nil
}

func gzipPoolPut(zr *gzip.Reader) {
	var r flate.Reader = eofReader{}
	zr.Reset(r)
	gzipPool.Put(zr)
}

func (gz *gzipReader) acquire() (*gzip.Reader, error) {
	gz.mu.Lock()
	defer gz.mu.Unlock()
	if gz.zerr != nil {
		return nil, gz.zerr
	}
	if gz.zr == nil {
		gz.zr, gz.zerr = gzipPoolGet(gz.body)
		if gz.zerr != nil {
			return nil, gz.zerr
		}
	}
	ret := gz.zr
	gz.zr, gz.zerr = nil, errConcurrentReadOnResBody
	return ret, nil
}

func (gz *gzipReader) release(zr *gzip.Reader) {
	gz.mu.Lock()
	defer gz.mu.Unlock()
	if gz.zerr == errConcurrentReadOnResBody {
		gz.zr, gz.zerr = zr, nil
	} else {
		gzipPoolPut(zr)
	}
}

func (gz *gzipReader) close() {
	gz.mu.Lock()
	defer gz.mu.Unlock()
	if gz.zerr == nil && gz.zr != nil {
		gzipPoolPut(gz.zr)
		gz.zr = nil
	}
	gz.zerr = errReadOnClosedResBody
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	zr, err := gz.acquire()
	if err != nil {
		return 0, err
	}
	defer gz.release(zr)

	return zr.Read(p)
}

func (gz *gzipReader) Close() error {
	gz.close()

	return gz.body.Close()
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

type fakeLocker struct{}

func (fakeLocker) Lock()   {}
func (fakeLocker) Unlock() {}

// cloneTLSConfig returns a shallow clone of cfg, or a new zero tls.Config if
// cfg is nil. This is safe to call even if cfg is in active use by a TLS
// client or server.
//
// cloneTLSConfig should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/searKing/golang
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname cloneTLSConfig
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

type connLRU struct {
	ll *list.List
	m  map[*persistConn]*list.Element
}

func (cl *connLRU) add(pc *persistConn) {
	if cl.ll == nil {
		cl.ll = list.New()
		cl.m = make(map[*persistConn]*list.Element)
	}
	ele := cl.ll.PushFront(pc)
	if _, ok := cl.m[pc]; ok {
		panic("persistConn was already in LRU")
	}
	cl.m[pc] = ele
}

func (cl *connLRU) removeOldest() *persistConn {
	ele := cl.ll.Back()
	pc := ele.Value.(*persistConn)
	cl.ll.Remove(ele)
	delete(cl.m, pc)
	return pc
}

func (cl *connLRU) remove(pc *persistConn) {
	if ele, ok := cl.m[pc]; ok {
		cl.ll.Remove(ele)
		delete(cl.m, pc)
	}
}

func (cl *connLRU) len() int {
	return len(cl.m)
}
