// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.



package http2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/internal/httpcommon"
	"github.com/metacubex/tls"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

const (
	prefaceTimeout        = 10 * time.Second
	firstSettingsTimeout  = 2 * time.Second
	handlerChunkWriteSize = 4 << 10
	defaultMaxStreams     = 250

	maxQueuedControlFrames = 10000
)

var (
	errClientDisconnected = errors.New("client disconnected")
	errClosedBody         = errors.New("body closed by handler")
	errHandlerComplete    = errors.New("http2: request body closed due to handler exiting")
	errStreamClosed       = errors.New("http2: stream closed")
)

var responseWriterStatePool = sync.Pool{
	New: func() interface{} {
		rws := &responseWriterState{}
		rws.bw = bufio.NewWriterSize(chunkWriter{rws}, handlerChunkWriteSize)
		return rws
	},
}

var (
	testHookOnConn        func()
	testHookGetServerConn func(*serverConn)
	testHookOnPanicMu     *sync.Mutex
	testHookOnPanic       func(sc *serverConn, panicVal interface{}) (rePanic bool)
)

type Server struct {
	MaxHandlers int

	MaxConcurrentStreams uint32

	MaxDecoderHeaderTableSize uint32

	MaxEncoderHeaderTableSize uint32

	MaxReadFrameSize uint32

	PermitProhibitedCipherSuites bool

	IdleTimeout time.Duration

	ReadIdleTimeout time.Duration

	PingTimeout time.Duration

	WriteByteTimeout time.Duration

	MaxUploadBufferPerConnection int32

	MaxUploadBufferPerStream int32

	NewWriteScheduler func() WriteScheduler

	CountError func(errType string)

	state *serverInternalState
}

type serverInternalState struct {
	mu          sync.Mutex
	activeConns map[*serverConn]struct{}

	errChanPool sync.Pool
}

func (s *serverInternalState) registerConn(sc *serverConn) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.activeConns[sc] = struct{}{}
	s.mu.Unlock()
}

func (s *serverInternalState) unregisterConn(sc *serverConn) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.activeConns, sc)
	s.mu.Unlock()
}

func (s *serverInternalState) startGracefulShutdown() {
	if s == nil {
		return
	}
	s.mu.Lock()
	for sc := range s.activeConns {
		sc.startGracefulShutdown()
	}
	s.mu.Unlock()
}

var errChanPool = sync.Pool{
	New: func() any { return make(chan error, 1) },
}

func (s *serverInternalState) getErrChan() chan error {
	if s == nil {
		return errChanPool.Get().(chan error)
	}
	return s.errChanPool.Get().(chan error)
}

func (s *serverInternalState) putErrChan(ch chan error) {
	if s == nil {
		errChanPool.Put(ch)
		return
	}
	s.errChanPool.Put(ch)
}

func ConfigureServer(s *http.Server, conf *Server) error {
	if s == nil {
		panic("nil *http.Server")
	}
	if conf == nil {
		conf = new(Server)
	}
	conf.state = &serverInternalState{
		activeConns: make(map[*serverConn]struct{}),
		errChanPool: sync.Pool{New: func() any { return make(chan error, 1) }},
	}
	if h1, h2 := s, conf; h2.IdleTimeout == 0 {
		if h1.IdleTimeout != 0 {
			h2.IdleTimeout = h1.IdleTimeout
		} else {
			h2.IdleTimeout = h1.ReadTimeout
		}
	}
	s.RegisterOnShutdown(conf.state.startGracefulShutdown)

	if s.TLSConfig == nil {
		s.TLSConfig = new(tls.Config)
	} else if s.TLSConfig.CipherSuites != nil && s.TLSConfig.MinVersion < tls.VersionTLS13 {
		haveRequired := false
		for _, cs := range s.TLSConfig.CipherSuites {
			switch cs {
			case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
				haveRequired = true
			}
		}
		if !haveRequired {
			return fmt.Errorf("http2: TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher (need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)")
		}
	}


	s.TLSConfig.PreferServerCipherSuites = true

	if !strSliceContains(s.TLSConfig.NextProtos, NextProtoTLS) {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, NextProtoTLS)
	}
	if !strSliceContains(s.TLSConfig.NextProtos, "http/1.1") {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "http/1.1")
	}

	if s.TLSNextProto == nil {
		s.TLSNextProto = map[string]func(*http.Server, http.TLSConn, http.Handler){}
	}
	protoHandler := func(hs *http.Server, c net.Conn, h http.Handler, sawClientPreface bool) {
		if testHookOnConn != nil {
			testHookOnConn()
		}
		var ctx context.Context
		type baseContexter interface {
			BaseContext() context.Context
		}
		if bc, ok := h.(baseContexter); ok {
			ctx = bc.BaseContext()
		}
		conf.ServeConn(c, &ServeConnOpts{
			Context:          ctx,
			Handler:          h,
			BaseConfig:       hs,
			SawClientPreface: sawClientPreface,
		})
	}
	s.TLSNextProto[NextProtoTLS] = func(hs *http.Server, c http.TLSConn, h http.Handler) {
		protoHandler(hs, c, h, false)
	}
	s.TLSNextProto[nextProtoUnencryptedHTTP2] = func(hs *http.Server, c http.TLSConn, h http.Handler) {
		nc, err := unencryptedNetConnFromTLSConn(c)
		if err != nil {
			if lg := hs.ErrorLog; lg != nil {
				lg.Print(err)
			} else {
				log.Print(err)
			}
			go c.Close()
			return
		}
		protoHandler(hs, nc, h, true)
	}
	return nil
}

type ServeConnOpts struct {
	Context context.Context

	BaseConfig *http.Server

	Handler http.Handler

	UpgradeRequest *http.Request

	Settings []byte

	SawClientPreface bool
}

func (o *ServeConnOpts) context() context.Context {
	if o != nil && o.Context != nil {
		return o.Context
	}
	return context.Background()
}

func (o *ServeConnOpts) baseConfig() *http.Server {
	if o != nil && o.BaseConfig != nil {
		return o.BaseConfig
	}
	return new(http.Server)
}

func (o *ServeConnOpts) handler() http.Handler {
	if o != nil {
		if o.Handler != nil {
			return o.Handler
		}
		if o.BaseConfig != nil && o.BaseConfig.Handler != nil {
			return o.BaseConfig.Handler
		}
	}
	return http.DefaultServeMux
}

func (s *Server) ServeConn(c net.Conn, opts *ServeConnOpts) {
	if opts == nil {
		opts = &ServeConnOpts{}
	}
	s.serveConn(c, opts, nil)
}

func (s *Server) serveConn(c net.Conn, opts *ServeConnOpts, newf func(*serverConn)) {
	baseCtx, cancel := serverConnBaseContext(c, opts)
	defer cancel()

	http1srv := opts.baseConfig()
	conf := configFromServer(http1srv, s)
	sc := &serverConn{
		srv:                         s,
		hs:                          http1srv,
		conn:                        c,
		baseCtx:                     baseCtx,
		remoteAddrStr:               c.RemoteAddr().String(),
		bw:                          newBufferedWriter(c, conf.WriteByteTimeout),
		handler:                     opts.handler(),
		streams:                     make(map[uint32]*stream),
		readFrameCh:                 make(chan readFrameResult),
		wantWriteFrameCh:            make(chan FrameWriteRequest, 8),
		serveMsgCh:                  make(chan interface{}, 8),
		wroteFrameCh:                make(chan frameWriteResult, 1),
		bodyReadCh:                  make(chan bodyReadMsg),
		doneServing:                 make(chan struct{}),
		clientMaxStreams:            math.MaxUint32,
		advMaxStreams:               conf.MaxConcurrentStreams,
		initialStreamSendWindowSize: initialWindowSize,
		initialStreamRecvWindowSize: conf.MaxUploadBufferPerStream,
		maxFrameSize:                initialMaxFrameSize,
		pingTimeout:                 conf.PingTimeout,
		countErrorFunc:              conf.CountError,
		serveG:                      newGoroutineLock(),
		pushEnabled:                 true,
		sawClientPreface:            opts.SawClientPreface,
	}
	if newf != nil {
		newf(sc)
	}

	s.state.registerConn(sc)
	defer s.state.unregisterConn(sc)

	if sc.hs.WriteTimeout > 0 {
		sc.conn.SetWriteDeadline(time.Time{})
	}

	if s.NewWriteScheduler != nil {
		sc.writeSched = s.NewWriteScheduler()
	} else {
		sc.writeSched = newRoundRobinWriteScheduler()
	}

	sc.flow.add(initialWindowSize)
	sc.inflow.init(initialWindowSize)
	sc.hpackEncoder = hpack.NewEncoder(&sc.headerWriteBuf)
	sc.hpackEncoder.SetMaxDynamicTableSizeLimit(conf.MaxEncoderHeaderTableSize)

	fr := NewFramer(sc.bw, c)
	if conf.CountError != nil {
		fr.countError = conf.CountError
	}
	fr.ReadMetaHeaders = hpack.NewDecoder(conf.MaxDecoderHeaderTableSize, nil)
	fr.MaxHeaderListSize = sc.maxHeaderListSize()
	fr.SetMaxReadFrameSize(conf.MaxReadFrameSize)
	sc.framer = fr

	if tc, ok := c.(connectionStater); ok {
		sc.tlsState = new(tls.ConnectionState)
		*sc.tlsState = tc.ConnectionState()
		if sc.tlsState.Version < tls.VersionTLS12 {
			sc.rejectConn(ErrCodeInadequateSecurity, "TLS version too low")
			return
		}

		if sc.tlsState.ServerName == "" {
		}

		if !conf.PermitProhibitedCipherSuites && isBadCipher(sc.tlsState.CipherSuite) {
			sc.rejectConn(ErrCodeInadequateSecurity, fmt.Sprintf("Prohibited TLS 1.2 Cipher Suite: %x", sc.tlsState.CipherSuite))
			return
		}
	}

	if opts.Settings != nil {
		fr := &SettingsFrame{
			FrameHeader: FrameHeader{valid: true},
			p:           opts.Settings,
		}
		if err := fr.ForeachSetting(sc.processSetting); err != nil {
			sc.rejectConn(ErrCodeProtocol, "invalid settings")
			return
		}
		opts.Settings = nil
	}

	if hook := testHookGetServerConn; hook != nil {
		hook(sc)
	}

	if opts.UpgradeRequest != nil {
		sc.upgradeRequest(opts.UpgradeRequest)
		opts.UpgradeRequest = nil
	}

	sc.serve(conf)
}

func serverConnBaseContext(c net.Conn, opts *ServeConnOpts) (ctx context.Context, cancel func()) {
	ctx, cancel = context.WithCancel(opts.context())
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, c.LocalAddr())
	if hs := opts.baseConfig(); hs != nil {
		ctx = context.WithValue(ctx, http.ServerContextKey, hs)
	}
	return
}

func (sc *serverConn) rejectConn(err ErrCode, debug string) {
	sc.vlogf("http2: server rejecting conn: %v, %s", err, debug)
	sc.framer.WriteGoAway(0, err, []byte(debug))
	sc.bw.Flush()
	sc.conn.Close()
}

type serverConn struct {
	srv              *Server
	hs               *http.Server
	conn             net.Conn
	bw               *bufferedWriter
	handler          http.Handler
	baseCtx          context.Context
	framer           *Framer
	doneServing      chan struct{}
	readFrameCh      chan readFrameResult
	wantWriteFrameCh chan FrameWriteRequest
	wroteFrameCh     chan frameWriteResult
	bodyReadCh       chan bodyReadMsg
	serveMsgCh       chan interface{}
	flow             outflow
	inflow           inflow
	tlsState         *tls.ConnectionState
	remoteAddrStr    string
	writeSched       WriteScheduler
	countErrorFunc   func(errType string)

	serveG                      goroutineLock
	pushEnabled                 bool
	sawClientPreface            bool
	sawFirstSettings            bool
	needToSendSettingsAck       bool
	unackedSettings             int
	queuedControlFrames         int
	clientMaxStreams            uint32
	advMaxStreams               uint32
	curClientStreams            uint32
	curPushedStreams            uint32
	curHandlers                 uint32
	maxClientStreamID           uint32
	maxPushPromiseID            uint32
	streams                     map[uint32]*stream
	unstartedHandlers           []unstartedHandler
	initialStreamSendWindowSize int32
	initialStreamRecvWindowSize int32
	maxFrameSize                int32
	peerMaxHeaderListSize       uint32
	canonHeader                 map[string]string
	canonHeaderKeysSize         int
	writingFrame                bool
	writingFrameAsync           bool
	needsFrameFlush             bool
	inGoAway                    bool
	inFrameScheduleLoop         bool
	needToSendGoAway            bool
	pingSent                    bool
	sentPingData                [8]byte
	goAwayCode                  ErrCode
	shutdownTimer               *time.Timer
	idleTimer                   *time.Timer
	readIdleTimeout             time.Duration
	pingTimeout                 time.Duration
	readIdleTimer               *time.Timer

	headerWriteBuf bytes.Buffer
	hpackEncoder   *hpack.Encoder

	shutdownOnce sync.Once
}

func (sc *serverConn) maxHeaderListSize() uint32 {
	n := sc.hs.MaxHeaderBytes
	if n <= 0 {
		n = http.DefaultMaxHeaderBytes
	}
	return uint32(adjustHTTP1MaxHeaderSize(int64(n)))
}

func (sc *serverConn) curOpenStreams() uint32 {
	sc.serveG.check()
	return sc.curClientStreams + sc.curPushedStreams
}

type stream struct {
	sc        *serverConn
	id        uint32
	body      *pipe
	cw        closeWaiter
	ctx       context.Context
	cancelCtx func()

	bodyBytes        int64
	declBodyBytes    int64
	flow             outflow
	inflow           inflow
	state            streamState
	resetQueued      bool
	gotTrailerHeader bool
	wroteHeaders     bool
	readDeadline     *time.Timer
	writeDeadline    *time.Timer
	closeErr         error

	trailer    http.Header
	reqTrailer http.Header
}

func (sc *serverConn) Framer() *Framer  { return sc.framer }
func (sc *serverConn) CloseConn() error { return sc.conn.Close() }
func (sc *serverConn) Flush() error     { return sc.bw.Flush() }
func (sc *serverConn) HeaderEncoder() (*hpack.Encoder, *bytes.Buffer) {
	return sc.hpackEncoder, &sc.headerWriteBuf
}

func (sc *serverConn) state(streamID uint32) (streamState, *stream) {
	sc.serveG.check()
	if st, ok := sc.streams[streamID]; ok {
		return st.state, st
	}
	if streamID%2 == 1 {
		if streamID <= sc.maxClientStreamID {
			return stateClosed, nil
		}
	} else {
		if streamID <= sc.maxPushPromiseID {
			return stateClosed, nil
		}
	}
	return stateIdle, nil
}

func (sc *serverConn) setConnState(state http.ConnState) {
	if sc.hs.ConnState != nil {
		sc.hs.ConnState(sc.conn, state)
	}
}

func (sc *serverConn) vlogf(format string, args ...interface{}) {
	if VerboseLogs {
		sc.logf(format, args...)
	}
}

func (sc *serverConn) logf(format string, args ...interface{}) {
	if lg := sc.hs.ErrorLog; lg != nil {
		lg.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func errno(v error) uintptr {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Uintptr {
		return uintptr(rv.Uint())
	}
	return 0
}

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, net.ErrClosed) {
		return true
	}

	if runtime.GOOS == "windows" {
		if oe, ok := err.(*net.OpError); ok && oe.Op == "read" {
			if se, ok := oe.Err.(*os.SyscallError); ok && se.Syscall == "wsarecv" {
				const WSAECONNABORTED = 10053
				const WSAECONNRESET = 10054
				if n := errno(se.Err); n == WSAECONNRESET || n == WSAECONNABORTED {
					return true
				}
			}
		}
	}
	return false
}

func (sc *serverConn) condlogf(err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF || isClosedConnError(err) || err == errPrefaceTimeout {
		sc.vlogf(format, args...)
	} else {
		sc.logf(format, args...)
	}
}

const maxCachedCanonicalHeadersKeysSize = 2048

func (sc *serverConn) canonicalHeader(v string) string {
	sc.serveG.check()
	cv, ok := httpcommon.CachedCanonicalHeader(v)
	if ok {
		return cv
	}
	cv, ok = sc.canonHeader[v]
	if ok {
		return cv
	}
	if sc.canonHeader == nil {
		sc.canonHeader = make(map[string]string)
	}
	cv = http.CanonicalHeaderKey(v)
	size := 100 + len(v)*2
	if sc.canonHeaderKeysSize+size <= maxCachedCanonicalHeadersKeysSize {
		sc.canonHeader[v] = cv
		sc.canonHeaderKeysSize += size
	}
	return cv
}

type readFrameResult struct {
	f   Frame
	err error

	readMore func()
}

func (sc *serverConn) readFrames() {
	gate := make(chan struct{})
	gateDone := func() { gate <- struct{}{} }
	for {
		f, err := sc.framer.ReadFrame()
		select {
		case sc.readFrameCh <- readFrameResult{f, err, gateDone}:
		case <-sc.doneServing:
			return
		}
		select {
		case <-gate:
		case <-sc.doneServing:
			return
		}
		if terminalReadFrameError(err) {
			return
		}
	}
}

type frameWriteResult struct {
	_   incomparable
	wr  FrameWriteRequest
	err error
}

func (sc *serverConn) writeFrameAsync(wr FrameWriteRequest, wd *writeData) {
	var err error
	if wd == nil {
		err = wr.write.writeFrame(sc)
	} else {
		err = sc.framer.endWrite()
	}
	sc.wroteFrameCh <- frameWriteResult{wr: wr, err: err}
}

func (sc *serverConn) closeAllStreamsOnConnClose() {
	sc.serveG.check()
	for _, st := range sc.streams {
		sc.closeStream(st, errClientDisconnected)
	}
}

func (sc *serverConn) stopShutdownTimer() {
	sc.serveG.check()
	if t := sc.shutdownTimer; t != nil {
		t.Stop()
	}
}

func (sc *serverConn) notePanic() {
	if testHookOnPanicMu != nil {
		testHookOnPanicMu.Lock()
		defer testHookOnPanicMu.Unlock()
	}
	if testHookOnPanic != nil {
		if e := recover(); e != nil {
			if testHookOnPanic(sc, e) {
				panic(e)
			}
		}
	}
}

func (sc *serverConn) serve(conf http2Config) {
	sc.serveG.check()
	defer sc.notePanic()
	defer sc.conn.Close()
	defer sc.closeAllStreamsOnConnClose()
	defer sc.stopShutdownTimer()
	defer close(sc.doneServing)

	if VerboseLogs {
		sc.vlogf("http2: server connection from %v on %p", sc.conn.RemoteAddr(), sc.hs)
	}

	settings := writeSettings{
		{SettingMaxFrameSize, conf.MaxReadFrameSize},
		{SettingMaxConcurrentStreams, sc.advMaxStreams},
		{SettingMaxHeaderListSize, sc.maxHeaderListSize()},
		{SettingHeaderTableSize, conf.MaxDecoderHeaderTableSize},
		{SettingInitialWindowSize, uint32(sc.initialStreamRecvWindowSize)},
	}
	if !disableExtendedConnectProtocol {
		settings = append(settings, Setting{SettingEnableConnectProtocol, 1})
	}
	sc.writeFrame(FrameWriteRequest{
		write: settings,
	})
	sc.unackedSettings++

	if diff := conf.MaxUploadBufferPerConnection - initialWindowSize; diff > 0 {
		sc.sendWindowUpdate(nil, int(diff))
	}

	if err := sc.readPreface(); err != nil {
		sc.condlogf(err, "http2: server: error reading preface from client %v: %v", sc.conn.RemoteAddr(), err)
		return
	}
	sc.setConnState(http.StateActive)
	sc.setConnState(http.StateIdle)

	if sc.srv.IdleTimeout > 0 {
		sc.idleTimer = time.AfterFunc(sc.srv.IdleTimeout, sc.onIdleTimer)
		defer sc.idleTimer.Stop()
	}

	if conf.SendPingTimeout > 0 {
		sc.readIdleTimeout = conf.SendPingTimeout
		sc.readIdleTimer = time.AfterFunc(conf.SendPingTimeout, sc.onReadIdleTimer)
		defer sc.readIdleTimer.Stop()
	}

	go sc.readFrames()

	settingsTimer := time.AfterFunc(firstSettingsTimeout, sc.onSettingsTimer)
	defer settingsTimer.Stop()

	lastFrameTime := time.Now()
	loopNum := 0
	for {
		loopNum++
		select {
		case wr := <-sc.wantWriteFrameCh:
			if se, ok := wr.write.(StreamError); ok {
				sc.resetStream(se)
				break
			}
			sc.writeFrame(wr)
		case res := <-sc.wroteFrameCh:
			sc.wroteFrame(res)
		case res := <-sc.readFrameCh:
			lastFrameTime = time.Now()
			if sc.writingFrameAsync {
				select {
				case wroteRes := <-sc.wroteFrameCh:
					sc.wroteFrame(wroteRes)
				default:
				}
			}
			if !sc.processFrameFromReader(res) {
				return
			}
			res.readMore()
			if settingsTimer != nil {
				settingsTimer.Stop()
				settingsTimer = nil
			}
		case m := <-sc.bodyReadCh:
			sc.noteBodyRead(m.st, m.n)
		case msg := <-sc.serveMsgCh:
			switch v := msg.(type) {
			case func(int):
				v(loopNum)
			case *serverMessage:
				switch v {
				case settingsTimerMsg:
					sc.logf("timeout waiting for SETTINGS frames from %v", sc.conn.RemoteAddr())
					return
				case idleTimerMsg:
					sc.vlogf("connection is idle")
					sc.goAway(ErrCodeNo)
				case readIdleTimerMsg:
					sc.handlePingTimer(lastFrameTime)
				case shutdownTimerMsg:
					sc.vlogf("GOAWAY close timer fired; closing conn from %v", sc.conn.RemoteAddr())
					return
				case gracefulShutdownMsg:
					sc.startGracefulShutdownInternal()
				case handlerDoneMsg:
					sc.handlerDone()
				default:
					panic("unknown timer")
				}
			case *startPushRequest:
				sc.startPush(v)
			case func(*serverConn):
				v(sc)
			default:
				panic(fmt.Sprintf("unexpected type %T", v))
			}
		}

		if sc.queuedControlFrames > maxQueuedControlFrames {
			sc.vlogf("http2: too many control frames in send queue, closing connection")
			return
		}

		sentGoAway := sc.inGoAway && !sc.needToSendGoAway && !sc.writingFrame
		gracefulShutdownComplete := sc.goAwayCode == ErrCodeNo && sc.curOpenStreams() == 0
		if sentGoAway && sc.shutdownTimer == nil && (sc.goAwayCode != ErrCodeNo || gracefulShutdownComplete) {
			sc.shutDownIn(goAwayTimeout)
		}
	}
}

func (sc *serverConn) handlePingTimer(lastFrameReadTime time.Time) {
	if sc.pingSent {
		sc.logf("timeout waiting for PING response")
		if f := sc.countErrorFunc; f != nil {
			f("conn_close_lost_ping")
		}
		sc.conn.Close()
		return
	}

	pingAt := lastFrameReadTime.Add(sc.readIdleTimeout)
	now := time.Now()
	if pingAt.After(now) {
		sc.readIdleTimer.Reset(pingAt.Sub(now))
		return
	}

	sc.pingSent = true
	_, _ = rand.Read(sc.sentPingData[:])
	sc.writeFrame(FrameWriteRequest{
		write: &writePing{data: sc.sentPingData},
	})
	sc.readIdleTimer.Reset(sc.pingTimeout)
}

type serverMessage int

var (
	settingsTimerMsg    = new(serverMessage)
	idleTimerMsg        = new(serverMessage)
	readIdleTimerMsg    = new(serverMessage)
	shutdownTimerMsg    = new(serverMessage)
	gracefulShutdownMsg = new(serverMessage)
	handlerDoneMsg      = new(serverMessage)
)

func (sc *serverConn) onSettingsTimer() { sc.sendServeMsg(settingsTimerMsg) }
func (sc *serverConn) onIdleTimer()     { sc.sendServeMsg(idleTimerMsg) }
func (sc *serverConn) onReadIdleTimer() { sc.sendServeMsg(readIdleTimerMsg) }
func (sc *serverConn) onShutdownTimer() { sc.sendServeMsg(shutdownTimerMsg) }

func (sc *serverConn) sendServeMsg(msg interface{}) {
	sc.serveG.checkNotOn()
	select {
	case sc.serveMsgCh <- msg:
	case <-sc.doneServing:
	}
}

var errPrefaceTimeout = errors.New("timeout waiting for client preface")

func (sc *serverConn) readPreface() error {
	if sc.sawClientPreface {
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, len(ClientPreface))
		if _, err := io.ReadFull(sc.conn, buf); err != nil {
			errc <- err
		} else if !bytes.Equal(buf, clientPreface) {
			errc <- fmt.Errorf("bogus greeting %q", buf)
		} else {
			errc <- nil
		}
	}()
	timer := time.NewTimer(prefaceTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		return errPrefaceTimeout
	case err := <-errc:
		if err == nil {
			if VerboseLogs {
				sc.vlogf("http2: server: client %v said hello", sc.conn.RemoteAddr())
			}
		}
		return err
	}
}

var writeDataPool = sync.Pool{
	New: func() interface{} { return new(writeData) },
}

func (sc *serverConn) writeDataFromHandler(stream *stream, data []byte, endStream bool) error {
	ch := sc.srv.state.getErrChan()
	writeArg := writeDataPool.Get().(*writeData)
	*writeArg = writeData{stream.id, data, endStream}
	err := sc.writeFrameFromHandler(FrameWriteRequest{
		write:  writeArg,
		stream: stream,
		done:   ch,
	})
	if err != nil {
		return err
	}
	var frameWriteDone bool
	select {
	case err = <-ch:
		frameWriteDone = true
	case <-sc.doneServing:
		return errClientDisconnected
	case <-stream.cw:
		select {
		case err = <-ch:
			frameWriteDone = true
		default:
			return errStreamClosed
		}
	}
	sc.srv.state.putErrChan(ch)
	if frameWriteDone {
		writeDataPool.Put(writeArg)
	}
	return err
}

func (sc *serverConn) writeFrameFromHandler(wr FrameWriteRequest) error {
	sc.serveG.checkNotOn()
	select {
	case sc.wantWriteFrameCh <- wr:
		return nil
	case <-sc.doneServing:
		return errClientDisconnected
	}
}

func (sc *serverConn) writeFrame(wr FrameWriteRequest) {
	sc.serveG.check()

	var ignoreWrite bool

	if wr.StreamID() != 0 {
		_, isReset := wr.write.(StreamError)
		if state, _ := sc.state(wr.StreamID()); state == stateClosed && !isReset {
			ignoreWrite = true
		}
	}

	switch wr.write.(type) {
	case *writeResHeaders:
		wr.stream.wroteHeaders = true
	case write100ContinueHeadersFrame:
		if wr.stream.wroteHeaders {
			if wr.done != nil {
				panic("wr.done != nil for write100ContinueHeadersFrame")
			}
			ignoreWrite = true
		}
	}

	if !ignoreWrite {
		if wr.isControl() {
			sc.queuedControlFrames++
			if sc.queuedControlFrames < 0 {
				sc.conn.Close()
			}
		}
		sc.writeSched.Push(wr)
	}
	sc.scheduleFrameWrite()
}

func (sc *serverConn) startFrameWrite(wr FrameWriteRequest) {
	sc.serveG.check()
	if sc.writingFrame {
		panic("internal error: can only be writing one frame at a time")
	}

	st := wr.stream
	if st != nil {
		switch st.state {
		case stateHalfClosedLocal:
			switch wr.write.(type) {
			case StreamError, handlerPanicRST, writeWindowUpdate:
			default:
				panic(fmt.Sprintf("internal error: attempt to send frame on a half-closed-local stream: %v", wr))
			}
		case stateClosed:
			panic(fmt.Sprintf("internal error: attempt to send frame on a closed stream: %v", wr))
		}
	}
	if wpp, ok := wr.write.(*writePushPromise); ok {
		var err error
		wpp.promisedID, err = wpp.allocatePromisedID()
		if err != nil {
			sc.writingFrameAsync = false
			wr.replyToWriter(err)
			return
		}
	}

	sc.writingFrame = true
	sc.needsFrameFlush = true
	if wr.write.staysWithinBuffer(sc.bw.Available()) {
		sc.writingFrameAsync = false
		err := wr.write.writeFrame(sc)
		sc.wroteFrame(frameWriteResult{wr: wr, err: err})
	} else if wd, ok := wr.write.(*writeData); ok {
		sc.framer.startWriteDataPadded(wd.streamID, wd.endStream, wd.p, nil)
		sc.writingFrameAsync = true
		go sc.writeFrameAsync(wr, wd)
	} else {
		sc.writingFrameAsync = true
		go sc.writeFrameAsync(wr, nil)
	}
}

var errHandlerPanicked = errors.New("http2: handler panicked")

func (sc *serverConn) wroteFrame(res frameWriteResult) {
	sc.serveG.check()
	if !sc.writingFrame {
		panic("internal error: expected to be already writing a frame")
	}
	sc.writingFrame = false
	sc.writingFrameAsync = false

	if res.err != nil {
		sc.conn.Close()
	}

	wr := res.wr

	if writeEndsStream(wr.write) {
		st := wr.stream
		if st == nil {
			panic("internal error: expecting non-nil stream")
		}
		switch st.state {
		case stateOpen:
			st.state = stateHalfClosedLocal
			sc.resetStream(streamError(st.id, ErrCodeNo))
		case stateHalfClosedRemote:
			sc.closeStream(st, errHandlerComplete)
		}
	} else {
		switch v := wr.write.(type) {
		case StreamError:
			if st, ok := sc.streams[v.StreamID]; ok {
				sc.closeStream(st, v)
			}
		case handlerPanicRST:
			sc.closeStream(wr.stream, errHandlerPanicked)
		}
	}

	wr.replyToWriter(res.err)

	sc.scheduleFrameWrite()
}

func (sc *serverConn) scheduleFrameWrite() {
	sc.serveG.check()
	if sc.writingFrame || sc.inFrameScheduleLoop {
		return
	}
	sc.inFrameScheduleLoop = true
	for !sc.writingFrameAsync {
		if sc.needToSendGoAway {
			sc.needToSendGoAway = false
			sc.startFrameWrite(FrameWriteRequest{
				write: &writeGoAway{
					maxStreamID: sc.maxClientStreamID,
					code:        sc.goAwayCode,
				},
			})
			continue
		}
		if sc.needToSendSettingsAck {
			sc.needToSendSettingsAck = false
			sc.startFrameWrite(FrameWriteRequest{write: writeSettingsAck{}})
			continue
		}
		if !sc.inGoAway || sc.goAwayCode == ErrCodeNo {
			if wr, ok := sc.writeSched.Pop(); ok {
				if wr.isControl() {
					sc.queuedControlFrames--
				}
				sc.startFrameWrite(wr)
				continue
			}
		}
		if sc.needsFrameFlush {
			sc.startFrameWrite(FrameWriteRequest{write: flushFrameWriter{}})
			sc.needsFrameFlush = false
			continue
		}
		break
	}
	sc.inFrameScheduleLoop = false
}

func (sc *serverConn) startGracefulShutdown() {
	sc.serveG.checkNotOn()
	sc.shutdownOnce.Do(func() { sc.sendServeMsg(gracefulShutdownMsg) })
}

var goAwayTimeout = 1 * time.Second

func (sc *serverConn) startGracefulShutdownInternal() {
	sc.goAway(ErrCodeNo)
}

func (sc *serverConn) goAway(code ErrCode) {
	sc.serveG.check()
	if sc.inGoAway {
		if sc.goAwayCode == ErrCodeNo {
			sc.goAwayCode = code
		}
		return
	}
	sc.inGoAway = true
	sc.needToSendGoAway = true
	sc.goAwayCode = code
	sc.scheduleFrameWrite()
}

func (sc *serverConn) shutDownIn(d time.Duration) {
	sc.serveG.check()
	sc.shutdownTimer = time.AfterFunc(d, sc.onShutdownTimer)
}

func (sc *serverConn) resetStream(se StreamError) {
	sc.serveG.check()
	sc.writeFrame(FrameWriteRequest{write: se})
	if st, ok := sc.streams[se.StreamID]; ok {
		st.resetQueued = true
	}
}

func (sc *serverConn) processFrameFromReader(res readFrameResult) bool {
	sc.serveG.check()
	err := res.err
	if err != nil {
		if err == ErrFrameTooLarge {
			sc.goAway(ErrCodeFrameSize)
			return true
		}
		clientGone := err == io.EOF || err == io.ErrUnexpectedEOF || isClosedConnError(err)
		if clientGone {
			return false
		}
	} else {
		f := res.f
		if VerboseLogs {
			sc.vlogf("http2: server read frame %v", summarizeFrame(f))
		}
		err = sc.processFrame(f)
		if err == nil {
			return true
		}
	}

	switch ev := err.(type) {
	case StreamError:
		sc.resetStream(ev)
		return true
	case goAwayFlowError:
		sc.goAway(ErrCodeFlowControl)
		return true
	case ConnectionError:
		if res.f != nil {
			if id := res.f.Header().StreamID; id > sc.maxClientStreamID {
				sc.maxClientStreamID = id
			}
		}
		sc.logf("http2: server connection error from %v: %v", sc.conn.RemoteAddr(), ev)
		sc.goAway(ErrCode(ev))
		return true
	default:
		if res.err != nil {
			sc.vlogf("http2: server closing client connection; error reading frame from client %s: %v", sc.conn.RemoteAddr(), err)
		} else {
			sc.logf("http2: server closing client connection: %v", err)
		}
		return false
	}
}

func (sc *serverConn) processFrame(f Frame) error {
	sc.serveG.check()

	if !sc.sawFirstSettings {
		if _, ok := f.(*SettingsFrame); !ok {
			return sc.countError("first_settings", ConnectionError(ErrCodeProtocol))
		}
		sc.sawFirstSettings = true
	}

	if sc.inGoAway && (sc.goAwayCode != ErrCodeNo || f.Header().StreamID > sc.maxClientStreamID) {

		if f, ok := f.(*DataFrame); ok {
			if !sc.inflow.take(f.Length) {
				return sc.countError("data_flow", streamError(f.Header().StreamID, ErrCodeFlowControl))
			}
			sc.sendWindowUpdate(nil, int(f.Length))
		}
		return nil
	}

	switch f := f.(type) {
	case *SettingsFrame:
		return sc.processSettings(f)
	case *MetaHeadersFrame:
		return sc.processHeaders(f)
	case *WindowUpdateFrame:
		return sc.processWindowUpdate(f)
	case *PingFrame:
		return sc.processPing(f)
	case *DataFrame:
		return sc.processData(f)
	case *RSTStreamFrame:
		return sc.processResetStream(f)
	case *PriorityFrame:
		return sc.processPriority(f)
	case *GoAwayFrame:
		return sc.processGoAway(f)
	case *PushPromiseFrame:
		return sc.countError("push_promise", ConnectionError(ErrCodeProtocol))
	default:
		sc.vlogf("http2: server ignoring frame: %v", f.Header())
		return nil
	}
}

func (sc *serverConn) processPing(f *PingFrame) error {
	sc.serveG.check()
	if f.IsAck() {
		if sc.pingSent && sc.sentPingData == f.Data {
			sc.pingSent = false
			sc.readIdleTimer.Reset(sc.readIdleTimeout)
		}
		return nil
	}
	if f.StreamID != 0 {
		return sc.countError("ping_on_stream", ConnectionError(ErrCodeProtocol))
	}
	sc.writeFrame(FrameWriteRequest{write: writePingAck{f}})
	return nil
}

func (sc *serverConn) processWindowUpdate(f *WindowUpdateFrame) error {
	sc.serveG.check()
	switch {
	case f.StreamID != 0:
		state, st := sc.state(f.StreamID)
		if state == stateIdle {
			return sc.countError("stream_idle", ConnectionError(ErrCodeProtocol))
		}
		if st == nil {
			return nil
		}
		if !st.flow.add(int32(f.Increment)) {
			return sc.countError("bad_flow", streamError(f.StreamID, ErrCodeFlowControl))
		}
	default:
		if !sc.flow.add(int32(f.Increment)) {
			return goAwayFlowError{}
		}
	}
	sc.scheduleFrameWrite()
	return nil
}

func (sc *serverConn) processResetStream(f *RSTStreamFrame) error {
	sc.serveG.check()

	state, st := sc.state(f.StreamID)
	if state == stateIdle {
		return sc.countError("reset_idle_stream", ConnectionError(ErrCodeProtocol))
	}
	if st != nil {
		st.cancelCtx()
		sc.closeStream(st, streamError(f.StreamID, f.ErrCode))
	}
	return nil
}

func (sc *serverConn) closeStream(st *stream, err error) {
	sc.serveG.check()
	if st.state == stateIdle || st.state == stateClosed {
		panic(fmt.Sprintf("invariant; can't close stream in state %v", st.state))
	}
	st.state = stateClosed
	if st.readDeadline != nil {
		st.readDeadline.Stop()
	}
	if st.writeDeadline != nil {
		st.writeDeadline.Stop()
	}
	if st.isPushed() {
		sc.curPushedStreams--
	} else {
		sc.curClientStreams--
	}
	delete(sc.streams, st.id)
	if len(sc.streams) == 0 {
		sc.setConnState(http.StateIdle)
		if sc.srv.IdleTimeout > 0 && sc.idleTimer != nil {
			sc.idleTimer.Reset(sc.srv.IdleTimeout)
		}
		if h1ServerKeepAlivesDisabled(sc.hs) {
			sc.startGracefulShutdownInternal()
		}
	}
	if p := st.body; p != nil {
		sc.sendWindowUpdate(nil, p.Len())

		p.CloseWithError(err)
	}
	if e, ok := err.(StreamError); ok {
		if e.Cause != nil {
			err = e.Cause
		} else {
			err = errStreamClosed
		}
	}
	st.closeErr = err
	st.cancelCtx()
	st.cw.Close()
	sc.writeSched.CloseStream(st.id)
}

func (sc *serverConn) processSettings(f *SettingsFrame) error {
	sc.serveG.check()
	if f.IsAck() {
		sc.unackedSettings--
		if sc.unackedSettings < 0 {
			return sc.countError("ack_mystery", ConnectionError(ErrCodeProtocol))
		}
		return nil
	}
	if f.NumSettings() > 100 || f.HasDuplicates() {
		return sc.countError("settings_big_or_dups", ConnectionError(ErrCodeProtocol))
	}
	if err := f.ForeachSetting(sc.processSetting); err != nil {
		return err
	}
	sc.needToSendSettingsAck = true
	sc.scheduleFrameWrite()
	return nil
}

func (sc *serverConn) processSetting(s Setting) error {
	sc.serveG.check()
	if err := s.Valid(); err != nil {
		return err
	}
	if VerboseLogs {
		sc.vlogf("http2: server processing setting %v", s)
	}
	switch s.ID {
	case SettingHeaderTableSize:
		sc.hpackEncoder.SetMaxDynamicTableSize(s.Val)
	case SettingEnablePush:
		sc.pushEnabled = s.Val != 0
	case SettingMaxConcurrentStreams:
		sc.clientMaxStreams = s.Val
	case SettingInitialWindowSize:
		return sc.processSettingInitialWindowSize(s.Val)
	case SettingMaxFrameSize:
		sc.maxFrameSize = int32(s.Val)
	case SettingMaxHeaderListSize:
		sc.peerMaxHeaderListSize = s.Val
	case SettingEnableConnectProtocol:
	default:
		if VerboseLogs {
			sc.vlogf("http2: server ignoring unknown setting %v", s)
		}
	}
	return nil
}

func (sc *serverConn) processSettingInitialWindowSize(val uint32) error {
	sc.serveG.check()

	old := sc.initialStreamSendWindowSize
	sc.initialStreamSendWindowSize = int32(val)
	growth := int32(val) - old
	for _, st := range sc.streams {
		if !st.flow.add(growth) {
			return sc.countError("setting_win_size", ConnectionError(ErrCodeFlowControl))
		}
	}
	return nil
}

func (sc *serverConn) processData(f *DataFrame) error {
	sc.serveG.check()
	id := f.Header().StreamID

	data := f.Data()
	state, st := sc.state(id)
	if id == 0 || state == stateIdle {
		return sc.countError("data_on_idle", ConnectionError(ErrCodeProtocol))
	}

	if st == nil || state != stateOpen || st.gotTrailerHeader || st.resetQueued {

		if !sc.inflow.take(f.Length) {
			return sc.countError("data_flow", streamError(id, ErrCodeFlowControl))
		}
		sc.sendWindowUpdate(nil, int(f.Length))

		if st != nil && st.resetQueued {
			return nil
		}
		return sc.countError("closed", streamError(id, ErrCodeStreamClosed))
	}
	if st.body == nil {
		panic("internal error: should have a body in this state")
	}

	if st.declBodyBytes != -1 && st.bodyBytes+int64(len(data)) > st.declBodyBytes {
		if !sc.inflow.take(f.Length) {
			return sc.countError("data_flow", streamError(id, ErrCodeFlowControl))
		}
		sc.sendWindowUpdate(nil, int(f.Length))

		st.body.CloseWithError(fmt.Errorf("sender tried to send more than declared Content-Length of %d bytes", st.declBodyBytes))
		return sc.countError("send_too_much", streamError(id, ErrCodeProtocol))
	}
	if f.Length > 0 {
		if !takeInflows(&sc.inflow, &st.inflow, f.Length) {
			return sc.countError("flow_on_data_length", streamError(id, ErrCodeFlowControl))
		}

		if len(data) > 0 {
			st.bodyBytes += int64(len(data))
			wrote, err := st.body.Write(data)
			if err != nil {
				sc.sendWindowUpdate(nil, int(f.Length)-wrote)
				return nil
			}
			if wrote != len(data) {
				panic("internal error: bad Writer")
			}
		}

		pad := int32(f.Length) - int32(len(data))
		sc.sendWindowUpdate32(nil, pad)
		sc.sendWindowUpdate32(st, pad)
	}
	if f.StreamEnded() {
		st.endStream()
	}
	return nil
}

func (sc *serverConn) processGoAway(f *GoAwayFrame) error {
	sc.serveG.check()
	if f.ErrCode != ErrCodeNo {
		sc.logf("http2: received GOAWAY %+v, starting graceful shutdown", f)
	} else {
		sc.vlogf("http2: received GOAWAY %+v, starting graceful shutdown", f)
	}
	sc.startGracefulShutdownInternal()
	sc.pushEnabled = false
	return nil
}

func (st *stream) isPushed() bool {
	return st.id%2 == 0
}

func (st *stream) endStream() {
	sc := st.sc
	sc.serveG.check()

	if st.declBodyBytes != -1 && st.declBodyBytes != st.bodyBytes {
		st.body.CloseWithError(fmt.Errorf("request declared a Content-Length of %d but only wrote %d bytes",
			st.declBodyBytes, st.bodyBytes))
	} else {
		st.body.closeWithErrorAndCode(io.EOF, st.copyTrailersToHandlerRequest)
		st.body.CloseWithError(io.EOF)
	}
	st.state = stateHalfClosedRemote
}

func (st *stream) copyTrailersToHandlerRequest() {
	for k, vv := range st.trailer {
		if _, ok := st.reqTrailer[k]; ok {
			st.reqTrailer[k] = vv
		}
	}
}

func (st *stream) onReadTimeout() {
	if st.body != nil {
		st.body.CloseWithError(fmt.Errorf("%w", os.ErrDeadlineExceeded))
	}
}

func (st *stream) onWriteTimeout() {
	st.sc.writeFrameFromHandler(FrameWriteRequest{write: StreamError{
		StreamID: st.id,
		Code:     ErrCodeInternal,
		Cause:    os.ErrDeadlineExceeded,
	}})
}

func (sc *serverConn) processHeaders(f *MetaHeadersFrame) error {
	sc.serveG.check()
	id := f.StreamID
	if id%2 != 1 {
		return sc.countError("headers_even", ConnectionError(ErrCodeProtocol))
	}
	if st := sc.streams[f.StreamID]; st != nil {
		if st.resetQueued {
			return nil
		}
		if st.state == stateHalfClosedRemote {
			return sc.countError("headers_half_closed", streamError(id, ErrCodeStreamClosed))
		}
		return st.processTrailerHeaders(f)
	}

	if id <= sc.maxClientStreamID {
		return sc.countError("stream_went_down", ConnectionError(ErrCodeProtocol))
	}
	sc.maxClientStreamID = id

	if sc.idleTimer != nil {
		sc.idleTimer.Stop()
	}

	if sc.curClientStreams+1 > sc.advMaxStreams {
		if sc.unackedSettings == 0 {
			return sc.countError("over_max_streams", streamError(id, ErrCodeProtocol))
		}
		return sc.countError("over_max_streams_race", streamError(id, ErrCodeRefusedStream))
	}

	initialState := stateOpen
	if f.StreamEnded() {
		initialState = stateHalfClosedRemote
	}
	st := sc.newStream(id, 0, initialState)

	if f.HasPriority() {
		if err := sc.checkPriority(f.StreamID, f.Priority); err != nil {
			return err
		}
		sc.writeSched.AdjustStream(st.id, f.Priority)
	}

	rw, req, err := sc.newWriterAndRequest(st, f)
	if err != nil {
		return err
	}
	st.reqTrailer = req.Trailer
	if st.reqTrailer != nil {
		st.trailer = make(http.Header)
	}
	st.body = req.Body.(*requestBody).pipe
	st.declBodyBytes = req.ContentLength

	handler := sc.handler.ServeHTTP
	if f.Truncated {
		handler = handleHeaderListTooLong
	} else if err := checkValidHTTP2RequestHeaders(req.Header); err != nil {
		handler = new400Handler(err)
	}

	if sc.hs.ReadTimeout > 0 {
		sc.conn.SetReadDeadline(time.Time{})
		st.readDeadline = time.AfterFunc(sc.hs.ReadTimeout, st.onReadTimeout)
	}

	return sc.scheduleHandler(id, rw, req, handler)
}

func (sc *serverConn) upgradeRequest(req *http.Request) {
	sc.serveG.check()
	id := uint32(1)
	sc.maxClientStreamID = id
	st := sc.newStream(id, 0, stateHalfClosedRemote)
	st.reqTrailer = req.Trailer
	if st.reqTrailer != nil {
		st.trailer = make(http.Header)
	}
	rw := sc.newResponseWriter(st, req)

	if sc.hs.ReadTimeout > 0 {
		sc.conn.SetReadDeadline(time.Time{})
	}

	sc.curHandlers++
	go sc.runHandler(rw, req, sc.handler.ServeHTTP)
}

func (st *stream) processTrailerHeaders(f *MetaHeadersFrame) error {
	sc := st.sc
	sc.serveG.check()
	if st.gotTrailerHeader {
		return sc.countError("dup_trailers", ConnectionError(ErrCodeProtocol))
	}
	st.gotTrailerHeader = true
	if !f.StreamEnded() {
		return sc.countError("trailers_not_ended", streamError(st.id, ErrCodeProtocol))
	}

	if len(f.PseudoFields()) > 0 {
		return sc.countError("trailers_pseudo", streamError(st.id, ErrCodeProtocol))
	}
	if st.trailer != nil {
		for _, hf := range f.RegularFields() {
			key := sc.canonicalHeader(hf.Name)
			if !httpguts.ValidTrailerHeader(key) {
				return sc.countError("trailers_bogus", streamError(st.id, ErrCodeProtocol))
			}
			st.trailer[key] = append(st.trailer[key], hf.Value)
		}
	}
	st.endStream()
	return nil
}

func (sc *serverConn) checkPriority(streamID uint32, p PriorityParam) error {
	if streamID == p.StreamDep {
		return sc.countError("priority", streamError(streamID, ErrCodeProtocol))
	}
	return nil
}

func (sc *serverConn) processPriority(f *PriorityFrame) error {
	if err := sc.checkPriority(f.StreamID, f.PriorityParam); err != nil {
		return err
	}
	sc.writeSched.AdjustStream(f.StreamID, f.PriorityParam)
	return nil
}

func (sc *serverConn) newStream(id, pusherID uint32, state streamState) *stream {
	sc.serveG.check()
	if id == 0 {
		panic("internal error: cannot create stream with id 0")
	}

	ctx, cancelCtx := context.WithCancel(sc.baseCtx)
	st := &stream{
		sc:        sc,
		id:        id,
		state:     state,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}
	st.cw.Init()
	st.flow.conn = &sc.flow
	st.flow.add(sc.initialStreamSendWindowSize)
	st.inflow.init(sc.initialStreamRecvWindowSize)
	if sc.hs.WriteTimeout > 0 {
		st.writeDeadline = time.AfterFunc(sc.hs.WriteTimeout, st.onWriteTimeout)
	}

	sc.streams[id] = st
	sc.writeSched.OpenStream(st.id, OpenStreamOptions{PusherID: pusherID})
	if st.isPushed() {
		sc.curPushedStreams++
	} else {
		sc.curClientStreams++
	}
	if sc.curOpenStreams() == 1 {
		sc.setConnState(http.StateActive)
	}

	return st
}

func (sc *serverConn) newWriterAndRequest(st *stream, f *MetaHeadersFrame) (*responseWriter, *http.Request, error) {
	sc.serveG.check()

	rp := httpcommon.ServerRequestParam{
		Method:    f.PseudoValue("method"),
		Scheme:    f.PseudoValue("scheme"),
		Authority: f.PseudoValue("authority"),
		Path:      f.PseudoValue("path"),
		Protocol:  f.PseudoValue("protocol"),
	}

	if disableExtendedConnectProtocol && rp.Protocol != "" {
		return nil, nil, sc.countError("bad_connect", streamError(f.StreamID, ErrCodeProtocol))
	}

	isConnect := rp.Method == "CONNECT"
	if isConnect {
		if rp.Protocol == "" && (rp.Path != "" || rp.Scheme != "" || rp.Authority == "") {
			return nil, nil, sc.countError("bad_connect", streamError(f.StreamID, ErrCodeProtocol))
		}
	} else if rp.Method == "" || rp.Path == "" || (rp.Scheme != "https" && rp.Scheme != "http") {
		return nil, nil, sc.countError("bad_path_method", streamError(f.StreamID, ErrCodeProtocol))
	}

	header := make(http.Header)
	rp.Header = header
	for _, hf := range f.RegularFields() {
		header.Add(sc.canonicalHeader(hf.Name), hf.Value)
	}
	if rp.Authority == "" {
		rp.Authority = header.Get("Host")
	}
	if rp.Protocol != "" {
		header.Set(":protocol", rp.Protocol)
	}

	rw, req, err := sc.newWriterAndRequestNoBody(st, rp)
	if err != nil {
		return nil, nil, err
	}
	bodyOpen := !f.StreamEnded()
	if bodyOpen {
		if vv, ok := rp.Header["Content-Length"]; ok {
			if cl, err := strconv.ParseUint(vv[0], 10, 63); err == nil {
				req.ContentLength = int64(cl)
			} else {
				req.ContentLength = 0
			}
		} else {
			req.ContentLength = -1
		}
		req.Body.(*requestBody).pipe = &pipe{
			b: &dataBuffer{expected: req.ContentLength},
		}
	}
	return rw, req, nil
}

func (sc *serverConn) newWriterAndRequestNoBody(st *stream, rp httpcommon.ServerRequestParam) (*responseWriter, *http.Request, error) {
	sc.serveG.check()

	var tlsState *tls.ConnectionState
	if rp.Scheme == "https" {
		tlsState = sc.tlsState
	}

	res := httpcommon.NewServerRequest(rp)
	if res.InvalidReason != "" {
		return nil, nil, sc.countError(res.InvalidReason, streamError(st.id, ErrCodeProtocol))
	}

	body := &requestBody{
		conn:          sc,
		stream:        st,
		needsContinue: res.NeedsContinue,
	}
	req := (&http.Request{
		Method:     rp.Method,
		URL:        res.URL,
		RemoteAddr: sc.remoteAddrStr,
		Header:     rp.Header,
		RequestURI: res.RequestURI,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		TLS:        tlsState,
		Host:       rp.Authority,
		Body:       body,
		Trailer:    res.Trailer,
	}).WithContext(st.ctx)
	rw := sc.newResponseWriter(st, req)
	return rw, req, nil
}

func (sc *serverConn) newResponseWriter(st *stream, req *http.Request) *responseWriter {
	rws := responseWriterStatePool.Get().(*responseWriterState)
	bwSave := rws.bw
	*rws = responseWriterState{}
	rws.conn = sc
	rws.bw = bwSave
	rws.bw.Reset(chunkWriter{rws})
	rws.stream = st
	rws.req = req
	return &responseWriter{rws: rws}
}

type unstartedHandler struct {
	streamID uint32
	rw       *responseWriter
	req      *http.Request
	handler  func(http.ResponseWriter, *http.Request)
}

func (sc *serverConn) scheduleHandler(streamID uint32, rw *responseWriter, req *http.Request, handler func(http.ResponseWriter, *http.Request)) error {
	sc.serveG.check()
	maxHandlers := sc.advMaxStreams
	if sc.curHandlers < maxHandlers {
		sc.curHandlers++
		go sc.runHandler(rw, req, handler)
		return nil
	}
	if len(sc.unstartedHandlers) > int(4*sc.advMaxStreams) {
		return sc.countError("too_many_early_resets", ConnectionError(ErrCodeEnhanceYourCalm))
	}
	sc.unstartedHandlers = append(sc.unstartedHandlers, unstartedHandler{
		streamID: streamID,
		rw:       rw,
		req:      req,
		handler:  handler,
	})
	return nil
}

func (sc *serverConn) handlerDone() {
	sc.serveG.check()
	sc.curHandlers--
	i := 0
	maxHandlers := sc.advMaxStreams
	for ; i < len(sc.unstartedHandlers); i++ {
		u := sc.unstartedHandlers[i]
		if sc.streams[u.streamID] == nil {
			continue
		}
		if sc.curHandlers >= maxHandlers {
			break
		}
		sc.curHandlers++
		go sc.runHandler(u.rw, u.req, u.handler)
		sc.unstartedHandlers[i] = unstartedHandler{}
	}
	sc.unstartedHandlers = sc.unstartedHandlers[i:]
	if len(sc.unstartedHandlers) == 0 {
		sc.unstartedHandlers = nil
	}
}

func (sc *serverConn) runHandler(rw *responseWriter, req *http.Request, handler func(http.ResponseWriter, *http.Request)) {
	defer sc.sendServeMsg(handlerDoneMsg)
	didPanic := true
	defer func() {
		rw.rws.stream.cancelCtx()
		if req.MultipartForm != nil {
			req.MultipartForm.RemoveAll()
		}
		if didPanic {
			e := recover()
			sc.writeFrameFromHandler(FrameWriteRequest{
				write:  handlerPanicRST{rw.rws.stream.id},
				stream: rw.rws.stream,
			})
			if e != nil && e != http.ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				sc.logf("http2: panic serving %v: %v\n%s", sc.conn.RemoteAddr(), e, buf)
			}
			return
		}
		rw.handlerDone()
	}()
	handler(rw, req)
	didPanic = false
}

func handleHeaderListTooLong(w http.ResponseWriter, r *http.Request) {
	const statusRequestHeaderFieldsTooLarge = 431
	w.WriteHeader(statusRequestHeaderFieldsTooLarge)
	io.WriteString(w, "<h1>HTTP Error 431</h1><p>Request Header Field(s) Too Large</p>")
}

func (sc *serverConn) writeHeaders(st *stream, headerData *writeResHeaders) error {
	sc.serveG.checkNotOn()
	var errc chan error
	if headerData.h != nil {
		errc = sc.srv.state.getErrChan()
	}
	if err := sc.writeFrameFromHandler(FrameWriteRequest{
		write:  headerData,
		stream: st,
		done:   errc,
	}); err != nil {
		return err
	}
	if errc != nil {
		select {
		case err := <-errc:
			sc.srv.state.putErrChan(errc)
			return err
		case <-sc.doneServing:
			return errClientDisconnected
		case <-st.cw:
			return errStreamClosed
		}
	}
	return nil
}

func (sc *serverConn) write100ContinueHeaders(st *stream) {
	sc.writeFrameFromHandler(FrameWriteRequest{
		write:  write100ContinueHeadersFrame{st.id},
		stream: st,
	})
}

type bodyReadMsg struct {
	st *stream
	n  int
}

func (sc *serverConn) noteBodyReadFromHandler(st *stream, n int, err error) {
	sc.serveG.checkNotOn()
	if n > 0 {
		select {
		case sc.bodyReadCh <- bodyReadMsg{st, n}:
		case <-sc.doneServing:
		}
	}
}

func (sc *serverConn) noteBodyRead(st *stream, n int) {
	sc.serveG.check()
	sc.sendWindowUpdate(nil, n)
	if st.state != stateHalfClosedRemote && st.state != stateClosed {
		sc.sendWindowUpdate(st, n)
	}
}

func (sc *serverConn) sendWindowUpdate32(st *stream, n int32) {
	sc.sendWindowUpdate(st, int(n))
}

func (sc *serverConn) sendWindowUpdate(st *stream, n int) {
	sc.serveG.check()
	var streamID uint32
	var send int32
	if st == nil {
		send = sc.inflow.add(n)
	} else {
		streamID = st.id
		send = st.inflow.add(n)
	}
	if send == 0 {
		return
	}
	sc.writeFrame(FrameWriteRequest{
		write:  writeWindowUpdate{streamID: streamID, n: uint32(send)},
		stream: st,
	})
}

type requestBody struct {
	_             incomparable
	stream        *stream
	conn          *serverConn
	closeOnce     sync.Once
	sawEOF        bool
	pipe          *pipe
	needsContinue bool
}

func (b *requestBody) Close() error {
	b.closeOnce.Do(func() {
		if b.pipe != nil {
			b.pipe.BreakWithError(errClosedBody)
		}
	})
	return nil
}

func (b *requestBody) Read(p []byte) (n int, err error) {
	if b.needsContinue {
		b.needsContinue = false
		b.conn.write100ContinueHeaders(b.stream)
	}
	if b.pipe == nil || b.sawEOF {
		return 0, io.EOF
	}
	n, err = b.pipe.Read(p)
	if err == io.EOF {
		b.sawEOF = true
	}
	if b.conn == nil {
		return
	}
	b.conn.noteBodyReadFromHandler(b.stream, n, err)
	return
}

type responseWriter struct {
	rws *responseWriterState
}

var (
	_ http.CloseNotifier = (*responseWriter)(nil)
	_ http.Flusher       = (*responseWriter)(nil)
	_ stringWriter       = (*responseWriter)(nil)
)

type responseWriterState struct {
	stream *stream
	req    *http.Request
	conn   *serverConn

	bw *bufio.Writer

	handlerHeader http.Header
	snapHeader    http.Header
	trailers      []string
	status        int
	wroteHeader   bool
	sentHeader    bool
	handlerDone   bool

	sentContentLen int64
	wroteBytes     int64

	closeNotifierMu sync.Mutex
	closeNotifierCh chan bool
}

type chunkWriter struct{ rws *responseWriterState }

func (cw chunkWriter) Write(p []byte) (n int, err error) {
	n, err = cw.rws.writeChunk(p)
	if err == errStreamClosed {
		err = cw.rws.stream.closeErr
	}
	return n, err
}

func (rws *responseWriterState) hasTrailers() bool { return len(rws.trailers) > 0 }

func (rws *responseWriterState) hasNonemptyTrailers() bool {
	for _, trailer := range rws.trailers {
		if _, ok := rws.handlerHeader[trailer]; ok {
			return true
		}
	}
	return false
}

func (rws *responseWriterState) declareTrailer(k string) {
	k = http.CanonicalHeaderKey(k)
	if !httpguts.ValidTrailerHeader(k) {
		rws.conn.logf("ignoring invalid trailer %q", k)
		return
	}
	if !strSliceContains(rws.trailers, k) {
		rws.trailers = append(rws.trailers, k)
	}
}

func (rws *responseWriterState) writeChunk(p []byte) (n int, err error) {
	if !rws.wroteHeader {
		rws.writeHeader(200)
	}

	if rws.handlerDone {
		rws.promoteUndeclaredTrailers()
	}

	isHeadResp := rws.req.Method == "HEAD"
	if !rws.sentHeader {
		rws.sentHeader = true
		var ctype, clen string
		if clen = rws.snapHeader.Get("Content-Length"); clen != "" {
			rws.snapHeader.Del("Content-Length")
			if cl, err := strconv.ParseUint(clen, 10, 63); err == nil {
				rws.sentContentLen = int64(cl)
			} else {
				clen = ""
			}
		}
		_, hasContentLength := rws.snapHeader["Content-Length"]
		if !hasContentLength && clen == "" && rws.handlerDone && bodyAllowedForStatus(rws.status) && (len(p) > 0 || !isHeadResp) {
			clen = strconv.Itoa(len(p))
		}
		_, hasContentType := rws.snapHeader["Content-Type"]
		ce := rws.snapHeader.Get("Content-Encoding")
		hasCE := len(ce) > 0
		if !hasCE && !hasContentType && bodyAllowedForStatus(rws.status) && len(p) > 0 {
			ctype = http.DetectContentType(p)
		}
		var date string
		if _, ok := rws.snapHeader["Date"]; !ok {
			date = time.Now().UTC().Format(http.TimeFormat)
		}

		for _, v := range rws.snapHeader["Trailer"] {
			foreachHeaderElement(v, rws.declareTrailer)
		}

		if _, ok := rws.snapHeader["Connection"]; ok {
			v := rws.snapHeader.Get("Connection")
			delete(rws.snapHeader, "Connection")
			if v == "close" {
				rws.conn.startGracefulShutdown()
			}
		}

		endStream := (rws.handlerDone && !rws.hasTrailers() && len(p) == 0) || isHeadResp
		err = rws.conn.writeHeaders(rws.stream, &writeResHeaders{
			streamID:      rws.stream.id,
			httpResCode:   rws.status,
			h:             rws.snapHeader,
			endStream:     endStream,
			contentType:   ctype,
			contentLength: clen,
			date:          date,
		})
		if err != nil {
			return 0, err
		}
		if endStream {
			return 0, nil
		}
	}
	if isHeadResp {
		return len(p), nil
	}
	if len(p) == 0 && !rws.handlerDone {
		return 0, nil
	}

	hasNonemptyTrailers := rws.hasNonemptyTrailers()
	endStream := rws.handlerDone && !hasNonemptyTrailers
	if len(p) > 0 || endStream {
		if err := rws.conn.writeDataFromHandler(rws.stream, p, endStream); err != nil {
			return 0, err
		}
	}

	if rws.handlerDone && hasNonemptyTrailers {
		err = rws.conn.writeHeaders(rws.stream, &writeResHeaders{
			streamID:  rws.stream.id,
			h:         rws.handlerHeader,
			trailers:  rws.trailers,
			endStream: true,
		})
		return len(p), err
	}
	return len(p), nil
}

const TrailerPrefix = "Trailer:"

func (rws *responseWriterState) promoteUndeclaredTrailers() {
	for k, vv := range rws.handlerHeader {
		if !strings.HasPrefix(k, TrailerPrefix) {
			continue
		}
		trailerKey := strings.TrimPrefix(k, TrailerPrefix)
		rws.declareTrailer(trailerKey)
		rws.handlerHeader[http.CanonicalHeaderKey(trailerKey)] = vv
	}

	if len(rws.trailers) > 1 {
		sorter := sorterPool.Get().(*sorter)
		sorter.SortStrings(rws.trailers)
		sorterPool.Put(sorter)
	}
}

func (w *responseWriter) SetReadDeadline(deadline time.Time) error {
	st := w.rws.stream
	if !deadline.IsZero() && deadline.Before(time.Now()) {
		st.onReadTimeout()
		return nil
	}
	w.rws.conn.sendServeMsg(func(sc *serverConn) {
		if st.readDeadline != nil {
			if !st.readDeadline.Stop() {
				return
			}
		}
		if deadline.IsZero() {
			st.readDeadline = nil
		} else if st.readDeadline == nil {
			st.readDeadline = time.AfterFunc(deadline.Sub(time.Now()), st.onReadTimeout)
		} else {
			st.readDeadline.Reset(deadline.Sub(time.Now()))
		}
	})
	return nil
}

func (w *responseWriter) SetWriteDeadline(deadline time.Time) error {
	st := w.rws.stream
	if !deadline.IsZero() && deadline.Before(time.Now()) {
		st.onWriteTimeout()
		return nil
	}
	w.rws.conn.sendServeMsg(func(sc *serverConn) {
		if st.writeDeadline != nil {
			if !st.writeDeadline.Stop() {
				return
			}
		}
		if deadline.IsZero() {
			st.writeDeadline = nil
		} else if st.writeDeadline == nil {
			st.writeDeadline = time.AfterFunc(deadline.Sub(time.Now()), st.onWriteTimeout)
		} else {
			st.writeDeadline.Reset(deadline.Sub(time.Now()))
		}
	})
	return nil
}

func (w *responseWriter) EnableFullDuplex() error {
	return nil
}

func (w *responseWriter) Flush() {
	w.FlushError()
}

func (w *responseWriter) FlushError() error {
	rws := w.rws
	if rws == nil {
		panic("Header called after Handler finished")
	}
	var err error
	if rws.bw.Buffered() > 0 {
		err = rws.bw.Flush()
	} else {
		_, err = chunkWriter{rws}.Write(nil)
		if err == nil {
			select {
			case <-rws.stream.cw:
				err = rws.stream.closeErr
			default:
			}
		}
	}
	return err
}

func (w *responseWriter) CloseNotify() <-chan bool {
	rws := w.rws
	if rws == nil {
		panic("CloseNotify called after Handler finished")
	}
	rws.closeNotifierMu.Lock()
	ch := rws.closeNotifierCh
	if ch == nil {
		ch = make(chan bool, 1)
		rws.closeNotifierCh = ch
		cw := rws.stream.cw
		go func() {
			cw.Wait()
			ch <- true
		}()
	}
	rws.closeNotifierMu.Unlock()
	return ch
}

func (w *responseWriter) Header() http.Header {
	rws := w.rws
	if rws == nil {
		panic("Header called after Handler finished")
	}
	if rws.handlerHeader == nil {
		rws.handlerHeader = make(http.Header)
	}
	return rws.handlerHeader
}

func checkWriteHeaderCode(code int) {
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
}

func (w *responseWriter) WriteHeader(code int) {
	rws := w.rws
	if rws == nil {
		panic("WriteHeader called after Handler finished")
	}
	rws.writeHeader(code)
}

func (rws *responseWriterState) writeHeader(code int) {
	if rws.wroteHeader {
		return
	}

	checkWriteHeaderCode(code)

	if code >= 100 && code <= 199 {
		h := rws.handlerHeader

		_, cl := h["Content-Length"]
		_, te := h["Transfer-Encoding"]
		if cl || te {
			h = h.Clone()
			h.Del("Content-Length")
			h.Del("Transfer-Encoding")
		}

		rws.conn.writeHeaders(rws.stream, &writeResHeaders{
			streamID:    rws.stream.id,
			httpResCode: code,
			h:           h,
			endStream:   rws.handlerDone && !rws.hasTrailers(),
		})

		return
	}

	rws.wroteHeader = true
	rws.status = code
	if len(rws.handlerHeader) > 0 {
		rws.snapHeader = cloneHeader(rws.handlerHeader)
	}
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func (w *responseWriter) Write(p []byte) (n int, err error) {
	return w.write(len(p), p, "")
}

func (w *responseWriter) WriteString(s string) (n int, err error) {
	return w.write(len(s), nil, s)
}

func (w *responseWriter) write(lenData int, dataB []byte, dataS string) (n int, err error) {
	rws := w.rws
	if rws == nil {
		panic("Write called after Handler finished")
	}
	if !rws.wroteHeader {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(rws.status) {
		return 0, http.ErrBodyNotAllowed
	}
	rws.wroteBytes += int64(len(dataB)) + int64(len(dataS))
	if rws.sentContentLen != 0 && rws.wroteBytes > rws.sentContentLen {
		return 0, errors.New("http2: handler wrote more than declared Content-Length")
	}

	if dataB != nil {
		return rws.bw.Write(dataB)
	} else {
		return rws.bw.WriteString(dataS)
	}
}

func (w *responseWriter) handlerDone() {
	rws := w.rws
	rws.handlerDone = true
	w.Flush()
	w.rws = nil
	responseWriterStatePool.Put(rws)
}

var (
	ErrRecursivePush    = errors.New("http2: recursive push not allowed")
	ErrPushLimitReached = errors.New("http2: push would exceed peer's SETTINGS_MAX_CONCURRENT_STREAMS")
)

var _ http.Pusher = (*responseWriter)(nil)

func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	st := w.rws.stream
	sc := st.sc
	sc.serveG.checkNotOn()

	if st.isPushed() {
		return ErrRecursivePush
	}

	if opts == nil {
		opts = new(http.PushOptions)
	}

	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Header == nil {
		opts.Header = http.Header{}
	}
	wantScheme := "http"
	if w.rws.req.TLS != nil {
		wantScheme = "https"
	}

	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Scheme == "" {
		if !strings.HasPrefix(target, "/") {
			return fmt.Errorf("target must be an absolute URL or an absolute path: %q", target)
		}
		u.Scheme = wantScheme
		u.Host = w.rws.req.Host
	} else {
		if u.Scheme != wantScheme {
			return fmt.Errorf("cannot push URL with scheme %q from request with scheme %q", u.Scheme, wantScheme)
		}
		if u.Host == "" {
			return errors.New("URL must have a host")
		}
	}
	for k := range opts.Header {
		if strings.HasPrefix(k, ":") {
			return fmt.Errorf("promised request headers cannot include pseudo header %q", k)
		}
		if asciiEqualFold(k, "content-length") ||
			asciiEqualFold(k, "content-encoding") ||
			asciiEqualFold(k, "trailer") ||
			asciiEqualFold(k, "te") ||
			asciiEqualFold(k, "expect") ||
			asciiEqualFold(k, "host") {
			return fmt.Errorf("promised request headers cannot include %q", k)
		}
	}
	if err := checkValidHTTP2RequestHeaders(opts.Header); err != nil {
		return err
	}

	if opts.Method != "GET" && opts.Method != "HEAD" {
		return fmt.Errorf("method %q must be GET or HEAD", opts.Method)
	}

	msg := &startPushRequest{
		parent: st,
		method: opts.Method,
		url:    u,
		header: cloneHeader(opts.Header),
		done:   sc.srv.state.getErrChan(),
	}

	select {
	case <-sc.doneServing:
		return errClientDisconnected
	case <-st.cw:
		return errStreamClosed
	case sc.serveMsgCh <- msg:
	}

	select {
	case <-sc.doneServing:
		return errClientDisconnected
	case <-st.cw:
		return errStreamClosed
	case err := <-msg.done:
		sc.srv.state.putErrChan(msg.done)
		return err
	}
}

type startPushRequest struct {
	parent *stream
	method string
	url    *url.URL
	header http.Header
	done   chan error
}

func (sc *serverConn) startPush(msg *startPushRequest) {
	sc.serveG.check()

	if msg.parent.state != stateOpen && msg.parent.state != stateHalfClosedRemote {
		msg.done <- errStreamClosed
		return
	}

	if !sc.pushEnabled {
		msg.done <- http.ErrNotSupported
		return
	}

	allocatePromisedID := func() (uint32, error) {
		sc.serveG.check()

		if !sc.pushEnabled {
			return 0, http.ErrNotSupported
		}
		if sc.curPushedStreams+1 > sc.clientMaxStreams {
			return 0, ErrPushLimitReached
		}

		if sc.maxPushPromiseID+2 >= 1<<31 {
			sc.startGracefulShutdownInternal()
			return 0, ErrPushLimitReached
		}
		sc.maxPushPromiseID += 2
		promisedID := sc.maxPushPromiseID

		promised := sc.newStream(promisedID, msg.parent.id, stateHalfClosedRemote)
		rw, req, err := sc.newWriterAndRequestNoBody(promised, httpcommon.ServerRequestParam{
			Method:    msg.method,
			Scheme:    msg.url.Scheme,
			Authority: msg.url.Host,
			Path:      msg.url.RequestURI(),
			Header:    cloneHeader(msg.header),
		})
		if err != nil {
			panic(fmt.Sprintf("newWriterAndRequestNoBody(%+v): %v", msg.url, err))
		}

		sc.curHandlers++
		go sc.runHandler(rw, req, sc.handler.ServeHTTP)
		return promisedID, nil
	}

	sc.writeFrame(FrameWriteRequest{
		write: &writePushPromise{
			streamID:           msg.parent.id,
			method:             msg.method,
			url:                msg.url,
			h:                  msg.header,
			allocatePromisedID: allocatePromisedID,
		},
		stream: msg.parent,
		done:   msg.done,
	})
}

func foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for _, f := range strings.Split(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}

var connHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
	"Upgrade",
}

func checkValidHTTP2RequestHeaders(h http.Header) error {
	for _, k := range connHeaders {
		if _, ok := h[k]; ok {
			return fmt.Errorf("request header %q is not valid in HTTP/2", k)
		}
	}
	te := h["Te"]
	if len(te) > 0 && (len(te) > 1 || (te[0] != "trailers" && te[0] != "")) {
		return errors.New(`request header "TE" may only be "trailers" in HTTP/2`)
	}
	return nil
}

func new400Handler(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func h1ServerKeepAlivesDisabled(hs *http.Server) bool {
	var x interface{} = hs
	type I interface {
		doKeepAlives() bool
	}
	if hs, ok := x.(I); ok {
		return !hs.doKeepAlives()
	}
	return false
}

func (sc *serverConn) countError(name string, err error) error {
	if sc == nil || sc.srv == nil {
		return err
	}
	f := sc.countErrorFunc
	if f == nil {
		return err
	}
	var typ string
	var code ErrCode
	switch e := err.(type) {
	case ConnectionError:
		typ = "conn"
		code = ErrCode(e)
	case StreamError:
		typ = "stream"
		code = ErrCode(e.Code)
	default:
		return err
	}
	codeStr := errCodeName[code]
	if codeStr == "" {
		codeStr = strconv.Itoa(int(code))
	}
	f(fmt.Sprintf("%s_%s_%s", typ, codeStr, name))
	return err
}
