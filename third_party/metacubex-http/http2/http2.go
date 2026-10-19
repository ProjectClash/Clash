// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"

	"golang.org/x/net/http/httpguts"
)

var (
	VerboseLogs    bool
	logFrameWrites bool
	logFrameReads  bool

	disableExtendedConnectProtocol = true
)

func init() {
	e := os.Getenv("GODEBUG")
	if strings.Contains(e, "http2debug=1") {
		VerboseLogs = true
	}
	if strings.Contains(e, "http2debug=2") {
		VerboseLogs = true
		logFrameWrites = true
		logFrameReads = true
	}
	if strings.Contains(e, "http2xconnect=1") {
		disableExtendedConnectProtocol = false
	}
}

const (
	ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	initialMaxFrameSize = 16384

	NextProtoTLS = "h2"

	initialHeaderTableSize = 4096

	initialWindowSize = 65535

	defaultMaxReadFrameSize = 1 << 20
)

var (
	clientPreface = []byte(ClientPreface)
)

type streamState int

const (
	stateIdle streamState = iota
	stateOpen
	stateHalfClosedLocal
	stateHalfClosedRemote
	stateClosed
)

var stateName = [...]string{
	stateIdle:             "Idle",
	stateOpen:             "Open",
	stateHalfClosedLocal:  "HalfClosedLocal",
	stateHalfClosedRemote: "HalfClosedRemote",
	stateClosed:           "Closed",
}

func (st streamState) String() string {
	return stateName[st]
}

type Setting struct {
	ID SettingID

	Val uint32
}

func (s Setting) String() string {
	return fmt.Sprintf("[%v = %d]", s.ID, s.Val)
}

func (s Setting) Valid() error {
	switch s.ID {
	case SettingEnablePush:
		if s.Val != 1 && s.Val != 0 {
			return ConnectionError(ErrCodeProtocol)
		}
	case SettingInitialWindowSize:
		if s.Val > 1<<31-1 {
			return ConnectionError(ErrCodeFlowControl)
		}
	case SettingMaxFrameSize:
		if s.Val < 16384 || s.Val > 1<<24-1 {
			return ConnectionError(ErrCodeProtocol)
		}
	case SettingEnableConnectProtocol:
		if s.Val != 1 && s.Val != 0 {
			return ConnectionError(ErrCodeProtocol)
		}
	}
	return nil
}

type SettingID uint16

const (
	SettingHeaderTableSize       SettingID = 0x1
	SettingEnablePush            SettingID = 0x2
	SettingMaxConcurrentStreams  SettingID = 0x3
	SettingInitialWindowSize     SettingID = 0x4
	SettingMaxFrameSize          SettingID = 0x5
	SettingMaxHeaderListSize     SettingID = 0x6
	SettingEnableConnectProtocol SettingID = 0x8
)

var settingName = map[SettingID]string{
	SettingHeaderTableSize:       "HEADER_TABLE_SIZE",
	SettingEnablePush:            "ENABLE_PUSH",
	SettingMaxConcurrentStreams:  "MAX_CONCURRENT_STREAMS",
	SettingInitialWindowSize:     "INITIAL_WINDOW_SIZE",
	SettingMaxFrameSize:          "MAX_FRAME_SIZE",
	SettingMaxHeaderListSize:     "MAX_HEADER_LIST_SIZE",
	SettingEnableConnectProtocol: "ENABLE_CONNECT_PROTOCOL",
}

func (s SettingID) String() string {
	if v, ok := settingName[s]; ok {
		return v
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", uint16(s))
}

func validWireHeaderFieldName(v string) bool {
	if len(v) == 0 {
		return false
	}
	for _, r := range v {
		if !httpguts.IsTokenRune(r) {
			return false
		}
		if 'A' <= r && r <= 'Z' {
			return false
		}
	}
	return true
}

func httpCodeString(code int) string {
	switch code {
	case 200:
		return "200"
	case 404:
		return "404"
	}
	return strconv.Itoa(code)
}

type stringWriter interface {
	WriteString(s string) (n int, err error)
}

type closeWaiter chan struct{}

func (cw *closeWaiter) Init() {
	*cw = make(chan struct{})
}

func (cw closeWaiter) Close() {
	close(cw)
}

func (cw closeWaiter) Wait() {
	<-cw
}

type bufferedWriter struct {
	_           incomparable
	conn        net.Conn
	bw          *bufio.Writer
	byteTimeout time.Duration
}

func newBufferedWriter(conn net.Conn, timeout time.Duration) *bufferedWriter {
	return &bufferedWriter{
		conn:        conn,
		byteTimeout: timeout,
	}
}

const bufWriterPoolBufferSize = 4 << 10

var bufWriterPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, bufWriterPoolBufferSize)
	},
}

func (w *bufferedWriter) Available() int {
	if w.bw == nil {
		return bufWriterPoolBufferSize
	}
	return w.bw.Available()
}

func (w *bufferedWriter) Write(p []byte) (n int, err error) {
	if w.bw == nil {
		bw := bufWriterPool.Get().(*bufio.Writer)
		bw.Reset((*bufferedWriterTimeoutWriter)(w))
		w.bw = bw
	}
	return w.bw.Write(p)
}

func (w *bufferedWriter) Flush() error {
	bw := w.bw
	if bw == nil {
		return nil
	}
	err := bw.Flush()
	bw.Reset(nil)
	bufWriterPool.Put(bw)
	w.bw = nil
	return err
}

type bufferedWriterTimeoutWriter bufferedWriter

func (w *bufferedWriterTimeoutWriter) Write(p []byte) (n int, err error) {
	return writeWithByteTimeout(w.conn, w.byteTimeout, p)
}

func writeWithByteTimeout(conn net.Conn, timeout time.Duration, p []byte) (n int, err error) {
	if timeout <= 0 {
		return conn.Write(p)
	}
	for {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		nn, err := conn.Write(p[n:])
		n += nn
		if n == len(p) || nn == 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			conn.SetWriteDeadline(time.Time{})
			return n, err
		}
	}
}

func mustUint31(v int32) uint32 {
	if v < 0 || v > 2147483647 {
		panic("out of range")
	}
	return uint32(v)
}

func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

type httpError struct {
	_       incomparable
	msg     string
	timeout bool
}

func (e *httpError) Error() string   { return e.msg }
func (e *httpError) Timeout() bool   { return e.timeout }
func (e *httpError) Temporary() bool { return true }

var errTimeout error = &httpError{msg: "http2: timeout awaiting response headers", timeout: true}

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

var sorterPool = sync.Pool{New: func() interface{} { return new(sorter) }}

type sorter struct {
	v []string
}

func (s *sorter) Len() int           { return len(s.v) }
func (s *sorter) Swap(i, j int)      { s.v[i], s.v[j] = s.v[j], s.v[i] }
func (s *sorter) Less(i, j int) bool { return s.v[i] < s.v[j] }

func (s *sorter) Keys(h http.Header) []string {
	keys := s.v[:0]
	for k := range h {
		keys = append(keys, k)
	}
	s.v = keys
	sort.Sort(s)
	return keys
}

func (s *sorter) SortStrings(ss []string) {
	save := s.v
	s.v = ss
	sort.Sort(s)
	s.v = save
}

type incomparable [0]func()
