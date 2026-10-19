// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package h2c

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"strings"

	"github.com/metacubex/http"

	"golang.org/x/net/http/httpguts"
)

var (
	http2VerboseLogs bool
)

func init() {
	e := os.Getenv("GODEBUG")
	if strings.Contains(e, "http2debug=1") || strings.Contains(e, "http2debug=2") {
		http2VerboseLogs = true
	}
}

type h2cHandler struct {
	Handler http.Handler
	s       *http.Http2Server
}

func NewHandler(h http.Handler, s *http.Http2Server) http.Handler {
	return &h2cHandler{
		Handler: h,
		s:       s,
	}
}

func extractServer(r *http.Request) *http.Server {
	server, ok := r.Context().Value(http.ServerContextKey).(*http.Server)
	if ok {
		return server
	}
	return new(http.Server)
}

func (s h2cHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0" {
		if http2VerboseLogs {
			log.Print("h2c: attempting h2c with prior knowledge.")
		}
		conn, err := initH2CWithPriorKnowledge(w)
		if err != nil {
			if http2VerboseLogs {
				log.Printf("h2c: error h2c with prior knowledge: %v", err)
			}
			return
		}
		defer conn.Close()
		s.s.ServeConn(conn, &http.Http2ServeConnOpts{
			Context:          r.Context(),
			BaseConfig:       extractServer(r),
			Handler:          s.Handler,
			SawClientPreface: true,
		})
		return
	}
	if isH2CUpgrade(r.Header) {
		conn, settings, err := h2cUpgrade(w, r)
		if err != nil {
			if http2VerboseLogs {
				log.Printf("h2c: error h2c upgrade: %v", err)
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		s.s.ServeConn(conn, &http.Http2ServeConnOpts{
			Context:        r.Context(),
			BaseConfig:     extractServer(r),
			Handler:        s.Handler,
			UpgradeRequest: r,
			Settings:       settings,
		})
		return
	}
	s.Handler.ServeHTTP(w, r)
	return
}

func initH2CWithPriorKnowledge(w http.ResponseWriter) (net.Conn, error) {
	rc := http.NewResponseController(w)
	conn, rw, err := rc.Hijack()
	if err != nil {
		return nil, err
	}

	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(rw, buf)
	if err != nil {
		return nil, fmt.Errorf("h2c: error reading client preface: %s", err)
	}

	if string(buf[:n]) == expectedBody {
		return newBufConn(conn, rw), nil
	}

	conn.Close()
	return nil, errors.New("h2c: invalid client preface")
}

func h2cUpgrade(w http.ResponseWriter, r *http.Request) (_ net.Conn, settings []byte, err error) {
	settings, err = getH2Settings(r.Header)
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	rc := http.NewResponseController(w)
	conn, rw, err := rc.Hijack()
	if err != nil {
		return nil, nil, err
	}

	rw.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: h2c\r\n\r\n"))
	return newBufConn(conn, rw), settings, nil
}

func isH2CUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Upgrade")], "h2c") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Connection")], "HTTP2-Settings")
}

func getH2Settings(h http.Header) ([]byte, error) {
	vals, ok := h[textproto.CanonicalMIMEHeaderKey("HTTP2-Settings")]
	if !ok {
		return nil, errors.New("missing HTTP2-Settings header")
	}
	if len(vals) != 1 {
		return nil, fmt.Errorf("expected 1 HTTP2-Settings. Got: %v", vals)
	}
	settings, err := base64.RawURLEncoding.DecodeString(vals[0])
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func newBufConn(conn net.Conn, rw *bufio.ReadWriter) net.Conn {
	rw.Flush()
	if rw.Reader.Buffered() == 0 {
		return conn
	}
	return &bufConn{conn, rw.Reader}
}

type bufConn struct {
	net.Conn
	*bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(p)
	}
	n := c.Reader.Buffered()
	if n == 0 {
		c.Reader = nil
		return c.Conn.Read(p)
	}
	if n < len(p) {
		p = p[:n]
	}
	return c.Reader.Read(p)
}
