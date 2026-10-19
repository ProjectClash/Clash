// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package httptest

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/metacubex/http"
	"github.com/metacubex/http/internal/testcert"
	"github.com/metacubex/tls"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Server struct {
	URL      string
	Listener net.Listener

	EnableHTTP2 bool

	TLS *tls.Config

	Config *http.Server

	certificate *x509.Certificate

	wg sync.WaitGroup

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]http.ConnState

	client *http.Client
}

func newLocalListener() net.Listener {
	if serveFlag != "" {
		l, err := net.Listen("tcp", serveFlag)
		if err != nil {
			panic(fmt.Sprintf("httptest: failed to listen on %v: %v", serveFlag, err))
		}
		return l
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("httptest: failed to listen on a port: %v", err))
		}
	}
	return l
}

var serveFlag string

func init() {
	if strSliceContainsPrefix(os.Args, "-httptest.serve=") || strSliceContainsPrefix(os.Args, "--httptest.serve=") {
		flag.StringVar(&serveFlag, "httptest.serve", "", "if non-empty, httptest.NewServer serves on this address and blocks.")
	}
}

func strSliceContainsPrefix(v []string, pre string) bool {
	for _, s := range v {
		if strings.HasPrefix(s, pre) {
			return true
		}
	}
	return false
}

func NewServer(handler http.Handler) *Server {
	ts := NewUnstartedServer(handler)
	ts.Start()
	return ts
}

func NewUnstartedServer(handler http.Handler) *Server {
	return &Server{
		Listener: newLocalListener(),
		Config:   &http.Server{Handler: handler},
	}
}

func (s *Server) Start() {
	if s.URL != "" {
		panic("Server already started")
	}

	if s.client == nil {
		tr := &http.Transport{}
		dialer := net.Dialer{}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if tr.Dial != nil {
				return tr.Dial(network, addr)
			}
			if addr == "example.com:80" || strings.HasSuffix(addr, ".example.com:80") {
				addr = s.Listener.Addr().String()
			}
			return dialer.DialContext(ctx, network, addr)
		}
		s.client = &http.Client{Transport: tr}

	}
	s.URL = "http://" + s.Listener.Addr().String()
	s.wrap()
	s.goServe()
	if serveFlag != "" {
		fmt.Fprintln(os.Stderr, "httptest: serving on", s.URL)
		select {}
	}
}

func (s *Server) StartTLS() {
	if s.URL != "" {
		panic("Server already started")
	}
	if s.client == nil {
		s.client = &http.Client{}
	}
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		panic(fmt.Sprintf("httptest: NewTLSServer: %v", err))
	}

	existingConfig := s.TLS
	if existingConfig != nil {
		s.TLS = existingConfig.Clone()
	} else {
		s.TLS = new(tls.Config)
	}
	if s.TLS.NextProtos == nil {
		nextProtos := []string{"http/1.1"}
		if s.EnableHTTP2 {
			nextProtos = []string{"h2"}
		}
		s.TLS.NextProtos = nextProtos
	}
	if len(s.TLS.Certificates) == 0 {
		s.TLS.Certificates = []tls.Certificate{cert}
	}
	s.certificate, err = x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("httptest: NewTLSServer: %v", err))
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(s.certificate)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certpool,
		},
		ForceAttemptHTTP2: s.EnableHTTP2,
	}
	dialer := net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if tr.Dial != nil {
			return tr.Dial(network, addr)
		}
		if addr == "example.com:443" || strings.HasSuffix(addr, ".example.com:443") {
			addr = s.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, addr)
	}
	s.client.Transport = tr
	s.Listener = tls.NewListener(s.Listener, s.TLS)
	s.URL = "https://" + s.Listener.Addr().String()
	s.wrap()
	s.goServe()
}

func NewTLSServer(handler http.Handler) *Server {
	ts := NewUnstartedServer(handler)
	ts.StartTLS()
	return ts
}

type closeIdleTransport interface {
	CloseIdleConnections()
}

func (s *Server) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.Listener.Close()
		s.Config.SetKeepAlivesEnabled(false)
		for c, st := range s.conns {
			if st == http.StateIdle || st == http.StateNew {
				s.closeConn(c)
			}
		}
		t := time.AfterFunc(5*time.Second, s.logCloseHangDebugInfo)
		defer t.Stop()
	}
	s.mu.Unlock()

	if t, ok := http.DefaultTransport.(closeIdleTransport); ok {
		t.CloseIdleConnections()
	}

	if s.client != nil {
		if t, ok := s.client.Transport.(closeIdleTransport); ok {
			t.CloseIdleConnections()
		}
	}

	s.wg.Wait()
}

func (s *Server) logCloseHangDebugInfo() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf strings.Builder
	buf.WriteString("httptest.Server blocked in Close after 5 seconds, waiting for connections:\n")
	for c, st := range s.conns {
		fmt.Fprintf(&buf, "  %T %p %v in state %v\n", c, c, c.RemoteAddr(), st)
	}
	log.Print(buf.String())
}

func (s *Server) CloseClientConnections() {
	s.mu.Lock()
	nconn := len(s.conns)
	ch := make(chan struct{}, nconn)
	for c := range s.conns {
		go s.closeConnChan(c, ch)
	}
	s.mu.Unlock()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for i := 0; i < nconn; i++ {
		select {
		case <-ch:
		case <-timer.C:
			return
		}
	}
}

func (s *Server) Certificate() *x509.Certificate {
	return s.certificate
}

func (s *Server) Client() *http.Client {
	return s.client
}

func (s *Server) goServe() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.Config.Serve(s.Listener)
	}()
}

func (s *Server) wrap() {
	oldHook := s.Config.ConnState
	s.Config.ConnState = func(c net.Conn, cs http.ConnState) {
		s.mu.Lock()
		defer s.mu.Unlock()

		switch cs {
		case http.StateNew:
			if _, exists := s.conns[c]; exists {
				panic("invalid state transition")
			}
			if s.conns == nil {
				s.conns = make(map[net.Conn]http.ConnState)
			}
			s.wg.Add(1)
			s.conns[c] = cs
			if s.closed {
				s.closeConn(c)
			}
		case http.StateActive:
			if oldState, ok := s.conns[c]; ok {
				if oldState != http.StateNew && oldState != http.StateIdle {
					panic("invalid state transition")
				}
				s.conns[c] = cs
			}
		case http.StateIdle:
			if oldState, ok := s.conns[c]; ok {
				if oldState != http.StateActive {
					panic("invalid state transition")
				}
				s.conns[c] = cs
			}
			if s.closed {
				s.closeConn(c)
			}
		case http.StateHijacked, http.StateClosed:
			if _, ok := s.conns[c]; ok {
				delete(s.conns, c)
				defer s.wg.Done()
			}
		}
		if oldHook != nil {
			oldHook(c, cs)
		}
	}
}

func (s *Server) closeConn(c net.Conn) { s.closeConnChan(c, nil) }

func (s *Server) closeConnChan(c net.Conn, done chan<- struct{}) {
	c.Close()
	if done != nil {
		done <- struct{}{}
	}
}
