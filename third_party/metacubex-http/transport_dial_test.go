// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http_test

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

func TestTransportPoolConnReusePriorConnection(t *testing.T) {
	dt := newTransportDialTester(t, http1Mode)

	rt1 := dt.roundTrip()
	c1 := dt.wantDial()
	c1.finish(nil)
	rt1.wantDone(c1)
	rt1.finish()

	rt2 := dt.roundTrip()
	rt2.wantDone(c1)
	rt2.finish()
}

func TestTransportPoolConnCannotReuseConnectionInUse(t *testing.T) {
	dt := newTransportDialTester(t, http1Mode)

	rt1 := dt.roundTrip()
	c1 := dt.wantDial()
	c1.finish(nil)
	rt1.wantDone(c1)

	rt2 := dt.roundTrip()
	c2 := dt.wantDial()
	c2.finish(nil)
	rt2.wantDone(c2)
}

func TestTransportPoolConnConnectionBecomesAvailableDuringDial(t *testing.T) {
	dt := newTransportDialTester(t, http1Mode)

	rt1 := dt.roundTrip()
	c1 := dt.wantDial()
	c1.finish(nil)
	rt1.wantDone(c1)

	rt2 := dt.roundTrip()
	c2 := dt.wantDial()
	rt1.finish()
	rt2.wantDone(c1)

	rt3 := dt.roundTrip()
	c3 := dt.wantDial()
	c2.finish(nil)
	rt3.wantDone(c2)

	c3.finish(nil)
}

type transportDialTester struct {
	t   *testing.T
	cst *clientServerTest

	dials chan *transportDialTesterConn

	roundTripCount int
	dialCount      int
}

type transportDialTesterRoundTrip struct {
	t *testing.T

	roundTripID int
	cancel      context.CancelFunc
	reqBody     io.WriteCloser
	finished    bool

	done chan struct{}
	res  *http.Response
	err  error
	conn *transportDialTesterConn
}

type transportDialTesterConn struct {
	t *testing.T

	connID int
	ready  chan error

	net.Conn
}

func newTransportDialTester(t *testing.T, mode testMode) *transportDialTester {
	t.Helper()
	dt := &transportDialTester{
		t:     t,
		dials: make(chan *transportDialTesterConn),
	}
	dt.cst = newClientServerTest(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).EnableFullDuplex()
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		io.ReadAll(r.Body)
	}), func(tr *http.Transport) {
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			c := &transportDialTesterConn{
				t:     t,
				ready: make(chan error),
			}
			dt.dials <- c
			if err := <-c.ready; err != nil {
				return nil, err
			}
			nc, err := net.Dial(network, address)
			if err != nil {
				return nil, err
			}
			c.Conn = nc
			return c, err
		}
	})
	return dt
}

func (dt *transportDialTester) roundTrip() *transportDialTesterRoundTrip {
	dt.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	rt := &transportDialTesterRoundTrip{
		t:           dt.t,
		roundTripID: dt.roundTripCount,
		done:        make(chan struct{}),
		reqBody:     pw,
		cancel:      cancel,
	}
	dt.roundTripCount++
	dt.t.Logf("RoundTrip %v: started", rt.roundTripID)
	dt.t.Cleanup(func() {
		rt.cancel()
		rt.finish()
	})
	go func() {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				rt.conn = info.Conn.(*transportDialTesterConn)
			},
		})
		req, _ := http.NewRequestWithContext(ctx, "POST", dt.cst.ts.URL, pr)
		req.Header.Set("Content-Type", "text/plain")
		rt.res, rt.err = dt.cst.tr.RoundTrip(req)
		dt.t.Logf("RoundTrip %v: done (err:%v)", rt.roundTripID, rt.err)
		close(rt.done)
	}()
	return rt
}

func (rt *transportDialTesterRoundTrip) wantDone(c *transportDialTesterConn) {
	rt.t.Helper()
	<-rt.done
	if rt.err != nil {
		rt.t.Fatalf("RoundTrip %v: want success, got err %v", rt.roundTripID, rt.err)
	}
	if rt.conn != c {
		rt.t.Fatalf("RoundTrip %v: want on conn %v, got conn %v", rt.roundTripID, c.connID, rt.conn.connID)
	}
}

func (rt *transportDialTesterRoundTrip) finish() {
	rt.t.Helper()

	if rt.finished {
		return
	}
	rt.finished = true

	<-rt.done

	if rt.err != nil {
		return
	}
	rt.reqBody.Close()
	io.ReadAll(rt.res.Body)
	rt.res.Body.Close()
	rt.t.Logf("RoundTrip %v: closed request body", rt.roundTripID)
}

func (dt *transportDialTester) wantDial() *transportDialTesterConn {
	c := <-dt.dials
	c.connID = dt.dialCount
	dt.dialCount++
	dt.t.Logf("Dial %v: started", c.connID)
	return c
}

func (c *transportDialTesterConn) finish(err error) {
	c.t.Logf("Dial %v: finished (err:%v)", c.connID, err)
	c.ready <- err
	close(c.ready)
}
