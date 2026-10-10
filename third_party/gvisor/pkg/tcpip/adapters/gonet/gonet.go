// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gonet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

var (
	errCanceled   = errors.New("operation canceled")
	errWouldBlock = errors.New("operation would block")
)

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

type TCPListener struct {
	stack      *stack.Stack
	ep         tcpip.Endpoint
	wq         *waiter.Queue
	cancelOnce sync.Once
	cancel     chan struct{}
}

func NewTCPListener(s *stack.Stack, wq *waiter.Queue, ep tcpip.Endpoint) *TCPListener {
	return &TCPListener{
		stack:  s,
		ep:     ep,
		wq:     wq,
		cancel: make(chan struct{}),
	}
}

const maxListenBacklog = 4096

func ListenTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPListener, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, TranslateNetstackError(err)
	}

	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  TranslateNetstackError(err),
		}
	}

	if err := ep.Listen(maxListenBacklog); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "listen",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  TranslateNetstackError(err),
		}
	}

	return NewTCPListener(s, &wq, ep), nil
}

func (l *TCPListener) Close() error {
	l.ep.Close()
	return nil
}

func (l *TCPListener) Shutdown() {
	l.ep.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	l.cancelOnce.Do(func() {
		close(l.cancel)
	})
}

func (l *TCPListener) Addr() net.Addr {
	a, err := l.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

type deadlineTimer struct {
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *deadlineTimer) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *deadlineTimer) readCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.readCancelCh
	d.mu.Unlock()
	return c
}
func (d *deadlineTimer) writeCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.writeCancelCh
	d.mu.Unlock()
	return c
}

func (d *deadlineTimer) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	if t.IsZero() {
		*timer = nil
		return
	}

	timeout := time.Until(t)
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}

func (d *deadlineTimer) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *deadlineTimer) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *deadlineTimer) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

type TCPConn struct {
	deadlineTimer

	wq *waiter.Queue
	ep tcpip.Endpoint

	readMu sync.Mutex

	read []byte
}

func NewTCPConn(wq *waiter.Queue, ep tcpip.Endpoint) *TCPConn {
	c := &TCPConn{
		wq: wq,
		ep: ep,
	}
	c.deadlineTimer.init()
	return c
}

func (l *TCPListener) Accept() (net.Conn, error) {
	n, wq, err := l.ep.Accept(nil)

	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		l.wq.EventRegister(&waitEntry)
		defer l.wq.EventUnregister(&waitEntry)

		for {
			n, wq, err = l.ep.Accept(nil)

			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}

			select {
			case <-l.cancel:
				return nil, errCanceled
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  TranslateNetstackError(err),
		}
	}

	return NewTCPConn(wq, n), nil
}

type opErrorer interface {
	newOpError(op string, err error) *net.OpError
}

func commonRead(b []byte, ep tcpip.Endpoint, wq *waiter.Queue, deadline <-chan struct{}, addr *tcpip.FullAddress, errorer opErrorer) (int, error) {
	select {
	case <-deadline:
		return 0, errorer.newOpError("read", &timeoutError{})
	default:
	}

	w := tcpip.SliceWriter(b)
	opts := tcpip.ReadOptions{NeedRemoteAddr: addr != nil}
	res, err := ep.Read(&w, opts)

	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)
		for {
			res, err = ep.Read(&w, opts)
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}
			select {
			case <-deadline:
				return 0, errorer.newOpError("read", &timeoutError{})
			case <-notifyCh:
			}
		}
	}

	if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
		return 0, io.EOF
	}

	if err != nil {
		return 0, errorer.newOpError("read", TranslateNetstackError(err))
	}

	if addr != nil {
		*addr = res.RemoteAddr
	}
	return res.Count, nil
}

func (c *TCPConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	deadline := c.readCancel()

	n, err := commonRead(b, c.ep, c.wq, deadline, nil, c)
	if n != 0 {
		c.ep.ModerateRecvBuf(n)
	}
	return n, err
}

func (c *TCPConn) Write(b []byte) (int, error) {
	deadline := c.writeCancel()

	select {
	case <-deadline:
		return 0, c.newOpError("write", &timeoutError{})
	default:
	}

	var (
		r      bytes.Reader
		nbytes int
		entry  waiter.Entry
		ch     <-chan struct{}
	)
	for nbytes != len(b) {
		r.Reset(b[nbytes:])
		n, err := c.ep.Write(&r, tcpip.WriteOptions{})
		nbytes += int(n)
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			if ch == nil {
				entry, ch = waiter.NewChannelEntry(waiter.WritableEvents)
				c.wq.EventRegister(&entry)
				defer c.wq.EventUnregister(&entry)
			} else {
				select {
				case <-deadline:
					return nbytes, c.newOpError("write", &timeoutError{})
				case <-ch:
					continue
				}
			}
		default:
			return nbytes, c.newOpError("write", TranslateNetstackError(err))
		}
	}
	return nbytes, nil
}

func (c *TCPConn) Close() error {
	c.ep.Close()
	return nil
}

func (c *TCPConn) CloseRead() error {
	if terr := c.ep.Shutdown(tcpip.ShutdownRead); terr != nil {
		return c.newOpError("close", errors.New(terr.String()))
	}
	return nil
}

func (c *TCPConn) CloseWrite() error {
	if terr := c.ep.Shutdown(tcpip.ShutdownWrite); terr != nil {
		return c.newOpError("close", errors.New(terr.String()))
	}
	return nil
}

func (c *TCPConn) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

func (c *TCPConn) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

func (c *TCPConn) newOpError(op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Source: c.LocalAddr(),
		Addr:   c.RemoteAddr(),
		Err:    err,
	}
}

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr.AsSlice()), Port: int(addr.Port)}
}

func fullToUDPAddr(addr tcpip.FullAddress) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(addr.Addr.AsSlice()), Port: int(addr.Port)}
}

func DialTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPConn, error) {
	return DialContextTCP(context.Background(), s, addr, network)
}

func DialTCPWithBind(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, TranslateNetstackError(err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if localAddr != (tcpip.FullAddress{}) {
		if err = ep.Bind(localAddr); err != nil {
			return nil, fmt.Errorf("ep.Bind(%+v) = %s", localAddr, err)
		}
	}

	err = ep.Connect(remoteAddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}

		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: fullToTCPAddr(remoteAddr),
			Err:  TranslateNetstackError(err),
		}
	}

	return NewTCPConn(&wq, ep), nil
}

func DialContextTCP(ctx context.Context, s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPConn, error) {
	return DialTCPWithBind(ctx, s, tcpip.FullAddress{}, addr, network)
}

type UDPConn struct {
	deadlineTimer

	ep tcpip.Endpoint
	wq *waiter.Queue
}

func NewUDPConn(wq *waiter.Queue, ep tcpip.Endpoint) *UDPConn {
	c := &UDPConn{
		ep: ep,
		wq: wq,
	}
	c.deadlineTimer.init()
	return c
}

func DialUDP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*UDPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, TranslateNetstackError(err)
	}

	if laddr != nil {
		if err := ep.Bind(*laddr); err != nil {
			ep.Close()
			return nil, &net.OpError{
				Op:   "bind",
				Net:  "udp",
				Addr: fullToUDPAddr(*laddr),
				Err:  TranslateNetstackError(err),
			}
		}
	}

	c := NewUDPConn(&wq, ep)

	if raddr != nil {
		if err := c.ep.Connect(*raddr); err != nil {
			c.ep.Close()
			return nil, &net.OpError{
				Op:   "connect",
				Net:  "udp",
				Addr: fullToUDPAddr(*raddr),
				Err:  TranslateNetstackError(err),
			}
		}
	}

	return c, nil
}

func (c *UDPConn) newOpError(op string, err error) *net.OpError {
	return c.newRemoteOpError(op, nil, err)
}

func (c *UDPConn) newRemoteOpError(op string, remote net.Addr, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "udp",
		Source: c.LocalAddr(),
		Addr:   remote,
		Err:    err,
	}
}

func (c *UDPConn) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return fullToUDPAddr(a)
}

func (c *UDPConn) Read(b []byte) (int, error) {
	bytesRead, _, err := c.ReadFrom(b)
	return bytesRead, err
}

func (c *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	deadline := c.readCancel()

	var addr tcpip.FullAddress
	n, err := commonRead(b, c.ep, c.wq, deadline, &addr, c)
	if err != nil {
		return 0, nil, err
	}
	return n, fullToUDPAddr(addr), nil
}

func (c *UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, nil)
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	deadline := c.writeCancel()

	select {
	case <-deadline:
		return 0, c.newRemoteOpError("write", addr, &timeoutError{})
	default:
	}

	writeOptions := tcpip.WriteOptions{}
	if addr != nil {
		ua := addr.(*net.UDPAddr)
		writeOptions.To = &tcpip.FullAddress{
			Addr: tcpip.AddrFromSlice(ua.IP),
			Port: uint16(ua.Port),
		}
	}

	var r bytes.Reader
	r.Reset(b)
	n, err := c.ep.Write(&r, writeOptions)
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
		c.wq.EventRegister(&waitEntry)
		defer c.wq.EventUnregister(&waitEntry)
		for {
			select {
			case <-deadline:
				return int(n), c.newRemoteOpError("write", addr, &timeoutError{})
			case <-notifyCh:
			}

			n, err = c.ep.Write(&r, writeOptions)
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}
		}
	}

	if err == nil {
		return int(n), nil
	}

	return int(n), c.newRemoteOpError("write", addr, TranslateNetstackError(err))
}

func (c *UDPConn) Close() error {
	c.ep.Close()
	return nil
}

func (c *UDPConn) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToUDPAddr(a)
}
