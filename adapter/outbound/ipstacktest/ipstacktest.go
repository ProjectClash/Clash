package ipstacktest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

func New(mtu uint32) *StandIn {
	return &StandIn{mtu: mtu, closed: make(chan struct{})}
}

type StandIn struct {
	mtu       uint32
	closeOnce sync.Once
	closed    chan struct{}
}

var errStandIn = errors.New("the stand-in IP stack carries nothing")

func (s *StandIn) Start() error { return nil }
func (s *StandIn) DialTCP(ctx context.Context, _ string, _, _ netip.AddrPort) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, net.ErrClosed
	}
}
func (s *StandIn) DialUDP(context.Context, string, netip.AddrPort, netip.AddrPort) (net.Conn, error) {
	return nil, errStandIn
}
func (s *StandIn) DialIP(context.Context, string, netip.Addr, netip.Addr) (net.Conn, error) {
	return nil, errStandIn
}
func (s *StandIn) ListenTCP(context.Context, string, netip.AddrPort) (net.Listener, error) {
	return nil, errStandIn
}
func (s *StandIn) ListenUDP(context.Context, string, netip.AddrPort) (net.PacketConn, error) {
	return &standInPacketConn{stack: s, closed: make(chan struct{})}, nil
}

type standInPacketConn struct {
	stack     *StandIn
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *standInPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
	case <-c.stack.closed:
	}
	return 0, nil, net.ErrClosed
}

func (c *standInPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.stack.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *standInPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *standInPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)} }
func (c *standInPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *standInPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *standInPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (s *StandIn) ListenIP(context.Context, string, netip.Addr) (net.PacketConn, error) {
	return nil, errStandIn
}
func (s *StandIn) Read([][]byte, []int, int) (int, error) {
	<-s.closed
	return 0, os.ErrClosed
}
func (s *StandIn) Write(buffers [][]byte, _ int) (int, error) { return len(buffers), nil }
func (s *StandIn) MTU() (int, error)                          { return int(s.mtu), nil }
func (s *StandIn) Name() (string, error)                      { return "stand-in", nil }
func (s *StandIn) BatchSize() int                             { return 1 }
func (s *StandIn) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}
