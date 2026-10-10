package inner

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

var ErrNoTunnel = errors.New("tunnel uninitialized")

var tcpLifecycle struct {
	sessionMu sync.Mutex
	mu        sync.Mutex
	tunnel    C.Tunnel
	closed    bool
	active    map[*tcpConnection]struct{}
}

func New(t C.Tunnel) {
	tcpLifecycle.sessionMu.Lock()
	defer tcpLifecycle.sessionMu.Unlock()
	tcpLifecycle.mu.Lock()
	defer tcpLifecycle.mu.Unlock()
	tcpLifecycle.tunnel = t
	tcpLifecycle.closed = false
}

func GetTunnel() C.Tunnel {
	tcpLifecycle.mu.Lock()
	defer tcpLifecycle.mu.Unlock()
	return tcpLifecycle.tunnel
}

func CloseTCPConnections() {
	tcpLifecycle.sessionMu.Lock()
	defer tcpLifecycle.sessionMu.Unlock()
	tcpLifecycle.mu.Lock()
	tcpLifecycle.closed = true
	active := make([]*tcpConnection, 0, len(tcpLifecycle.active))
	for conn := range tcpLifecycle.active {
		active = append(active, conn)
	}
	tcpLifecycle.mu.Unlock()
	for _, conn := range active {
		_ = conn.Close()
	}
	deadline := time.NewTimer(closeTCPConnectionsJoinTimeout)
	defer deadline.Stop()
	for _, conn := range active {
		select {
		case <-conn.done:
		case <-deadline.C:
			log.Warnln("[Inner] %d internal TCP handler(s) still running after %s; continuing shutdown without them", len(active), closeTCPConnectionsJoinTimeout)
			return
		}
	}
}

const closeTCPConnectionsJoinTimeout = 3 * time.Second

type tcpConnection struct {
	net.Conn
	server net.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

func (c *tcpConnection) Upstream() any           { return c.Conn }
func (c *tcpConnection) ReaderReplaceable() bool { return true }
func (c *tcpConnection) WriterReplaceable() bool { return true }

func (c *tcpConnection) Close() error {
	c.cancel()
	_ = c.server.Close()
	return c.Conn.Close()
}

type contextTunnel interface {
	HandleTCPConnContext(context.Context, net.Conn, *C.Metadata)
}

func HandleTcp(tunnel C.Tunnel, address string, proxy string) (net.Conn, error) {
	return HandleTcpContext(context.Background(), tunnel, address, proxy)
}

func HandleTcpContext(parent context.Context, tunnel C.Tunnel, address string, proxy string) (net.Conn, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DNSMode: C.DNSNormal, Process: C.MihomoName, SpecialProxy: proxy}
	if err := metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}

	handler, managed := tunnel.(contextTunnel)
	tcpLifecycle.mu.Lock()
	defer tcpLifecycle.mu.Unlock()
	if tcpLifecycle.closed && (managed || tunnel == nil) {
		return nil, net.ErrClosed
	}
	if tunnel == nil {
		return nil, ErrNoTunnel
	}
	conn1, conn2 := N.Pipe()
	ctx, cancel := context.WithCancel(parent)
	conn := &tcpConnection{Conn: conn1, server: conn2, cancel: cancel, done: make(chan struct{})}
	if managed {
		if tcpLifecycle.active == nil {
			tcpLifecycle.active = make(map[*tcpConnection]struct{})
		}
		tcpLifecycle.active[conn] = struct{}{}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	go func() {
		defer func() {
			stop()
			cancel()
			_ = conn2.Close()
			tcpLifecycle.mu.Lock()
			delete(tcpLifecycle.active, conn)
			close(conn.done)
			tcpLifecycle.mu.Unlock()
		}()
		if managed {
			handler.HandleTCPConnContext(ctx, conn2, metadata)
		} else {
			tunnel.HandleTCPConn(conn2, metadata)
		}
	}()
	return conn, nil
}
