package tun

import (
	"context"
	"net"
	"os"
	"sync"
	"time"
)

const deferredHandshakeCompletion = 10 * time.Second

type DeferredHandshakeConn interface {
	HandshakeDeferred() bool
	HandshakeSuccess() error
	HandshakeFailure(err error) error
}

var _ DeferredHandshakeConn = (*deferredConn)(nil)

type deferredRequest interface {
	accept(ctx context.Context) (net.Conn, error)
	reject() error
	done() <-chan struct{}
}

type deferredConn struct {
	request deferredRequest
	ctx     context.Context
	stackDone <-chan struct{}
	local     net.Addr
	remote    net.Addr
	settled   chan struct{}

	access  sync.Mutex
	claimed bool
	done    bool
	conn    net.Conn
	err     error
	closing bool
	deadlines    [2]time.Duration
	deadlinesSet [2]bool
}

const (
	deadlineRead = iota
	deadlineWrite
)

func newDeferredConn(ctx context.Context, request deferredRequest, stackDone <-chan struct{}, local, remote net.Addr) *deferredConn {
	return &deferredConn{request: request, ctx: ctx, stackDone: stackDone, local: local, remote: remote, settled: make(chan struct{})}
}

func (c *deferredConn) Settled() <-chan struct{} { return c.settled }

func (c *deferredConn) settleLocked(conn net.Conn, err error) {
	if c.done {
		return
	}
	c.done = true
	c.conn = conn
	c.err = err
	close(c.settled)
}

func (c *deferredConn) claim() bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.claimed {
		return false
	}
	c.claimed = true
	return true
}

func (c *deferredConn) accept() error {
	if !c.claim() {
		<-c.settled
		c.access.Lock()
		defer c.access.Unlock()
		return c.err
	}
	ctx, cancel := context.WithTimeout(c.ctx, deferredHandshakeCompletion)
	defer cancel()
	if c.stackDone != nil {
		go func() {
			select {
			case <-c.stackDone:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	conn, err := c.request.accept(ctx)

	c.access.Lock()
	defer c.access.Unlock()
	if err != nil {
		deferredStats.notCompleted.Add(1)
		c.settleLocked(nil, err)
		return err
	}
	deferredStats.completed.Add(1)
	if c.closing {
		if linger, ok := conn.(interface{ SetLinger(int) error }); ok {
			_ = linger.SetLinger(0)
		}
		_ = conn.Close()
		c.settleLocked(nil, net.ErrClosed)
		return net.ErrClosed
	}
	c.applyDeadlines(conn)
	c.settleLocked(conn, nil)
	return nil
}

func (c *deferredConn) HandshakeSuccess() error { return c.accept() }

func (c *deferredConn) HandshakeFailure(err error) error {
	if !c.claim() {
		return nil
	}
	return c.reject(err)
}

func (c *deferredConn) reject(err error) error {
	deferredStats.refused.Add(1)
	_ = c.request.reject()
	c.access.Lock()
	c.settleLocked(nil, err)
	c.access.Unlock()
	return nil
}

func (c *deferredConn) abandon(err error) {
	if c.claim() {
		_ = c.reject(err)
		return
	}
	<-c.settled
}

func (c *deferredConn) established() (net.Conn, error) {
	c.access.Lock()
	if c.done {
		conn, err := c.conn, c.err
		c.access.Unlock()
		if conn == nil && err == nil {
			err = net.ErrClosed
		}
		return conn, err
	}
	c.access.Unlock()
	if err := c.accept(); err != nil {
		return nil, err
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn == nil {
		if c.err != nil {
			return nil, c.err
		}
		return nil, net.ErrClosed
	}
	return c.conn, nil
}

func (c *deferredConn) Read(b []byte) (int, error) {
	conn, err := c.established()
	if err != nil {
		return 0, err
	}
	return conn.Read(b)
}

func (c *deferredConn) Write(b []byte) (int, error) {
	conn, err := c.established()
	if err != nil {
		return 0, err
	}
	return conn.Write(b)
}

func (c *deferredConn) Close() error {
	c.access.Lock()
	if !c.done {
		c.closing = true
		c.access.Unlock()
		if c.claim() {
			return c.reject(net.ErrClosed)
		}
		return nil
	}
	conn := c.conn
	c.access.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (c *deferredConn) HandshakeDeferred() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.done
}

func (c *deferredConn) Upstream() any {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn == nil {
		return nil
	}
	return c.conn
}

func (c *deferredConn) ReaderReplaceable() bool { return c.Upstream() != nil }

func (c *deferredConn) WriterReplaceable() bool { return c.Upstream() != nil }

func (c *deferredConn) CloseWrite() error {
	c.access.Lock()
	conn := c.conn
	undecided := !c.done
	c.access.Unlock()
	if conn == nil {
		if undecided {
			return net.ErrClosed
		}
		return c.Close()
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return conn.Close()
}

func (c *deferredConn) LocalAddr() net.Addr  { return c.local }
func (c *deferredConn) RemoteAddr() net.Addr { return c.remote }

func (c *deferredConn) setDeadline(read, write bool, t time.Time) error {
	c.access.Lock()
	conn := c.conn
	if conn == nil && c.done {
		err := c.err
		c.access.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return err
	}
	if conn == nil {
		remaining := time.Until(t)
		if t.IsZero() {
			remaining = 0
		}
		if read {
			c.deadlines[deadlineRead], c.deadlinesSet[deadlineRead] = remaining, !t.IsZero()
		}
		if write {
			c.deadlines[deadlineWrite], c.deadlinesSet[deadlineWrite] = remaining, !t.IsZero()
		}
		c.access.Unlock()
		return nil
	}
	c.access.Unlock()
	switch {
	case read && write:
		return conn.SetDeadline(t)
	case read:
		return conn.SetReadDeadline(t)
	default:
		return conn.SetWriteDeadline(t)
	}
}

func (c *deferredConn) applyDeadlines(conn net.Conn) {
	now := time.Now()
	if c.deadlinesSet[deadlineRead] {
		_ = conn.SetReadDeadline(now.Add(c.deadlines[deadlineRead]))
	}
	if c.deadlinesSet[deadlineWrite] {
		_ = conn.SetWriteDeadline(now.Add(c.deadlines[deadlineWrite]))
	}
}

func (c *deferredConn) SetDeadline(t time.Time) error { return c.setDeadline(true, true, t) }

func (c *deferredConn) SetReadDeadline(t time.Time) error { return c.setDeadline(true, false, t) }

func (c *deferredConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(false, true, t) }

func (c *deferredConn) SetLinger(sec int) error {
	c.access.Lock()
	conn := c.conn
	c.access.Unlock()
	if conn == nil {
		return nil
	}
	if linger, ok := conn.(interface{ SetLinger(int) error }); ok {
		return linger.SetLinger(sec)
	}
	return nil
}

func (c *deferredConn) waitForVerdict(stackDone <-chan struct{}) {
	timer := time.NewTimer(deferredHandshakeVerdictWait())
	defer timer.Stop()
	select {
	case <-c.Settled():
	case <-c.request.done():
		c.abandon(net.ErrClosed)
	case <-stackDone:
		c.abandon(net.ErrClosed)
	case <-timer.C:
		c.abandon(os.ErrDeadlineExceeded)
	}
}
