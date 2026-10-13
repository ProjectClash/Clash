package outbound

import (
	"context"
	"sync"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)


type sessionUse struct {
	mu         sync.Mutex
	dialing    int
	conns      int
	open       bool
	userOpened bool
	lastActive time.Time
	node       *catalogNode
}

func sessionUseFor(adapter ProxyAdapter) *sessionUse {
	if node, ok := adapter.(*catalogNode); ok {
		node.use.node = node
		return &node.use
	}
	return &sessionUse{}
}

func (u *sessionUse) mayBeIdle() {
	if u.node != nil {
		u.node.afterUse()
	}
}

func (u *sessionUse) dial(ctx context.Context) func() {
	probe := dialer.DialKindOf(ctx) == dialer.DialKindProbe
	u.mu.Lock()
	u.dialing++
	u.open = true
	if !probe {
		u.userOpened = true
	}
	u.lastActive = time.Now()
	u.mu.Unlock()
	return func() {
		u.mu.Lock()
		u.dialing--
		u.lastActive = time.Now()
		u.mu.Unlock()
		u.mayBeIdle()
	}
}

func (p *autoCloseProxyAdapter) dialing(ctx context.Context) func() {
	if dials, ok := ctx.Value(probeDialsKey{}).(*probeDials); ok {
		dials.note(p)
	}
	return p.use.dial(ctx)
}

type probeDialsKey struct{}

type probeDials struct {
	mu    sync.Mutex
	nodes []C.ProxyAdapter
}

func (d *probeDials) note(node C.ProxyAdapter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, seen := range d.nodes {
		if seen == node {
			return
		}
	}
	d.nodes = append(d.nodes, node)
}

func WithProbeDials(ctx context.Context) context.Context {
	return context.WithValue(ctx, probeDialsKey{}, &probeDials{})
}

func ProbeDialed(ctx context.Context) []C.ProxyAdapter {
	dials, ok := ctx.Value(probeDialsKey{}).(*probeDials)
	if !ok {
		return nil
	}
	dials.mu.Lock()
	defer dials.mu.Unlock()
	return append([]C.ProxyAdapter(nil), dials.nodes...)
}

type connClosing interface {
	onClose(closed func())
}

func (u *sessionUse) opened(c any) {
	u.mu.Lock()
	u.conns++
	u.mu.Unlock()
	hook, ok := c.(connClosing)
	if !ok {
		return
	}
	var once sync.Once
	hook.onClose(func() {
		once.Do(func() {
			u.mu.Lock()
			u.conns--
			u.lastActive = time.Now()
			u.mu.Unlock()
			u.mayBeIdle()
		})
	})
}

func (c *conn) onClose(closed func()) {
	c.ExtendedConn = &closingConn{ExtendedConn: c.ExtendedConn, closed: closed}
}

func (c *packetConn) onClose(closed func()) {
	c.EnhancePacketConn = &closingPacketConn{EnhancePacketConn: c.EnhancePacketConn, closed: closed}
}

type closingConn struct {
	N.ExtendedConn
	closed func()
}

func (c *closingConn) Close() error {
	defer c.closed()
	return c.ExtendedConn.Close()
}

func (c *closingConn) Upstream() any           { return c.ExtendedConn }
func (c *closingConn) ReaderReplaceable() bool { return true }
func (c *closingConn) WriterReplaceable() bool { return true }

type closingPacketConn struct {
	N.EnhancePacketConn
	closed func()
}

func (c *closingPacketConn) Close() error {
	defer c.closed()
	return c.EnhancePacketConn.Close()
}

func (c *closingPacketConn) Upstream() any           { return c.EnhancePacketConn }
func (c *closingPacketConn) ReaderReplaceable() bool { return true }
func (c *closingPacketConn) WriterReplaceable() bool { return true }

type SessionReleaser interface {
	ReleaseSessions() bool
}

func (u *sessionUse) inUse() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.dialing > 0 || u.conns > 0
}

func (u *sessionUse) release(node C.ProxyAdapter, resetter NetworkResetter, allowed func() bool) bool {
	released := u.releaseLocked(node, resetter, allowed)
	u.mayBeIdle()
	return released
}

func (u *sessionUse) releaseLocked(node C.ProxyAdapter, resetter NetworkResetter, allowed func() bool) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.open || u.dialing > 0 || u.conns > 0 || !allowed() {
		return false
	}
	if releaser, ok := node.(SessionReleaser); ok {
		if !releaser.ReleaseSessions() {
			return false
		}
	} else {
		resetter.ResetNetwork()
	}
	u.open, u.userOpened = false, false
	return true
}

func releasable(a C.ProxyAdapter) (*autoCloseProxyAdapter, NetworkResetter, bool) {
	wrapped, ok := a.(*autoCloseProxyAdapter)
	if !ok {
		return nil, nil, false
	}
	if node, ok := wrapped.ProxyAdapter.(*catalogNode); ok {
		return wrapped, node, node.keepsSessions()
	}
	resetter, ok := wrapped.ProxyAdapter.(NetworkResetter)
	if !ok {
		_, ok = wrapped.ProxyAdapter.(SessionReleaser)
	}
	return wrapped, resetter, ok
}

func ReleaseProbedSession(a C.ProxyAdapter) bool {
	wrapped, resetter, ok := releasable(a)
	if !ok {
		return false
	}
	return wrapped.use.release(wrapped.ProxyAdapter, resetter, func() bool {
		return !wrapped.use.userOpened
	})
}

func ReleaseUserSessionIfIdle(a C.ProxyAdapter, now time.Time, idle time.Duration) bool {
	wrapped, resetter, ok := releasable(a)
	if !ok {
		return false
	}
	return wrapped.use.release(wrapped.ProxyAdapter, resetter, func() bool {
		return now.Sub(wrapped.use.lastActive) >= idle
	})
}

func sessionDialing(a C.ProxyAdapter) bool {
	wrapped, ok := a.(*autoCloseProxyAdapter)
	if !ok {
		return false
	}
	wrapped.use.mu.Lock()
	defer wrapped.use.mu.Unlock()
	return wrapped.use.dialing > 0
}
