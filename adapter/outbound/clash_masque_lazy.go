package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	"github.com/metacubex/quic-go"
)

type clashMasqueStack struct {
	mu        sync.Mutex
	closed    bool
	builds    int
	releases  int
	prefixes  []netip.Prefix
	mtu       uint32
	built     atomic.Pointer[clashMasqueBuilt]
	runCancel context.CancelFunc
	runConn   *quic.Conn

	handle clashMasqueTun

	resolverUse sessionUse
}

type clashMasqueBuilt struct {
	stack ipStack
}

const clashMasqueRunStopWait = 2 * time.Second

func (s *clashMasqueStack) tunHandle() ipStack {
	s.handle.s = s
	return &s.handle
}

func (w *Masque) clashBuildStack() (ipStack, error) {
	s := &w.clashStack
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errOutboundClosed
	}
	if built := s.built.Load(); built != nil {
		return built.stack, nil
	}
	stack, err := newIPStack(w.option.IPStack, s.prefixes, s.mtu)
	if err != nil {
		return nil, fmt.Errorf("create device: %w", err)
	}
	s.built.Store(&clashMasqueBuilt{stack: stack})
	s.builds++
	return stack, nil
}

func (w *Masque) clashRunConn(conn *quic.Conn) {
	w.clashStack.mu.Lock()
	w.clashStack.runConn = conn
	w.clashStack.mu.Unlock()
}

func (w *Masque) clashRunStarted(cancel context.CancelFunc) {
	w.clashStack.mu.Lock()
	w.clashStack.runCancel = cancel
	w.clashStack.mu.Unlock()
}

func (w *Masque) ReleaseSessions() bool {
	if w.l4Client != nil {
		return true
	}
	if !w.runLock.TryAcquire(1) {
		return false
	}
	defer w.runLock.Release(1)
	s := &w.clashStack
	s.mu.Lock()
	if s.closed || s.built.Load() == nil {
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	resolver := &s.resolverUse
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.dialing > 0 || resolver.conns > 0 {
		return false
	}
	if clashMasqueReleaseChecked != nil {
		clashMasqueReleaseChecked()
	}
	s.mu.Lock()
	cancel, conn := s.runCancel, s.runConn
	s.runCancel, s.runConn = nil, nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if cancel != nil {
		cancel()
		for deadline := time.Now().Add(clashMasqueRunStopWait); w.running.Load(); {
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(time.Millisecond)
		}
	}
	if w.running.Load() {
		return false
	}
	s.mu.Lock()
	built := s.built.Swap(nil)
	if built != nil {
		s.releases++
	}
	s.mu.Unlock()
	w.runDevice.Store(false)
	if built != nil {
		_ = built.stack.Close()
	}
	return true
}

func (s *clashMasqueStack) close() {
	s.mu.Lock()
	s.closed = true
	built := s.built.Swap(nil)
	s.mu.Unlock()
	if built != nil {
		_ = built.stack.Close()
	}
}

func (w *Masque) clashStackBuilds() int {
	w.clashStack.mu.Lock()
	defer w.clashStack.mu.Unlock()
	return w.clashStack.builds
}

type clashMasqueTun struct{ s *clashMasqueStack }

func (h *clashMasqueTun) current() (ipStack, error) {
	built := h.s.built.Load()
	if built == nil {
		return nil, errClashReleased
	}
	return built.stack, nil
}

func (h *clashMasqueTun) Start() error {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if h.s.closed {
		return errOutboundClosed
	}
	stack, err := h.current()
	if err != nil {
		return err
	}
	return stack.Start()
}

func (h *clashMasqueTun) Close() error {
	h.s.close()
	return nil
}

func (h *clashMasqueTun) DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.DialTCP(ctx, network, source, destination)
}

func (h *clashMasqueTun) DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.DialUDP(ctx, network, source, destination)
}

func (h *clashMasqueTun) DialIP(ctx context.Context, network string, source, destination netip.Addr) (net.Conn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.DialIP(ctx, network, source, destination)
}

func (h *clashMasqueTun) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.ListenTCP(ctx, network, local)
}

func (h *clashMasqueTun) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.ListenUDP(ctx, network, local)
}

func (h *clashMasqueTun) ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.ListenIP(ctx, network, local)
}

func (h *clashMasqueTun) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	stack, err := h.current()
	if err != nil {
		return 0, os.ErrClosed
	}
	return stack.Read(buffers, sizes, offset)
}

func (h *clashMasqueTun) Write(buffers [][]byte, offset int) (int, error) {
	stack, err := h.current()
	if err != nil {
		return 0, os.ErrClosed
	}
	return stack.Write(buffers, offset)
}

func (h *clashMasqueTun) MTU() (int, error) {
	stack, err := h.current()
	if err != nil {
		return 0, err
	}
	return stack.MTU()
}

func (h *clashMasqueTun) Name() (string, error) {
	stack, err := h.current()
	if err != nil {
		return "", err
	}
	return stack.Name()
}

func (h *clashMasqueTun) BatchSize() int {
	stack, err := h.current()
	if err != nil {
		return 1
	}
	return stack.BatchSize()
}

var clashMasqueReleaseChecked func()

type clashMasqueResolverDialer struct {
	*Masque
}

func (d clashMasqueResolverDialer) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	defer d.clashStack.resolverUse.dial(ctx)()
	c, err := d.Masque.DialContext(ctx, metadata)
	if err == nil {
		d.clashStack.resolverUse.opened(c)
	}
	return c, err
}

func (d clashMasqueResolverDialer) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	defer d.clashStack.resolverUse.dial(ctx)()
	pc, err := d.Masque.ListenPacketContext(ctx, metadata)
	if err == nil {
		d.clashStack.resolverUse.opened(pc)
	}
	return pc, err
}
