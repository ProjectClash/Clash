package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	"github.com/metacubex/wireguard-go/tun"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type clashWireGuardDevice struct {
	mu       sync.Mutex
	closed   bool
	builds   int
	releases int
	built    atomic.Pointer[clashWireGuardBuilt]
	released time.Time

	tunHandle    clashWireGuardTun
	deviceHandle clashWireGuardGoDevice

	resolverUse sessionUse

	bindDials clashBindDials
}

type clashWireGuardBuilt struct {
	tun    wireguardDevice
	device wireguardGoDevice

	upStarted atomic.Bool
	up        chan struct{}
}

func (w *WireGuard) clashDeviceUp() {
	built := w.clashDevice.built.Load()
	if built == nil || !built.upStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(built.up)
		if up, ok := built.device.(interface{ Up() error }); ok {
			_ = up.Up()
		}
	}()
}

func (w *WireGuard) clashAwaitUp(ctx context.Context) error {
	built := w.clashDevice.built.Load()
	if built == nil || !built.upStarted.Load() {
		return nil
	}
	select {
	case <-built.up:
		return nil
	default:
	}
	select {
	case <-built.up:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

const clashReleaseSettle = 200 * time.Millisecond

func (b *clashWireGuardBuilt) clashSettles(dials *clashBindDials, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	if b.upStarted.Load() {
		select {
		case <-b.up:
		case <-timer.C:
			return false
		}
	}
	select {
	case <-dials.quiet():
		return true
	case <-timer.C:
		return false
	}
}

func (b *clashWireGuardBuilt) clashComingUp() bool {
	if !b.upStarted.Load() {
		return false
	}
	select {
	case <-b.up:
		return false
	default:
		return true
	}
}

var errClashReleased = errors.New("outbound released its idle session; dial again")

func (d *clashWireGuardDevice) handles() (wireguardDevice, wireguardGoDevice) {
	d.tunHandle.d, d.deviceHandle.d = d, d
	return &d.tunHandle, &d.deviceHandle
}

const clashRehandshakeGap = 50 * time.Millisecond

func (w *WireGuard) clashAwaitRehandshakeGap() {
	d := &w.clashDevice
	d.mu.Lock()
	wait := clashRehandshakeGap - time.Since(d.released)
	d.mu.Unlock()
	if wait > 0 && wait <= clashRehandshakeGap {
		time.Sleep(wait)
	}
}

func (w *WireGuard) clashForgetRebuildFailure() {
	d := &w.clashDevice
	d.mu.Lock()
	released := d.releases != 0
	d.mu.Unlock()
	if released {
		w.initErr = nil
	}
}

func (w *WireGuard) clashPublish(tunDevice wireguardDevice, wgDevice wireguardGoDevice) error {
	d := &w.clashDevice
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errOutboundClosed
	}
	d.built.Store(&clashWireGuardBuilt{tun: tunDevice, device: wgDevice, up: make(chan struct{})})
	d.builds++
	return nil
}

func (w *WireGuard) ReleaseSessions() bool {
	if !w.initMutex.TryLock() {
		return false
	}
	defer w.initMutex.Unlock()
	resolver := &w.clashDevice.resolverUse
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.dialing > 0 || resolver.conns > 0 {
		return false
	}
	if clashWireGuardReleaseChecked != nil {
		clashWireGuardReleaseChecked()
	}
	d := &w.clashDevice
	if built := d.built.Load(); built != nil {
		d.bindDials.stop(false)
		if !built.clashSettles(&d.bindDials, clashReleaseSettle) {
			d.bindDials.resume()
			return false
		}
		defer d.bindDials.resume()
	}
	d.mu.Lock()
	built := d.built.Load()
	if built != nil {
		w.initOk.Store(false)
		w.initErr = nil
		d.built.Store(nil)
		d.releases++
		d.released = time.Now()
	}
	d.mu.Unlock()
	if built != nil {
		built.device.Close()
	}
	return true
}

func (d *clashWireGuardDevice) close() {
	d.mu.Lock()
	d.closed = true
	built := d.built.Swap(nil)
	d.mu.Unlock()
	dialing := d.bindDials.stop(true)
	if built == nil {
		return
	}
	if dialing || built.clashComingUp() {
		go built.device.Close()
		return
	}
	built.device.Close()
}

type clashBindDials struct {
	mu      sync.Mutex
	refuse  bool
	closed  bool
	next    uint64
	cancels map[uint64]context.CancelFunc
	quietCh chan struct{}
}

var clashClosedChan = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

func (b *clashBindDials) quiet() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cancels) == 0 {
		return clashClosedChan
	}
	if b.quietCh == nil {
		b.quietCh = make(chan struct{})
	}
	return b.quietCh
}

func (b *clashBindDials) start(ctx context.Context) (context.Context, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refuse {
		return nil, nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	if b.cancels == nil {
		b.cancels = make(map[uint64]context.CancelFunc)
	}
	id := b.next
	b.next++
	b.cancels[id] = cancel
	return ctx, func() {
		b.mu.Lock()
		delete(b.cancels, id)
		if len(b.cancels) == 0 && b.quietCh != nil {
			close(b.quietCh)
			b.quietCh = nil
		}
		b.mu.Unlock()
		cancel()
	}, nil
}

func (b *clashBindDials) stop(forGood bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refuse = true
	b.closed = b.closed || forGood
	for _, cancel := range b.cancels {
		cancel()
	}
	return len(b.cancels) > 0
}

func (b *clashBindDials) resume() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refuse = b.closed
}

type clashBindDialer struct {
	N.Dialer
	dials *clashBindDials
}

func (d clashBindDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, done, err := d.dials.start(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d clashBindDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, done, err := d.dials.start(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return d.Dialer.ListenPacket(ctx, destination)
}

func (w *WireGuard) clashDeviceBuilds() int {
	w.clashDevice.mu.Lock()
	defer w.clashDevice.mu.Unlock()
	return w.clashDevice.builds
}

type clashWireGuardGoDevice struct{ d *clashWireGuardDevice }

func (h *clashWireGuardGoDevice) Close() { h.d.close() }

func (h *clashWireGuardGoDevice) IpcSet(uapiConf string) error {
	built := h.d.built.Load()
	if built == nil {
		return errClashReleased
	}
	return built.device.IpcSet(uapiConf)
}

type clashWireGuardTun struct{ d *clashWireGuardDevice }

func (h *clashWireGuardTun) current() (wireguardDevice, error) {
	built := h.d.built.Load()
	if built == nil {
		return nil, errClashReleased
	}
	return built.tun, nil
}

func (h *clashWireGuardTun) Start() error {
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	if h.d.closed {
		return errOutboundClosed
	}
	stack, err := h.current()
	if err != nil {
		return err
	}
	return stack.Start()
}

func (h *clashWireGuardTun) Close() error {
	h.d.close()
	return nil
}

func (h *clashWireGuardTun) DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.DialTCP(ctx, network, source, destination)
}

func (h *clashWireGuardTun) DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.DialUDP(ctx, network, source, destination)
}

func (h *clashWireGuardTun) DialIP(ctx context.Context, network string, source, destination netip.Addr) (net.Conn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.DialIP(ctx, network, source, destination)
}

func (h *clashWireGuardTun) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.ListenTCP(ctx, network, local)
}

func (h *clashWireGuardTun) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.ListenUDP(ctx, network, local)
}

func (h *clashWireGuardTun) ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error) {
	stack, err := h.current()
	if err != nil {
		return nil, err
	}
	return stack.ListenIP(ctx, network, local)
}

func (h *clashWireGuardTun) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	stack, err := h.current()
	if err != nil {
		return 0, os.ErrClosed
	}
	return stack.Read(buffers, sizes, offset)
}

func (h *clashWireGuardTun) Write(buffers [][]byte, offset int) (int, error) {
	stack, err := h.current()
	if err != nil {
		return 0, os.ErrClosed
	}
	return stack.Write(buffers, offset)
}

func (h *clashWireGuardTun) MTU() (int, error) {
	stack, err := h.current()
	if err != nil {
		return 0, err
	}
	return stack.MTU()
}

func (h *clashWireGuardTun) Name() (string, error) {
	stack, err := h.current()
	if err != nil {
		return "", err
	}
	return stack.Name()
}

func (h *clashWireGuardTun) BatchSize() int {
	stack, err := h.current()
	if err != nil {
		return 1
	}
	return stack.BatchSize()
}

func (h *clashWireGuardTun) File() *os.File { return nil }

func (h *clashWireGuardTun) Events() <-chan tun.Event {
	stack, err := h.current()
	if err != nil {
		return nil
	}
	return stack.Events()
}

var clashWireGuardReleaseChecked func()

type clashResolverDialer struct {
	*WireGuard
}

func (d clashResolverDialer) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	defer d.clashDevice.resolverUse.dial(ctx)()
	c, err := d.WireGuard.DialContext(ctx, metadata)
	if err == nil {
		d.clashDevice.resolverUse.opened(c)
	}
	return c, err
}

func (d clashResolverDialer) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	defer d.clashDevice.resolverUse.dial(ctx)()
	pc, err := d.WireGuard.ListenPacketContext(ctx, metadata)
	if err == nil {
		d.clashDevice.resolverUse.opened(pc)
	}
	return pc, err
}
