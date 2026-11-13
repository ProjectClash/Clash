package clash

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/listener/sing_tun"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	L "github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	gotun "github.com/sagernet/sing-tun"
	goCommon "github.com/sagernet/sing/common"
	gobuf "github.com/sagernet/sing/common/buf"
	goM "github.com/sagernet/sing/common/metadata"
	goN "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

func init() {
	sing_tun.SetGoStackFactory(newGoStack)
}

type goStack struct {
	stack   *gotun.Go
	tun     interface{ Close() error }
	device  any
	bridge  *goStackBridge
	logger  *goStackLogger
	failure func(error)
	cancel  context.CancelFunc
}

func newGoStack(options sing_tun.GoStackOptions) (tun.Stack, error) {
	opened, isUtun := options.Device.(interface{ UtunFileDescriptor() int })
	if !isUtun {
		return nil, E.New("go stack: unsupported TUN implementation")
	}
	device := options.TunOptions
	tunOptions := gotun.Options{
		Name:                      device.Name,
		Inet4Address:              device.Inet4Address,
		Inet6Address:              device.Inet6Address,
		MTU:                       device.MTU,
		EXP_MultiPendingPackets:   true,
		EXP_ExternalConfiguration: true,
	}
	var (
		goDevice gotun.Tun
		bridge   *goStackBridge
	)
	if !goStackDescriptorIsUtun(opened.UtunFileDescriptor()) {
		bridge = newGoStackBridge(options.Device, int(device.MTU))
		goDevice = bridge.memory
	} else {
		fd, err := goStackDupDescriptor(opened.UtunFileDescriptor())
		if err != nil {
			return nil, E.Cause(err, "go stack: duplicate the utun descriptor")
		}
		tunOptions.FileDescriptor = fd
		goDevice, err = goStackNewTun(tunOptions)
		if err != nil {
			if !errors.Is(err, errGoStackOpenPanicked) {
				_ = unix.Close(fd)
			}
			return nil, E.Cause(err, "go stack: open the utun")
		}
	}
	congestion := goStackCongestion(options.CongestionControl)
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	dnsContext, cancel := context.WithCancel(parent)
	dns := &goStackDNS{ctx: dnsContext}
	logger := &goStackLogger{ContextLogger: log.SingLogger}
	stack, err := goStackNewGo(gotun.StackOptions{
		Context:              options.Context,
		Tun:                  goDevice,
		TunOptions:           tunOptions,
		UDPTimeout:           options.UDPTimeout,
		UDPMapping:           goStackUDPMapping,
		UDPFiltering:         goStackUDPFiltering,
		UDPNATMax:            goStackUDPNATMax,
		ICMPTimeout:          options.ICMPTimeout,
		Handler:              goStackHandler{handler: options.Handler, dns: dns},
		Logger:               logger,
		MemoryPressure:       goStackMemoryPressure,
		TCPCongestionControl: congestion,
	})
	if err != nil {
		cancel()
		_ = goDevice.Close()
		return nil, err
	}
	rewriter := tun.NewIPRewriter(tun.LoopbackAddresses(device.Inet4LoopbackAddress, device.Inet6LoopbackAddress))
	stack.SetPacketRewrite(rewriter.Apply)
	running := &goStack{stack: stack, tun: goDevice, device: options.Device, bridge: bridge, logger: logger, failure: device.DeviceFailure, cancel: cancel}
	if bridge != nil {
		running.tun = bridge
		running.device = nil
	}
	return running, nil
}

var goStackDescriptorIsUtun = func(fd int) bool {
	_, err := tunDescriptorUtun(fd)
	return err == nil
}

var goStackNewGo = gotun.NewGo

func goStackDupDescriptor(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}

var goStackOpenTunOnce = gotun.New

var errGoStackOpenPanicked = errors.New("go stack: opening the utun panicked")

func goStackNewTun(options gotun.Options) (device gotun.Tun, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			device, err = nil, fmt.Errorf("%w: %v", errGoStackOpenPanicked, recovered)
		}
	}()
	return goStackOpenTunOnce(options)
}

func goStackCongestion(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "bbr3" {
		return "bbr"
	}
	return name
}

const (
	goStackUDPMapping   = gotun.NATMappingEndpointIndependent
	goStackUDPFiltering = gotun.NATFilteringEndpointIndependent
)

func (s *goStack) Start() error {
	err := s.stack.Start()
	if err != nil {
		return err
	}
	if s.bridge != nil {
		s.bridge.start()
	}
	if detaching, canDetach := s.device.(interface{ DetachFromRuntimePoller() error }); canDetach {
		if err := detaching.DetachFromRuntimePoller(); err != nil {
			s.logger.Warn("go stack: the utun stays on the runtime poller: ", err)
		}
	}
	if s.failure != nil {
		go s.reportStop(s.stack.EngineStopped())
	}
	return nil
}

func (s *goStack) reportStop(stopped <-chan struct{}) {
	if stopped == nil {
		return
	}
	<-stopped
	if s.stack.Closed() {
		return
	}
	reason := "the go stack stopped reading the utun"
	if last := s.logger.lastError.Load(); last != nil {
		reason += ": " + *last
	}
	s.failure(E.New(reason))
}

func (s *goStack) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return E.Errors(s.stack.Close(), s.tun.Close())
}

func goStackMemoryPressure() gotun.MemoryPressure {
	switch pressureShedLayerGauge.Load() {
	case 0:
		return gotun.MemoryPressureNone
	case 1:
		return gotun.MemoryPressureWarning
	default:
		return gotun.MemoryPressureCritical
	}
}

type goStackLogger struct {
	L.ContextLogger
	lastError atomic.Pointer[string]
}

func (l *goStackLogger) Error(args ...any) {
	message := fmt.Sprint(args...)
	l.lastError.Store(&message)
	l.ContextLogger.Error(args...)
}

type goStackDoor interface {
	PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error)
	DeferHandshake(network string, source M.Socksaddr, destination M.Socksaddr) bool
}

type goStackHandler struct {
	handler *sing_tun.ListenerHandler
	door    goStackDoor
	dns     *goStackDNS
}

type goStackDNS struct {
	ctx context.Context
}

func (h goStackHandler) doorway() goStackDoor {
	if h.door != nil {
		return h.door
	}
	return h.handler
}

func (h goStackHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) gotun.FlowVerdict {
	if network == unix.IPPROTO_UDP && h.handler != nil && h.handler.ShouldHijackDns(destination) {
		return gotun.FlowVerdict{Action: gotun.ActionHijackDNS}
	}
	switch network {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		name := N.NetworkTCP
		if network == unix.IPPROTO_UDP {
			name = N.NetworkUDP
		}
		if _, err := h.doorway().PrepareConnection(name, M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(destination), nil, 0); err != nil {
			return gotun.FlowVerdict{Action: gotun.ActionReject}
		}
		if network == unix.IPPROTO_UDP {
			return gotun.FlowVerdict{Action: gotun.ActionAccept, UDPTimeout: tunnel.UDPProtocolTimeout(firstPacket, destination.Port())}
		}
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		if !resolver.CurrentIPQueryPolicy().AllowsAddress(destination.Addr()) {
			return gotun.FlowVerdict{Action: gotun.ActionReject}
		}
	}
	return gotun.FlowVerdict{Action: gotun.ActionAccept}
}

func (h goStackHandler) NewDNSPacket(payload []byte, source goM.Socksaddr, destination goM.Socksaddr, writer goN.PacketWriter) {
	parent := context.Background()
	if h.dns != nil {
		parent = h.dns.ctx
	}
	query := append([]byte(nil), payload...)
	log.Debugln("[DNS] hijack udp:%s from %s", fromGoSocksaddr(destination), fromGoSocksaddr(source))
	go func() {
		ctx, cancel := context.WithTimeout(parent, resolver.DefaultDnsRelayTimeout)
		defer cancel()
		reply := gobuf.NewSize(resolver.SafeDnsPacketSize)
		message, err := resolver.RelayDnsPacket(ctx, query, reply.FreeBytes())
		if err != nil {
			reply.Release()
			return
		}
		reply.Truncate(len(message))
		if parent.Err() != nil {
			reply.Release()
			return
		}
		_ = writer.WritePacket(reply, destination)
	}()
}

func (h goStackHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source goM.Socksaddr, destination goM.Socksaddr, onClose goN.CloseHandlerFunc) {
	from, to := fromGoSocksaddr(source), fromGoSocksaddr(destination)
	if side, isGoConn := conn.(goStreamSide); isGoConn {
		if !h.doorway().DeferHandshake(N.NetworkTCP, from, to) {
			if err := side.HandshakeSuccess(); err != nil {
				_ = conn.Close()
				if onClose != nil {
					onClose(err)
				}
				return
			}
		}
		conn = &goStreamConn{Conn: conn, side: side, local: to.TCPAddr(), remote: from.TCPAddr()}
	}
	err := h.handler.NewConnection(ctx, conn, M.Metadata{Source: from, Destination: to})
	if onClose != nil {
		onClose(err)
	}
}

func (h goStackHandler) NewPacketConnectionEx(ctx context.Context, conn goN.PacketConn, source goM.Socksaddr, destination goM.Socksaddr, onClose goN.CloseHandlerFunc) {
	err := h.handler.NewPacketConnection(ctx, &goPacketConn{PacketConn: conn}, M.Metadata{Source: fromGoSocksaddr(source), Destination: fromGoSocksaddr(destination)})
	if onClose != nil {
		onClose(err)
	}
}

func fromGoSocksaddr(address goM.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: address.Addr, Port: address.Port, Fqdn: address.Fqdn}
}

func toGoSocksaddr(address M.Socksaddr) goM.Socksaddr {
	return goM.Socksaddr{Addr: address.Addr, Port: address.Port, Fqdn: address.Fqdn}
}

func (c *goStreamConn) QueuedSendBytes() (int, bool) {
	if reporter, ok := c.Conn.(interface{ QueuedSendBytes() (int, bool) }); ok {
		return reporter.QueuedSendBytes()
	}
	return 0, false
}

func (c *goStreamConn) SetLinger(sec int) error {
	if linger, ok := c.Conn.(interface{ SetLinger(int) error }); ok {
		return linger.SetLinger(sec)
	}
	return nil
}

type goStreamSide interface {
	WaitReadable() error
	NeedHandshakeForRead() bool
	HandshakeSuccess() error
	HandshakeFailure(err error) error
	CloseRead() error
	CloseWrite() error
}

var _ goStreamSide = (*gotun.GoConn)(nil)

type goStreamConn struct {
	net.Conn
	side    goStreamSide
	local   net.Addr
	remote  net.Addr
	options N.ReadWaitOptions
}

var _ N.ReadWaiter = (*goStreamConn)(nil)

func (c *goStreamConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.options = options
	return false
}

func (c *goStreamConn) newBlock() *buf.Buffer {
	options := c.options
	if block := goStreamBlock - options.FrontHeadroom - options.RearHeadroom; options.MTU < block && pressureShedLayerGauge.Load() == 0 {
		options.MTU = block
	}
	return options.NewBuffer()
}

func (c *goStreamConn) WaitReadBuffer() (*buf.Buffer, error) {
	err := c.side.WaitReadable()
	if err != nil {
		return nil, err
	}
	buffer := c.newBlock()
	n, err := c.Conn.Read(buffer.FreeBytes())
	if err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.Truncate(n)
	c.options.PostReturn(buffer)
	return buffer, nil
}

func (c *goStreamConn) HandshakeDeferred() bool          { return c.side.NeedHandshakeForRead() }
func (c *goStreamConn) HandshakeSuccess() error          { return c.side.HandshakeSuccess() }
func (c *goStreamConn) HandshakeFailure(err error) error { return c.side.HandshakeFailure(err) }
func (c *goStreamConn) CloseRead() error                 { return c.side.CloseRead() }
func (c *goStreamConn) CloseWrite() error                { return c.side.CloseWrite() }
func (c *goStreamConn) LocalAddr() net.Addr              { return c.local }
func (c *goStreamConn) RemoteAddr() net.Addr             { return c.remote }

type goPacketConn struct {
	goN.PacketConn
	lastDestination atomic.Pointer[goM.Socksaddr]
	read            atomic.Bool
}

var (
	_ N.PacketConn            = (*goPacketConn)(nil)
	_ N.PacketReadWaitCreator = (*goPacketConn)(nil)
)

func (c *goPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		packet, destination, err := c.readDatagram()
		if err != nil {
			return M.Socksaddr{}, err
		}
		if packet.Len() > buffer.FreeLen() {
			goStackDropOversized(packet.Len(), destination, buffer.FreeLen())
			packet.Release()
			continue
		}
		_, err = buffer.Write(packet.Bytes())
		packet.Release()
		return fromGoSocksaddr(destination), err
	}
}

func (c *goPacketConn) readDatagram() (*gobuf.Buffer, goM.Socksaddr, error) {
	var (
		packet      *gobuf.Buffer
		destination goM.Socksaddr
		err         error
	)
	if waiter, isWaiter := c.PacketConn.(goN.PacketReadWaiter); isWaiter {
		packet, destination, err = waiter.WaitReadPacket()
	} else {
		packet = gobuf.NewPacket()
		destination, err = c.PacketConn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			packet = nil
		}
	}
	if err != nil {
		return nil, goM.Socksaddr{}, err
	}
	if previous := c.lastDestination.Load(); previous == nil || *previous != destination {
		last := destination
		c.lastDestination.Store(&last)
	}
	if !c.read.Load() && c.read.CompareAndSwap(false, true) {
		if success, canSucceed := goCommon.Cast[goN.HandshakeSuccess](c.PacketConn); canSucceed {
			_ = success.HandshakeSuccess()
		}
	}
	return packet, destination, nil
}

func (c *goPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	return &goPacketReadWaiter{conn: c}, true
}

type goPacketReadWaiter struct {
	conn    *goPacketConn
	options N.ReadWaitOptions
}

func (w *goPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *goPacketReadWaiter) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	for {
		packet, destination, err := w.conn.readDatagram()
		if err != nil {
			return nil, M.Socksaddr{}, err
		}
		if w.options.MTU > 0 && packet.Len() > w.options.MTU {
			goStackDropOversized(packet.Len(), destination, w.options.MTU)
			packet.Release()
			continue
		}
		buffer := buf.NewSize(w.options.FrontHeadroom + packet.Len() + w.options.RearHeadroom)
		buffer.Resize(w.options.FrontHeadroom, 0)
		_, err = buffer.Write(packet.Bytes())
		packet.Release()
		if err != nil {
			buffer.Release()
			return nil, M.Socksaddr{}, err
		}
		return buffer, fromGoSocksaddr(destination), nil
	}
}

func goStackDropOversized(size int, destination goM.Socksaddr, room int) {
	goStackOversizedDatagram.Do(func() {
		log.Warnln("[TUN] a %d-byte datagram for %s does not fit the %d bytes its reader holds; it is dropped",
			size, fromGoSocksaddr(destination), room)
	})
}

var goStackOversizedDatagram sync.Once

func (c *goPacketConn) ReportUnreachable() error {
	reporter, canReport := c.PacketConn.(interface {
		ReportPortUnreachable(goM.Socksaddr) error
	})
	destination := c.lastDestination.Load()
	if !canReport || destination == nil {
		return os.ErrInvalid
	}
	return reporter.ReportPortUnreachable(*destination)
}

func (c *goPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	frontHeadroom := goN.CalculateFrontHeadroom(c.PacketConn)
	packet := gobuf.NewSize(frontHeadroom + buffer.Len() + goN.CalculateRearHeadroom(c.PacketConn))
	packet.Resize(frontHeadroom, 0)
	_, err := packet.Write(buffer.Bytes())
	if err != nil {
		packet.Release()
		return err
	}
	return c.PacketConn.WritePacket(packet, toGoSocksaddr(destination))
}
