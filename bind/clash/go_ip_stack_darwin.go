package clash

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/log"

	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	goM "github.com/sagernet/sing/common/metadata"
	goN "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"golang.org/x/sys/unix"
)

func init() {
	outbound.SetGoIPStackFactory(newGoIPStack)
}

const (
	goIPStackBatch      = 1
	goIPStackQueue      = 256
	goIPStackUDPTimeout = 5 * time.Minute
	goIPStackKeepAlive  = 15 * time.Second
)

var errGoIPStackClosed = errors.New("the node's IP stack is closed")

type goIPStack struct {
	stack     *gotun.Go
	local     []netip.Addr
	memory    *gotun.MemoryTun
	mtu       int
	inet4     netip.Addr
	inet6     netip.Addr
	fromStack chan *gobuf.Buffer
	closeOnce sync.Once
	closed    chan struct{}
}

var _ outbound.IPStack = (*goIPStack)(nil)

func newGoIPStack(options outbound.GoIPStackOptions) (outbound.IPStack, error) {
	mtu := int(options.MTU)
	if mtu == 0 {
		mtu = 1420
	}
	s := &goIPStack{
		mtu:       mtu,
		fromStack: make(chan *gobuf.Buffer, goIPStackQueue),
		closed:    make(chan struct{}),
	}
	for _, prefix := range options.LocalAddresses {
		address := prefix.Addr().Unmap()
		s.local = append(s.local, address)
		if address.Is4() && !s.inet4.IsValid() {
			s.inet4 = address
		} else if address.Is6() && !s.inet6.IsValid() {
			s.inet6 = address
		}
	}
	s.memory = gotun.NewMemoryTun(gotun.MemoryTunOptions{MTU: mtu, Outbound: s.toProtocol})
	stack, err := goStackNewGo(gotun.StackOptions{
		Context:              context.Background(),
		Tun:                  s.memory,
		TunOptions:           gotun.Options{MTU: uint32(mtu)},
		UDPTimeout:           goIPStackUDPTimeout,
		UDPMapping:           goStackUDPMapping,
		UDPFiltering:         goStackUDPFiltering,
		UDPNATMax:            goStackUDPNATMax,
		Handler:              goIPStackHandler{},
		Logger:               &goStackLogger{ContextLogger: log.SingLogger},
		MemoryPressure:       goStackMemoryPressure,
		TCPCongestionControl: goStackCongestion(options.CongestionController),
	})
	if err != nil {
		_ = s.memory.Close()
		return nil, err
	}
	s.stack = stack
	return s, nil
}

func (s *goIPStack) Start() error {
	return s.stack.Start()
}

func (s *goIPStack) toProtocol(packets []*gobuf.Buffer) {
	for i, packet := range packets {
		select {
		case s.fromStack <- packet:
		case <-s.closed:
			gobuf.ReleaseMulti(packets[i:])
			return
		}
	}
}

func (s *goIPStack) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if len(buffers) == 0 {
		return 0, nil
	}
	var packet *gobuf.Buffer
	select {
	case packet = <-s.fromStack:
	case <-s.closed:
		return 0, os.ErrClosed
	}
	count := 0
	for {
		sizes[count] = copy(buffers[count][offset:], packet.Bytes())
		packet.Release()
		count++
		if count == len(buffers) {
			return count, nil
		}
		select {
		case packet = <-s.fromStack:
		default:
			return count, nil
		}
	}
}

func (s *goIPStack) Write(buffers [][]byte, offset int) (int, error) {
	packets := make([][]byte, 0, len(buffers))
	for _, buffer := range buffers {
		if len(buffer) > offset && s.toNode(buffer[offset:]) {
			packets = append(packets, buffer[offset:])
		}
	}
	if len(packets) == 0 {
		return len(buffers), nil
	}
	if err := s.memory.WaitWritePackets(packets); err != nil {
		return 0, err
	}
	return len(buffers), nil
}

func (s *goIPStack) toNode(packet []byte) bool {
	var destination netip.Addr
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return false
		}
		destination = netip.AddrFrom4([4]byte(packet[16:20]))
	case 6:
		if len(packet) < 40 {
			return false
		}
		destination = netip.AddrFrom16([16]byte(packet[24:40]))
	default:
		return false
	}
	return slices.Contains(s.local, destination)
}

func (s *goIPStack) MTU() (int, error)     { return s.mtu, nil }
func (s *goIPStack) Name() (string, error) { return "go", nil }
func (s *goIPStack) BatchSize() int        { return goIPStackBatch }

func (s *goIPStack) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	err := s.stack.Close()
	_ = s.memory.Close()
	for {
		select {
		case packet := <-s.fromStack:
			packet.Release()
		default:
			return err
		}
	}
}

func (s *goIPStack) source(source netip.Addr, destination netip.Addr) (netip.Addr, error) {
	if source.IsValid() {
		return source.Unmap(), nil
	}
	if destination.Unmap().Is4() {
		if s.inet4.IsValid() {
			return s.inet4, nil
		}
	} else if s.inet6.IsValid() {
		return s.inet6, nil
	}
	return netip.Addr{}, errors.New("the node has no local address of the destination's IP version")
}

func (s *goIPStack) DialTCP(ctx context.Context, _ string, source, destination netip.AddrPort) (net.Conn, error) {
	bind, err := s.source(source.Addr(), destination.Addr())
	if err != nil {
		return nil, err
	}
	conn, err := s.stack.DialTCP(ctx, bind, destination)
	if err != nil {
		return nil, err
	}
	conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: goIPStackKeepAlive, Interval: goIPStackKeepAlive})
	return &goIPStackConn{GoConn: conn}, nil
}

func (s *goIPStack) DialUDP(_ context.Context, _ string, source, destination netip.AddrPort) (net.Conn, error) {
	bind, err := s.source(source.Addr(), destination.Addr())
	if err != nil {
		return nil, err
	}
	return s.stack.DialUDP(netip.AddrPortFrom(bind, source.Port()), destination)
}

func (s *goIPStack) ListenTCP(_ context.Context, _ string, local netip.AddrPort) (net.Listener, error) {
	return s.stack.ListenTCP(local)
}

func (s *goIPStack) ListenUDP(_ context.Context, _ string, local netip.AddrPort) (net.PacketConn, error) {
	if local.Addr().IsValid() {
		return s.stack.ListenUDP(local)
	}
	switch {
	case s.inet4.IsValid() && s.inet6.IsValid():
		return newGoIPStackDualPacketConn(s.stack, s.inet4, s.inet6, local.Port())
	case s.inet4.IsValid():
		return s.stack.ListenUDP(netip.AddrPortFrom(s.inet4, local.Port()))
	case s.inet6.IsValid():
		return s.stack.ListenUDP(netip.AddrPortFrom(s.inet6, local.Port()))
	}
	return nil, errors.New("the node has no local address")
}

type goIPStackDualPacketConn struct {
	sockets   [2]*gotun.GoUDPConn
	received  chan goIPStackDatagram
	deadline  pipe.Deadline
	closeOnce sync.Once
	closed    chan struct{}
}

type goIPStackDatagram struct {
	payload *gobuf.Buffer
	source  goM.Socksaddr
	err     error
}

const goIPStackDualPortAttempts = 8

func newGoIPStackDualPacketConn(stack *gotun.Go, inet4, inet6 netip.Addr, port uint16) (*goIPStackDualPacketConn, error) {
	var v4, v6 *gotun.GoUDPConn
	var err error
	for attempt := 0; attempt < goIPStackDualPortAttempts; attempt++ {
		v4, err = stack.ListenUDP(netip.AddrPortFrom(inet4, port))
		if err != nil {
			return nil, err
		}
		v6, err = stack.ListenUDP(netip.AddrPortFrom(inet6, v4.LocalAddr().(*net.UDPAddr).AddrPort().Port()))
		if err == nil {
			break
		}
		_ = v4.Close()
		if port != 0 || !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	c := &goIPStackDualPacketConn{
		sockets:  [2]*gotun.GoUDPConn{v4, v6},
		received: make(chan goIPStackDatagram),
		deadline: pipe.MakeDeadline(),
		closed:   make(chan struct{}),
	}
	for _, socket := range c.sockets {
		go c.receive(socket)
	}
	return c, nil
}

func (c *goIPStackDualPacketConn) receive(socket *gotun.GoUDPConn) {
	for {
		payload, source, err := socket.WaitReadPacket()
		select {
		case c.received <- goIPStackDatagram{payload: payload, source: source, err: err}:
		case <-c.closed:
			if payload != nil {
				payload.Release()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *goIPStackDualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case datagram := <-c.received:
		if datagram.err != nil {
			return 0, nil, datagram.err
		}
		n := copy(p, datagram.payload.Bytes())
		datagram.payload.Release()
		return n, net.UDPAddrFromAddrPort(datagram.source.AddrPort()), nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-c.deadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *goIPStackDualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var destination netip.AddrPort
	switch address := addr.(type) {
	case *net.UDPAddr:
		destination = address.AddrPort()
	default:
		parsed, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return 0, err
		}
		destination = parsed
	}
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	socket := c.sockets[0]
	if destination.Addr().Is6() {
		socket = c.sockets[1]
	}
	return socket.WriteToUDPAddrPort(p, destination)
}

func (c *goIPStackDualPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return errors.Join(c.sockets[0].Close(), c.sockets[1].Close())
}

func (c *goIPStackDualPacketConn) LocalAddr() net.Addr { return c.sockets[0].LocalAddr() }

func (c *goIPStackDualPacketConn) SetDeadline(t time.Time) error {
	c.deadline.Set(t)
	return errors.Join(c.sockets[0].SetWriteDeadline(t), c.sockets[1].SetWriteDeadline(t))
}

func (c *goIPStackDualPacketConn) SetReadDeadline(t time.Time) error {
	c.deadline.Set(t)
	return nil
}

func (c *goIPStackDualPacketConn) SetWriteDeadline(t time.Time) error {
	return errors.Join(c.sockets[0].SetWriteDeadline(t), c.sockets[1].SetWriteDeadline(t))
}

var errGoIPStackNoRawIP = errors.New("the go stack opens no raw IP sockets")

func (s *goIPStack) DialIP(context.Context, string, netip.Addr, netip.Addr) (net.Conn, error) {
	return nil, errGoIPStackNoRawIP
}

func (s *goIPStack) ListenIP(context.Context, string, netip.Addr) (net.PacketConn, error) {
	return nil, errGoIPStackNoRawIP
}

type goIPStackConn struct {
	*gotun.GoConn
}

func (c *goIPStackConn) ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error) {
	if err := c.GoConn.WaitReadable(); err != nil {
		return 0, err
	}
	return c.GoConn.Read(getBuffer(0))
}

type goIPStackHandler struct{}

func (goIPStackHandler) JudgeFlow(network uint8, _ netip.AddrPort, _ netip.AddrPort, _ []byte) gotun.FlowVerdict {
	if network == unix.IPPROTO_ICMP || network == unix.IPPROTO_ICMPV6 {
		return gotun.FlowVerdict{Action: gotun.ActionAccept}
	}
	return gotun.FlowVerdict{Action: gotun.ActionReject}
}

func (goIPStackHandler) NewDNSPacket([]byte, goM.Socksaddr, goM.Socksaddr, goN.PacketWriter) {}

func (goIPStackHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ goM.Socksaddr, _ goM.Socksaddr, onClose goN.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(errGoIPStackClosed)
	}
}

func (goIPStackHandler) NewPacketConnectionEx(_ context.Context, conn goN.PacketConn, _ goM.Socksaddr, _ goM.Socksaddr, onClose goN.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(errGoIPStackClosed)
	}
}
