package gvisorinterop_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

const (
	interopNIC tcpip.NICID = 1
	interopDefaultMTU uint32 = 1280

	interopRawIPProtocol tcpip.TransportProtocolNumber = 99
)

var interopFamilies = []interopFamily{
	{
		name:            "ipv4",
		tcpNetwork:      "tcp4",
		udpNetwork:      "udp4",
		icmpNetwork:     "ip4:icmp",
		rawNetwork:      "ip4:99",
		mipstackAddress: netip.MustParseAddr("192.0.2.1"),
		gvisorAddress:   netip.MustParseAddr("192.0.2.2"),
		forwardAddress:  netip.MustParseAddr("198.51.100.1"),
		prefixBits:      24,
		networkProtocol: ipv4.ProtocolNumber,
		icmpProtocol:    icmp.ProtocolNumber4,
	},
	{
		name:            "ipv6",
		tcpNetwork:      "tcp6",
		udpNetwork:      "udp6",
		icmpNetwork:     "ip6:ipv6-icmp",
		rawNetwork:      "ip6:99",
		mipstackAddress: netip.MustParseAddr("2001:db8::1"),
		gvisorAddress:   netip.MustParseAddr("2001:db8::2"),
		forwardAddress:  netip.MustParseAddr("2001:db8:1::1"),
		prefixBits:      64,
		networkProtocol: ipv6.ProtocolNumber,
		icmpProtocol:    icmp.ProtocolNumber6,
	},
}

type interopFamily struct {
	name string
	tcpNetwork string
	udpNetwork string
	icmpNetwork string
	rawNetwork  string
	mipstackAddress netip.Addr
	gvisorAddress   netip.Addr
	forwardAddress netip.Addr
	prefixBits int
	networkProtocol tcpip.NetworkProtocolNumber
	icmpProtocol    tcpip.TransportProtocolNumber
}

func (f interopFamily) mipstackPrefix() netip.Prefix {
	return netip.PrefixFrom(f.mipstackAddress, f.prefixBits)
}

func (f interopFamily) gvisorProtocolAddress() tcpip.ProtocolAddress {
	return tcpip.ProtocolAddress{
		Protocol: f.networkProtocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   gvisorAddress(f.gvisorAddress),
			PrefixLen: f.prefixBits,
		},
	}
}

type interopNetwork struct {
	t *testing.T
	mipstack *mipstack.Stack
	gvisor   *stack.Stack
	mtu uint32
	gvisorEndpoint *channel.Endpoint
	mipstackToGVisor interopPacketHook
	gvisorToMipstack interopPacketHook
	ctx    context.Context
	cancel context.CancelFunc
	waitGroup sync.WaitGroup
	closeOnce sync.Once
	bridgeError chan error
}

type interopPacketHook func(packet []byte) bool

type interopNetworkOptions struct {
	families []interopFamily
	mtu uint32
	gvisorMTU uint32
	promiscuous bool
	addressless bool
	tcp mipstack.TCPSocketDefaults
	ip mipstack.IPSocketDefaults
	forwarding bool
	mipstackToGVisor interopPacketHook
	gvisorToMipstack interopPacketHook
}

func newInteropNetwork(t *testing.T) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{})
}

func newFamilyInteropNetwork(t *testing.T, family interopFamily, mtu uint32) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{families: []interopFamily{family}, mtu: mtu})
}

func newForwarderInteropNetwork(t *testing.T, family interopFamily, mtu uint32) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: mtu, promiscuous: true, addressless: true,
	})
}

func newConfiguredForwarderInteropNetwork(t *testing.T, family interopFamily, mtu uint32) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: mtu, promiscuous: true,
	})
}

func newInteropNetworkWithOptions(t *testing.T, options interopNetworkOptions) *interopNetwork {
	t.Helper()
	families := options.families
	if len(families) == 0 {
		families = interopFamilies
	}
	mtu := options.mtu
	if mtu == 0 {
		mtu = interopDefaultMTU
	}
	gvisorMTU := options.gvisorMTU
	if gvisorMTU == 0 {
		gvisorMTU = mtu
	}
	localAddresses := make([]netip.Prefix, 0, len(families))
	if !options.addressless {
		for _, family := range families {
			localAddresses = append(localAddresses, family.mipstackPrefix())
		}
	}
	var mipstackRoutes []mipstack.Route
	if options.addressless {
		mipstackRoutes = make([]mipstack.Route, 0, len(families))
		for _, family := range families {
			destination := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			if family.mipstackAddress.Is4() {
				destination = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			mipstackRoutes = append(mipstackRoutes, mipstack.Route{Destination: destination})
		}
	}

	mips, err := mipstack.New(mipstack.Config{
		LocalAddresses: localAddresses,
		MTU:            mtu,
		Promiscuous:    options.promiscuous,
		Routes:         mipstackRoutes,
		TCP:            options.tcp,
		IP:             options.ip,
	})
	if err != nil {
		t.Fatalf("create mipstack: %v", err)
	}
	if options.addressless && len(mips.LocalAddresses()) != 0 {
		_ = mips.Close()
		t.Fatal("addressless interop stack retained a local address")
	}
	if !options.addressless && len(mips.LocalAddresses()) == 0 {
		_ = mips.Close()
		t.Fatal("configured interop stack has no local address")
	}
	if err = mips.Start(); err != nil {
		_ = mips.Close()
		t.Fatalf("start mipstack: %v", err)
	}

	gvisorStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6, newRawTestProtocol},
		HandleLocal:        true,
	})
	endpoint := channel.New(1024, gvisorMTU, "")
	if tcpipErr := gvisorStack.CreateNIC(interopNIC, endpoint); tcpipErr != nil {
		_ = mips.Close()
		gvisorStack.Destroy()
		t.Fatalf("create gVisor NIC: %s", tcpipErr.String())
	}
	for _, family := range families {
		if tcpipErr := gvisorStack.AddProtocolAddress(interopNIC, family.gvisorProtocolAddress(), stack.AddressProperties{}); tcpipErr != nil {
			_ = mips.Close()
			gvisorStack.Destroy()
			t.Fatalf("add gVisor %s address: %s", family.name, tcpipErr.String())
		}
		if options.forwarding {
			if tcpipErr := gvisorStack.SetForwardingDefaultAndAllNICs(family.networkProtocol, true); tcpipErr != nil {
				_ = mips.Close()
				gvisorStack.Destroy()
				t.Fatalf("enable gVisor %s forwarding: %s", family.name, tcpipErr.String())
			}
		}
	}
	routes := make([]tcpip.Route, 0, len(families))
	for _, family := range families {
		destination := header.IPv6EmptySubnet
		if family.mipstackAddress.Is4() {
			destination = header.IPv4EmptySubnet
		}
		routes = append(routes, tcpip.Route{Destination: destination, NIC: interopNIC})
	}
	gvisorStack.SetRouteTable(routes)

	ctx, cancel := context.WithCancel(context.Background())
	network := &interopNetwork{
		t: t, mipstack: mips, gvisor: gvisorStack, mtu: mtu, gvisorEndpoint: endpoint,
		ctx: ctx, cancel: cancel, bridgeError: make(chan error, 1),
		mipstackToGVisor: options.mipstackToGVisor, gvisorToMipstack: options.gvisorToMipstack,
	}
	network.waitGroup.Add(2)
	go network.copyMipstackToGVisor()
	go network.copyGVisorToMipstack()
	t.Cleanup(network.close)
	return network
}

func (n *interopNetwork) close() {
	n.closeOnce.Do(func() {
		n.cancel()
		n.gvisorEndpoint.Close()
		_ = n.mipstack.Close()
		n.gvisor.Destroy()
		n.waitGroup.Wait()
		select {
		case err := <-n.bridgeError:
			n.t.Errorf("L3 bridge: %v", err)
		default:
		}
	})
}

func (n *interopNetwork) copyMipstackToGVisor() {
	defer n.waitGroup.Done()
	buffers := make([][]byte, n.mipstack.BatchSize())
	sizes := make([]int, len(buffers))
	for index := range buffers {
		buffers[index] = make([]byte, n.mtu)
	}
	for {
		count, err := n.mipstack.Read(buffers, sizes, 0)
		for index := 0; index < count; index++ {
			packetBytes := buffers[index][:sizes[index]]
			if n.mipstackToGVisor != nil && !n.mipstackToGVisor(packetBytes) {
				continue
			}
			if err := n.deliverToGVisor(packetBytes); err != nil {
				n.reportBridgeError(err)
				return
			}
		}
		if err != nil {
			if n.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				n.reportBridgeError(fmt.Errorf("read mipstack packets: %w", err))
			}
			return
		}
	}
}

func interopMTUsForFamily(family interopFamily) []uint32 {
	if family.mipstackAddress.Is4() {
		return []uint32{68, 576, 1280, 1420, 1500, 9000}
	}
	return []uint32{1280, 1420, 1500, 9000}
}

func interopMTUName(mtu uint32) string {
	return fmt.Sprintf("mtu-%d", mtu)
}

func fragmentedInteropPayloadSize(mtu uint32, pressureFloor int) int {
	size := int(mtu)*2 + 137
	if mtu >= 1280 && size < pressureFloor {
		return pressureFloor
	}
	return size
}

func rawInteropPayloadCapacity(family interopFamily, mtu uint32) int {
	headerSize := header.IPv6MinimumSize
	if family.mipstackAddress.Is4() {
		headerSize = header.IPv4MinimumSize
	}
	return int(mtu) - headerSize
}

func tcpInteropStreamSize(mtu uint32) int {
	if mtu <= 68 {
		return 32 * 1024
	}
	if mtu < 1280 {
		return 128 * 1024
	}
	return 512 * 1024
}

func (n *interopNetwork) copyGVisorToMipstack() {
	defer n.waitGroup.Done()
	for {
		packet := n.gvisorEndpoint.ReadContext(n.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		packet.DecRef()
		packetBytes := view.AsSlice()
		if n.gvisorToMipstack != nil && !n.gvisorToMipstack(packetBytes) {
			view.Release()
			continue
		}
		err := n.deliverToMipstack(packetBytes)
		view.Release()
		if err != nil {
			if n.ctx.Err() == nil {
				n.reportBridgeError(err)
			}
			return
		}
	}
}

func (n *interopNetwork) deliverToGVisor(packetBytes []byte) error {
	protocol, ok := packetNetworkProtocol(packetBytes)
	if !ok {
		return errors.New("mipstack emitted a packet without a valid IP version")
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packetBytes)})
	n.gvisorEndpoint.InjectInbound(protocol, packet)
	packet.DecRef()
	return nil
}

func (n *interopNetwork) deliverToMipstack(packetBytes []byte) error {
	count, err := n.mipstack.Write([][]byte{packetBytes}, 0)
	if count != 1 || err != nil {
		return fmt.Errorf("write gVisor packet to mipstack: count=%d, error=%v", count, err)
	}
	return nil
}

func (n *interopNetwork) reportBridgeError(err error) {
	select {
	case n.bridgeError <- err:
	default:
	}
}

func packetNetworkProtocol(packet []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		return header.IPv4ProtocolNumber, true
	case 6:
		return header.IPv6ProtocolNumber, true
	default:
		return 0, false
	}
}

func gvisorAddress(address netip.Addr) tcpip.Address {
	address = address.Unmap()
	if address.Is4() {
		return tcpip.AddrFrom4(address.As4())
	}
	return tcpip.AddrFrom16(address.As16())
}

func gvisorFullAddress(address netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: interopNIC, Addr: gvisorAddress(address), Port: port}
}

func netipAddrPort(address netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(address, port)
}

func patternedPayload(size int, seed byte) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte((index*131+int(seed))%251 + 1)
	}
	return payload
}

func readGVisorEndpoint(ctx context.Context, endpoint tcpip.Endpoint, notifications <-chan struct{}, capacity int) ([]byte, tcpip.FullAddress, error) {
	payload, result, err := readGVisorEndpointResult(ctx, endpoint, notifications, capacity)
	return payload, result.RemoteAddr, err
}

func readGVisorEndpointResult(ctx context.Context, endpoint tcpip.Endpoint, notifications <-chan struct{}, capacity int) ([]byte, tcpip.ReadResult, error) {
	for {
		storage := make([]byte, capacity)
		writer := tcpip.SliceWriter(storage)
		result, tcpipErr := endpoint.Read(&writer, tcpip.ReadOptions{NeedRemoteAddr: true})
		if tcpipErr == nil {
			return storage[:result.Count], result, nil
		}
		if _, wouldBlock := tcpipErr.(*tcpip.ErrWouldBlock); !wouldBlock {
			return nil, tcpip.ReadResult{}, errors.New(tcpipErr.String())
		}
		select {
		case <-ctx.Done():
			return nil, tcpip.ReadResult{}, ctx.Err()
		case <-notifications:
		}
	}
}

func registerReadable(queue *waiter.Queue) (waiter.Entry, <-chan struct{}) {
	entry, notifications := waiter.NewChannelEntry(waiter.ReadableEvents)
	queue.EventRegister(&entry)
	return entry, notifications
}

type rawTestProtocol struct {
	stack *stack.Stack
}

func newRawTestProtocol(protocolStack *stack.Stack) stack.TransportProtocol {
	return &rawTestProtocol{stack: protocolStack}
}

func (*rawTestProtocol) Number() tcpip.TransportProtocolNumber {
	return interopRawIPProtocol
}

func (*rawTestProtocol) NewEndpoint(tcpip.NetworkProtocolNumber, *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return nil, &tcpip.ErrNotSupported{}
}

func (p *rawTestProtocol) NewRawEndpoint(networkProtocol tcpip.NetworkProtocolNumber, queue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return raw.NewEndpoint(p.stack, networkProtocol, interopRawIPProtocol, queue)
}

func (*rawTestProtocol) MinimumPacketSize() int { return 1 }

func (*rawTestProtocol) ParsePorts([]byte) (uint16, uint16, tcpip.Error) {
	return 0, 0, nil
}

func (*rawTestProtocol) HandleUnknownDestinationPacket(stack.TransportEndpointID, *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	return stack.UnknownDestinationPacketHandled
}

func (*rawTestProtocol) SetOption(tcpip.SettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*rawTestProtocol) Option(tcpip.GettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*rawTestProtocol) Close() {}

func (*rawTestProtocol) Wait() {}

func (*rawTestProtocol) Pause() {}

func (*rawTestProtocol) Resume() {}

func (*rawTestProtocol) Restore() {}

func (*rawTestProtocol) Parse(packet *stack.PacketBuffer) bool {
	_, ok := packet.TransportHeader().Consume(1)
	return ok
}
