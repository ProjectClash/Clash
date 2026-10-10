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

package stack

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/log"
	cryptorand "github.com/metacubex/gvisor/pkg/rand"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/ports"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	DefaultTOS = 0
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(id TransportEndpointID, pkt *PacketBuffer) bool `state:"nosave"`
}

type RestoredEndpoint interface {
	Restore(*Stack)
}

type ResumableEndpoint interface {
	Resume()
}

var netRawMissingLogger = log.BasicRateLimitedLogger(time.Minute)

type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol

	rawFactory                   RawFactory
	packetEndpointWriteSupported bool

	demux *transportDemuxer

	stats tcpip.Stats

	routeMu routeStackRWMutex `state:"nosave"`

	routeTable tcpip.RouteList `state:"nosave"`

	mu stackRWMutex `state:"nosave"`
	nics map[tcpip.NICID]*nic `state:"nosave"`
	loopbackNIC *nic `state:"nosave"`
	defaultForwardingEnabled map[tcpip.NetworkProtocolNumber]struct{}

	nicIDGen atomicbitops.Int32 `state:"nosave"`

	cleanupEndpointsMu cleanupEndpointsMutex `state:"nosave"`
	cleanupEndpoints map[TransportEndpoint]struct{}

	*ports.PortManager

	clock tcpip.Clock

	handleLocal bool

	tables *IPTables `state:"nosave"`

	nftables atomic.Pointer[NFTablesInterface] `state:"nosave"`

	nftablesUpdateMu sync.Mutex `state:"nosave"`

	nftablesConfigured atomicbitops.Bool

	restoredEndpoints []RestoredEndpoint

	resumableEndpoints []ResumableEndpoint

	icmpRateLimiter *ICMPRateLimiter

	seed uint32

	nudConfigs NUDConfigurations

	nudDisp NUDDispatcher

	insecureRNG *rand.Rand `state:"nosave"`

	secureRNG cryptorand.RNG `state:"nosave"`

	sendBufferSize tcpip.SendBufferSizeOption

	receiveBufferSize tcpip.ReceiveBufferSizeOption

	tcpInvalidRateLimit time.Duration

	tsOffsetSecret uint32

	removeConf bool `state:"nosave"`

	allowLiveTCPMigration bool `state:"nosave"`

	externalNetworkingDisabled bool

	allowConnectedOnSave bool
}

type NetworkProtocolFactory func(*Stack) NetworkProtocol

type TransportProtocolFactory func(*Stack) TransportProtocol

type Options struct {
	NetworkProtocols []NetworkProtocolFactory

	TransportProtocols []TransportProtocolFactory

	Clock tcpip.Clock

	Stats tcpip.Stats

	HandleLocal bool

	NUDConfigs NUDConfigurations

	NUDDisp NUDDispatcher

	RawFactory RawFactory

	AllowPacketEndpointWrite bool

	AllowLiveTCPMigration bool

	RandSource rand.Source

	IPTables *IPTables

	NFTables NFTablesInterface

	DefaultIPTables func(clock tcpip.Clock, rand *rand.Rand) *IPTables

	SecureRNG io.Reader
}

type TransportEndpointInfo struct {

	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber


	ID TransportEndpointID
	BindNICID tcpip.NICID
	BindAddr  tcpip.Address
	RegisterNICID tcpip.NICID
}

func (t *TransportEndpointInfo) AddrNetProtoLocked(addr tcpip.FullAddress, v6only bool, bind bool) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	netProto := t.NetProto
	switch addr.Addr.BitLen() {
	case header.IPv4AddressSizeBits:
		netProto = header.IPv4ProtocolNumber
	case header.IPv6AddressSizeBits:
		if header.IsV4MappedAddress(addr.Addr) {
			netProto = header.IPv4ProtocolNumber
			addr.Addr = tcpip.AddrFrom4Slice(addr.Addr.AsSlice()[header.IPv6AddressSize-header.IPv4AddressSize:])
			if addr.Addr == header.IPv4Any {
				addr.Addr = tcpip.Address{}
			}
		}
	}

	switch t.ID.LocalAddress.BitLen() {
	case header.IPv4AddressSizeBits:
		if addr.Addr.BitLen() == header.IPv6AddressSizeBits {
			return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
		}
	case header.IPv6AddressSizeBits:
		if addr.Addr.BitLen() == header.IPv4AddressSizeBits {
			return tcpip.FullAddress{}, 0, &tcpip.ErrNetworkUnreachable{}
		}
	}

	if !bind && addr.Addr.Unspecified() {
		if t.ID.LocalAddress.Unspecified() {
			switch netProto {
			case header.IPv4ProtocolNumber:
				addr.Addr = header.IPv4Loopback
			case header.IPv6ProtocolNumber:
				addr.Addr = header.IPv6Loopback
			}
		} else {
			addr.Addr = t.ID.LocalAddress
		}
	}

	switch {
	case netProto == t.NetProto:
	case netProto == header.IPv4ProtocolNumber && t.NetProto == header.IPv6ProtocolNumber:
		if v6only {
			return tcpip.FullAddress{}, 0, &tcpip.ErrHostUnreachable{}
		}
	default:
		return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
	}

	return addr, netProto, nil
}

func (*TransportEndpointInfo) IsEndpointInfo() {}

func New(opts Options) *Stack {
	clock := opts.Clock
	if clock == nil {
		clock = tcpip.NewStdClock()
	}

	if opts.SecureRNG == nil {
		opts.SecureRNG = cryptorand.Reader
	}
	secureRNG := cryptorand.RNGFrom(opts.SecureRNG)

	randSrc := opts.RandSource
	if randSrc == nil {
		var v int64
		if err := binary.Read(opts.SecureRNG, binary.LittleEndian, &v); err != nil {
			panic(err)
		}
		randSrc = &lockedRandomSource{src: rand.NewSource(v)}
	}
	insecureRNG := rand.New(randSrc)

	if opts.IPTables == nil {
		if opts.DefaultIPTables == nil {
			opts.DefaultIPTables = DefaultTables
		}
		opts.IPTables = opts.DefaultIPTables(clock, insecureRNG)
	}

	opts.NUDConfigs.resetInvalidFields()

	s := &Stack{
		transportProtocols:           make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:             make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		nics:                         make(map[tcpip.NICID]*nic),
		packetEndpointWriteSupported: opts.AllowPacketEndpointWrite,
		defaultForwardingEnabled:     make(map[tcpip.NetworkProtocolNumber]struct{}),
		cleanupEndpoints:             make(map[TransportEndpoint]struct{}),
		PortManager:                  ports.NewPortManager(),
		clock:                        clock,
		stats:                        opts.Stats.FillIn(),
		handleLocal:                  opts.HandleLocal,
		tables:                       opts.IPTables,
		icmpRateLimiter:              NewICMPRateLimiter(clock),
		seed:                         secureRNG.Uint32(),
		nudConfigs:                   opts.NUDConfigs,
		nudDisp:                      opts.NUDDisp,
		insecureRNG:                  insecureRNG,
		secureRNG:                    secureRNG,
		sendBufferSize: tcpip.SendBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		receiveBufferSize: tcpip.ReceiveBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		tcpInvalidRateLimit:   defaultTCPInvalidRateLimit,
		tsOffsetSecret:        secureRNG.Uint32(),
		allowLiveTCPMigration: opts.AllowLiveTCPMigration,
	}
	s.SetNFTables(opts.NFTables)

	for _, netProtoFactory := range opts.NetworkProtocols {
		netProto := netProtoFactory(s)
		s.networkProtocols[netProto.Number()] = netProto
	}

	for _, transProtoFactory := range opts.TransportProtocols {
		transProto := transProtoFactory(s)
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}

	s.rawFactory = opts.RawFactory

	s.demux = newTransportDemuxer(s)

	return s
}

func (s *Stack) NextNICID() tcpip.NICID {
	next := s.nicIDGen.Add(1)
	if next < 0 {
		panic("NICID overflow")
	}
	return tcpip.NICID(next)
}

func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.SetOption(option)
}

func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.Option(option)
}

func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.SettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.SetOption(option)
}

func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.GettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.Option(option)
}

type SendBufSizeProto interface {
	SendBufferSize() tcpip.TCPSendBufferSizeRangeOption
}

func (s *Stack) TCPSendBufferLimits() tcpip.TCPSendBufferSizeRangeOption {
	return s.transportProtocols[header.TCPProtocolNumber].proto.(SendBufSizeProto).SendBufferSize()
}

func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(TransportEndpointID, *PacketBuffer) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

func (s *Stack) Clock() tcpip.Clock {
	return s.clock
}

func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

func (s *Stack) SetNICForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, enable bool) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.setForwarding(protocol, enable)
}

func (s *Stack) NICForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.forwarding(protocol)
}

func (s *Stack) SetForwardingDefaultAndAllNICs(protocol tcpip.NetworkProtocolNumber, enable bool) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	doneOnce := false
	for id, nic := range s.nics {
		if _, err := nic.setForwarding(protocol, enable); err != nil {
			if doneOnce {
				panic(fmt.Sprintf("nic(id=%d).setForwarding(%d, %t): %s", id, protocol, enable, err))
			}

			return err
		}

		doneOnce = true
	}

	if enable {
		s.defaultForwardingEnabled[protocol] = struct{}{}
	} else {
		delete(s.defaultForwardingEnabled, protocol)
	}

	return nil
}

func (s *Stack) AddMulticastRoute(protocol tcpip.NetworkProtocolNumber, addresses UnicastSourceAndMulticastDestination, route MulticastRoute) tcpip.Error {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	forwardingNetProto, ok := netProto.(MulticastForwardingNetworkProtocol)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	return forwardingNetProto.AddMulticastRoute(addresses, route)
}

func (s *Stack) RemoveMulticastRoute(protocol tcpip.NetworkProtocolNumber, addresses UnicastSourceAndMulticastDestination) tcpip.Error {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	forwardingNetProto, ok := netProto.(MulticastForwardingNetworkProtocol)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	return forwardingNetProto.RemoveMulticastRoute(addresses)
}

func (s *Stack) MulticastRouteLastUsedTime(protocol tcpip.NetworkProtocolNumber, addresses UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, tcpip.Error) {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return tcpip.MonotonicTime{}, &tcpip.ErrUnknownProtocol{}
	}

	forwardingNetProto, ok := netProto.(MulticastForwardingNetworkProtocol)
	if !ok {
		return tcpip.MonotonicTime{}, &tcpip.ErrNotSupported{}
	}

	return forwardingNetProto.MulticastRouteLastUsedTime(addresses)
}

func (s *Stack) EnableMulticastForwardingForProtocol(protocol tcpip.NetworkProtocolNumber, disp MulticastForwardingEventDispatcher) (bool, tcpip.Error) {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return false, &tcpip.ErrUnknownProtocol{}
	}

	forwardingNetProto, ok := netProto.(MulticastForwardingNetworkProtocol)
	if !ok {
		return false, &tcpip.ErrNotSupported{}
	}

	return forwardingNetProto.EnableMulticastForwarding(disp)
}

func (s *Stack) DisableMulticastForwardingForProtocol(protocol tcpip.NetworkProtocolNumber) tcpip.Error {
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	forwardingNetProto, ok := netProto.(MulticastForwardingNetworkProtocol)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	forwardingNetProto.DisableMulticastForwarding()
	return nil
}

func (s *Stack) SetNICMulticastForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, enable bool) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.setMulticastForwarding(protocol, enable)
}

func (s *Stack) NICMulticastForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.multicastForwarding(protocol)
}

func (s *Stack) PortRange() (uint16, uint16) {
	return s.PortManager.PortRange()
}

func (s *Stack) SetPortRange(start uint16, end uint16) tcpip.Error {
	return s.PortManager.SetPortRange(start, end)
}

func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.routeTable.Reset()
	for _, r := range table {
		r := r
		s.addRouteLocked(&r)
	}
}

func (s *Stack) GetRouteTable() []tcpip.Route {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	table := make([]tcpip.Route, 0)
	for r := s.routeTable.Front(); r != nil; r = r.Next() {
		table = append(table, *r)
	}
	return table
}

func (s *Stack) AddRoute(route tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.addRouteLocked(&route)
}

func (s *Stack) addRouteLocked(route *tcpip.Route) {
	routePrefix := route.Destination.Prefix()
	n := s.routeTable.Front()
	for ; n != nil; n = n.Next() {
		if n.Destination.Prefix() < routePrefix {
			s.routeTable.InsertBefore(n, route)
			return
		}
	}
	s.routeTable.PushBack(route)
}

func (s *Stack) RemoveRoutes(match func(tcpip.Route) bool) int {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()

	return s.removeRoutesLocked(match)
}

func (s *Stack) removeRoutesLocked(match func(tcpip.Route) bool) int {
	count := 0
	for route := s.routeTable.Front(); route != nil; {
		next := route.Next()
		if match(*route) {
			s.routeTable.Remove(route)
			count++
		}
		route = next
	}
	return count
}

func (s *Stack) ReplaceRoute(route tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()

	s.removeRoutesLocked(func(rt tcpip.Route) bool {
		return rt.Equal(route)
	})
	s.addRouteLocked(&route)
}

func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewEndpoint(network, waiterQueue)
}

func (s *Stack) NewRawEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, tcpip.Error) {
	if s.rawFactory == nil {
		netRawMissingLogger.Infof("A process tried to create a raw socket, but --net-raw was not specified. Should runsc be run with --net-raw?")
		return nil, &tcpip.ErrNotPermitted{}
	}

	if !associated {
		return s.rawFactory.NewUnassociatedEndpoint(s, network, transport, waiterQueue)
	}

	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewRawEndpoint(network, waiterQueue)
}

func (s *Stack) NewPacketEndpoint(cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	if s.rawFactory == nil {
		return nil, &tcpip.ErrNotPermitted{}
	}

	return s.rawFactory.NewPacketEndpoint(s, cooked, netProto, waiterQueue)
}

type NICContext any

type NICOptions struct {
	Name string

	Disabled bool

	Context NICContext

	QDisc QueueingDiscipline

	DeliverLinkPackets bool

	EnableExperimentIPOption bool
}

func (s *Stack) GetNICByID(id tcpip.NICID) (*nic, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n, ok := s.nics[id]
	if !ok {
		return nil, &tcpip.ErrNoSuchFile{}
	}
	return n, nil
}

func (s *Stack) CreateNICWithOptions(id tcpip.NICID, ep LinkEndpoint, opts NICOptions) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == 0 {
		return &tcpip.ErrInvalidNICID{}
	}
	if _, ok := s.nics[id]; ok {
		return &tcpip.ErrDuplicateNICID{}
	}

	if opts.Name != "" {
		for _, n := range s.nics {
			if n.Name() == opts.Name {
				return &tcpip.ErrDuplicateNICID{}
			}
		}
	}

	n := newNIC(s, id, ep, opts)
	for proto := range s.defaultForwardingEnabled {
		if _, err := n.setForwarding(proto, true); err != nil {
			panic(fmt.Sprintf("newNIC(%d, ...).setForwarding(%d, true): %s", id, proto, err))
		}
	}
	s.nics[id] = n
	if n.IsLoopback() {
		s.loopbackNIC = n
	}
	ep.SetOnCloseAction(func() {
		s.RemoveNIC(id)
	})
	if !opts.Disabled {
		return n.enable()
	}

	return nil
}

func (s *Stack) CreateNIC(id tcpip.NICID, ep LinkEndpoint) tcpip.Error {
	return s.CreateNICWithOptions(id, ep, NICOptions{})
}

func (s *Stack) GetLinkEndpointByName(name string) LinkEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, nic := range s.nics {
		if nic.Name() == name {
			linkEP, ok := nic.NetworkLinkEndpoint.(LinkEndpoint)
			if !ok {
				panic(fmt.Sprintf("unexpected NetworkLinkEndpoint(%#v) is not a LinkEndpoint", nic.NetworkLinkEndpoint))
			}
			return linkEP
		}
	}
	return nil
}

func (s *Stack) EnableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.enable()
}

func (s *Stack) DisableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.disable()
	return nil
}

func (s *Stack) CheckNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false
	}

	return nic.Enabled()
}

func (s *Stack) RemoveNIC(id tcpip.NICID) tcpip.Error {
	s.mu.Lock()
	deferAct, err := s.removeNICLocked(id, true)
	s.mu.Unlock()
	if deferAct != nil {
		deferAct()
	}
	return err
}

func (s *Stack) removeNICLocked(id tcpip.NICID, closeLinkEndpoint bool) (func(), tcpip.Error) {
	nic, ok := s.nics[id]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}
	delete(s.nics, id)

	if nic.Primary != nil {
		b := nic.Primary.NetworkLinkEndpoint.(CoordinatorNIC)
		if err := b.DelNIC(nic); err != nil {
			return nil, err
		}
	}

	s.routeMu.Lock()
	for r := s.routeTable.Front(); r != nil; {
		next := r.Next()
		if r.NIC == id {
			s.routeTable.Remove(r)
		}
		r = next
	}
	s.routeMu.Unlock()

	if s.loopbackNIC == nic {
		s.loopbackNIC = nil
	}
	return nic.remove(closeLinkEndpoint)
}

func (s *Stack) GetNICCoordinatorID(id tcpip.NICID) (tcpip.NICID, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if nic, ok := s.nics[id]; ok {
		if nic.Primary != nil {
			return nic.Primary.id, true
		}
	}
	return 0, false
}

func (s *Stack) SetNICCoordinator(id tcpip.NICID, mid tcpip.NICID) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	if _, ok := nic.NetworkLinkEndpoint.(CoordinatorNIC); ok {
		return &tcpip.ErrNoSuchFile{}
	}
	m, ok := s.nics[mid]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	b, ok := m.NetworkLinkEndpoint.(CoordinatorNIC)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}
	if err := b.AddNIC(nic); err != nil {
		return err
	}
	nic.Primary = m
	return nil
}

func (s *Stack) SetNICAddress(id tcpip.NICID, addr tcpip.LinkAddress) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.NetworkLinkEndpoint.SetLinkAddress(addr)
	return nil
}

func (s *Stack) SetNICName(id tcpip.NICID, name string) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.name = name
	return nil
}

func (s *Stack) SetNICMTU(id tcpip.NICID, mtu uint32) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.NetworkLinkEndpoint.SetMTU(mtu)
	return nil
}

type NICInfo struct {
	Name              string
	LinkAddress       tcpip.LinkAddress
	ProtocolAddresses []tcpip.ProtocolAddress

	Flags NICStateFlags

	MTU uint32

	Stats tcpip.NICStats

	NetworkStats map[tcpip.NetworkProtocolNumber]NetworkEndpointStats

	Context NICContext

	ARPHardwareType header.ARPHardwareType

	Forwarding map[tcpip.NetworkProtocolNumber]bool

	MulticastForwarding map[tcpip.NetworkProtocolNumber]bool

	Primary tcpip.NICID
}

func (s *Stack) HasNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	_, ok := s.nics[id]
	s.mu.RUnlock()
	return ok
}

type forwardingFn func(tcpip.NetworkProtocolNumber) (bool, tcpip.Error)

func forwardingValue(forwardingFn forwardingFn, proto tcpip.NetworkProtocolNumber, nicID tcpip.NICID, fnName string) (forward bool, ok bool) {
	switch forwarding, err := forwardingFn(proto); err.(type) {
	case nil:
		return forwarding, true
	case *tcpip.ErrUnknownProtocol:
		panic(fmt.Sprintf("expected network protocol %d to be available on NIC %d", proto, nicID))
	case *tcpip.ErrNotSupported:
	default:
		panic(fmt.Sprintf("nic(id=%d).%s(%d): %s", nicID, fnName, proto, err))
	}
	return false, false
}

func (s *Stack) nicInfo(nic *nic, id tcpip.NICID) *NICInfo {
	flags := NICStateFlags{
		Up:          true,
		Running:     nic.Enabled(),
		Promiscuous: nic.Promiscuous(),
		Loopback:    nic.IsLoopback(),
	}

	netStats := make(map[tcpip.NetworkProtocolNumber]NetworkEndpointStats)
	for proto, netEP := range nic.networkEndpoints {
		netStats[proto] = netEP.Stats()
	}

	info := NICInfo{
		Name:                nic.name,
		LinkAddress:         nic.NetworkLinkEndpoint.LinkAddress(),
		ProtocolAddresses:   nic.primaryAddresses(),
		Flags:               flags,
		MTU:                 nic.NetworkLinkEndpoint.MTU(),
		Stats:               nic.stats.local,
		NetworkStats:        netStats,
		Context:             nic.context,
		ARPHardwareType:     nic.NetworkLinkEndpoint.ARPHardwareType(),
		Forwarding:          make(map[tcpip.NetworkProtocolNumber]bool),
		MulticastForwarding: make(map[tcpip.NetworkProtocolNumber]bool),
	}

	for proto := range s.networkProtocols {
		if forwarding, ok := forwardingValue(nic.forwarding, proto, id, "forwarding"); ok {
			info.Forwarding[proto] = forwarding
		}

		if multicastForwarding, ok := forwardingValue(nic.multicastForwarding, proto, id, "multicastForwarding"); ok {
			info.MulticastForwarding[proto] = multicastForwarding
		}
	}

	if nic.Primary != nil {
		info.Primary = nic.Primary.id
	}

	return &info
}

func (s *Stack) SingleNICInfo(id tcpip.NICID) (*NICInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; !ok {
		return nil, false
	} else {
		return s.nicInfo(nic, id), true
	}
}

func (s *Stack) NICInfo() map[tcpip.NICID]NICInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID]NICInfo)
	for id, nic := range s.nics {
		nics[id] = *s.nicInfo(nic, id)
	}
	return nics
}

type NICStateFlags struct {
	Up bool

	Running bool

	Promiscuous bool

	Loopback bool
}

func (s *Stack) AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, properties AddressProperties) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addAddress(protocolAddress, properties)
}

func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.removeAddress(addr)
	}

	return &tcpip.ErrUnknownNICID{}
}

func (s *Stack) SetAddressLifetimes(id tcpip.NICID, addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.setAddressLifetimes(addr, lifetimes)
	}

	return &tcpip.ErrUnknownNICID{}
}

func (s *Stack) AllAddresses() map[tcpip.NICID][]tcpip.ProtocolAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID][]tcpip.ProtocolAddress)
	for id, nic := range s.nics {
		nics[id] = nic.allPermanentAddresses()
	}
	return nics
}

func (s *Stack) GetMainNICAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrUnknownNICID{}
	}

	return nic.PrimaryAddress(protocol)
}

func (s *Stack) getAddressEP(nic *nic, localAddr, remoteAddr, srcHint tcpip.Address, netProto tcpip.NetworkProtocolNumber) AssignableAddressEndpoint {
	if localAddr.BitLen() == 0 {
		return nic.primaryEndpoint(netProto, remoteAddr, srcHint)
	}
	return nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
}

func (s *Stack) NewRouteForMulticast(nicID tcpip.NICID, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok || !nic.Enabled() {
		return nil
	}

	if addressEndpoint := s.getAddressEP(nic, tcpip.Address{}, remoteAddr, tcpip.Address{}, netProto); addressEndpoint != nil {
		return constructAndValidateRoute(netProto, addressEndpoint, nic, nic, tcpip.Address{}, tcpip.Address{}, remoteAddr, s.handleLocal, false, 0)
	}
	return nil
}

func (s *Stack) findLocalRouteFromNICRLocked(localAddressNIC *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	localAddressEndpoint := localAddressNIC.getAddressOrCreateTempInner(netProto, localAddr, false, NeverPrimaryEndpoint)
	if localAddressEndpoint == nil {
		return nil
	}

	var outgoingNIC *nic
	if localAddressNIC.hasAddress(netProto, remoteAddr) {
		outgoingNIC = localAddressNIC
	}

	if outgoingNIC == nil {
		for _, nic := range s.nics {
			if nic.hasAddress(netProto, remoteAddr) {
				outgoingNIC = nic
				break
			}
		}
	}

	if outgoingNIC == nil {
		localAddressEndpoint.DecRef()
		return nil
	}

	r := makeLocalRoute(
		netProto,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		localAddressEndpoint,
	)

	if r.IsOutboundBroadcast() {
		r.Release()
		return nil
	}

	return r
}

func (s *Stack) loopbackLocalRoute(localAddressNIC *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	localAddressEndpoint := localAddressNIC.getAddressOrCreateTempInner(netProto, localAddr, true, NeverPrimaryEndpoint)
	if localAddressEndpoint == nil {
		return nil
	}

	r := makeLocalRoute(
		netProto,
		localAddr,
		remoteAddr,
		localAddressNIC,
		localAddressNIC,
		localAddressEndpoint,
	)

	if r.IsOutboundBroadcast() {
		r.Release()
		return nil
	}

	return r
}

func (s *Stack) findLocalRouteRLocked(localAddressNICID tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	if localAddr.BitLen() == 0 {
		localAddr = remoteAddr
	}

	if localAddressNICID == 0 {
		if s.loopbackNIC != nil {
			for _, nic := range s.nics {
				if !nic.hasAddress(netProto, remoteAddr) {
					continue
				}
				if isSubnetBroadcastOnNIC(nic, netProto, remoteAddr) {
					break
				}
				if r := s.loopbackLocalRoute(s.loopbackNIC, localAddr, remoteAddr, netProto); r != nil {
					return r
				}
				break
			}
		}

		for _, localAddressNIC := range s.nics {
			if r := s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto); r != nil {
				return r
			}
		}

		return nil
	}

	if localAddressNIC, ok := s.nics[localAddressNICID]; ok {
		return s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto)
	}

	return nil
}

func (s *Stack) HandleLocal() bool {
	return s.handleLocal
}

func isNICForwarding(nic *nic, proto tcpip.NetworkProtocolNumber) bool {
	switch forwarding, err := nic.forwarding(proto); err.(type) {
	case nil:
		return forwarding
	case *tcpip.ErrUnknownProtocol:
		panic(fmt.Sprintf("expected network protocol %d to be available on NIC %d", proto, nic.ID()))
	case *tcpip.ErrNotSupported:
		return false
	default:
		panic(fmt.Sprintf("nic(id=%d).forwarding(%d): %s", nic.ID(), proto, err))
	}
}

func (s *Stack) findRouteWithLocalAddrFromAnyInterfaceRLocked(outgoingNIC *nic, localAddr, remoteAddr, srcHint, gateway tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool, mtu uint32) *Route {
	for _, aNIC := range s.nics {
		addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, srcHint, netProto)
		if addressEndpoint == nil {
			continue
		}

		if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC, outgoingNIC, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop, mtu); r != nil {
			return r
		}
	}
	return nil
}

func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) (*Route, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.CheckNetworkProtocol(netProto) {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	isLinkLocal := header.IsV6LinkLocalUnicastAddress(remoteAddr) || header.IsV6LinkLocalMulticastAddress(remoteAddr)
	isLocalBroadcast := remoteAddr == header.IPv4Broadcast
	isMulticast := header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)
	isLoopback := header.IsV4LoopbackAddress(remoteAddr) || header.IsV6LoopbackAddress(remoteAddr)
	needRoute := !(isLocalBroadcast || isMulticast || isLinkLocal || isLoopback)

	if s.handleLocal && !isMulticast && !isLocalBroadcast {
		if r := s.findLocalRouteRLocked(id, localAddr, remoteAddr, netProto); r != nil {
			return r, nil
		}
	}

	if id != 0 && !needRoute {
		if nic, ok := s.nics[id]; ok && nic.Enabled() {
			if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, tcpip.Address{}, netProto); addressEndpoint != nil {
				return makeRoute(
					netProto,
					tcpip.Address{},
					localAddr,
					remoteAddr,
					nic,
					nic,
					addressEndpoint,
					s.handleLocal,
					multicastLoop,
					0,
				), nil
			}
		}

		if isLoopback {
			return nil, &tcpip.ErrBadLocalAddress{}
		}
		return nil, &tcpip.ErrNetworkUnreachable{}
	}

	onlyGlobalAddresses := !header.IsV6LinkLocalUnicastAddress(localAddr) && !isLinkLocal

	var chosenRoute tcpip.Route
	if r := func() *Route {
		s.routeMu.RLock()
		defer s.routeMu.RUnlock()

		for route := s.routeTable.Front(); route != nil; route = route.Next() {
			if remoteAddr.BitLen() != 0 && !route.Destination.Contains(remoteAddr) {
				continue
			}

			nic, ok := s.nics[route.NIC]
			if !ok || !nic.Enabled() {
				continue
			}

			if id == 0 || id == route.NIC {
				if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, route.SourceHint, netProto); addressEndpoint != nil {
					var gateway tcpip.Address
					if needRoute {
						gateway = route.Gateway
					}
					r := constructAndValidateRoute(netProto, addressEndpoint, nic, nic, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop, route.MTU)
					if r == nil {
						panic(fmt.Sprintf("non-forwarding route validation failed with route table entry = %#v, id = %d, localAddr = %s, remoteAddr = %s", route, id, localAddr, remoteAddr))
					}
					return r
				}
			}

			locallyGenerated := (id != 0 || localAddr != tcpip.Address{})
			if onlyGlobalAddresses && chosenRoute.Equal(tcpip.Route{}) && isNICForwarding(nic, netProto) {
				if locallyGenerated {
					chosenRoute = *route
					continue
				}

				if r := s.findRouteWithLocalAddrFromAnyInterfaceRLocked(nic, localAddr, remoteAddr, route.SourceHint, route.Gateway, netProto, multicastLoop, route.MTU); r != nil {
					return r
				}
			}
		}

		return nil
	}(); r != nil {
		return r, nil
	}

	if !chosenRoute.Equal(tcpip.Route{}) {
		nic, ok := s.nics[chosenRoute.NIC]
		if !ok {
			panic(fmt.Sprintf("chosen route must have a valid NIC with ID = %d", chosenRoute.NIC))
		}

		var gateway tcpip.Address
		if needRoute {
			gateway = chosenRoute.Gateway
		}

		if id != 0 {
			if aNIC, ok := s.nics[id]; ok {
				if addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, chosenRoute.SourceHint, netProto); addressEndpoint != nil {
					if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC, nic, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop, chosenRoute.MTU); r != nil {
						return r, nil
					}
				}
			}

			return nil, &tcpip.ErrNetworkUnreachable{}
		}

		if id == 0 {
			if r := s.findRouteWithLocalAddrFromAnyInterfaceRLocked(nic, localAddr, remoteAddr, chosenRoute.SourceHint, gateway, netProto, multicastLoop, chosenRoute.MTU); r != nil {
				return r, nil
			}
		}
	}

	if needRoute {
		return nil, &tcpip.ErrNetworkUnreachable{}
	}
	if header.IsV6LoopbackAddress(remoteAddr) {
		return nil, &tcpip.ErrBadLocalAddress{}
	}
	return nil, &tcpip.ErrNetworkUnreachable{}
}

func (s *Stack) CheckNetworkProtocol(protocol tcpip.NetworkProtocolNumber) bool {
	_, ok := s.networkProtocols[protocol]
	return ok
}

func (s *Stack) CheckDuplicateAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, h DADCompletionHandler) (DADCheckAddressDisposition, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return 0, &tcpip.ErrUnknownNICID{}
	}

	return nic.checkDuplicateAddress(protocol, addr, h)
}

func (s *Stack) CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return 0
		}
		if protocol == header.IPv4ProtocolNumber {
			return nic.id
		}
		if nic.CheckLocalAddress(protocol, addr) {
			return nic.id
		}
		return 0
	}

	for _, nic := range s.nics {
		if nic.CheckLocalAddress(protocol, addr) {
			return nic.id
		}
	}

	return 0
}

func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setPromiscuousMode(enable)

	return nil
}

func (s *Stack) SetSpoofing(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setSpoofing(enable)

	return nil
}

func (s *Stack) SetAllowPromiscuousSource(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setAllowPromiscuousSource(enable)

	return nil
}

type LinkResolutionResult struct {
	LinkAddress tcpip.LinkAddress
	Err         tcpip.Error
}

func (s *Stack) GetLinkAddress(nicID tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, onResolve func(LinkResolutionResult)) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.getLinkAddress(addr, localAddr, protocol, onResolve)
}

func (s *Stack) Neighbors(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) ([]NeighborEntry, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.neighbors(protocol)
}

func (s *Stack) AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addStaticNeighbor(addr, protocol, linkAddr)
}

func (s *Stack) RemoveNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.removeNeighbor(protocol, addr)
}

func (s *Stack) ClearNeighbors(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.clearNeighbors(protocol)
}

func (s *Stack) RegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.registerEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

func (s *Stack) CheckRegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.checkEndpoint(netProtos, protocol, id, flags, bindToDevice)
}

func (s *Stack) UnregisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

func (s *Stack) StartTransportEndpointCleanup(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.cleanupEndpointsMu.Lock()
	s.cleanupEndpoints[ep] = struct{}{}
	s.cleanupEndpointsMu.Unlock()

	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

func (s *Stack) CompleteTransportEndpointCleanup(ep TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	delete(s.cleanupEndpoints, ep)
	s.cleanupEndpointsMu.Unlock()
}

func (s *Stack) FindTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, id TransportEndpointID, nicID tcpip.NICID) TransportEndpoint {
	return s.demux.findTransportEndpoint(netProto, transProto, id, nicID)
}

func (s *Stack) RegisterRawTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) tcpip.Error {
	return s.demux.registerRawEndpoint(netProto, transProto, ep)
}

func (s *Stack) UnregisterRawTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	s.demux.unregisterRawEndpoint(netProto, transProto, ep)
}

func (s *Stack) RegisterRestoredEndpoint(e RestoredEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.restoredEndpoints = append(s.restoredEndpoints, e)
}

func (s *Stack) RegisterResumableEndpoint(e ResumableEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resumableEndpoints = append(s.resumableEndpoints, e)
}

func (s *Stack) RegisteredEndpoints() []TransportEndpoint {
	s.mu.Lock()
	defer s.mu.Unlock()

	var es []TransportEndpoint
	for _, e := range s.demux.protocol {
		es = append(es, e.transportEndpoints()...)
	}
	return es
}

func (s *Stack) CleanupEndpoints() []TransportEndpoint {
	s.cleanupEndpointsMu.Lock()
	defer s.cleanupEndpointsMu.Unlock()

	es := make([]TransportEndpoint, 0, len(s.cleanupEndpoints))
	for e := range s.cleanupEndpoints {
		es = append(es, e)
	}
	return es
}

func (s *Stack) RestoreCleanupEndpoints(es []TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	defer s.cleanupEndpointsMu.Unlock()

	for _, e := range es {
		s.cleanupEndpoints[e] = struct{}{}
	}
}

func (s *Stack) Close() {
	for _, e := range s.RegisteredEndpoints() {
		e.Abort()
	}
	for _, p := range s.transportProtocols {
		p.proto.Close()
	}
	for _, p := range s.networkProtocols {
		p.Close()
	}
}

func (s *Stack) Wait() {
	for _, e := range s.RegisteredEndpoints() {
		e.Wait()
	}
	for _, e := range s.CleanupEndpoints() {
		e.Wait()
	}
	for _, p := range s.transportProtocols {
		p.proto.Wait()
	}
	for _, p := range s.networkProtocols {
		p.Wait()
	}

	deferActs := make([]func(), 0)

	s.mu.Lock()
	for id, n := range s.nics {
		act, _ := s.removeNICLocked(id, true)
		n.NetworkLinkEndpoint.Wait()
		if act != nil {
			deferActs = append(deferActs, act)
		}
	}
	s.mu.Unlock()

	for _, act := range deferActs {
		act()
	}
}

func (s *Stack) Destroy() {
	s.Close()
	s.Wait()
}

func (s *Stack) Pause() {
	for _, p := range s.transportProtocols {
		p.proto.Pause()
	}
}

func (s *Stack) getNICs() map[tcpip.NICID]*nic {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := s.nics
	return nics
}

func (s *Stack) ResetConfig() {
	nics := make(map[tcpip.NICID]*nic)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nics = nics
	s.loopbackNIC = nil
	s.nicIDGen.Store(0)
}

func (s *Stack) ReplaceConfig(st *Stack) {
	if st == nil {
		panic("stack.Stack cannot be nil when replacing config")
	}

	s.SetRouteTable(st.GetRouteTable())

	nics := st.getNICs()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tables = st.IPTables()
	s.SetNFTables(st.NFTables())
	for id, nic := range nics {
		nic.stack = s
		s.nics[id] = nic
		if nic.IsLoopback() {
			s.loopbackNIC = nic
		} else if s.externalNetworkingDisabled {
			nic.disable()
		}
		_ = s.NextNICID()
	}
}

func (s *Stack) Restore() {
	s.mu.Lock()
	eps := s.restoredEndpoints
	s.restoredEndpoints = nil
	s.mu.Unlock()
	for _, e := range eps {
		e.Restore(s)
	}

	tcpip.AsyncLoading.Wait()

	for _, p := range s.transportProtocols {
		p.proto.Restore()
	}
}

func (s *Stack) Resume() {
	s.mu.Lock()
	eps := s.resumableEndpoints
	s.resumableEndpoints = nil
	s.mu.Unlock()
	for _, e := range eps {
		e.Resume()
	}
	for _, p := range s.transportProtocols {
		p.proto.Resume()
	}
}

func (s *Stack) RegisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if nicID == 0 {
		for _, nic := range s.nics {
			nic.registerPacketEndpoint(netProto, ep)
		}
		return nil
	}

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.registerPacketEndpoint(netProto, ep)

	return nil
}

func (s *Stack) UnregisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unregisterPacketEndpointLocked(nicID, netProto, ep)
}

func (s *Stack) unregisterPacketEndpointLocked(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	if nicID == 0 {
		for _, nic := range s.nics {
			nic.unregisterPacketEndpoint(netProto, ep)
		}
		return
	}

	nic, ok := s.nics[nicID]
	if !ok {
		return
	}
	nic.unregisterPacketEndpoint(netProto, ep)
}

func (s *Stack) WritePacketToRemote(nicID tcpip.NICID, remote tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, payload buffer.Buffer) tcpip.Error {
	return s.WritePacketToRemoteWithMark(nicID, remote, netProto, payload, 0)
}

func (s *Stack) WritePacketToRemoteWithMark(nicID tcpip.NICID, remote tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, payload buffer.Buffer, mark uint32) tcpip.Error {
	s.mu.Lock()
	nic, ok := s.nics[nicID]
	s.mu.Unlock()
	if !ok {
		return &tcpip.ErrUnknownDevice{}
	}
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(nic.MaxHeaderLength()),
		Payload:            payload,
		Mark:               mark,
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = netProto
	return nic.WritePacketToRemote(remote, pkt)
}

func (s *Stack) WriteRawPacket(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, payload buffer.Buffer) tcpip.Error {
	return s.WriteRawPacketWithMark(nicID, proto, payload, 0)
}

func (s *Stack) WriteRawPacketWithMark(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, payload buffer.Buffer, mark uint32) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	pkt := NewPacketBuffer(PacketBufferOptions{
		Payload: payload,
		Mark:    mark,
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = proto
	return nic.writeRawPacketWithLinkHeaderInPayload(pkt)
}

func (s *Stack) NetworkProtocolInstance(num tcpip.NetworkProtocolNumber) NetworkProtocol {
	if p, ok := s.networkProtocols[num]; ok {
		return p
	}
	return nil
}

func (s *Stack) TransportProtocolInstance(num tcpip.TransportProtocolNumber) TransportProtocol {
	if pState, ok := s.transportProtocols[num]; ok {
		return pState.proto
	}
	return nil
}

func (s *Stack) JoinGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.joinGroup(protocol, multicastAddr)
	}
	return &tcpip.ErrUnknownNICID{}
}

func (s *Stack) LeaveGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.leaveGroup(protocol, multicastAddr)
	}
	return &tcpip.ErrUnknownNICID{}
}

func (s *Stack) IsInGroup(nicID tcpip.NICID, multicastAddr tcpip.Address) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.isInGroup(multicastAddr), nil
	}
	return false, &tcpip.ErrUnknownNICID{}
}

func (s *Stack) IPTables() *IPTables {
	return s.tables
}

func (s *Stack) SetIPTables(tables *IPTables) {
	s.tables = tables
}

func (s *Stack) NFTables() NFTablesInterface {
	val := s.nftables.Load()
	if val == nil {
		return nil
	}
	return *val
}

func (s *Stack) SetNFTables(nft NFTablesInterface) {
	if nft == nil {
		s.nftables.Store(nil)
	} else {
		s.nftables.Store(&nft)
	}
}

func (s *Stack) LockNFTablesUpdate() {
	s.nftablesUpdateMu.Lock()
}

func (s *Stack) UnlockNFTablesUpdate() {
	s.nftablesUpdateMu.Unlock()
}

func (s *Stack) IsNFTablesConfigured() bool {
	return s.nftablesConfigured.Load()
}

func (s *Stack) SetNFTablesConfigured(configured bool) {
	s.nftablesConfigured.Store(configured)
}

func (s *Stack) ICMPLimit() rate.Limit {
	return s.icmpRateLimiter.Limit()
}

func (s *Stack) SetICMPLimit(newLimit rate.Limit) {
	s.icmpRateLimiter.SetLimit(newLimit)
}

func (s *Stack) ICMPBurst() int {
	return s.icmpRateLimiter.Burst()
}

func (s *Stack) SetICMPBurst(burst int) {
	s.icmpRateLimiter.SetBurst(burst)
}

func (s *Stack) AllowICMPMessage() bool {
	return s.icmpRateLimiter.Allow()
}

func (s *Stack) GetNetworkEndpoint(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NetworkEndpoint, tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.getNetworkEndpoint(proto), nil
}

func (s *Stack) NUDConfigurations(id tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NUDConfigurations, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()

	if !ok {
		return NUDConfigurations{}, &tcpip.ErrUnknownNICID{}
	}

	return nic.nudConfigs(proto)
}

func (s *Stack) SetNUDConfigurations(id tcpip.NICID, proto tcpip.NetworkProtocolNumber, c NUDConfigurations) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.setNUDConfigs(proto, c)
}

func (s *Stack) Seed() uint32 {
	return s.seed
}

func (s *Stack) InsecureRNG() *rand.Rand {
	return s.insecureRNG
}

func (s *Stack) SecureRNG() cryptorand.RNG {
	return s.secureRNG
}

func (s *Stack) FindNICNameFromID(id tcpip.NICID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return ""
	}

	return nic.Name()
}

type ParseResult int

const (
	ParsedOK ParseResult = iota

	UnknownTransportProtocol

	TransportLayerParseError
)

func (s *Stack) ParsePacketBufferTransport(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) ParseResult {
	pkt.TransportProtocolNumber = protocol
	state, ok := s.transportProtocols[protocol]
	if !ok {
		return UnknownTransportProtocol
	}

	if !state.proto.Parse(pkt) {
		return TransportLayerParseError
	}

	return ParsedOK
}

func (s *Stack) networkProtocolNumbers() []tcpip.NetworkProtocolNumber {
	protos := make([]tcpip.NetworkProtocolNumber, 0, len(s.networkProtocols))
	for p := range s.networkProtocols {
		protos = append(protos, p)
	}
	return protos
}

func isSubnetBroadcastOnNIC(nic *nic, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	addressEndpoint := nic.getAddressOrCreateTempInner(protocol, addr, false, NeverPrimaryEndpoint)
	if addressEndpoint == nil {
		return false
	}

	subnet := addressEndpoint.Subnet()
	addressEndpoint.DecRef()
	return subnet.IsBroadcast(addr)
}

func (s *Stack) IsSubnetBroadcast(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return false
		}

		return isSubnetBroadcastOnNIC(nic, protocol, addr)
	}

	for _, nic := range s.nics {
		if isSubnetBroadcastOnNIC(nic, protocol, addr) {
			return true
		}
	}

	return false
}

func (s *Stack) PacketEndpointWriteSupported() bool {
	return s.packetEndpointWriteSupported
}

func (s *Stack) SetNICStack(id tcpip.NICID, peer *Stack) (tcpip.NICID, tcpip.Error) {
	s.mu.Lock()
	nic, ok := s.nics[id]
	if !ok {
		s.mu.Unlock()
		return 0, &tcpip.ErrUnknownNICID{}
	}
	if s == peer {
		s.mu.Unlock()
		return id, nil
	}

	linkEp := nic.NetworkLinkEndpoint.(LinkEndpoint)
	name := nic.Name()

	deferAct, err := s.removeNICLocked(id, false)
	s.mu.Unlock()
	if deferAct != nil {
		deferAct()
	}
	if err != nil {
		return 0, err
	}

	id = tcpip.NICID(peer.NextNICID())
	return id, peer.CreateNICWithOptions(id, linkEp, NICOptions{Name: name})
}

func (s *Stack) SetRemoveConf(removeConf bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeConf = removeConf
}

func (s *Stack) GetRemoveConf() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.removeConf
}

func (s *Stack) SetAllowConnectedOnSave(allowConnectedOnSave bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowConnectedOnSave = allowConnectedOnSave
}

func (s *Stack) GetAllowConnectedOnSave() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowConnectedOnSave
}

func (s *Stack) AllowLiveTCPMigration() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowLiveTCPMigration
}

func (s *Stack) SetAllowLiveTCPMigration(allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowLiveTCPMigration = allow
}

func (s *Stack) DisableAllNonLoopbackNICs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.externalNetworkingDisabled = true
	for _, nic := range s.nics {
		if !nic.IsLoopback() {
			nic.disable()
		}
	}
}

func (s *Stack) EnableAllNonLoopbackNICs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.externalNetworkingDisabled = false
	for _, nic := range s.nics {
		if !nic.IsLoopback() {
			nic.enable()
		}
	}
}
