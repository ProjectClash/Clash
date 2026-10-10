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

package arp

import (
	"fmt"
	"reflect"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/header/parse"
	"github.com/metacubex/gvisor/pkg/tcpip/network/internal/ip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	ProtocolNumber = header.ARPProtocolNumber
)

var _ stack.DuplicateAddressDetector = (*endpoint)(nil)
var _ stack.LinkAddressResolver = (*endpoint)(nil)
var _ ip.DADProtocol = (*endpoint)(nil)

var _ stack.NetworkEndpoint = (*endpoint)(nil)

type endpoint struct {
	protocol *protocol

	enabled atomicbitops.Uint32

	nic   stack.NetworkInterface
	stats sharedStats

	mu sync.Mutex `state:"nosave"`

	dad ip.DAD
}

func (e *endpoint) CheckDuplicateAddress(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dad.CheckDuplicateAddressLocked(addr, h)
}

func (e *endpoint) SetDADConfigurations(c stack.DADConfigurations) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dad.SetConfigsLocked(c)
}

func (*endpoint) DuplicateAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv4ProtocolNumber
}

func (e *endpoint) SendDADMessage(addr tcpip.Address, _ []byte) tcpip.Error {
	return e.sendARPRequest(header.IPv4Any, addr, header.EthernetBroadcastAddress)
}

func (e *endpoint) Enable() tcpip.Error {
	if !e.nic.Enabled() {
		return &tcpip.ErrNotPermitted{}
	}

	e.setEnabled(true)
	return nil
}

func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

func (e *endpoint) isEnabled() bool {
	return e.enabled.Load() == 1
}

func (e *endpoint) setEnabled(v bool) {
	if v {
		e.enabled.Store(1)
	} else {
		e.enabled.Store(0)
	}
}

func (e *endpoint) Disable() {
	e.setEnabled(false)
}

func (*endpoint) DefaultTTL() uint8 {
	return 0
}

func (e *endpoint) MTU() uint32 {
	lmtu := e.nic.MTU()
	return lmtu - uint32(e.MaxHeaderLength())
}

func (e *endpoint) EndpointHeaderSize() uint32 {
	return header.ARPSize
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.ARPSize
}

func (*endpoint) Close() {}

func (*endpoint) WritePacket(*stack.Route, stack.NetworkHeaderParams, *stack.PacketBuffer) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

func (*endpoint) WriteHeaderIncludedPacket(*stack.Route, *stack.PacketBuffer) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	stats := e.stats.arp
	stats.packetsReceived.Increment()

	if !e.isEnabled() {
		stats.disabledPacketsReceived.Increment()
		return
	}

	if _, _, ok := e.protocol.Parse(pkt); !ok {
		stats.malformedPacketsReceived.Increment()
		return
	}

	h := header.ARP(pkt.NetworkHeader().Slice())
	if !h.IsValid() {
		stats.malformedPacketsReceived.Increment()
		return
	}

	switch h.Op() {
	case header.ARPRequest:
		stats.requestsReceived.Increment()
		localAddr := tcpip.AddrFrom4Slice(h.ProtocolAddressTarget())

		if !e.nic.CheckLocalAddress(header.IPv4ProtocolNumber, localAddr) {
			stats.requestsReceivedUnknownTargetAddress.Increment()
			return
		}

		remoteAddr := tcpip.AddrFrom4Slice(h.ProtocolAddressSender())
		remoteLinkAddr := tcpip.LinkAddress(h.HardwareAddressSender())

		switch err := e.nic.HandleNeighborProbe(header.IPv4ProtocolNumber, remoteAddr, remoteLinkAddr); err.(type) {
		case nil:
		case *tcpip.ErrNotSupported:
		default:
			panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
		}

		respPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(e.nic.MaxHeaderLength()) + header.ARPSize,
		})
		defer respPkt.DecRef()
		packet := header.ARP(respPkt.NetworkHeader().Push(header.ARPSize))
		respPkt.NetworkProtocolNumber = ProtocolNumber
		packet.SetIPv4OverEthernet()
		packet.SetOp(header.ARPReply)
		_ = copy(packet.HardwareAddressSender(), e.nic.LinkAddress())
		if n := copy(packet.ProtocolAddressSender(), h.ProtocolAddressTarget()); n != header.IPv4AddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
		}
		origSender := h.HardwareAddressSender()
		if n := copy(packet.HardwareAddressTarget(), origSender); n != header.EthernetAddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.EthernetAddressSize))
		}
		if n := copy(packet.ProtocolAddressTarget(), h.ProtocolAddressSender()); n != header.IPv4AddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
		}

		if err := e.nic.WritePacketToRemote(tcpip.LinkAddress(origSender), respPkt); err != nil {
			stats.outgoingRepliesDropped.Increment()
		} else {
			stats.outgoingRepliesSent.Increment()
		}

	case header.ARPReply:
		stats.repliesReceived.Increment()
		addr := tcpip.AddrFrom4Slice(h.ProtocolAddressSender())
		linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())

		e.mu.Lock()
		e.dad.StopLocked(addr, &stack.DADDupAddrDetected{HolderLinkAddress: linkAddr})
		e.mu.Unlock()

		switch err := e.nic.HandleNeighborConfirmation(header.IPv4ProtocolNumber, addr, linkAddr, stack.ReachabilityConfirmationFlags{
			Solicited: pkt.PktType == tcpip.PacketHost,
			Override: false,
			IsRouter: false,
		}); err.(type) {
		case nil:
		case *tcpip.ErrNotSupported:
		default:
			panic(fmt.Sprintf("unexpected error when informing NIC of neighbor confirmation message: %s", err))
		}
	}
}

func (e *endpoint) Stats() stack.NetworkEndpointStats {
	return &e.stats.localStats
}

var _ stack.NetworkProtocol = (*protocol)(nil)

type protocol struct {
	stack   *stack.Stack
	options Options
}

func (p *protocol) Number() tcpip.NetworkProtocolNumber { return ProtocolNumber }
func (p *protocol) MinimumPacketSize() int              { return header.ARPSize }

func (*protocol) ParseAddresses([]byte) (src, dst tcpip.Address) {
	return tcpip.Address{}, tcpip.Address{}
}

func (p *protocol) NewEndpoint(nic stack.NetworkInterface, _ stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		protocol: p,
		nic:      nic,
	}

	e.mu.Lock()
	e.dad.Init(&e.mu, p.options.DADConfigs, ip.DADOptions{
		Clock:     p.stack.Clock(),
		SecureRNG: p.stack.SecureRNG().Reader,
		NonceSize: 0,
		Protocol:  e,
		NICID:     nic.ID(),
	})
	e.mu.Unlock()

	tcpip.InitStatCounters(reflect.ValueOf(&e.stats.localStats).Elem())

	stackStats := p.stack.Stats()
	e.stats.arp.init(&e.stats.localStats.ARP, &stackStats.ARP)

	return e
}

func (*endpoint) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv4ProtocolNumber
}

func (e *endpoint) LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error {
	stats := e.stats.arp

	if len(remoteLinkAddr) == 0 {
		remoteLinkAddr = header.EthernetBroadcastAddress
	}

	if localAddr.BitLen() == 0 {
		addr, err := e.nic.PrimaryAddress(header.IPv4ProtocolNumber)
		if err != nil {
			return err
		}

		if addr.Address.BitLen() == 0 {
			stats.outgoingRequestInterfaceHasNoLocalAddressErrors.Increment()
			return &tcpip.ErrNetworkUnreachable{}
		}

		localAddr = addr.Address
	} else if !e.nic.CheckLocalAddress(header.IPv4ProtocolNumber, localAddr) {
		stats.outgoingRequestBadLocalAddressErrors.Increment()
		return &tcpip.ErrBadLocalAddress{}
	}

	return e.sendARPRequest(localAddr, targetAddr, remoteLinkAddr)
}

func (e *endpoint) sendARPRequest(localAddr, targetAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(e.MaxHeaderLength()),
	})
	defer pkt.DecRef()
	h := header.ARP(pkt.NetworkHeader().Push(header.ARPSize))
	pkt.NetworkProtocolNumber = ProtocolNumber
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	_ = copy(h.HardwareAddressSender(), e.nic.LinkAddress())
	if n := copy(h.ProtocolAddressSender(), localAddr.AsSlice()); n != header.IPv4AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
	}
	if n := copy(h.ProtocolAddressTarget(), targetAddr.AsSlice()); n != header.IPv4AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
	}

	stats := e.stats.arp
	if err := e.nic.WritePacketToRemote(remoteLinkAddr, pkt); err != nil {
		stats.outgoingRequestsDropped.Increment()
		return err
	}
	stats.outgoingRequestsSent.Increment()
	return nil
}

func (*endpoint) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == header.IPv4Broadcast {
		return header.EthernetBroadcastAddress, true
	}
	if header.IsV4MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv4Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}

func (*protocol) SetOption(tcpip.SettableNetworkProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*protocol) Option(tcpip.GettableNetworkProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*protocol) Close() {}

func (*protocol) Wait() {}

func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	return 0, false, parse.ARP(pkt)
}

type Options struct {
	DADConfigs stack.DADConfigurations
}

func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	return func(s *stack.Stack) stack.NetworkProtocol {
		return &protocol{
			stack:   s,
			options: opts,
		}
	}
}

func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}
