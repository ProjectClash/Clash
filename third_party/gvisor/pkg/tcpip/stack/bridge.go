// Copyright 2024 The gVisor Authors.
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
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

var _ NetworkLinkEndpoint = (*BridgeEndpoint)(nil)

type bridgePort struct {
	bridge *BridgeEndpoint
	nic    *nic
}

type BridgeFDBKey tcpip.LinkAddress

type BridgeFDBEntry struct {
	port *bridgePort
}

func (e BridgeFDBEntry) PortLinkAddress() tcpip.LinkAddress {
	if e.port == nil {
		return ""
	}
	return e.port.nic.LinkAddress()
}

func (p *bridgePort) ParseHeader(pkt *PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

func (p *bridgePort) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	bridge := p.bridge
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	updateFDB := false
	bridge.mu.RLock()
	sourceAddress := eth.SourceAddress()
	if _, hasSourceFDB := bridge.fdbTable[BridgeFDBKey(sourceAddress)]; !header.IsMulticastEthernetAddress(sourceAddress) && !hasSourceFDB {
		updateFDB = true
	}
	if entry, exist := bridge.fdbTable[BridgeFDBKey(eth.DestinationAddress())]; !exist {
		for _, port := range bridge.ports {
			if p == port {
				continue
			}
			newPkt := NewPacketBuffer(PacketBufferOptions{
				ReserveHeaderBytes: int(port.nic.MaxHeaderLength()),
				Payload:            pkt.ToBuffer(),
			})
			port.nic.writeRawPacket(newPkt)
			newPkt.DecRef()
		}
	} else if entry.port != p {
		destPort := entry.port
		newPkt := NewPacketBuffer(PacketBufferOptions{
			ReserveHeaderBytes: int(destPort.nic.MaxHeaderLength()),
			Payload:            pkt.ToBuffer(),
		})
		destPort.nic.writeRawPacket(newPkt)
		newPkt.DecRef()
	}

	d := bridge.dispatcher
	bridge.mu.RUnlock()
	if updateFDB {
		bridge.mu.Lock()
		bridge.addFDBEntryLocked(eth.SourceAddress(), p, 0)
		bridge.mu.Unlock()
	}
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func (p *bridgePort) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
}

func NewBridgeEndpoint(mtu uint32) *BridgeEndpoint {
	b := &BridgeEndpoint{
		mtu:  mtu,
		addr: tcpip.GetRandMacAddr(),
	}
	b.ports = make(map[tcpip.NICID]*bridgePort)
	b.fdbTable = make(map[BridgeFDBKey]BridgeFDBEntry)
	return b
}

type BridgeEndpoint struct {
	mu bridgeRWMutex `state:"nosave"`
	ports map[tcpip.NICID]*bridgePort
	dispatcher NetworkDispatcher
	addr tcpip.LinkAddress
	attached bool
	mtu uint32
	fdbTable        map[BridgeFDBKey]BridgeFDBEntry
	maxHeaderLength atomicbitops.Uint32
}

func (b *BridgeEndpoint) WritePackets(pkts PacketBufferList) (int, tcpip.Error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	pktsSlice := pkts.AsSlice()
	n := len(pktsSlice)
	for _, p := range b.ports {
		for _, pkt := range pktsSlice {
			newPkt := NewPacketBuffer(PacketBufferOptions{
				Payload:            pkt.ToBuffer(),
				ReserveHeaderBytes: int(p.nic.MaxHeaderLength()),
			})
			newPkt.EgressRoute = pkt.EgressRoute
			newPkt.NetworkProtocolNumber = pkt.NetworkProtocolNumber
			p.nic.writePacket(newPkt)
			newPkt.DecRef()
		}
	}

	return n, nil
}

func (b *BridgeEndpoint) AddNIC(n *nic) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()

	port := &bridgePort{
		nic:    n,
		bridge: b,
	}
	n.NetworkLinkEndpoint.Attach(port)
	b.ports[n.id] = port

	if b.maxHeaderLength.Load() < uint32(n.MaxHeaderLength()) {
		b.maxHeaderLength.Store(uint32(n.MaxHeaderLength()))
	}

	return nil
}

func (b *BridgeEndpoint) DelNIC(nic *nic) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()

	port := b.ports[nic.id]
	for k, e := range b.fdbTable {
		if e.port == port {
			delete(b.fdbTable, k)
		}
	}
	delete(b.ports, nic.id)
	nic.NetworkLinkEndpoint.Attach(nic)
	return nil
}

func (b *BridgeEndpoint) MTU() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.mtu > header.EthernetMinimumSize {
		return b.mtu - header.EthernetMinimumSize
	}
	return 0
}

func (b *BridgeEndpoint) SetMTU(mtu uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mtu = mtu
}

func (b *BridgeEndpoint) MaxHeaderLength() uint16 {
	return uint16(b.maxHeaderLength.Load())
}

func (b *BridgeEndpoint) LinkAddress() tcpip.LinkAddress {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.addr
}

func (b *BridgeEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addr = addr
}

func (b *BridgeEndpoint) Capabilities() LinkEndpointCapabilities {
	return CapabilityRXChecksumOffload | CapabilitySaveRestore | CapabilityResolutionRequired
}

func (b *BridgeEndpoint) Attach(dispatcher NetworkDispatcher) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.ports {
		p.nic.Primary = nil
	}
	b.dispatcher = dispatcher
	b.ports = make(map[tcpip.NICID]*bridgePort)
	b.fdbTable = make(map[BridgeFDBKey]BridgeFDBEntry)
}

func (b *BridgeEndpoint) IsAttached() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dispatcher != nil
}

func (b *BridgeEndpoint) Wait() {
}

func (b *BridgeEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

func (b *BridgeEndpoint) AddHeader(pkt *PacketBuffer) {
}

func (b *BridgeEndpoint) ParseHeader(*PacketBuffer) bool {
	return true
}

func (b *BridgeEndpoint) Close() {}

func (b *BridgeEndpoint) SetOnCloseAction(func()) {}

func (b *BridgeEndpoint) addFDBEntryLocked(addr tcpip.LinkAddress, source *bridgePort, flags uint64) bool {
	b.fdbTable[BridgeFDBKey(addr)] = BridgeFDBEntry{
		port: source,
	}
	return true
}

func (b *BridgeEndpoint) FindFDBEntry(addr tcpip.LinkAddress) BridgeFDBEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.fdbTable[BridgeFDBKey(addr)]
}
