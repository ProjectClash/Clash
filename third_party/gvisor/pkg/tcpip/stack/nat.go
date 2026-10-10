// Copyright 2020 The gVisor Authors.
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
	"fmt"
	"math"

	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

type NATType int

const (
	SNAT NATType = iota
	DNAT
	NATUnknown
)

func ToNATType(t uint8) NATType {
	switch t {
	case 0:
		return SNAT
	case 1:
		return DNAT
	}
	return NATUnknown
}

func (natType NATType) String() string {
	switch natType {
	case SNAT:
		return "SNAT"
	case DNAT:
		return "DNAT"
	default:
		return "NATUnknown"
	}
}

func NfNATPriority(hook NFHook) (int, bool) {
	switch hook {
	case NFPrerouting:
		return -100, true
	case NFPostrouting:
		return 100, true
	case NFOutput:
		return -100, true
	case NFInput:
		return 100, true
	}
	return 0, false
}

func NfHookToNATType(hook NFHook) NATType {
	switch hook {
	case NFPrerouting, NFOutput:
		return DNAT
	case NFInput, NFPostrouting:
		return SNAT
	}
	return NATUnknown
}

type handlePacketOpts struct {
	fullChecksum       bool
	updatePseudoHeader bool
	natType            NATType
}

func handlePacket(pkt *PacketBuffer, opts *handlePacketOpts) bool {
	if opts == nil || opts.natType == NATUnknown {
		return false
	}
	netHdr, transHdr, isICMPError, ok := pkt.GetHeaders()
	if !ok {
		return false
	}

	natDone := &pkt.snatDone
	dnat := false
	if opts.natType == DNAT {
		natDone = &pkt.dnatDone
		dnat = true
	}

	if *natDone {
		panic(fmt.Sprintf("packet already had NAT: %s performed; pkt=%#v", opts.natType, pkt))
	}


	reply := pkt.tuple.reply
	cn := pkt.tuple.conn

	tid, manip := func() (tupleID, manipType) {
		cn.mu.RLock()
		defer cn.mu.RUnlock()

		if reply {
			tid := cn.original.tupleID

			if dnat {
				return tid, cn.sourceManip
			}
			return tid, cn.destinationManip
		}

		tid := cn.reply.tupleID
		if dnat {
			return tid, cn.destinationManip
		}
		return tid, cn.sourceManip
	}()
	switch manip {
	case manipNotPerformed:
		return false
	case manipPerformedNoop:
		*natDone = true
		return true
	case manipPerformed:
	default:
		panic(fmt.Sprintf("unhandled manip = %d", manip))
	}

	newPort := tid.dstPortOrEchoReplyIdent
	newAddr := tid.dstAddr
	if dnat {
		newPort = tid.srcPortOrEchoRequestIdent
		newAddr = tid.srcAddr
	}

	UpdateHeaders(
		netHdr,
		transHdr,
		!dnat != isICMPError,
		opts.fullChecksum,
		opts.updatePseudoHeader,
		newPort,
		newAddr,
	)

	*natDone = true

	if !isICMPError {
		return true
	}

	switch pkt.TransportProtocolNumber {
	case header.ICMPv4ProtocolNumber:
		icmp := header.ICMPv4(pkt.TransportHeader().Slice())
		icmp.SetChecksum(0)
		icmp.SetChecksum(header.ICMPv4Checksum(icmp, pkt.Data().Checksum()))

		network := header.IPv4(pkt.NetworkHeader().Slice())
		if dnat {
			network.SetDestinationAddressWithChecksumUpdate(tid.srcAddr)
		} else {
			network.SetSourceAddressWithChecksumUpdate(tid.dstAddr)
		}
	case header.ICMPv6ProtocolNumber:
		network := header.IPv6(pkt.NetworkHeader().Slice())
		srcAddr := network.SourceAddress()
		dstAddr := network.DestinationAddress()
		if dnat {
			dstAddr = tid.srcAddr
		} else {
			srcAddr = tid.dstAddr
		}

		icmp := header.ICMPv6(pkt.TransportHeader().Slice())
		icmp.SetChecksum(0)
		payload := pkt.Data()
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmp,
			Src:         srcAddr,
			Dst:         dstAddr,
			PayloadCsum: payload.Checksum(),
			PayloadLen:  payload.Size(),
		}))

		if dnat {
			network.SetDestinationAddress(dstAddr)
		} else {
			network.SetSourceAddress(srcAddr)
		}
	}

	return true
}

func IPTHandlePacket(pkt *PacketBuffer, hook Hook, r *Route) bool {
	opts := handlePacketOpts{
		fullChecksum:       false,
		updatePseudoHeader: false,
		natType:            SNAT,
	}
	requiresTXTransportChecksum := false
	if r != nil {
		requiresTXTransportChecksum = r.RequiresTXTransportChecksum()
	}
	switch hook {
	case Prerouting:
		opts.fullChecksum = true
		opts.updatePseudoHeader = true
		opts.natType = DNAT
	case Input:
	case Forward:
		panic("should not handle packet in the forwarding hook")
	case Output:
		opts.natType = DNAT
		fallthrough
	case Postrouting:
		if pkt.TransportProtocolNumber == header.TCPProtocolNumber && pkt.GSOOptions.Type != GSONone && pkt.GSOOptions.NeedsCsum {
			opts.updatePseudoHeader = true
		} else if requiresTXTransportChecksum {
			opts.fullChecksum = true
			opts.updatePseudoHeader = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %d", hook))
	}

	return handlePacket(pkt, &opts)
}

type PortOrIdentRange struct {
	Start uint16
	Size  uint32
}

func (cn *conn) ConfigureNAT(portsOrIdents PortOrIdentRange, natAddress tcpip.Address, natType NATType, changePort, changeAddress bool) bool {
	lastPortOrIdentU32 := uint32(portsOrIdents.Start) + portsOrIdents.Size - 1
	if lastPortOrIdentU32 > math.MaxUint16 {
		log.Warningf("got lastPortOrIdent = %d, want <= MaxUint16(=%d); portsOrIdents=%#v", lastPortOrIdentU32, math.MaxUint16, portsOrIdents)
		return false
	}
	lastPortOrIdent := uint16(lastPortOrIdentU32)

	cn.mu.Lock()
	defer cn.mu.Unlock()

	var manip *manipType
	var address *tcpip.Address
	var portOrIdent *uint16
	if natType == DNAT {
		manip = &cn.destinationManip
		address = &cn.reply.tupleID.srcAddr
		portOrIdent = &cn.reply.tupleID.srcPortOrEchoRequestIdent
	} else {
		manip = &cn.sourceManip
		address = &cn.reply.tupleID.dstAddr
		portOrIdent = &cn.reply.tupleID.dstPortOrEchoReplyIdent
	}

	if *manip != manipNotPerformed {
		return true
	}
	*manip = manipPerformed
	if changeAddress {
		*address = natAddress
	}

	if !changePort {
		return true
	}

	if portsOrIdents.Start <= *portOrIdent && *portOrIdent <= lastPortOrIdent {
		other := cn.ct.connForTID(cn.reply.tupleID)
		if other == nil || other.conn == cn {
			return true
		}
	}

	const maxAttemptsForInitialRound uint32 = 128
	const minAttemptsToContinue = 16

	allowedInitialAttempts := maxAttemptsForInitialRound
	if allowedInitialAttempts > portsOrIdents.Size {
		allowedInitialAttempts = portsOrIdents.Size
	}

	for maxAttempts := allowedInitialAttempts; ; maxAttempts /= 2 {
		randOffset := cn.ct.rng.Uint32()

		for i := uint32(0); i < maxAttempts; i++ {
			newPortOrIdentU32 := uint32(portsOrIdents.Start) + (randOffset+i)%portsOrIdents.Size
			if newPortOrIdentU32 > math.MaxUint16 {
				log.Warningf("got newPortOrIdentU32 = %d, want <= MaxUint16(=%d); portsOrIdents=%#v", newPortOrIdentU32, math.MaxUint16, portsOrIdents)
				continue
			}

			*portOrIdent = uint16(newPortOrIdentU32)

			if other := cn.ct.connForTID(cn.reply.tupleID); other == nil {
				return true
			}
		}

		if maxAttempts == portsOrIdents.Size {
			return false
		}

		if maxAttempts < minAttemptsToContinue {
			return false
		}
	}

}

func IPTPerformNAT(pkt *PacketBuffer, hook Hook, r *Route, portsOrIdents PortOrIdentRange, natAddress tcpip.Address, dnat, changePort, changeAddress bool) {
	defer func() {
		_ = IPTHandlePacket(pkt, hook, r)
	}()
	cn := pkt.tuple.conn
	natType := SNAT
	if dnat {
		natType = DNAT
	}
	_ = cn.ConfigureNAT(portsOrIdents, natAddress, natType, changePort, changeAddress)
}

func IPTMaybePerformNoopNAT(pkt *PacketBuffer, hook Hook, r *Route, dnat bool) {
	cn := pkt.tuple.conn
	cn.mu.Lock()
	var manip *manipType
	if dnat {
		manip = &cn.destinationManip
	} else {
		manip = &cn.sourceManip
	}
	if *manip != manipNotPerformed {
		cn.mu.Unlock()
		_ = IPTHandlePacket(pkt, hook, r)
		return
	}
	if dnat {
		*manip = manipPerformedNoop
		cn.mu.Unlock()
		_ = IPTHandlePacket(pkt, hook, r)
		return
	}
	cn.mu.Unlock()

	_, _ = snatAction(pkt, hook, r, 0, tcpip.Address{}, true, false)
}

func NFTApplyNAT(pkt *PacketBuffer, hook NFHook, rt *Route) bool {
	requiresTXTransportChecksum := false
	if rt != nil {
		requiresTXTransportChecksum = rt.RequiresTXTransportChecksum()
	}
	opts := handlePacketOpts{
		fullChecksum:       false,
		updatePseudoHeader: false,
		natType:            SNAT,
	}
	switch hook {
	case NFPrerouting:
		opts.fullChecksum = true
		opts.updatePseudoHeader = true
		opts.natType = DNAT
	case NFInput:
	case NFForward:
		panic("should not handle packet in the forwarding hook")
	case NFOutput:
		opts.natType = DNAT
		fallthrough
	case NFPostrouting:
		if pkt.TransportProtocolNumber == header.TCPProtocolNumber && pkt.GSOOptions.Type != GSONone && pkt.GSOOptions.NeedsCsum {
			opts.updatePseudoHeader = true
		} else if requiresTXTransportChecksum {
			opts.fullChecksum = true
			opts.updatePseudoHeader = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %d", hook))
	}

	return handlePacket(pkt, &opts)
}

func (cn *conn) IsNATConfigured(natType NATType) bool {
	cn.mu.RLock()
	defer cn.mu.RUnlock()
	switch natType {
	case SNAT:
		return cn.sourceManip != manipNotPerformed
	case DNAT:
		return cn.destinationManip != manipNotPerformed
	}
	return false
}

func (cn *conn) ConfigureNoopNAT(pkt *PacketBuffer, natType NATType) bool {
	cn.mu.Lock()
	var manip *manipType
	if natType == DNAT {
		manip = &cn.destinationManip
	} else {
		manip = &cn.sourceManip
	}

	if *manip != manipNotPerformed {
		cn.mu.Unlock()
		return true
	}

	if natType == DNAT {
		*manip = manipPerformedNoop
		cn.mu.Unlock()
		return true
	}
	cn.mu.Unlock()


	portsOrIdents := PortOrIdentRange{Start: 0, Size: math.MaxUint16 + 1}

	var port uint16
	switch pkt.TransportProtocolNumber {
	case header.UDPProtocolNumber:
		port = header.UDP(pkt.TransportHeader().Slice()).SourcePort()
	case header.TCPProtocolNumber:
		port = header.TCP(pkt.TransportHeader().Slice()).SourcePort()
	}

	if port != 0 {
		portsOrIdents = targetPortRangeForTCPAndUDP(port)
	}

	return cn.ConfigureNAT(portsOrIdents, tcpip.Address{}, natType, true, false)
}

func (cn *conn) configureMasquerade(pkt *PacketBuffer, route *Route, stk *Stack, ports PortOrIdentRange, changePort bool) bool {
	srcAddr := pkt.Network().SourceAddress()
	if srcAddr == header.IPv4Any || srcAddr == header.IPv6Any {
		return false
	}
	if route == nil {
		return false
	}

	netEP, err := stk.GetNetworkEndpoint(route.NICID(), route.NetProto())
	if err != nil {
		return false
	}

	addressEP, ok := netEP.(AddressableEndpoint)
	if !ok {
		return false
	}

	nh := route.NextHop()
	if nh.Len() == 0 {
		nh = pkt.Network().DestinationAddress()
	}

	ep := addressEP.AcquireOutgoingPrimaryAddress(nh, tcpip.Address{}, false)
	if ep == nil {
		return false
	}
	address := ep.AddressWithPrefix().Address
	ep.DecRef()

	return cn.ConfigureNAT(ports, address, SNAT, changePort, true)
}
