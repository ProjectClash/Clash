// Copyright 2019 The gVisor Authors.
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

type AcceptTarget struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (*AcceptTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleAccept, 0
}

type DropTarget struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (*DropTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleDrop, 0
}

type RejectIPv4WithHandler interface {
	SendRejectionError(pkt *PacketBuffer, rejectWith RejectIPv4WithICMPType, inputHook bool) tcpip.Error
}

type RejectIPv4WithICMPType int

const (
	_ RejectIPv4WithICMPType = iota
	RejectIPv4WithICMPNetUnreachable
	RejectIPv4WithICMPHostUnreachable
	RejectIPv4WithICMPPortUnreachable
	RejectIPv4WithICMPProtUnreachable
	RejectIPv4WithICMPEchoReply
	RejectIPv4WithICMPNetProhibited
	RejectIPv4WithICMPHostProhibited
	RejectIPv4WithTCPReset
	RejectIPv4WithICMPAdminProhibited
)

type RejectIPv4Target struct {
	Handler    RejectIPv4WithHandler
	RejectWith RejectIPv4WithICMPType
}

func (rt *RejectIPv4Target) Action(pkt *PacketBuffer, hook Hook, _ *Route, _ AddressableEndpoint) (RuleVerdict, int) {
	switch hook {
	case Input, Forward, Output:
		_ = rt.Handler.SendRejectionError(pkt, rt.RejectWith, hook == Input)
		return RuleDrop, 0
	case Prerouting, Postrouting:
		panic(fmt.Sprintf("%s hook not supported for REDIRECT", hook))
	default:
		panic(fmt.Sprintf("unhandled hook = %s", hook))
	}
}

type RejectIPv6WithHandler interface {
	SendRejectionError(pkt *PacketBuffer, rejectWith RejectIPv6WithICMPType, forwardingHook bool) tcpip.Error
}

type RejectIPv6WithICMPType int

const (
	_ RejectIPv6WithICMPType = iota
	RejectIPv6WithICMPNoRoute
	RejectIPv6WithICMPAdminProhibited
	RejectIPv6WithICMPNotNeighbour
	RejectIPv6WithICMPAddrUnreachable
	RejectIPv6WithICMPPortUnreachable
	RejectIPv6WithICMPEchoReply
	RejectIPv6WithTCPReset
	RejectIPv6WithICMPPolicyFail
	RejectIPv6WithICMPRejectRoute
)

type RejectIPv6Target struct {
	Handler    RejectIPv6WithHandler
	RejectWith RejectIPv6WithICMPType
}

func (rt *RejectIPv6Target) Action(pkt *PacketBuffer, hook Hook, _ *Route, _ AddressableEndpoint) (RuleVerdict, int) {
	switch hook {
	case Input, Forward, Output:
		_ = rt.Handler.SendRejectionError(pkt, rt.RejectWith, hook == Input)
		return RuleDrop, 0
	case Prerouting, Postrouting:
		panic(fmt.Sprintf("%s hook not supported for REDIRECT", hook))
	default:
		panic(fmt.Sprintf("unhandled hook = %s", hook))
	}
}

type ErrorTarget struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (*ErrorTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

type UserChainTarget struct {
	Name string

	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (*UserChainTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

type ReturnTarget struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (*ReturnTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleReturn, 0
}

type DNATTarget struct {
	Addr tcpip.Address

	Port uint16

	NetworkProtocol tcpip.NetworkProtocolNumber

	ChangeAddress bool

	ChangePort bool
}

func (rt *DNATTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint) (RuleVerdict, int) {
	if rt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"DNATTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			rt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	switch hook {
	case Prerouting, Output:
	case Input, Forward, Postrouting:
		panic(fmt.Sprintf("%s not supported for DNAT", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	return dnatAction(pkt, hook, r, rt.Port, rt.Addr, rt.ChangePort, rt.ChangeAddress)

}

type RedirectTarget struct {
	Port uint16

	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (rt *RedirectTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint) (RuleVerdict, int) {
	if rt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"RedirectTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			rt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	var address tcpip.Address
	switch hook {
	case Output:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			address = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
		} else {
			address = header.IPv6Loopback
		}
	case Prerouting:
		address = addressEP.MainAddress().Address
	default:
		panic("redirect target is supported only on output and prerouting hooks")
	}

	return dnatAction(pkt, hook, r, rt.Port, address, true, true)
}

type SNATTarget struct {
	Addr tcpip.Address
	Port uint16

	NetworkProtocol tcpip.NetworkProtocolNumber

	ChangeAddress bool

	ChangePort bool
}

func dnatAction(pkt *PacketBuffer, hook Hook, r *Route, port uint16, address tcpip.Address, changePort, changeAddress bool) (RuleVerdict, int) {
	return natAction(pkt, hook, r, PortOrIdentRange{Start: port, Size: 1}, address, true, changePort, changeAddress)
}

func targetPortRangeForTCPAndUDP(originalSrcPort uint16) PortOrIdentRange {
	switch {
	case originalSrcPort < 512:
		return PortOrIdentRange{Start: 1, Size: 511}
	case originalSrcPort < 1024:
		return PortOrIdentRange{Start: 1, Size: 1023}
	default:
		return PortOrIdentRange{Start: 1024, Size: math.MaxUint16 - 1023}
	}
}

func snatAction(pkt *PacketBuffer, hook Hook, r *Route, port uint16, address tcpip.Address, changePort, changeAddress bool) (RuleVerdict, int) {
	portsOrIdents := PortOrIdentRange{Start: port, Size: 1}

	switch pkt.TransportProtocolNumber {
	case header.UDPProtocolNumber:
		if port == 0 {
			portsOrIdents = targetPortRangeForTCPAndUDP(header.UDP(pkt.TransportHeader().Slice()).SourcePort())
		}
	case header.TCPProtocolNumber:
		if port == 0 {
			portsOrIdents = targetPortRangeForTCPAndUDP(header.TCP(pkt.TransportHeader().Slice()).SourcePort())
		}
	case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
		portsOrIdents = PortOrIdentRange{Start: 0, Size: math.MaxUint16 + 1}
	}

	return natAction(pkt, hook, r, portsOrIdents, address, false, changePort, changeAddress)
}

func natAction(pkt *PacketBuffer, hook Hook, r *Route, portsOrIdents PortOrIdentRange, address tcpip.Address, dnat, changePort, changeAddress bool) (RuleVerdict, int) {
	if len(pkt.NetworkHeader().Slice()) == 0 || len(pkt.TransportHeader().Slice()) == 0 {
		return RuleDrop, 0
	}

	if t := pkt.tuple; t != nil {
		IPTPerformNAT(pkt, hook, r, portsOrIdents, address, dnat, changePort, changeAddress)
		return RuleAccept, 0
	}

	return RuleDrop, 0
}

func (st *SNATTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, _ AddressableEndpoint) (RuleVerdict, int) {
	if st.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"SNATTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			st.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	switch hook {
	case Postrouting, Input:
	case Prerouting, Output, Forward:
		panic(fmt.Sprintf("%s not supported", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	return snatAction(pkt, hook, r, st.Port, st.Addr, st.ChangePort, st.ChangeAddress)
}

type MasqueradeTarget struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (mt *MasqueradeTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint) (RuleVerdict, int) {
	if mt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"MasqueradeTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			mt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	switch hook {
	case Postrouting:
	case Prerouting, Input, Forward, Output:
		panic(fmt.Sprintf("masquerade target is supported only on postrouting hook; hook = %d", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	ep := addressEP.AcquireOutgoingPrimaryAddress(pkt.Network().DestinationAddress(), tcpip.Address{}, false)
	if ep == nil {
		return RuleDrop, 0
	}

	address := ep.AddressWithPrefix().Address
	ep.DecRef()
	return snatAction(pkt, hook, r, 0, address, true, true)
}

type CTTarget struct {
	NetworkProtocol tcpip.NetworkProtocolNumber

	Zone uint16
}

func (*CTTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleAccept, 0
}
