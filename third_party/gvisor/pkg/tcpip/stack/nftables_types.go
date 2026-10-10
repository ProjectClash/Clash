// Copyright 2025 The gVisor Authors.
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
)

type NFTablesInterface interface {
	CheckPrerouting(pkt *PacketBuffer, route *Route, af AddressFamily) bool
	CheckInput(pkt *PacketBuffer, route *Route, af AddressFamily) bool
	CheckForward(pkt *PacketBuffer, route *Route, af AddressFamily) bool
	CheckOutput(pkt *PacketBuffer, route *Route, af AddressFamily) bool
	CheckPostrouting(pkt *PacketBuffer, route *Route, af AddressFamily) bool
	CheckIngress(pkt *PacketBuffer, route *Route, af AddressFamily) bool
	CheckEgress(pkt *PacketBuffer, route *Route, af AddressFamily) bool
}

type NFHook uint16

const (
	NFPrerouting NFHook = iota

	NFInput

	NFForward

	NFOutput

	NFPostrouting

	NFIngress

	NFEgress

	NFNumHooks
)

var hookStrings = map[NFHook]string{
	NFPrerouting:  "Prerouting",
	NFInput:       "Input",
	NFForward:     "Forward",
	NFOutput:      "Output",
	NFPostrouting: "Postrouting",
	NFIngress:     "Ingress",
	NFEgress:      "Egress",
}

func (h NFHook) String() string {
	if hook, ok := hookStrings[h]; ok {
		return hook
	}
	panic(fmt.Sprintf("invalid NFHook: %d", int(h)))
}

type AddressFamily int

const (
	Unspec AddressFamily = iota

	IP

	IP6

	Inet

	Arp

	Bridge

	Netdev

	NumAFs
)

var AddressFamilyStrings = map[AddressFamily]string{
	Unspec: "UNSPEC",
	IP:     "IPv4",
	IP6:    "IPv6",
	Inet:   "Internet (Both IPv4/IPv6)",
	Arp:    "ARP",
	Bridge: "Bridge",
	Netdev: "Netdev",
}

func ValidateAddressFamily(family AddressFamily) error {
	if family < 1 || family >= NumAFs {
		return fmt.Errorf("invalid address family: %d", int(family))
	}
	return nil
}

func (f AddressFamily) String() string {
	if af, ok := AddressFamilyStrings[f]; ok {
		return af
	}
	panic(fmt.Sprintf("invalid address family: %d", int(f)))
}
