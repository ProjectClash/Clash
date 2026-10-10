package gvisorinterop_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

func TestIPv4BroadcastInterop(t *testing.T) {
	for _, target := range []netip.Addr{
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("192.0.2.255"),
	} {
		target := target
		family := interopFamilies[0]
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(target.String()+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()

				const (
					mipstackPort = 43001
					gvisorPort   = 43002
				)
				mipstackConnection, err := network.mipstack.ListenUDP(ctx, "udp4", netipAddrPort(netip.IPv4Unspecified(), mipstackPort))
				if err != nil {
					t.Fatalf("listen with mipstack broadcast socket: %v", err)
				}
				defer mipstackConnection.Close()

				gvisorConnection := newGVisorUDPSocket(t, network, ipv4.ProtocolNumber, tcpip.FullAddress{NIC: interopNIC, Port: gvisorPort}, func(endpoint tcpip.Endpoint) {
					endpoint.SocketOptions().SetBroadcast(true)
				})
				defer gvisorConnection.Close()
				setPacketDeadlines(t, mipstackConnection, gvisorConnection)

				storage := make([]byte, 65535)
				for index, size := range []int{67, fragmentedInteropPayloadSize(mtu, 12_000)} {
					request := patternedPayload(size, byte(181+index))
					written, err := gvisorConnection.WriteTo(request, net.UDPAddrFromAddrPort(netipAddrPort(target, mipstackPort)))
					if err != nil || written != len(request) {
						t.Fatalf("write gVisor broadcast: n=%d, error=%v", written, err)
					}
					read, _, err := mipstackConnection.ReadFrom(storage)
					if err != nil || !bytes.Equal(storage[:read], request) {
						t.Fatalf("read mipstack broadcast: n=%d, error=%v", read, err)
					}

					response := patternedPayload(size+19, byte(197+index))
					written, err = mipstackConnection.WriteTo(response, net.UDPAddrFromAddrPort(netipAddrPort(target, gvisorPort)))
					if err != nil || written != len(response) {
						t.Fatalf("write mipstack broadcast: n=%d, error=%v", written, err)
					}
					read, _, err = gvisorConnection.ReadFrom(storage)
					if err != nil || !bytes.Equal(storage[:read], response) {
						t.Fatalf("read gVisor broadcast: n=%d, error=%v", read, err)
					}
				}
			})
		}
	}
}

func TestMulticastInterop(t *testing.T) {
	groups := []netip.Addr{
		netip.MustParseAddr("239.192.0.1"),
		netip.MustParseAddr("ff05::1234"),
	}
	for index, family := range interopFamilies {
		family := family
		group := groups[index]
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				const port = 43101

				mipstackConnection, err := network.mipstack.ListenMulticastUDP(ctx, family.udpNetwork, netipAddrPort(group, port))
				if err != nil {
					t.Fatalf("join multicast with mipstack: %v", err)
				}
				defer mipstackConnection.Close()

				gvisorConnection := newGVisorUDPSocket(t, network, family.networkProtocol, tcpip.FullAddress{NIC: interopNIC, Port: port}, func(endpoint tcpip.Endpoint) {
					endpoint.SocketOptions().SetMulticastLoop(false)
					membership := tcpip.AddMembershipOption{
						NIC:           interopNIC,
						MulticastAddr: gvisorAddress(group),
					}
					if tcpipErr := endpoint.SetSockOpt(&membership); tcpipErr != nil {
						t.Fatalf("join multicast with gVisor: %s", tcpipErr.String())
					}
				})
				defer gvisorConnection.Close()
				setPacketDeadlines(t, mipstackConnection, gvisorConnection)

				groupAddress := net.UDPAddrFromAddrPort(netipAddrPort(group, port))
				storage := make([]byte, 65535)
				for payloadIndex, size := range []int{101, fragmentedInteropPayloadSize(mtu, 12_000)} {
					request := patternedPayload(size, byte(211+index+payloadIndex))
					written, err := gvisorConnection.WriteTo(request, groupAddress)
					if err != nil || written != len(request) {
						t.Fatalf("write gVisor multicast: n=%d, error=%v", written, err)
					}
					read, _, err := mipstackConnection.ReadFrom(storage)
					if err != nil || !bytes.Equal(storage[:read], request) {
						t.Fatalf("read mipstack multicast: n=%d, error=%v", read, err)
					}

					response := patternedPayload(size+19, byte(227+index+payloadIndex))
					written, err = mipstackConnection.WriteTo(response, groupAddress)
					if err != nil || written != len(response) {
						t.Fatalf("write mipstack multicast: n=%d, error=%v", written, err)
					}
					read, _, err = gvisorConnection.ReadFrom(storage)
					if err != nil || !bytes.Equal(storage[:read], response) {
						t.Fatalf("read gVisor multicast: n=%d, error=%v", read, err)
					}
				}
			})
		}
	}
}

func TestMulticastSourceFilterInterop(t *testing.T) {
	groups := []netip.Addr{
		netip.MustParseAddr("232.1.2.3"),
		netip.MustParseAddr("ff3e::1234"),
	}
	secondarySources := []netip.Addr{
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("2001:db8::3"),
	}
	for index, family := range interopFamilies {
		family := family
		group := groups[index]
		secondarySource := secondarySources[index]
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			if tcpipErr := network.gvisor.AddProtocolAddress(interopNIC, tcpip.ProtocolAddress{
				Protocol: family.networkProtocol,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address: gvisorAddress(secondarySource), PrefixLen: family.prefixBits,
				},
			}, stack.AddressProperties{}); tcpipErr != nil {
				t.Fatalf("add secondary gVisor multicast source: %s", tcpipErr.String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			const (
				listenerPort  = 43201
				primaryPort   = 43202
				secondaryPort = 43203
			)
			packetConnection, err := network.mipstack.ListenUDP(ctx, family.udpNetwork, netipAddrPort(netip.Addr{}, listenerPort))
			if err != nil {
				t.Fatalf("listen with mipstack SSM socket: %v", err)
			}
			listener := packetConnection.(*mipstack.UDPConn)
			defer listener.Close()
			if err = listener.JoinSourceSpecificGroup(group, family.gvisorAddress); err != nil {
				t.Fatalf("join mipstack source-specific multicast group: %v", err)
			}
			primary := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, primaryPort), func(tcpip.Endpoint) {})
			defer primary.Close()
			secondary := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(secondarySource, secondaryPort), func(tcpip.Endpoint) {})
			defer secondary.Close()
			if err = listener.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
				t.Fatalf("set mipstack SSM deadline: %v", err)
			}
			target := net.UDPAddrFromAddrPort(netipAddrPort(group, listenerPort))
			storage := make([]byte, 256)

			firstBlocked := []byte("secondary-source-blocked")
			if written, writeErr := secondary.WriteTo(firstBlocked, target); writeErr != nil || written != len(firstBlocked) {
				t.Fatalf("write blocked secondary multicast source: n=%d, error=%v", written, writeErr)
			}
			firstAllowed := []byte("primary-source-allowed")
			if written, writeErr := primary.WriteTo(firstAllowed, target); writeErr != nil || written != len(firstAllowed) {
				t.Fatalf("write allowed primary multicast source: n=%d, error=%v", written, writeErr)
			}
			read, source, err := listener.ReadFrom(storage)
			if err != nil || requireAddrPort(t, source).Addr() != family.gvisorAddress || !bytes.Equal(storage[:read], firstAllowed) {
				t.Fatalf("read primary source-filter datagram: n=%d, source=%v, error=%v", read, source, err)
			}

			if err = listener.SetMulticastSourceFilter(group, mipstack.MulticastSourceFilter{
				Mode: mipstack.MulticastSourceFilterInclude, Sources: []netip.Addr{secondarySource},
			}); err != nil {
				t.Fatalf("replace mipstack multicast source filter: %v", err)
			}
			secondBlocked := []byte("primary-source-blocked")
			if written, writeErr := primary.WriteTo(secondBlocked, target); writeErr != nil || written != len(secondBlocked) {
				t.Fatalf("write blocked primary multicast source: n=%d, error=%v", written, writeErr)
			}
			secondAllowed := []byte("secondary-source-allowed")
			if written, writeErr := secondary.WriteTo(secondAllowed, target); writeErr != nil || written != len(secondAllowed) {
				t.Fatalf("write allowed secondary multicast source: n=%d, error=%v", written, writeErr)
			}
			read, source, err = listener.ReadFrom(storage)
			if err != nil || requireAddrPort(t, source).Addr() != secondarySource || !bytes.Equal(storage[:read], secondAllowed) {
				t.Fatalf("read replaced source-filter datagram: n=%d, source=%v, error=%v", read, source, err)
			}
		})
	}
}

func newGVisorUDPSocket(t *testing.T, network *interopNetwork, networkProtocol tcpip.NetworkProtocolNumber, local tcpip.FullAddress, configure func(tcpip.Endpoint)) *gonet.UDPConn {
	t.Helper()
	var queue waiter.Queue
	endpoint, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, networkProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor UDP endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Bind(local); tcpipErr != nil {
		endpoint.Close()
		t.Fatalf("bind gVisor UDP endpoint: %s", tcpipErr.String())
	}
	configure(endpoint)
	return gonet.NewUDPConn(&queue, endpoint)
}

func setPacketDeadlines(t *testing.T, first, second net.PacketConn) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	if err := first.SetDeadline(deadline); err != nil {
		t.Fatalf("set first packet deadline: %v", err)
	}
	if err := second.SetDeadline(deadline); err != nil {
		t.Fatalf("set second packet deadline: %v", err)
	}
}
