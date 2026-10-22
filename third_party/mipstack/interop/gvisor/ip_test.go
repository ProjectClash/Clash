package gvisorinterop_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

func TestRawIPInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				testRawIP(t, network, family, mtu)
			})
		}
	}
}

func TestIPUnconnectedClosedPortErrorInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			observed := make(chan []byte, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					parsed, err := mipstack.ParseIPPacket(packet)
					if err != nil || parsed.Protocol != mipstack.ProtocolICMPv4 && parsed.Protocol != mipstack.ProtocolICMPv6 {
						return true
					}
					select {
					case observed <- append([]byte(nil), packet...):
					default:
					}
					return true
				},
			})
			rawNetwork := "ip4:udp"
			if family.mipstackAddress.Is6() {
				rawNetwork = "ip6:udp"
			}
			packetConnection, err := network.mipstack.ListenIP(context.Background(), rawNetwork, family.mipstackAddress)
			if err != nil {
				t.Fatal(err)
			}
			connection := packetConnection.(*mipstack.IPConn)
			defer connection.Close()
			if err = connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			closed := netipAddrPort(family.gvisorAddress, 44996)
			outgoing := mipstack.UDPDatagram{
				Source: netipAddrPort(family.mipstackAddress, 44995), Destination: closed, Payload: []byte{1},
			}
			wire, err := outgoing.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if n, writeErr := connection.WriteTo(wire, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || n != len(wire) {
				t.Fatalf("raw UDP write to closed gVisor port = %d, %v", n, writeErr)
			}
			var response []byte
			select {
			case response = <-observed:
			case <-time.After(3 * time.Second):
				t.Fatal("gVisor did not emit Port Unreachable for raw UDP")
			}
			packet, err := mipstack.ParseIPPacket(response)
			if err != nil || packet.Source != family.gvisorAddress || packet.Destination != family.mipstackAddress {
				t.Fatalf("gVisor ICMP packet = %+v, %v", packet, err)
			}
			message, err := packet.ICMPMessage()
			if err != nil {
				t.Fatal(err)
			}
			networkError, err := message.ICMPError()
			if err != nil || networkError.QuotedSource != family.mipstackAddress || networkError.QuotedTarget != family.gvisorAddress ||
				networkError.QuotedProtocol != mipstack.ProtocolUDP ||
				networkError.QuotedSourcePort != outgoing.Source.Port() || networkError.QuotedTargetPort != closed.Port() {
				t.Fatalf("gVisor Port Unreachable quote = %+v, %v", networkError, err)
			}
			if family.mipstackAddress.Is4() {
				if networkError.Type != mipstack.ICMPv4TypeDestinationUnreachable || networkError.Code != mipstack.ICMPv4DestinationUnreachableCodePort {
					t.Fatalf("gVisor IPv4 error type/code = %d/%d", networkError.Type, networkError.Code)
				}
			} else if networkError.Type != mipstack.ICMPv6TypeDestinationUnreachable || networkError.Code != mipstack.ICMPv6DestinationUnreachableCodePort {
				t.Fatalf("gVisor IPv6 error type/code = %d/%d", networkError.Type, networkError.Code)
			}

			sink, err := network.mipstack.ListenUDP(context.Background(), family.udpNetwork, netipAddrPort(family.mipstackAddress, 44998))
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, 44997), func(tcpip.Endpoint) {})
			defer peer.Close()
			if _, err = peer.WriteTo([]byte{2}, net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, 44998))); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			n, source, readErr := connection.ReadFrom(buffer)
			if readErr != nil || source == nil || source.String() != family.gvisorAddress.String() {
				t.Fatalf("raw IP read after gVisor ICMP = %d, %v, %v", n, source, readErr)
			}
			received, err := (mipstack.IPPacket{
				Source: family.gvisorAddress, Destination: family.mipstackAddress,
				Protocol: mipstack.ProtocolUDP, Payload: buffer[:n],
			}).UDPDatagram()
			if err != nil || received.Source != netipAddrPort(family.gvisorAddress, 44997) ||
				received.Destination != netipAddrPort(family.mipstackAddress, 44998) || !bytes.Equal(received.Payload, []byte{2}) {
				t.Fatalf("raw IP UDP datagram after ICMP = %+v, %v", received, err)
			}
			if count, readErr := connection.ReadBatch([]mipstack.SocketMessage{{Buffers: [][]byte{buffer}}}, mipstack.MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("raw IP read after payload = %d, %v", count, readErr)
			}
			if queued, readErr := connection.ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("default IP error queue = %+v, %v", queued, readErr)
			}
			if info := connection.Info(); info.ErrorQueueEntries != 0 || info.ICMPErrors != 0 || info.LastError != nil {
				t.Fatalf("default unconnected IP retained ICMP error: %+v", info)
			}

			if err = connection.SetReceiveErrors(true); err != nil {
				t.Fatal(err)
			}
			enabledClosed := netipAddrPort(family.gvisorAddress, 44999)
			outgoing.Destination = enabledClosed
			wire, err = outgoing.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if n, writeErr := connection.WriteTo(wire, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || n != len(wire) {
				t.Fatalf("raw UDP write with error reception enabled = %d, %v", n, writeErr)
			}
			select {
			case <-observed:
			case <-time.After(3 * time.Second):
				t.Fatal("gVisor did not emit Port Unreachable with IP error reception enabled")
			}
			if err = connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, _, readErr := connection.ReadFrom(buffer); n != 0 || readErr == nil {
				t.Fatalf("raw IP ordinary pending error = %d, %v", n, readErr)
			} else {
				var pending mipstack.ICMPError
				if !errors.Is(readErr, syscall.ECONNREFUSED) || !errors.As(readErr, &pending) || pending.QuotedTarget != family.gvisorAddress || pending.QuotedTargetPort != enabledClosed.Port() {
					t.Fatalf("raw IP ordinary error lost its quote: %v", readErr)
				}
			}
			if _, err = peer.WriteTo([]byte{4}, net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, 44998))); err != nil {
				t.Fatal(err)
			}
			n, source, readErr = connection.ReadFrom(buffer)
			if readErr != nil || source == nil || source.String() != family.gvisorAddress.String() {
				t.Fatalf("raw IP read with error reception enabled = %d, %v, %v", n, source, readErr)
			}
			received, err = (mipstack.IPPacket{
				Source: family.gvisorAddress, Destination: family.mipstackAddress,
				Protocol: mipstack.ProtocolUDP, Payload: buffer[:n],
			}).UDPDatagram()
			if err != nil || received.Source != netipAddrPort(family.gvisorAddress, 44997) ||
				received.Destination != netipAddrPort(family.mipstackAddress, 44998) || !bytes.Equal(received.Payload, []byte{4}) {
				t.Fatalf("raw IP UDP datagram with error reception enabled = %+v, %v", received, err)
			}
			reported, readErr := connection.ReadError()
			var reportedError mipstack.ICMPError
			if readErr != nil || !errors.Is(reported, syscall.ECONNREFUSED) || !errors.As(reported, &reportedError) ||
				reportedError.QuotedSource != family.mipstackAddress || reportedError.QuotedTarget != family.gvisorAddress ||
				reportedError.QuotedProtocol != mipstack.ProtocolUDP ||
				reportedError.QuotedSourcePort != outgoing.Source.Port() || reportedError.QuotedTargetPort != enabledClosed.Port() ||
				reportedError.Type != networkError.Type || reportedError.Code != networkError.Code {
				t.Fatalf("enabled unconnected IP error = %+v, %v", reported, readErr)
			}
		})
	}
}

func TestIPConnectedClosedPortErrorInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			rawNetwork := "ip4:udp"
			if family.mipstackAddress.Is6() {
				rawNetwork = "ip6:udp"
			}
			connection, err := network.mipstack.DialIP(context.Background(), rawNetwork, family.mipstackAddress, family.gvisorAddress)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ipConnection := connection.(*mipstack.IPConn)
			if err = ipConnection.SetReceiveErrors(true); err != nil {
				t.Fatal(err)
			}
			closed := netipAddrPort(family.gvisorAddress, 44996)
			outgoing := mipstack.UDPDatagram{
				Source: netipAddrPort(family.mipstackAddress, 44995), Destination: closed, Payload: []byte{7},
			}
			wire, err := outgoing.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if n, writeErr := connection.Write(wire); n != len(wire) || writeErr != nil {
				t.Fatalf("connected raw UDP write = %d, %v", n, writeErr)
			}
			if n, readErr := connection.Read(make([]byte, 64)); n != 0 || readErr == nil {
				t.Fatalf("connected raw IP ordinary error = %d, %v", n, readErr)
			} else {
				var networkError mipstack.ICMPError
				if !errors.As(readErr, &networkError) || networkError.QuotedSourcePort != outgoing.Source.Port() || networkError.QuotedTargetPort != closed.Port() {
					t.Fatalf("connected raw IP ordinary error lost its quote: %v", readErr)
				}
			}
			queued, readErr := ipConnection.ReadError()
			var networkError mipstack.ICMPError
			if readErr != nil || !errors.As(queued, &networkError) ||
				networkError.QuotedSource != family.mipstackAddress || networkError.QuotedTarget != family.gvisorAddress ||
				networkError.QuotedSourcePort != outgoing.Source.Port() || networkError.QuotedTargetPort != closed.Port() {
				t.Fatalf("connected raw IP extended error = %v, %v", queued, readErr)
			}
		})
	}
}

func TestIPReadWithBufferInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			connection, err := network.mipstack.DialIP(ctx, family.rawNetwork, family.mipstackAddress, family.gvisorAddress)
			if err != nil {
				t.Fatalf("dial mipstack raw socket: %v", err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			mipstackIP := connection.(*mipstack.IPConn)

			var queue waiter.Queue
			peer, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer peer.Close()
			if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			for index, mode := range []string{"ReadWithBuffer", "ReadFromWithBuffer", "ReadFromIPWithBuffer"} {
				request := patternedPayload(29+index, byte(0x41+index))
				if written, writeErr := peer.Write(bytes.NewReader(request), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(request)) {
					t.Fatalf("gVisor raw request %s = %d, error=%s", mode, written, tcpipErrorString(writeErr))
				}
				buffer := make([]byte, len(request))
				var read int
				var source net.Addr
				var readErr error
				getBuffer := func(sizeHint int) []byte {
					if sizeHint != len(request) {
						t.Fatalf("raw IP %s size hint = %d; want %d", mode, sizeHint, len(request))
					}
					return buffer
				}
				switch mode {
				case "ReadWithBuffer":
					read, readErr = mipstackIP.ReadWithBuffer(getBuffer)
				case "ReadFromWithBuffer":
					read, source, readErr = mipstackIP.ReadFromWithBuffer(getBuffer)
				case "ReadFromIPWithBuffer":
					var address *net.IPAddr
					read, address, readErr = mipstackIP.ReadFromIPWithBuffer(getBuffer)
					source = address
				}
				if readErr != nil || !bytes.Equal(buffer[:read], request) {
					t.Fatalf("mipstack raw IP %s = n=%d source=%v error=%v", mode, read, source, readErr)
				}
				if mode != "ReadWithBuffer" {
					address, ok := source.(*net.IPAddr)
					if !ok || address == nil || !address.IP.Equal(net.IP(family.gvisorAddress.AsSlice())) {
						t.Fatalf("mipstack raw IP %s source = %#v; want %v", mode, source, family.gvisorAddress)
					}
				}

				response := patternedPayload(37+index, byte(0x81+index))
				if written, writeErr := mipstackIP.Write(response); writeErr != nil || written != len(response) {
					t.Fatalf("mipstack raw response %s = %d, %v", mode, written, writeErr)
				}
				packet, remote, endpointErr := readGVisorEndpoint(ctx, peer, notifications, 65535)
				if endpointErr != nil {
					t.Fatalf("gVisor raw response %s: %v", mode, endpointErr)
				}
				payload, stripErr := stripGVisorRawHeader(family, packet)
				if stripErr != nil || remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(payload, response) {
					t.Fatalf("gVisor raw response %s = source=%v payload=%x error=%v", mode, remote, payload, stripErr)
				}
			}
		})
	}
}

func TestIPConnectedWriteBatchInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				connection, err := network.mipstack.DialIP(ctx, family.rawNetwork, family.mipstackAddress, family.gvisorAddress)
				if err != nil {
					t.Fatalf("dial connected mipstack IP socket: %v", err)
				}
				defer connection.Close()
				if err = connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}

				var queue waiter.Queue
				peer, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
				}
				defer peer.Close()
				if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
					t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
				}
				if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
					t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)

				payloads := [][]byte{
					patternedPayload(29, 0x71),
					patternedPayload(911, 0x91),
				}
				messages := []mipstack.SocketMessage{
					{Buffers: [][]byte{payloads[0]}},
					{Buffers: [][]byte{payloads[1][:19], payloads[1][19:]}},
				}
				count, err := connection.(*mipstack.IPConn).WriteBatch(messages, 0)
				if err != nil || count != len(messages) {
					t.Fatalf("connected IP WriteBatch = %d, %v", count, err)
				}
				for index, payload := range payloads {
					wire, remote, readErr := readGVisorEndpoint(ctx, peer, notifications, 65535)
					if readErr != nil {
						t.Fatalf("read gVisor IP batch message %d: %v", index, readErr)
					}
					wire, readErr = stripGVisorRawHeader(family, wire)
					if readErr != nil || remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(wire, payload) {
						t.Fatalf("gVisor IP batch message %d = n=%d source=%v error=%v", index, len(wire), remote, readErr)
					}
					if messages[index].N != len(payload) || messages[index].NN != 0 || messages[index].Flags != 0 {
						t.Fatalf("connected IP batch result %d = %+v", index, messages[index])
					}
				}
			})
		}
	}
}

func TestIPHeaderIncludedStoppedDeviceReadInterop(t *testing.T) {
	family := interopFamilies[1]
	bridgeStopped := make(chan struct{})
	releaseBridge := make(chan struct{})
	var bridgeArmed atomic.Bool
	var stopOnce, releaseOnce sync.Once
	network := newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: 1500,
		ip: mipstack.IPSocketDefaults{
			IPHeaderIncludedOnRead:  true,
			IPHeaderIncludedOnWrite: true,
		},
		mipstackToGVisor: func([]byte) bool {
			if bridgeArmed.Load() {
				stopOnce.Do(func() {
					close(bridgeStopped)
					<-releaseBridge
				})
			}
			return true
		},
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseBridge) }) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := network.mipstack.DialIP(ctx, family.rawNetwork, family.mipstackAddress, family.gvisorAddress)
	if err != nil {
		t.Fatalf("dial complete-packet mipstack socket: %v", err)
	}
	defer connection.Close()
	if info := connection.(*mipstack.IPConn).Info(); !info.IPHeaderIncludedOnRead || !info.IPHeaderIncludedOnWrite {
		t.Fatalf("global complete-packet defaults were not inherited: %+v", info)
	}

	var queue waiter.Queue
	peer, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor complete-packet endpoint: %s", tcpipErr.String())
	}
	defer peer.Close()
	peer.SocketOptions().SetHeaderIncluded(true)
	if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		t.Fatalf("bind gVisor complete-packet endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor complete-packet endpoint: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	makePacket := func(flowLabel uint32, payload []byte) []byte {
		t.Helper()
		packet, marshalErr := (mipstack.IPPacket{
			Source: family.mipstackAddress, Destination: family.gvisorAddress,
			Protocol: int(interopRawIPProtocol), HopLimit: 37, FlowLabel: flowLabel, Payload: payload,
		}).AppendBinary(nil)
		if marshalErr != nil {
			t.Fatalf("marshal complete packet: %v", marshalErr)
		}
		return packet
	}
	bulk := makePacket(0x11111, []byte("complete-packet-pressure"))
	late := makePacket(0x22222, []byte("late-complete-packet-flow"))
	bridgeArmed.Store(true)
	if written, writeErr := connection.Write(bulk); writeErr != nil || written != len(bulk) {
		t.Fatalf("write bridge-stop complete packet: n=%d, error=%v", written, writeErr)
	}
	select {
	case <-bridgeStopped:
	case <-ctx.Done():
		t.Fatal("mipstack complete-packet bridge did not stop")
	}

	overloaded := make(chan error, 1)
	go func() {
		for write := 0; write < 2048; write++ {
			written, writeErr := connection.Write(bulk)
			if writeErr != nil {
				overloaded <- writeErr
				return
			}
			if written != len(bulk) {
				overloaded <- fmt.Errorf("short complete-packet write: %d", written)
				return
			}
		}
		overloaded <- nil
	}()
	select {
	case overloadErr := <-overloaded:
		if overloadErr != nil {
			t.Fatalf("stopped-read complete-packet overload: %v", overloadErr)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("complete-packet writes blocked while Stack.Read was stopped")
	}
	if stats := network.mipstack.Stats(); stats.OutboundQueueDrops == 0 {
		t.Fatalf("stopped-read complete-packet overload reported no outbound queue drops: %+v", stats)
	}
	if written, writeErr := connection.Write(late); writeErr != nil || written != len(late) {
		t.Fatalf("late complete-packet write: n=%d, error=%v", written, writeErr)
	}

	releaseOnce.Do(func() { close(releaseBridge) })
	foundLate := false
	for read := 0; read < 3; read++ {
		received, _, readErr := readGVisorEndpoint(ctx, peer, notifications, 1500)
		if readErr != nil {
			t.Fatalf("read recovered gVisor complete packet: %v", readErr)
		}
		if bytes.Equal(received, late) {
			foundLate = true
			break
		}
	}
	if !foundLate {
		t.Fatal("late complete-packet flow was not served after device-read recovery")
	}
}

func TestPublicIPPacketCodecInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			captured := make(chan []byte, 4)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					select {
					case captured <- append([]byte(nil), packet...):
					default:
					}
					return false
				},
			})
			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := []byte("public-ip-codec-request")
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: int(interopRawIPProtocol), HopLimit: 37, TrafficClass: 0x2e, Payload: request,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public IP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public IP packet: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			received, _, err := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if err != nil {
				t.Fatalf("read public packet in gVisor: %v", err)
			}
			received, err = stripGVisorRawHeader(family, received)
			if err != nil || !bytes.Equal(received, request) {
				t.Fatalf("gVisor raw payload = %x, %v", received, err)
			}

			response := []byte("gvisor-native-response")
			if written, writeErr := endpoint.Write(bytes.NewReader(response), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(response)) {
				t.Fatalf("write gVisor raw response: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			select {
			case responseWire := <-captured:
				parsed, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor response: %v", parseErr)
				}
				protocol, payload, upperErr := parsed.UpperLayer()
				if upperErr != nil || protocol != int(interopRawIPProtocol) || parsed.Source != family.gvisorAddress || parsed.Destination != family.mipstackAddress || !bytes.Equal(payload, response) {
					t.Fatalf("parsed gVisor response = protocol %d source %s target %s payload %x, %v", protocol, parsed.Source, parsed.Destination, payload, upperErr)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestPublicRawIPPacketCodecInterop(t *testing.T) {
	const (
		mipstackPort = 44091
		gvisorPort   = 44092
	)
	family := interopFamilies[1]
	network := newFamilyInteropNetwork(t, family, 1500)
	peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("public-raw-ip-codec-request")
	udpWire, err := (mipstack.UDPDatagram{
		Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
		Destination: netipAddrPort(family.gvisorAddress, gvisorPort),
		Payload:     payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fragment := mipstack.IPv6ExtensionHeader{
		Type: mipstack.IPv6ExtensionHeaderFragment,
		Data: []byte{0x7f, 0, 0x06, 0x12, 0x34, 0x56, 0x78},
	}
	packet := mipstack.IPPacket{
		Source: family.mipstackAddress, Destination: family.gvisorAddress,
		HopLimit: 37, TrafficClass: 0x2e,
	}
	if err = packet.SetRawIPv6ExtensionHeaders([]mipstack.IPv6ExtensionHeader{fragment}, mipstack.ProtocolUDP, udpWire); err != nil {
		t.Fatal(err)
	}
	strictWire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strictWire[41] != 0 || binary.BigEndian.Uint16(strictWire[42:44]) != 0 {
		t.Fatalf("strict IPv6 Fragment reserved fields = %x", strictWire[40:48])
	}
	wire, err := packet.AppendRawBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if wire[6] != mipstack.IPv6ExtensionHeaderFragment || wire[40] != mipstack.ProtocolUDP ||
		wire[41] != 0x7f || binary.BigEndian.Uint16(wire[42:44]) != 0x0006 {
		t.Fatalf("raw IPv6 Fragment fields = %x", wire[40:48])
	}
	if err = network.deliverToGVisor(wire); err != nil {
		t.Fatalf("deliver public raw IP packet: %v", err)
	}
	storage := make([]byte, len(payload)+64)
	read, source, err := peer.ReadFrom(storage)
	if err != nil || !bytes.Equal(storage[:read], payload) || source.String() != netipAddrPort(family.mipstackAddress, mipstackPort).String() {
		t.Fatalf("gVisor raw IPv6 delivery = n=%d source=%v error=%v", read, source, err)
	}
}

func TestPublicIPFragmentCodecInterop(t *testing.T) {
	const (
		mipstackPort = 44101
		gvisorPort   = 44102
	)
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				captured := make(chan []byte, 1024)
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: mtu,
					gvisorToMipstack: func(packet []byte) bool {
						captured <- append([]byte(nil), packet...)
						return false
					},
				})
				peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
				defer peer.Close()
				if err := peer.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
					t.Fatal(err)
				}

				request := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096), 0xa7)
				udpWire, err := (mipstack.UDPDatagram{
					Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
					Destination: netipAddrPort(family.gvisorAddress, gvisorPort), Payload: request,
				}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				packet := mipstack.IPPacket{
					Source: family.mipstackAddress, Destination: family.gvisorAddress,
					Protocol: mipstack.ProtocolUDP, HopLimit: 41, TrafficClass: 0x2e, Payload: udpWire,
				}
				if family.mipstackAddress.Is4() {
					packet.Identification = 0x5317
					if err = packet.SetIPv4HeaderOptions([]mipstack.IPv4HeaderOption{
						{Type: mipstack.IPv4HeaderOptionNOP},
						{Type: mipstack.IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
					}); err != nil {
						t.Fatal(err)
					}
				} else {
					hop := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderHopByHop}
					atomic := mipstack.IPv6ExtensionHeader{}
					destination := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderDestination}
					if err = hop.SetOptions(nil); err != nil {
						t.Fatal(err)
					}
					if err = atomic.SetFragment(0, false, 0x10203040); err != nil {
						t.Fatal(err)
					}
					if err = destination.SetOptions(nil); err != nil {
						t.Fatal(err)
					}
					if err = packet.SetIPv6ExtensionHeaders([]mipstack.IPv6ExtensionHeader{hop, atomic, destination}, mipstack.ProtocolUDP, udpWire); err != nil {
						t.Fatal(err)
					}
				}
				fragments, err := packet.MarshalFragments(int(mtu), 0x89abcdef)
				if err != nil || len(fragments) < 2 {
					t.Fatalf("mipstack MarshalFragments = %d packets, %v", len(fragments), err)
				}
				for index, wire := range fragments {
					if len(wire) > int(mtu) {
						t.Fatalf("mipstack fragment %d length = %d, MTU %d", index, len(wire), mtu)
					}
					parsed, parseErr := mipstack.ParseIPPacket(wire)
					if parseErr != nil {
						t.Fatalf("parse mipstack fragment %d: %v", index, parseErr)
					}
					view, fragmented := parsed.Fragment()
					if !fragmented || view.Protocol != mipstack.ProtocolUDP && family.mipstackAddress.Is4() {
						t.Fatalf("mipstack fragment %d view = %+v, valid %t", index, view, fragmented)
					}
					if family.mipstackAddress.Is4() {
						options, optionsErr := parsed.IPv4HeaderOptions()
						if optionsErr != nil || !containsIPv4RouterAlert(options) {
							t.Fatalf("mipstack fragment %d copied options = %+v, %v", index, options, optionsErr)
						}
					} else if view.Protocol != mipstack.IPv6ExtensionHeaderDestination {
						t.Fatalf("mipstack IPv6 fragment %d Next Header = %d, want Destination Options", index, view.Protocol)
					}
					if err = network.deliverToGVisor(wire); err != nil {
						t.Fatalf("deliver mipstack fragment %d: %v", index, err)
					}
				}
				storage := make([]byte, len(request)+64)
				read, source, err := peer.ReadFrom(storage)
				if err != nil || !bytes.Equal(storage[:read], request) || source.String() != netipAddrPort(family.mipstackAddress, mipstackPort).String() {
					t.Fatalf("gVisor reassembly = n=%d source=%v error=%v", read, source, err)
				}

				response := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096)+17, 0xb7)
				written, err := peer.WriteTo(response, net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, mipstackPort)))
				if err != nil || written != len(response) {
					t.Fatalf("gVisor fragmented write = %d, %v", written, err)
				}
				reassembled := readGVisorPublicFragments(t, captured, family, 8*time.Second)
				datagram, err := reassembled.UDPDatagram()
				if err != nil || datagram.Source != netipAddrPort(family.gvisorAddress, gvisorPort) ||
					datagram.Destination != netipAddrPort(family.mipstackAddress, mipstackPort) || !bytes.Equal(datagram.Payload, response) {
					t.Fatalf("mipstack decoded gVisor fragments = %+v, %v", datagram, err)
				}
			})
		}
	}
}

func TestPublicIPv4RefragmentInterop(t *testing.T) {
	const (
		mtu           = 576
		mipstackPort  = 44201
		gvisorPort    = 44202
		originalSplit = 1600
	)
	family := interopFamilies[0]
	network := newFamilyInteropNetwork(t, family, mtu)
	peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
	defer peer.Close()
	if err := peer.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := patternedPayload(3203, 0xc7)
	udpWire, err := (mipstack.UDPDatagram{
		Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
		Destination: netipAddrPort(family.gvisorAddress, gvisorPort), Payload: payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	first := mipstack.IPPacket{
		Source: family.mipstackAddress, Destination: family.gvisorAddress,
		Protocol: mipstack.ProtocolUDP, HopLimit: 37, Identification: 0x7421,
		MoreFragments: true, Payload: udpWire[:originalSplit],
	}
	if err = first.SetIPv4HeaderOptions([]mipstack.IPv4HeaderOption{
		{Type: mipstack.IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
		{Type: mipstack.IPv4HeaderOptionTimestamp, Data: []byte{5, 0}},
	}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.MoreFragments = false
	second.FragmentOffset = originalSplit
	second.Payload = udpWire[originalSplit:]
	if err = second.SetIPv4HeaderOptions([]mipstack.IPv4HeaderOption{
		{Type: mipstack.IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
		{Type: mipstack.IPv4HeaderOptionNOP}, {Type: mipstack.IPv4HeaderOptionNOP},
		{Type: mipstack.IPv4HeaderOptionNOP}, {Type: mipstack.IPv4HeaderOptionNOP},
	}); err != nil {
		t.Fatal(err)
	}
	var fragments [][]byte
	for _, original := range []mipstack.IPPacket{first, second} {
		part, fragmentErr := original.MarshalFragments(mtu, 0)
		if fragmentErr != nil || len(part) < 2 {
			t.Fatalf("refragment offset %d = %d packets, %v", original.FragmentOffset, len(part), fragmentErr)
		}
		fragments = append(fragments, part...)
	}
	for index, wire := range fragments {
		parsed, parseErr := mipstack.ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatalf("parse refragment %d: %v", index, parseErr)
		}
		view, fragmented := parsed.Fragment()
		options, optionsErr := parsed.IPv4HeaderOptions()
		if !fragmented || optionsErr != nil || !containsIPv4RouterAlert(options) {
			t.Fatalf("refragment %d = %+v, options %+v, errors %t/%v", index, view, options, fragmented, optionsErr)
		}
		if view.Offset == 0 {
			if !containsIPv4Timestamp(options) {
				t.Fatal("offset-zero refragment lost its non-copied Timestamp option")
			}
		} else if containsIPv4Timestamp(options) {
			t.Fatalf("refragment at offset %d retained non-copied Timestamp", view.Offset)
		}
		if err = network.deliverToGVisor(wire); err != nil {
			t.Fatalf("deliver refragment %d: %v", index, err)
		}
	}
	storage := make([]byte, len(payload)+64)
	read, source, err := peer.ReadFrom(storage)
	if err != nil || !bytes.Equal(storage[:read], payload) || source.String() != netipAddrPort(family.mipstackAddress, mipstackPort).String() {
		t.Fatalf("gVisor refragment reassembly = n=%d source=%v error=%v", read, source, err)
	}
}

func TestPublicIPv6FragmentHeaderChainBoundaryInterop(t *testing.T) {
	const (
		mtu           = 1280
		mipstackPort  = 44301
		gvisorPort    = 44302
		headerDataLen = 1223
	)
	family := interopFamilies[1]
	network := newFamilyInteropNetwork(t, family, mtu)
	peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
	defer peer.Close()
	if err := peer.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := patternedPayload(2003, 0xd7)
	udpWire, err := (mipstack.UDPDatagram{
		Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
		Destination: netipAddrPort(family.gvisorAddress, gvisorPort), Payload: payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	destination := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderDestination, Data: make([]byte, headerDataLen)}
	destination.Data[0] = byte((headerDataLen+1)/8 - 1)
	packet := mipstack.IPPacket{Source: family.mipstackAddress, Destination: family.gvisorAddress, HopLimit: 43}
	if err = packet.SetIPv6ExtensionHeaders([]mipstack.IPv6ExtensionHeader{destination}, mipstack.ProtocolUDP, udpWire); err != nil {
		t.Fatal(err)
	}
	fragments, err := packet.MarshalFragments(mtu, 0x31415926)
	if err != nil || len(fragments) < 2 || len(fragments[0]) != mtu {
		t.Fatalf("exact RFC 7112 boundary = %d packets, first %d bytes, %v", len(fragments), len(fragments[0]), err)
	}
	for index, wire := range fragments {
		if err = network.deliverToGVisor(wire); err != nil {
			t.Fatalf("deliver boundary fragment %d: %v", index, err)
		}
	}
	storage := make([]byte, len(payload)+64)
	read, source, err := peer.ReadFrom(storage)
	if err != nil || !bytes.Equal(storage[:read], payload) || source.String() != netipAddrPort(family.mipstackAddress, mipstackPort).String() {
		t.Fatalf("gVisor boundary reassembly = n=%d source=%v error=%v", read, source, err)
	}

	tooLarge := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderDestination, Data: make([]byte, headerDataLen+8)}
	tooLarge.Data[0] = byte((len(tooLarge.Data)+1)/8 - 1)
	if err = packet.SetIPv6ExtensionHeaders([]mipstack.IPv6ExtensionHeader{tooLarge}, mipstack.ProtocolUDP, udpWire); err != nil {
		t.Fatal(err)
	}
	if fragments, err = packet.MarshalFragments(mtu, 1); !errors.Is(err, syscall.EMSGSIZE) || fragments != nil {
		t.Fatalf("oversized RFC 7112 chain = %d packets, %v", len(fragments), err)
	}
}

func readGVisorPublicFragments(t *testing.T, captured <-chan []byte, family interopFamily, timeout time.Duration) mipstack.IPPacket {
	t.Helper()
	var reassembly mipstack.IPPacketReassembly
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case wire := <-captured:
			packet, err := mipstack.ParseIPPacket(wire)
			if err != nil || packet.Source != family.gvisorAddress || packet.Destination != family.mipstackAddress {
				continue
			}
			view, fragmented := packet.Fragment()
			if !fragmented || view.IsAtomic() {
				t.Fatalf("gVisor emitted invalid fragment: packet=%+v view=%+v valid=%t error=%v", packet, view, fragmented, err)
			}
			result, complete, addErr := reassembly.Add(packet)
			if addErr != nil {
				t.Fatalf("reassemble gVisor fragment at %d: %v", view.Offset, addErr)
			}
			if complete {
				return result
			}
		case <-timer.C:
			t.Fatal("timed out while reassembling gVisor fragments")
		}
	}
}

func containsIPv4RouterAlert(options []mipstack.IPv4HeaderOption) bool {
	for _, option := range options {
		if value, ok := option.RouterAlert(); ok && value == 0 {
			return true
		}
	}
	return false
}

func containsIPv4Timestamp(options []mipstack.IPv4HeaderOption) bool {
	for _, option := range options {
		if option.Type == mipstack.IPv4HeaderOptionTimestamp {
			return true
		}
	}
	return false
}

func TestPublicIPHeaderOptionsInterop(t *testing.T) {
	const (
		mipstackPort = 44031
		gvisorPort   = 44032
	)
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			peer := newGVisorUDPSocket(
				t, network, family.networkProtocol,
				gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {},
			)
			defer peer.Close()

			payload := []byte("public-ip-options")
			datagram := mipstack.UDPDatagram{
				Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
				Destination: netipAddrPort(family.gvisorAddress, gvisorPort),
				Payload:     payload,
			}
			udpWire, err := datagram.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public UDP datagram: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolUDP, HopLimit: 37, TrafficClass: 0x2e, Payload: udpWire,
			}
			if family.mipstackAddress.Is4() {
				routerAlert := mipstack.IPv4HeaderOption{}
				routerAlert.SetRouterAlert(0)
				if err = packet.SetIPv4HeaderOptions([]mipstack.IPv4HeaderOption{
					{Type: mipstack.IPv4HeaderOptionNOP},
					routerAlert,
				}); err != nil {
					t.Fatalf("construct public IPv4 options: %v", err)
				}
			} else {
				hopByHop := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderHopByHop}
				routerAlert := mipstack.IPv6ExtensionOption{}
				routerAlert.SetRouterAlert(0)
				if err = hopByHop.SetOptions([]mipstack.IPv6ExtensionOption{
					routerAlert,
				}); err != nil {
					t.Fatalf("construct public Hop-by-Hop options: %v", err)
				}
				destination := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderDestination}
				if err = destination.SetOptions([]mipstack.IPv6ExtensionOption{
					{Type: 0x1e, Data: []byte("opaque")},
				}); err != nil {
					t.Fatalf("construct public Destination options: %v", err)
				}
				if err = packet.SetIPv6ExtensionHeaders(
					[]mipstack.IPv6ExtensionHeader{hopByHop, destination}, mipstack.ProtocolUDP, udpWire,
				); err != nil {
					t.Fatalf("construct public IPv6 extension chain: %v", err)
				}
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public option packet: %v", err)
			}
			parsedPacket, err := mipstack.ParseIPPacket(wire)
			if err != nil {
				t.Fatalf("parse public option packet: %v", err)
			}
			if family.mipstackAddress.Is4() {
				options, parseErr := parsedPacket.IPv4HeaderOptions()
				if parseErr != nil || len(options) < 2 {
					t.Fatalf("parse public IPv4 options: %+v, %v", options, parseErr)
				}
				if value, ok := options[1].RouterAlert(); !ok || value != 0 {
					t.Fatalf("public IPv4 Router Alert = %d/%t", value, ok)
				}
			} else {
				headers, _, _, parseErr := parsedPacket.IPv6ExtensionHeaders()
				if parseErr != nil || len(headers) != 2 {
					t.Fatalf("parse public IPv6 headers: %+v, %v", headers, parseErr)
				}
				options, parseErr := headers[0].Options()
				if parseErr != nil || len(options) == 0 {
					t.Fatalf("parse public IPv6 options: %+v, %v", options, parseErr)
				}
				if value, ok := options[0].RouterAlert(); !ok || value != 0 {
					t.Fatalf("public IPv6 Router Alert = %d/%t", value, ok)
				}
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public option packet: %v", err)
			}
			if err = peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			storage := make([]byte, 64)
			read, source, err := peer.ReadFrom(storage)
			if err != nil {
				t.Fatalf("read public option packet in gVisor: %v", err)
			}
			if !bytes.Equal(storage[:read], payload) || source.String() != netipAddrPort(family.mipstackAddress, mipstackPort).String() {
				t.Fatalf("gVisor option payload/source = %q/%v", storage[:read], source)
			}
		})
	}
}

func TestIPv6RawChecksumInterop(t *testing.T) {
	family := interopFamilies[1]
	for _, mtu := range interopMTUsForFamily(family) {
		mtu := mtu
		t.Run(interopMTUName(mtu), func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, mtu)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			connection, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{
				mipstack.SocketOptions.IPv6Checksum(true, 2),
			}}).ListenIP(ctx, network.mipstack, family.rawNetwork, family.mipstackAddress)
			if err != nil {
				t.Fatalf("listen with mipstack IPv6 checksum: %v", err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatalf("set mipstack raw checksum deadline: %v", err)
			}

			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor checksummed raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.SetSockOptInt(tcpip.IPv6Checksum, 2); tcpipErr != nil {
				t.Fatalf("enable gVisor IPv6 checksum: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor checksummed raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor checksummed raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := patternedPayload(257, 0x61)
			request[2], request[3] = 0, 0
			written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write gVisor checksummed payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			storage := make([]byte, 65535)
			read, source, readErr := connection.ReadFrom(storage)
			if readErr != nil {
				t.Fatalf("read gVisor checksummed payload in mipstack: %v", readErr)
			}
			sourceAddress, valid := netip.AddrFromSlice(source.(*net.IPAddr).IP)
			if !valid || sourceAddress != family.gvisorAddress || !validIPv6RawChecksum(storage[:read], family.gvisorAddress, family.mipstackAddress, byte(interopRawIPProtocol)) {
				t.Fatalf("mipstack received invalid gVisor checksum: source=%v payload=%x", source, storage[:read])
			}
			storage[2], storage[3] = 0, 0
			if !bytes.Equal(storage[:read], request) {
				t.Fatal("gVisor checksum insertion changed bytes outside its field")
			}

			response := patternedPayload(263, 0x71)
			original := append([]byte(nil), response...)
			writtenInt, writeToErr := connection.WriteTo(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
			if writeToErr != nil || writtenInt != len(response) {
				t.Fatalf("write mipstack checksummed payload: n=%d, error=%v", writtenInt, writeToErr)
			}
			if !bytes.Equal(response, original) {
				t.Fatal("mipstack checksum insertion mutated caller payload")
			}
			packet, remote, endpointErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if endpointErr != nil {
				t.Fatalf("read mipstack checksummed payload in gVisor: %v", endpointErr)
			}
			if remote.Addr != gvisorAddress(family.mipstackAddress) || !validIPv6RawChecksum(packet, family.mipstackAddress, family.gvisorAddress, byte(interopRawIPProtocol)) {
				t.Fatalf("gVisor received invalid mipstack checksum: source=%v payload=%x", remote.Addr, packet)
			}
			packet[2], packet[3] = 0, 0
			original[2], original[3] = 0, 0
			if !bytes.Equal(packet, original) {
				t.Fatal("mipstack checksum insertion changed bytes outside its field")
			}

			testIPv6RawChecksumFragmentInterop(t, ctx, network, family, mtu)
		})
	}
}

func testIPv6RawChecksumFragmentInterop(t *testing.T, ctx context.Context, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	const (
		mipstackPort = 32101
		gvisorPort   = 32102
		udpHeaderLen = 8
	)
	connection, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{
		mipstack.SocketOptions.IPv6Checksum(true, 6),
	}}).ListenIP(ctx, network.mipstack, "ip6:udp", family.mipstackAddress)
	if err != nil {
		t.Fatalf("listen with raw UDP checksum: %v", err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set raw UDP checksum deadline: %v", err)
	}
	gvisorConnection := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
	defer gvisorConnection.Close()
	if err = gvisorConnection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set gVisor UDP checksum deadline: %v", err)
	}

	request := patternedPayload(211, 0x81)
	written, writeErr := gvisorConnection.WriteTo(request, net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, mipstackPort)))
	if writeErr != nil || written != len(request) {
		t.Fatalf("write gVisor UDP checksum request: n=%d, error=%v", written, writeErr)
	}
	storage := make([]byte, 65535)
	read, source, readErr := connection.ReadFrom(storage)
	if readErr != nil {
		t.Fatalf("read checksummed gVisor UDP payload: %v", readErr)
	}
	if read < udpHeaderLen || binary.BigEndian.Uint16(storage[0:2]) != gvisorPort ||
		binary.BigEndian.Uint16(storage[2:4]) != mipstackPort || int(binary.BigEndian.Uint16(storage[4:6])) != read ||
		!validIPv6RawChecksum(storage[:read], family.gvisorAddress, family.mipstackAddress, byte(udp.ProtocolNumber)) ||
		!bytes.Equal(storage[udpHeaderLen:read], request) {
		t.Fatalf("mipstack received invalid gVisor UDP datagram: source=%v payload=%x", source, storage[:read])
	}

	payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096)-udpHeaderLen, 0x91)
	datagram := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(datagram[0:2], mipstackPort)
	binary.BigEndian.PutUint16(datagram[2:4], gvisorPort)
	binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
	copy(datagram[udpHeaderLen:], payload)
	original := append([]byte(nil), datagram...)
	written, writeErr = connection.WriteTo(datagram, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
	if writeErr != nil || written != len(datagram) {
		t.Fatalf("write fragmented raw UDP checksum response: n=%d, error=%v", written, writeErr)
	}
	if !bytes.Equal(datagram, original) {
		t.Fatal("fragmented raw checksum insertion mutated caller payload")
	}
	read, _, readErr = gvisorConnection.ReadFrom(storage)
	if readErr != nil || !bytes.Equal(storage[:read], payload) {
		t.Fatalf("read fragmented raw UDP checksum response in gVisor: n=%d, error=%v", read, readErr)
	}
}

func TestIPDualStackWildcardInterop(t *testing.T) {
	network := newInteropNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := network.mipstack.ListenIP(ctx, "ip:99", netip.Addr{})
	if err != nil {
		t.Fatalf("listen on dual-stack raw IP wildcard: %v", err)
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set dual-stack raw IP deadline: %v", err)
	}
	storage := make([]byte, 65535)

	for index, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := patternedPayload(53+index, byte(31+index))
			written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write dual-stack raw IP request: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			read, source, readErr := listener.ReadFrom(storage)
			if readErr != nil || !bytes.Equal(storage[:read], request) {
				t.Fatalf("read dual-stack raw IP request: n=%d, source=%v, error=%v", read, source, readErr)
			}
			sourceAddress, valid := netip.AddrFromSlice(source.(*net.IPAddr).IP)
			if !valid || sourceAddress.Unmap() != family.gvisorAddress {
				t.Fatalf("dual-stack raw IP source = %v, want %v", source, family.gvisorAddress)
			}

			response := patternedPayload(79+index, byte(67+index))
			writtenInt, writeToErr := listener.WriteTo(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
			if writeToErr != nil || writtenInt != len(response) {
				t.Fatalf("write dual-stack raw IP response: n=%d, error=%v", writtenInt, writeToErr)
			}
			packet, remote, endpointErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if endpointErr != nil {
				t.Fatalf("read gVisor dual-stack raw IP response: %v", endpointErr)
			}
			payload, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			if remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(payload, response) {
				t.Fatalf("gVisor dual-stack raw IP response: source=%v, bytes=%d", remote.Addr, len(payload))
			}
		})
	}
}

func TestIPControlMessageInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			outbound := make(chan []byte, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: func(packet []byte) bool {
					copyPacket := append([]byte(nil), packet...)
					select {
					case outbound <- copyPacket:
					default:
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			connection, err := network.mipstack.ListenIP(ctx, family.rawNetwork, family.mipstackAddress)
			if err != nil {
				t.Fatalf("listen with mipstack raw IP: %v", err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
				t.Fatalf("set mipstack raw IP deadline: %v", err)
			}

			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			options := endpoint.SocketOptions()
			if family.mipstackAddress.Is4() {
				options.SetReceiveTOS(true)
				options.SetReceiveTTL(true)
				options.SetReceivePacketInfo(true)
				if tcpipErr = endpoint.SetSockOptInt(tcpip.IPv4TOSOption, 0x2e); tcpipErr == nil {
					tcpipErr = endpoint.SetSockOptInt(tcpip.IPv4TTLOption, 37)
				}
			} else {
				options.SetReceiveTClass(true)
				options.SetReceiveHopLimit(true)
				options.SetIPv6ReceivePacketInfo(true)
				if tcpipErr = endpoint.SetSockOptInt(tcpip.IPv6TrafficClassOption, 0x2e); tcpipErr == nil {
					tcpipErr = endpoint.SetSockOptInt(tcpip.IPv6HopLimitOption, 37)
				}
			}
			if tcpipErr != nil {
				t.Fatalf("configure gVisor raw IP header options: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := []byte("raw-control-request")
			written, tcpipErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if tcpipErr != nil || written != int64(len(request)) {
				t.Fatalf("write gVisor raw control request: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
			}
			payload := make([]byte, 256)
			control := make([]byte, 256)
			read, controlRead, flags, source, err := connection.(*mipstack.IPConn).ReadMsgIP(payload, control)
			if err != nil || flags != 0 || !bytes.Equal(payload[:read], request) {
				t.Fatalf("read mipstack raw control request: n=%d, oob=%d, flags=%#x, source=%v, error=%v", read, controlRead, flags, source, err)
			}
			sourceAddress, valid := netip.AddrFromSlice(source.IP)
			if !valid || sourceAddress.Unmap() != family.gvisorAddress {
				t.Fatalf("mipstack raw control source = %v, want %v", source, family.gvisorAddress)
			}
			if family.mipstackAddress.Is4() {
				var message mipstack.IPv4ControlMessage
				if err = message.Parse(control[:controlRead]); err != nil {
					t.Fatalf("parse mipstack raw IPv4 control message: %v", err)
				}
				if message.Dst != family.mipstackAddress || message.TTL != 37 || message.TOS != 0x2e {
					t.Fatalf("mipstack raw IPv4 control message = %+v", message)
				}
				if controlRead < 28 || !bytes.Equal(control[20:24], family.mipstackAddress.AsSlice()) || !bytes.Equal(control[24:28], family.mipstackAddress.AsSlice()) {
					t.Fatalf("mipstack raw IPv4 packet-info fields = %x/%x, want %s/%s", control[20:24], control[24:28], family.mipstackAddress, family.mipstackAddress)
				}
				control, err = (&mipstack.IPv4ControlMessage{TTL: 41, TOS: 0xb8}).Marshal()
			} else {
				var message mipstack.IPv6ControlMessage
				if err = message.Parse(control[:controlRead]); err != nil {
					t.Fatalf("parse mipstack raw IPv6 control message: %v", err)
				}
				if message.Dst != family.mipstackAddress || message.HopLimit != 37 || message.TrafficClass != 0x2e {
					t.Fatalf("mipstack raw IPv6 control message = %+v", message)
				}
				control, err = (&mipstack.IPv6ControlMessage{HopLimit: 41, TrafficClass: 0xb8, FlowLabel: 0x34567}).Marshal()
			}
			if err != nil {
				t.Fatalf("marshal mipstack raw control message: %v", err)
			}

			response := []byte("raw-control-response")
			writtenInt, controlWritten, err := connection.(*mipstack.IPConn).WriteMsgIP(response, control, source)
			if err != nil || writtenInt != len(response) || controlWritten != len(control) {
				t.Fatalf("write mipstack raw control response: n=%d, oob=%d, error=%v", writtenInt, controlWritten, err)
			}
			select {
			case packet := <-outbound:
				validateControlledIPHeader(t, family, packet, 41)
			case <-ctx.Done():
				t.Fatalf("capture mipstack raw control response: %v", ctx.Err())
			}
			packet, result, readErr := readGVisorEndpointResult(ctx, endpoint, notifications, 65535)
			if readErr != nil {
				t.Fatalf("read gVisor raw control response: %v", readErr)
			}
			received, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			if result.RemoteAddr.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(received, response) {
				t.Fatalf("gVisor raw control response: source=%v, bytes=%d", result.RemoteAddr, len(received))
			}
			messages := result.ControlMessages
			if family.mipstackAddress.Is4() {
				if !messages.HasTTL || messages.TTL != 41 || !messages.HasTOS || messages.TOS != 0xb8 || !messages.HasIPPacketInfo ||
					messages.PacketInfo.LocalAddr != gvisorAddress(family.gvisorAddress) || messages.PacketInfo.DestinationAddr != gvisorAddress(family.gvisorAddress) {
					t.Fatalf("gVisor raw IPv4 control messages = %+v", messages)
				}
			} else if !messages.HasHopLimit || messages.HopLimit != 41 || !messages.HasTClass || messages.TClass != 0xb8 || !messages.HasIPv6PacketInfo ||
				messages.IPv6PacketInfo.Addr != gvisorAddress(family.gvisorAddress) {
				t.Fatalf("gVisor raw IPv6 control messages = %+v", messages)
			}
		})
	}
}

func TestIPHeaderIncludedInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				config := mipstack.ListenConfig{Options: []mipstack.SocketOption{
					mipstack.SocketOptions.IPHeaderIncludedOnWrite(true),
					mipstack.SocketOptions.IPHeaderIncludedOnRead(true),
				}}
				mips, err := config.ListenIP(ctx, network.mipstack, family.rawNetwork, family.mipstackAddress)
				if err != nil {
					t.Fatalf("listen with complete-packet mipstack raw socket: %v", err)
				}
				defer mips.Close()
				if err = mips.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
					t.Fatalf("set mipstack complete-packet deadline: %v", err)
				}

				var queue waiter.Queue
				peer, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor complete-packet raw endpoint: %s", tcpipErr.String())
				}
				defer peer.Close()
				peer.SocketOptions().SetHeaderIncluded(true)
				if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
					t.Fatalf("bind gVisor complete-packet raw endpoint: %s", tcpipErr.String())
				}
				if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
					t.Fatalf("connect gVisor complete-packet raw endpoint: %s", tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)

				headerSize := header.IPv6MinimumSize
				if family.mipstackAddress.Is4() {
					headerSize = header.IPv4MinimumSize + 4
				}
				for index, sizes := range [][2]int{{19, 23}, {int(mtu) - headerSize, int(mtu) - 2*headerSize}} {
					request := buildHeaderIncludedInteropPacket(family, family.mipstackAddress, family.gvisorAddress, patternedPayload(sizes[0], byte(0xa1+index)))
					written, writeErr := mips.WriteTo(request, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
					if writeErr != nil || written != len(request) {
						t.Fatalf("write mipstack complete packet %d: n=%d, error=%v", index, written, writeErr)
					}
					received, remote, readErr := readGVisorEndpoint(ctx, peer, notifications, int(mtu))
					if readErr != nil || remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(received, request) {
						t.Fatalf("gVisor complete-packet read %d: bytes=%d, source=%v, error=%v", index, len(received), remote, readErr)
					}

					response := buildHeaderIncludedInteropPacket(family, family.gvisorAddress, family.mipstackAddress, patternedPayload(sizes[1], byte(0xb2+index)))
					written64, tcpipErr := peer.Write(bytes.NewReader(response), tcpip.WriteOptions{})
					if tcpipErr != nil || written64 != int64(len(response)) {
						t.Fatalf("write gVisor complete packet %d: n=%d, error=%s", index, written64, tcpipErrorString(tcpipErr))
					}
					storage := make([]byte, mtu)
					read, source, readErr := mips.ReadFrom(storage)
					if readErr != nil || source.String() != family.gvisorAddress.String() || !bytes.Equal(storage[:read], response) {
						t.Fatalf("mipstack complete-packet read %d: bytes=%d, source=%v, error=%v", index, read, source, readErr)
					}
				}
			})
		}
	}
}

func TestIPCompletePacketReassemblyInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				rawNetwork := "ip4:udp"
				if family.mipstackAddress.Is6() {
					rawNetwork = "ip6:udp"
				}
				config := mipstack.ListenConfig{Options: []mipstack.SocketOption{mipstack.SocketOptions.IPHeaderIncludedOnRead(true)}}
				rawConnection, err := config.ListenIP(ctx, network.mipstack, rawNetwork, family.mipstackAddress)
				if err != nil {
					t.Fatalf("listen for complete reassembled packets: %v", err)
				}
				defer rawConnection.Close()
				if err = rawConnection.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
					t.Fatalf("set complete-packet read deadline: %v", err)
				}
				const destinationPort = 45117
				udpListener, err := network.mipstack.ListenUDP(ctx, family.udpNetwork, netipAddrPort(family.mipstackAddress, destinationPort))
				if err != nil {
					t.Fatalf("listen for fragmented UDP interop: %v", err)
				}
				defer udpListener.Close()

				var queue waiter.Queue
				peer, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, family.networkProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor UDP fragment source: %s", tcpipErr.String())
				}
				defer peer.Close()
				if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
					t.Fatalf("bind gVisor UDP fragment source: %s", tcpipErr.String())
				}
				if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, destinationPort)); tcpipErr != nil {
					t.Fatalf("connect gVisor UDP fragment source: %s", tcpipErr.String())
				}
				localAddress, tcpipErr := peer.GetLocalAddress()
				if tcpipErr != nil {
					t.Fatalf("get gVisor UDP fragment source: %s", tcpipErr.String())
				}
				payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096), 0xc3)
				written, tcpipErr := peer.Write(bytes.NewReader(payload), tcpip.WriteOptions{})
				if tcpipErr != nil || written != int64(len(payload)) {
					t.Fatalf("write fragmented gVisor UDP datagram: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
				}
				packet := make([]byte, 65535)
				read, source, readErr := rawConnection.ReadFrom(packet)
				if readErr != nil || source.String() != family.gvisorAddress.String() {
					t.Fatalf("read complete reassembled packet: bytes=%d, source=%v, error=%v", read, source, readErr)
				}
				if err = validateCompleteUDPInteropPacket(family, packet[:read], localAddress.Port, destinationPort, payload); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestIPMixedECTFragmentReassemblyInterop(t *testing.T) {
	for _, family := range interopFamilies {
		for _, firstECT := range []byte{1, 2} {
			t.Run(fmt.Sprintf("%s/offset-zero-ECT-%d", family.name, firstECT), func(t *testing.T) {
				var fragmentCount atomic.Uint32
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1280,
					gvisorToMipstack: func(packet []byte) bool {
						offset, fragmented := ipFragmentOffset(packet)
						if !fragmented {
							return true
						}
						ecn := firstECT
						if offset != 0 {
							ecn = 3 - firstECT
						}
						if family.gvisorAddress.Is4() {
							ip := header.IPv4(packet)
							ip.SetTOS(0x28|ecn, 0)
							ip.SetChecksum(0)
							ip.SetChecksum(^ip.CalculateChecksum())
						} else {
							header.IPv6(packet).SetTOS(0x28|ecn, 0)
						}
						fragmentCount.Add(1)
						return true
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				rawNetwork := "ip4:udp"
				if family.mipstackAddress.Is6() {
					rawNetwork = "ip6:udp"
				}
				config := mipstack.ListenConfig{Options: []mipstack.SocketOption{mipstack.SocketOptions.IPHeaderIncludedOnRead(true)}}
				rawConnection, err := config.ListenIP(ctx, network.mipstack, rawNetwork, family.mipstackAddress)
				if err != nil {
					t.Fatal(err)
				}
				defer rawConnection.Close()
				_ = rawConnection.SetDeadline(time.Now().Add(5 * time.Second))
				connection, peer := openUDPPair(t, ctx, network, family, false)
				defer connection.Close()
				defer peer.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				payload := patternedPayload(4096, 0xc3)
				if n, err := connection.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("native gVisor fragmented write = %d, %v", n, err)
				}
				var packet [65535]byte
				read, _, err := rawConnection.ReadFrom(packet[:])
				if err != nil {
					t.Fatal(err)
				}
				if err := validateCompleteUDPInteropPacket(family, packet[:read], requireAddrPort(t, connection.LocalAddr()).Port(), requireAddrPort(t, peer.LocalAddr()).Port(), payload); err != nil {
					t.Fatal(err)
				}
				class, _ := header.IPv4(packet[:read]).TOS()
				if family.gvisorAddress.Is6() {
					class, _ = header.IPv6(packet[:read]).TOS()
				}
				if class != 0x28|firstECT || fragmentCount.Load() < 2 {
					t.Fatalf("reassembled class %d, fragment count %d; want %d and multiple fragments", class, fragmentCount.Load(), 0x28|firstECT)
				}
				read, source, err := peer.ReadFrom(packet[:])
				if err != nil || !bytes.Equal(packet[:read], payload) {
					t.Fatalf("mipstack UDP reassembly = %d, %v", read, err)
				}
				if n, err := peer.WriteTo(packet[:read], source); err != nil || n != len(payload) {
					t.Fatalf("mipstack UDP reply = %d, %v", n, err)
				}
				if read, err := connection.Read(packet[:]); err != nil || !bytes.Equal(packet[:read], payload) {
					t.Fatalf("native gVisor UDP reply = %d, %v", read, err)
				}
			})
		}
	}
}

func buildHeaderIncludedInteropPacket(family interopFamily, source, target netip.Addr, payload []byte) []byte {
	if source.Is4() {
		packet := make([]byte, header.IPv4MinimumSize+4+len(payload))
		packet[0], packet[1], packet[8], packet[9] = 0x46, 0x2e, 37, byte(interopRawIPProtocol)
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], 0x4321)
		copy(packet[12:16], source.AsSlice())
		copy(packet[16:20], target.AsSlice())
		copy(packet[20:24], []byte{1, 1, 0, 0})
		copy(packet[24:], payload)
		binary.BigEndian.PutUint16(packet[10:12], ^checksum.Checksum(packet[:24], 0))
		return packet
	}
	packet := make([]byte, header.IPv6MinimumSize+len(payload))
	packet[0], packet[1], packet[2], packet[3] = 0x6a, 0x55, 0x43, 0x21
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6], packet[7] = byte(interopRawIPProtocol), 37
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], target.AsSlice())
	copy(packet[40:], payload)
	return packet
}

func validateCompleteUDPInteropPacket(family interopFamily, packet []byte, sourcePort, targetPort uint16, payload []byte) error {
	offset := 0
	if family.mipstackAddress.Is4() {
		if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
			return errors.New("reassembled IPv4 packet has no valid base header")
		}
		offset = int(packet[0]&0x0f) * 4
		if offset < header.IPv4MinimumSize || offset > len(packet) || packet[9] != byte(udp.ProtocolNumber) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return errors.New("reassembled IPv4 packet retained invalid fragmentation state")
		}
	} else {
		if len(packet) < header.IPv6MinimumSize || packet[0]>>4 != 6 || packet[6] != byte(udp.ProtocolNumber) {
			return errors.New("reassembled IPv6 packet retained an extension or fragment header")
		}
		offset = header.IPv6MinimumSize
	}
	if len(packet)-offset != header.UDPMinimumSize+len(payload) {
		return errors.New("reassembled UDP packet has an unexpected length")
	}
	udpHeader := header.UDP(packet[offset : offset+header.UDPMinimumSize])
	if udpHeader.SourcePort() != sourcePort || udpHeader.DestinationPort() != targetPort || !bytes.Equal(packet[offset+header.UDPMinimumSize:], payload) {
		return errors.New("reassembled UDP packet tuple or payload mismatch")
	}
	return nil
}

func testRawIP(t *testing.T, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mipstackConnection, err := network.mipstack.ListenIP(ctx, family.rawNetwork, family.mipstackAddress)
	if err != nil {
		t.Fatalf("listen with mipstack IP socket: %v", err)
	}
	defer mipstackConnection.Close()
	if err = mipstackConnection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set mipstack IP deadline: %v", err)
	}

	var queue waiter.Queue
	gvisorEndpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor raw IP endpoint: %s", tcpipErr.String())
	}
	defer gvisorEndpoint.Close()
	if tcpipErr = gvisorEndpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		t.Fatalf("bind gVisor raw IP endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = gvisorEndpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor raw IP endpoint: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	storage := make([]byte, 65535)
	maximumPayload := rawInteropPayloadCapacity(family, mtu)
	cases := []struct {
		requestSize  int
		responseSize int
	}{
		{requestSize: 17, responseSize: 23},
		{requestSize: maximumPayload - 7, responseSize: maximumPayload},
	}
	for index, testCase := range cases {
		request := patternedPayload(testCase.requestSize, byte(113+index))
		written, writeErr := gvisorEndpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
		if writeErr != nil || written != int64(len(request)) {
			t.Fatalf("write gVisor raw IP payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
		}
		read, source, readErr := mipstackConnection.ReadFrom(storage)
		if readErr != nil {
			t.Fatalf("read mipstack raw IP payload: %v", readErr)
		}
		sourceAddress, validSource := netip.AddrFromSlice(source.(*net.IPAddr).IP)
		if !validSource || sourceAddress.Unmap() != family.gvisorAddress || !bytes.Equal(storage[:read], request) {
			t.Fatalf("mipstack raw IP request mismatch: source=%v, bytes=%d", source, read)
		}

		response := patternedPayload(testCase.responseSize, byte(149+index))
		writtenInt, writeToErr := mipstackConnection.WriteTo(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
		if writeToErr != nil || writtenInt != len(response) {
			t.Fatalf("write mipstack raw IP payload: n=%d, error=%v", writtenInt, writeToErr)
		}
		packet, remote, endpointErr := readGVisorEndpoint(ctx, gvisorEndpoint, notifications, 65535)
		if endpointErr != nil {
			stats := network.gvisor.Stats().IP
			t.Fatalf("read gVisor raw IP payload: %v (received=%d valid=%d delivered=%d malformed=%d malformed-fragments=%d)", endpointErr,
				stats.PacketsReceived.Value(), stats.ValidPacketsReceived.Value(), stats.PacketsDelivered.Value(),
				stats.MalformedPacketsReceived.Value(), stats.MalformedFragmentsReceived.Value())
		}
		payload, stripErr := stripGVisorRawHeader(family, packet)
		if stripErr != nil {
			t.Fatal(stripErr)
		}
		if remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(payload, response) {
			prefix := len(payload)
			if prefix > 16 {
				prefix = 16
			}
			wantPrefix := len(response)
			if wantPrefix > 16 {
				wantPrefix = 16
			}
			t.Fatalf("gVisor raw IP response mismatch: source=%v, bytes=%d, prefix=%x, want=%x", remote.Addr, len(payload), payload[:prefix], response[:wantPrefix])
		}
	}
}

func stripGVisorRawHeader(family interopFamily, packet []byte) ([]byte, error) {
	if family.networkProtocol == header.IPv6ProtocolNumber {
		return packet, nil
	}
	if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
		return nil, errors.New("gVisor raw IPv4 socket returned an invalid IPv4 header")
	}
	headerSize := int(packet[0]&0x0f) * 4
	if headerSize < header.IPv4MinimumSize || headerSize > len(packet) {
		return nil, errors.New("gVisor raw IPv4 socket returned an invalid header length")
	}
	return packet[headerSize:], nil
}

func validIPv6RawChecksum(payload []byte, source, target netip.Addr, protocol byte) bool {
	if len(payload) > 65535 {
		return false
	}
	sum := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(protocol), gvisorAddress(source), gvisorAddress(target), uint16(len(payload)))
	return checksum.Checksum(payload, sum) == 0xffff
}
