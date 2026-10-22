package gvisorinterop_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

func TestUDPInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, mipstackConnected := range []bool{true, false} {
				mipstackConnected := mipstackConnected
				mode := "gvisor-connected"
				if mipstackConnected {
					mode = "mipstack-connected"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newFamilyInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					defer cancel()

					connected, unconnected := openUDPPair(t, ctx, network, family, mipstackConnected)
					defer connected.Close()
					defer unconnected.Close()
					exerciseUDP(t, connected, unconnected, mtu)
				})
			}
		}
	}
}

func TestUDPReadWithBufferInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()

			gvisorConnection, mipstackPacket := openUDPPair(t, ctx, network, family, false)
			defer gvisorConnection.Close()
			defer mipstackPacket.Close()
			deadline := time.Now().Add(10 * time.Second)
			if err := gvisorConnection.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := mipstackPacket.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			mipstackUDP := mipstackPacket.(*mipstack.UDPConn)
			expectedSource := gvisorConnection.LocalAddr().(*net.UDPAddr).AddrPort()
			for index, mode := range []string{"ReadFrom", "ReadFromUDP", "ReadFromUDPAddrPort"} {
				request := patternedPayload(31+index, byte(0x31+index))
				if written, err := gvisorConnection.Write(request); err != nil || written != len(request) {
					t.Fatalf("gVisor UDP request %s = %d, %v", mode, written, err)
				}
				var buffer []byte
				var source netip.AddrPort
				var read int
				var readErr error
				var address net.Addr
				getBuffer := func(sizeHint int) []byte {
					if sizeHint != len(request) {
						t.Fatalf("UDP %s size hint = %d; want %d", mode, sizeHint, len(request))
					}
					buffer = make([]byte, sizeHint)
					return buffer
				}
				switch mode {
				case "ReadFrom":
					read, address, readErr = mipstackUDP.ReadFromWithBuffer(getBuffer)
				case "ReadFromUDP":
					var typedAddress *net.UDPAddr
					read, typedAddress, readErr = mipstackUDP.ReadFromUDPWithBuffer(getBuffer)
					address = typedAddress
				case "ReadFromUDPAddrPort":
					read, source, readErr = mipstackUDP.ReadFromUDPAddrPortWithBuffer(getBuffer)
				}
				if address != nil {
					typedAddress, ok := address.(*net.UDPAddr)
					if !ok {
						t.Fatalf("mipstack UDP %s address type = %T", mode, address)
					}
					source = typedAddress.AddrPort()
				}
				if readErr != nil || !bytes.Equal(buffer[:read], request) || source != expectedSource {
					t.Fatalf("mipstack UDP %s = n=%d source=%v error=%v", mode, read, source, readErr)
				}
				response := patternedPayload(47+index, byte(0x71+index))
				if written, err := mipstackUDP.WriteToUDPAddrPort(response, source); err != nil || written != len(response) {
					t.Fatalf("mipstack UDP response %s = %d, %v", mode, written, err)
				}
				responseBuffer := make([]byte, len(response))
				if read, err := io.ReadFull(gvisorConnection, responseBuffer); err != nil || !bytes.Equal(responseBuffer[:read], response) {
					t.Fatalf("gVisor UDP response %s = n=%d error=%v", mode, read, err)
				}
			}

			mipstackConnection, gvisorPacket := openUDPPairAt(t, ctx, network, family, true, 42101, 42102)
			defer mipstackConnection.Close()
			defer gvisorPacket.Close()
			if err := mipstackConnection.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := gvisorPacket.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			request := patternedPayload(53, 0x91)
			if written, err := gvisorPacket.WriteTo(request, mipstackConnection.LocalAddr()); err != nil || written != len(request) {
				t.Fatalf("gVisor connected-peer UDP request = %d, %v", written, err)
			}
			mipstackBuffer := make([]byte, len(request))
			if read, err := mipstackConnection.(*mipstack.UDPConn).ReadWithBuffer(func(sizeHint int) []byte {
				if sizeHint != len(request) {
					t.Fatalf("connected UDP size hint = %d; want %d", sizeHint, len(request))
				}
				return mipstackBuffer
			}); err != nil || read != len(request) || !bytes.Equal(mipstackBuffer, request) {
				t.Fatalf("mipstack connected UDP ReadWithBuffer = n=%d error=%v", read, err)
			}
			response := patternedPayload(61, 0xa1)
			if written, err := mipstackConnection.Write(response); err != nil || written != len(response) {
				t.Fatalf("mipstack connected UDP response = %d, %v", written, err)
			}
			responseBuffer := make([]byte, len(response))
			if read, _, err := gvisorPacket.ReadFrom(responseBuffer); err != nil || !bytes.Equal(responseBuffer[:read], response) {
				t.Fatalf("gVisor connected-peer UDP response = n=%d error=%v", read, err)
			}
		})
	}
}

func TestUDPConnectedWriteBatchInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				connected, peer := openUDPPair(t, ctx, network, family, true)
				defer connected.Close()
				defer peer.Close()
				if err := connected.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}

				payloads := [][]byte{
					patternedPayload(37, 0x31),
					patternedPayload(fragmentedInteropPayloadSize(mtu, 12_000), 0x51),
				}
				messages := []mipstack.SocketMessage{
					{Buffers: [][]byte{payloads[0]}},
					{Buffers: [][]byte{payloads[1][:17], payloads[1][17:]}},
				}
				count, err := connected.(*mipstack.UDPConn).WriteBatch(messages, 0)
				if err != nil || count != len(messages) {
					t.Fatalf("connected UDP WriteBatch = %d, %v", count, err)
				}
				buffer := make([]byte, 65535)
				for index, payload := range payloads {
					read, source, readErr := peer.ReadFrom(buffer)
					if readErr != nil || !bytes.Equal(buffer[:read], payload) || source.String() != connected.LocalAddr().String() {
						t.Fatalf("gVisor UDP batch message %d = n=%d source=%v error=%v", index, read, source, readErr)
					}
					if messages[index].N != len(payload) || messages[index].NN != 0 || messages[index].Flags != 0 {
						t.Fatalf("connected UDP batch result %d = %+v", index, messages[index])
					}
				}
			})
		}
	}
}

func TestUDPStoppedDeviceReadInterop(t *testing.T) {
	family := interopFamilies[0]
	bridgeStopped := make(chan struct{})
	releaseBridge := make(chan struct{})
	var stopOnce, releaseOnce sync.Once
	network := newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: 1500,
		mipstackToGVisor: func([]byte) bool {
			stopOnce.Do(func() {
				close(bridgeStopped)
				<-releaseBridge
			})
			return true
		},
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseBridge) }) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connected, peer := openUDPPair(t, ctx, network, family, true)
	defer connected.Close()
	defer peer.Close()
	lateConnected, latePeer := openUDPPairAt(t, ctx, network, family, true, 42003, 42004)
	defer lateConnected.Close()
	defer latePeer.Close()
	udpConnection := connected.(*mipstack.UDPConn)
	if err := udpConnection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	lateUDPConnection := lateConnected.(*mipstack.UDPConn)
	if err := lateUDPConnection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}
	if written, err := udpConnection.Write([]byte("bridge-stop")); err != nil || written != len("bridge-stop") {
		t.Fatalf("write bridge-stop datagram: n=%d, error=%v", written, err)
	}
	select {
	case <-bridgeStopped:
	case <-ctx.Done():
		t.Fatal("mipstack output bridge did not stop")
	}

	overloaded := make(chan error, 1)
	go func() {
		payload := []byte("queue-pressure")
		for write := 0; write < 2048; write++ {
			if written, err := udpConnection.Write(payload); err != nil {
				overloaded <- err
				return
			} else if written != len(payload) {
				overloaded <- fmt.Errorf("short UDP write: %d", written)
				return
			}
		}
		overloaded <- nil
	}()
	select {
	case err := <-overloaded:
		if err != nil {
			t.Fatalf("stopped-read overload: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("UDP writes blocked while Stack.Read was stopped")
	}
	if stats := network.mipstack.Stats(); stats.OutboundQueueDrops == 0 {
		t.Fatalf("stopped-read UDP overload reported no outbound queue drops: %+v", stats)
	}

	latePayload := []byte("late-flow")
	written, err := lateUDPConnection.Write(latePayload)
	if err != nil || written != len(latePayload) {
		t.Fatalf("late-flow UDP write = %d, %v", written, err)
	}
	if err = latePeer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(releaseBridge) })
	buffer := make([]byte, 64)
	read, _, err := latePeer.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:read], latePayload) {
		t.Fatalf("late-flow gVisor UDP read = %q, %v", buffer[:read], err)
	}
}

func TestPublicUDPDatagramCodecInterop(t *testing.T) {
	const (
		mipstackPort = 43011
		gvisorPort   = 43012
	)
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
			peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}

			request := []byte("public-udp-codec-request")
			datagram := mipstack.UDPDatagram{
				Source:           netipAddrPort(family.mipstackAddress, mipstackPort),
				Destination:      netipAddrPort(family.gvisorAddress, gvisorPort),
				ChecksumDisabled: family.mipstackAddress.Is4(),
				Payload:          request,
			}
			udpWire, err := datagram.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public UDP datagram: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolUDP, HopLimit: 64, Payload: udpWire,
			}
			if family.mipstackAddress.Is6() {
				packet.Protocol = 60
				packet.Payload = append([]byte{mipstack.ProtocolUDP, 0, 1, 4, 0, 0, 0, 0}, udpWire...)
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public UDP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public UDP packet: %v", err)
			}
			storage := make([]byte, 128)
			read, source, err := peer.ReadFrom(storage)
			if err != nil || !bytes.Equal(storage[:read], request) || source.String() != net.UDPAddrFromAddrPort(datagram.Source).String() {
				t.Fatalf("gVisor UDP receive: n=%d source=%v payload=%x error=%v", read, source, storage[:read], err)
			}

			response := []byte("gvisor-udp-response")
			if written, writeErr := peer.WriteTo(response, net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, mipstackPort))); writeErr != nil || written != len(response) {
				t.Fatalf("write gVisor UDP response: n=%d, error=%v", written, writeErr)
			}
			select {
			case responseWire := <-captured:
				parsedPacket, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor UDP packet: %v", parseErr)
				}
				parsed, parseErr := parsedPacket.UDPDatagram()
				if parseErr != nil || parsed.Source != netipAddrPort(family.gvisorAddress, gvisorPort) || parsed.Destination != datagram.Source || !bytes.Equal(parsed.Payload, response) {
					t.Fatalf("parsed gVisor UDP = %+v, %v", parsed, parseErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for gVisor UDP packet")
			}
		})
	}
}

func TestUDPMaximumDatagramInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackConnected := range []bool{true, false} {
			mipstackConnected := mipstackConnected
			mode := "gvisor-connected"
			if mipstackConnected {
				mode = "mipstack-connected"
			}
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, 9000)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				connected, unconnected := openUDPPair(t, ctx, network, family, mipstackConnected)
				defer connected.Close()
				defer unconnected.Close()
				deadline := time.Now().Add(12 * time.Second)
				if err := connected.SetDeadline(deadline); err != nil {
					t.Fatalf("set connected maximum-UDP deadline: %v", err)
				}
				if err := unconnected.SetDeadline(deadline); err != nil {
					t.Fatalf("set unconnected maximum-UDP deadline: %v", err)
				}

				maximum := 65527
				if family.mipstackAddress.Is4() {
					maximum = 65507
				}
				request := patternedPayload(maximum, 157)
				response := patternedPayload(maximum, 193)
				buffer := make([]byte, 65535)
				written, err := connected.Write(request)
				if err != nil || written != len(request) {
					t.Fatalf("write maximum UDP request: n=%d, error=%v", written, err)
				}
				read, source, err := unconnected.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:read], request) {
					t.Fatalf("read maximum UDP request: n=%d, error=%v", read, err)
				}
				written, err = unconnected.WriteTo(response, source)
				if err != nil || written != len(response) {
					t.Fatalf("write maximum UDP response: n=%d, error=%v", written, err)
				}
				read, err = connected.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:read], response) {
					t.Fatalf("read maximum UDP response: n=%d, error=%v", read, err)
				}
			})
		}
	}
}

func TestUDPFragmentImpairmentInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, impairment := range []string{"reorder", "duplicate"} {
			impairment := impairment
			t.Run(family.name+"/"+impairment, func(t *testing.T) {
				var network *interopNetwork
				var mipstackImpaired, gvisorImpaired atomic.Bool
				bridgeErrors := make(chan error, 2)
				options := interopNetworkOptions{families: []interopFamily{family}, mtu: 1280}
				if impairment == "reorder" {
					options.mipstackToGVisor = newFragmentReorderHook(func(packet []byte) error {
						return network.deliverToGVisor(packet)
					}, &mipstackImpaired, bridgeErrors)
					options.gvisorToMipstack = newFragmentReorderHook(func(packet []byte) error {
						return network.deliverToMipstack(packet)
					}, &gvisorImpaired, bridgeErrors)
				} else {
					options.mipstackToGVisor = newFragmentDuplicateHook(func(packet []byte) error {
						return network.deliverToGVisor(packet)
					}, &mipstackImpaired, bridgeErrors)
					options.gvisorToMipstack = newFragmentDuplicateHook(func(packet []byte) error {
						return network.deliverToMipstack(packet)
					}, &gvisorImpaired, bridgeErrors)
				}
				network = newInteropNetworkWithOptions(t, options)
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				connected, unconnected := openUDPPair(t, ctx, network, family, false)
				defer connected.Close()
				defer unconnected.Close()
				deadline := time.Now().Add(10 * time.Second)
				if err := connected.SetDeadline(deadline); err != nil {
					t.Fatalf("set impaired connected UDP deadline: %v", err)
				}
				if err := unconnected.SetDeadline(deadline); err != nil {
					t.Fatalf("set impaired unconnected UDP deadline: %v", err)
				}

				request := patternedPayload(12_000, 211)
				response := patternedPayload(12_019, 227)
				buffer := make([]byte, 65535)
				written, err := connected.Write(request)
				if err != nil || written != len(request) {
					t.Fatalf("write impaired UDP request: n=%d, error=%v", written, err)
				}
				read, source, err := unconnected.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:read], request) {
					t.Fatalf("read impaired UDP request: n=%d, error=%v", read, err)
				}
				written, err = unconnected.WriteTo(response, source)
				if err != nil || written != len(response) {
					t.Fatalf("write impaired UDP response: n=%d, error=%v", written, err)
				}
				read, err = connected.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:read], response) {
					t.Fatalf("read impaired UDP response: n=%d, error=%v", read, err)
				}
				if !mipstackImpaired.Load() || !gvisorImpaired.Load() {
					t.Fatalf("fragment impairment coverage = mipstack:%v gVisor:%v", mipstackImpaired.Load(), gvisorImpaired.Load())
				}
				select {
				case err := <-bridgeErrors:
					t.Fatal(err)
				default:
				}
			})
		}
	}
}

func newFragmentReorderHook(deliver func([]byte) error, reordered *atomic.Bool, bridgeErrors chan<- error) interopPacketHook {
	var held []byte
	var heldOffset uint16
	return func(packet []byte) bool {
		offset, fragment := ipFragmentOffset(packet)
		if !fragment || reordered.Load() {
			return true
		}
		if held == nil {
			held = append([]byte(nil), packet...)
			heldOffset = offset
			return false
		}
		if offset == heldOffset {
			return true
		}
		reportBridgeDelivery(deliver(packet), bridgeErrors)
		reportBridgeDelivery(deliver(held), bridgeErrors)
		held = nil
		reordered.Store(true)
		return false
	}
}

func newFragmentDuplicateHook(deliver func([]byte) error, duplicated *atomic.Bool, bridgeErrors chan<- error) interopPacketHook {
	return func(packet []byte) bool {
		if _, fragment := ipFragmentOffset(packet); fragment && duplicated.CompareAndSwap(false, true) {
			reportBridgeDelivery(deliver(packet), bridgeErrors)
		}
		return true
	}
}

func reportBridgeDelivery(err error, bridgeErrors chan<- error) {
	if err == nil {
		return
	}
	select {
	case bridgeErrors <- err:
	default:
	}
}

func ipFragmentOffset(packet []byte) (uint16, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	switch packet[0] >> 4 {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return 0, false
		}
		ipHeader := header.IPv4(packet)
		return ipHeader.FragmentOffset(), ipHeader.More() || ipHeader.FragmentOffset() != 0
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize+header.IPv6FragmentHeaderSize || header.IPv6(packet).TransportProtocol() != header.IPv6FragmentHeader {
			return 0, false
		}
		fragmentHeader := header.IPv6Fragment(packet[header.IPv6MinimumSize:])
		return fragmentHeader.FragmentOffset(), fragmentHeader.IsValid()
	default:
		return 0, false
	}
}

func TestUDPDualStackWildcardInterop(t *testing.T) {
	network := newInteropNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := network.mipstack.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		t.Fatalf("listen on dual-stack UDP wildcard: %v", err)
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set dual-stack UDP deadline: %v", err)
	}
	port := requireAddrPort(t, listener.LocalAddr()).Port()
	buffer := make([]byte, 2048)

	for index, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			local := gvisorFullAddress(family.gvisorAddress, 0)
			remote := gvisorFullAddress(family.mipstackAddress, port)
			client, dialErr := gonet.DialUDP(network.gvisor, &local, &remote, family.networkProtocol)
			if dialErr != nil {
				t.Fatalf("dial dual-stack UDP listener: %v", dialErr)
			}
			defer client.Close()
			if dialErr = client.SetDeadline(time.Now().Add(8 * time.Second)); dialErr != nil {
				t.Fatalf("set gVisor UDP deadline: %v", dialErr)
			}

			request := patternedPayload(73+index, byte(17+index))
			written, writeErr := client.Write(request)
			if writeErr != nil || written != len(request) {
				t.Fatalf("write dual-stack UDP request: n=%d, error=%v", written, writeErr)
			}
			read, source, readErr := listener.ReadFrom(buffer)
			if readErr != nil || !bytes.Equal(buffer[:read], request) {
				t.Fatalf("read dual-stack UDP request: n=%d, source=%v, error=%v", read, source, readErr)
			}
			if got := requireAddrPort(t, source); got != requireAddrPort(t, client.LocalAddr()) {
				t.Fatalf("dual-stack UDP source = %v, want %v", got, client.LocalAddr())
			}

			response := patternedPayload(91+index, byte(43+index))
			written, writeErr = listener.WriteTo(response, source)
			if writeErr != nil || written != len(response) {
				t.Fatalf("write dual-stack UDP response: n=%d, error=%v", written, writeErr)
			}
			read, readErr = client.Read(buffer)
			if readErr != nil || !bytes.Equal(buffer[:read], response) {
				t.Fatalf("read dual-stack UDP response: n=%d, error=%v", read, readErr)
			}
		})
	}
}

func TestUDPConnectedPeerFilterInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			const (
				mipstackPort = 44801
				peerPort     = 44802
				strayPort    = 44803
			)
			connection, err := network.mipstack.DialUDP(ctx, family.udpNetwork,
				netipAddrPort(family.mipstackAddress, mipstackPort), netipAddrPort(family.gvisorAddress, peerPort))
			if err != nil {
				t.Fatalf("dial connected mipstack UDP socket: %v", err)
			}
			defer connection.Close()
			peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, peerPort), func(tcpip.Endpoint) {})
			defer peer.Close()
			stray := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, strayPort), func(tcpip.Endpoint) {})
			defer stray.Close()
			deadline := time.Now().Add(6 * time.Second)
			if err = connection.SetDeadline(deadline); err != nil {
				t.Fatalf("set connected mipstack UDP deadline: %v", err)
			}
			if err = peer.SetDeadline(deadline); err != nil {
				t.Fatalf("set gVisor UDP peer deadline: %v", err)
			}
			targetAddress := netipAddrPort(family.mipstackAddress, mipstackPort)
			target := net.UDPAddrFromAddrPort(targetAddress)
			strayPayload := []byte("wrong-connected-peer")
			if written, writeErr := stray.WriteTo(strayPayload, target); writeErr != nil || written != len(strayPayload) {
				t.Fatalf("write stray gVisor UDP datagram: n=%d, error=%v", written, writeErr)
			}
			peerPayload := []byte("configured-connected-peer")
			if written, writeErr := peer.WriteTo(peerPayload, target); writeErr != nil || written != len(peerPayload) {
				t.Fatalf("write configured gVisor UDP datagram: n=%d, error=%v", written, writeErr)
			}
			storage := make([]byte, 128)
			read, err := connection.Read(storage)
			if err != nil || !bytes.Equal(storage[:read], peerPayload) {
				t.Fatalf("read connected mipstack UDP datagram: n=%d, payload=%q, error=%v", read, storage[:read], err)
			}

			response := []byte("connected-peer-response")
			if written, writeErr := connection.Write(response); writeErr != nil || written != len(response) {
				t.Fatalf("write connected mipstack UDP response: n=%d, error=%v", written, writeErr)
			}
			read, source, err := peer.ReadFrom(storage)
			if err != nil || requireAddrPort(t, source) != targetAddress || !bytes.Equal(storage[:read], response) {
				t.Fatalf("read gVisor UDP response: n=%d, source=%v, error=%v", read, source, err)
			}
		})
	}
}

func TestUDPChecksumInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mutation := range []string{"zero", "corrupt"} {
			mutation := mutation
			t.Run(family.name+"/"+mutation, func(t *testing.T) {
				var network *interopNetwork
				var mutated atomic.Bool
				options := interopNetworkOptions{families: []interopFamily{family}, mtu: 1500}
				options.gvisorToMipstack = func(packet []byte) bool {
					offset, ok := udpHeaderOffset(packet)
					if !ok || !mutated.CompareAndSwap(false, true) {
						return true
					}
					modified := append([]byte(nil), packet...)
					if mutation == "zero" {
						binary.BigEndian.PutUint16(modified[offset+6:offset+8], 0)
					} else {
						modified[len(modified)-1] ^= 0xff
					}
					if err := network.deliverToMipstack(modified); err != nil {
						network.reportBridgeError(err)
					}
					return false
				}
				network = newInteropNetworkWithOptions(t, options)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				const (
					mipstackPort = 44811
					gvisorPort   = 44812
				)
				listener, err := network.mipstack.ListenUDP(ctx, family.udpNetwork, netipAddrPort(family.mipstackAddress, mipstackPort))
				if err != nil {
					t.Fatalf("listen with mipstack UDP checksum socket: %v", err)
				}
				defer listener.Close()
				sender := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
				defer sender.Close()
				if err = listener.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
					t.Fatalf("set mipstack UDP checksum deadline: %v", err)
				}
				target := net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, mipstackPort))
				alteredPayload := []byte("checksum-mutated-datagram")
				if written, writeErr := sender.WriteTo(alteredPayload, target); writeErr != nil || written != len(alteredPayload) {
					t.Fatalf("write mutated gVisor UDP datagram: n=%d, error=%v", written, writeErr)
				}
				validPayload := []byte("checksum-valid-datagram")
				if written, writeErr := sender.WriteTo(validPayload, target); writeErr != nil || written != len(validPayload) {
					t.Fatalf("write valid gVisor UDP datagram: n=%d, error=%v", written, writeErr)
				}
				storage := make([]byte, 128)
				if mutation == "zero" && family.mipstackAddress.Is4() {
					read, _, readErr := listener.ReadFrom(storage)
					if readErr != nil || !bytes.Equal(storage[:read], alteredPayload) {
						t.Fatalf("read zero-checksum IPv4 UDP datagram: n=%d, payload=%q, error=%v", read, storage[:read], readErr)
					}
				}
				read, _, readErr := listener.ReadFrom(storage)
				if readErr != nil || !bytes.Equal(storage[:read], validPayload) {
					t.Fatalf("read UDP after rejected checksum: n=%d, payload=%q, error=%v", read, storage[:read], readErr)
				}
				if !mutated.Load() {
					t.Fatal("UDP checksum hook did not match a packet")
				}
			})
		}
	}
}

func TestUDPRXChecksumOffloadInterop(t *testing.T) {
	for _, family := range interopFamilies {
		for _, category := range []string{"UDP", "IPv4Header"} {
			if category == "IPv4Header" && family.mipstackAddress.Is6() {
				continue
			}
			t.Run(family.name+"/"+category, func(t *testing.T) {
				var network *interopNetwork
				var mutated atomic.Bool
				network = newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					gvisorToMipstack: func(packet []byte) bool {
						offset, ok := udpHeaderOffset(packet)
						if !ok || !mutated.CompareAndSwap(false, true) {
							return true
						}
						modified := append([]byte(nil), packet...)
						if category == "IPv4Header" {
							ip := header.IPv4(modified)
							ip.SetChecksum(ip.Checksum() ^ 1)
						} else {
							udp := header.UDP(modified[offset:])
							value := udp.Checksum() ^ 1
							if value == 0 {
								value = 2
							}
							udp.SetChecksum(value)
						}
						if err := network.deliverToMipstack(modified); err != nil {
							network.reportBridgeError(err)
						}
						return false
					},
				})
				var offload mipstack.RXChecksumOffload
				offload.SetUDP(category == "UDP").SetIPv4Header(category == "IPv4Header")
				network.mipstack.SetRXChecksumOffload(offload)
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				connected, unconnected := openUDPPair(t, ctx, network, family, false)
				defer connected.Close()
				defer unconnected.Close()
				exerciseUDP(t, connected, unconnected, network.mtu)
				if !mutated.Load() {
					t.Fatal("offload packet mutation did not run")
				}
			})
		}
	}
}

func TestPublicChecksumPartsInterop(t *testing.T) {
	const (
		mipstackPort = 44821
		gvisorPort   = 44822
	)
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			payload := []byte("multipart-checksum-gvisor-interoperability")
			payloadParts := [][]byte{payload[:1], nil, payload[1:12], {}, payload[12:29], payload[29:]}
			var checksumer checksum.Checksumer
			for _, part := range payloadParts {
				checksumer.Add(part)
			}
			if got, want := mipstack.InternetChecksumParts(payloadParts...), ^checksumer.Checksum(); got != want {
				t.Fatalf("InternetChecksumParts = %#x, gVisor %#x", got, want)
			}

			udpHeader := make([]byte, header.UDPMinimumSize)
			binary.BigEndian.PutUint16(udpHeader[0:2], mipstackPort)
			binary.BigEndian.PutUint16(udpHeader[2:4], gvisorPort)
			binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(udpHeader)+len(payload)))
			parts := [][]byte{udpHeader[:3], nil, udpHeader[3:7], udpHeader[7:], payload[:1], {}, payload[1:17], payload[17:]}
			value, err := mipstack.IPTransportChecksumParts(
				family.mipstackAddress, family.gvisorAddress, mipstack.ProtocolUDP, parts...,
			)
			if err != nil {
				t.Fatal(err)
			}
			contiguous := append(append([]byte(nil), udpHeader...), payload...)
			initial := header.PseudoHeaderChecksum(
				udp.ProtocolNumber, gvisorAddress(family.mipstackAddress), gvisorAddress(family.gvisorAddress), uint16(len(contiguous)),
			)
			if want := ^checksum.Checksum(contiguous, initial); value != want {
				t.Fatalf("IPTransportChecksumParts = %#x, gVisor %#x", value, want)
			}
			if value == 0 {
				value = 0xffff
			}
			binary.BigEndian.PutUint16(udpHeader[6:8], value)

			network := newFamilyInteropNetwork(t, family, 1500)
			peer := newGVisorUDPSocket(
				t, network, family.networkProtocol,
				gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {},
			)
			defer peer.Close()
			if err = peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolUDP, HopLimit: 64,
				Payload: append(udpHeader, payload...),
			}
			wire, err := packet.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatal(err)
			}
			storage := make([]byte, len(payload)+8)
			read, source, err := peer.ReadFrom(storage)
			if err != nil || !bytes.Equal(storage[:read], payload) || requireAddrPort(t, source) != netipAddrPort(family.mipstackAddress, mipstackPort) {
				t.Fatalf("gVisor multipart-checksum UDP = n=%d source=%v payload=%q error=%v", read, source, storage[:read], err)
			}
		})
	}
}

func TestUDPClosedPortInterop(t *testing.T) {
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
			buffer := make([]byte, 1)

			var queue waiter.Queue
			gvisorEndpoint, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor UDP endpoint: %s", tcpipErr.String())
			}
			defer gvisorEndpoint.Close()
			if tcpipErr = gvisorEndpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor UDP endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = gvisorEndpoint.Connect(gvisorFullAddress(family.mipstackAddress, 44993)); tcpipErr != nil {
				t.Fatalf("connect gVisor UDP endpoint: %s", tcpipErr.String())
			}
			entry, notifications := waiter.NewChannelEntry(waiter.EventErr)
			queue.EventRegister(&entry)
			defer queue.EventUnregister(&entry)
			written, tcpipErr := gvisorEndpoint.Write(bytes.NewReader([]byte{1}), tcpip.WriteOptions{})
			if tcpipErr != nil || written != 1 {
				t.Fatalf("write to closed mipstack UDP port: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
			}
			localAddress, tcpipErr := gvisorEndpoint.GetLocalAddress()
			if tcpipErr != nil {
				t.Fatalf("get gVisor UDP local address: %s", tcpipErr.String())
			}
			select {
			case packet := <-outbound:
				validatePortUnreachable(t, family, packet, netipAddrPort(family.gvisorAddress, localAddress.Port), netipAddrPort(family.mipstackAddress, 44993))
			case <-time.After(time.Second):
				t.Fatal("mipstack did not emit UDP Port Unreachable")
			}
			select {
			case <-notifications:
			case <-time.After(time.Second):
				mipstackStats := network.mipstack.Stats()
				gvisorStats := network.gvisor.Stats().IP
				t.Fatalf("gVisor did not signal mipstack Port Unreachable (mipstack outbound=%d, gVisor received=%d valid=%d delivered=%d malformed=%d)",
					mipstackStats.OutboundPackets, gvisorStats.PacketsReceived.Value(), gvisorStats.ValidPacketsReceived.Value(),
					gvisorStats.PacketsDelivered.Value(), gvisorStats.MalformedPacketsReceived.Value())
			}
			if lastError := gvisorEndpoint.LastError(); lastError == nil {
				t.Fatal("gVisor UDP endpoint signaled an error without LastError")
			} else if _, refused := lastError.(*tcpip.ErrConnectionRefused); !refused {
				t.Fatalf("gVisor UDP LastError = %T %s, want ErrConnectionRefused", lastError, lastError.String())
			}

			deadline := time.Now().Add(5 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			mipstackConnection, err := network.mipstack.DialUDP(ctx, family.udpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, 44994))
			if err != nil {
				t.Fatalf("dial mipstack UDP socket: %v", err)
			}
			defer mipstackConnection.Close()
			if err = mipstackConnection.SetDeadline(deadline); err != nil {
				t.Fatalf("set mipstack UDP deadline: %v", err)
			}
			mipstackUDP := mipstackConnection.(*mipstack.UDPConn)
			if err = mipstackUDP.SetReceiveErrors(true); err != nil {
				t.Fatalf("reserve gVisor ICMP error for MSG_ERRQUEUE: %v", err)
			}
			if _, err = mipstackConnection.Write([]byte{2}); err != nil {
				t.Fatalf("write to closed gVisor UDP port: %v", err)
			}
			if count, readErr := mipstackUDP.Read(buffer); count != 0 || readErr == nil {
				t.Fatalf("read gVisor ICMP as an ordinary pending error: %d, %v", count, readErr)
			} else {
				var networkError mipstack.ICMPError
				if !errors.As(readErr, &networkError) || networkError.QuotedTarget != family.gvisorAddress || networkError.QuotedTargetPort != 44994 {
					t.Fatalf("ordinary gVisor ICMP error lost its quote: %v", readErr)
				}
			}
			message := []mipstack.SocketMessage{{Buffers: [][]byte{buffer}, OOB: make([]byte, 128)}}
			if count, readErr := mipstackUDP.ReadBatch(message, mipstack.MessageFlagErrorQueue); readErr != nil || count != 1 {
				t.Fatalf("read gVisor ICMP through MSG_ERRQUEUE after ordinary read: %d, %v", count, readErr)
			}
			if message[0].N != 1 || buffer[0] != 2 || message[0].Flags != mipstack.MessageFlagErrorQueue || message[0].Addr.(*net.UDPAddr).AddrPort() != netipAddrPort(family.gvisorAddress, 44994) {
				t.Fatalf("gVisor ICMP error-queue message = %+v payload=%x", message[0], buffer[:message[0].N])
			}
			var socketError mipstack.SocketErrorControlMessage
			if err = socketError.Parse(message[0].OOB[:message[0].NN]); err != nil {
				t.Fatalf("parse gVisor ICMP error control: %v", err)
			}
			wantType, wantCode := byte(3), byte(3)
			wantOrigin := mipstack.SocketErrorOriginICMP
			if family.mipstackAddress.Is6() {
				wantType, wantCode = 1, 4
				wantOrigin = mipstack.SocketErrorOriginICMP6
			}
			if socketError.Errno != 111 || socketError.Origin != wantOrigin || socketError.Type != wantType || socketError.Code != wantCode || socketError.Offender != family.gvisorAddress {
				t.Fatalf("mipstack UDP MSG_ERRQUEUE control = %+v", socketError)
			}
			canonicalControl, err := socketError.MarshalBinary()
			if err != nil {
				t.Fatalf("re-encode mipstack UDP MSG_ERRQUEUE control: %v", err)
			}
			if !bytes.Equal(canonicalControl, message[0].OOB[:message[0].NN]) {
				t.Fatalf("re-encoded mipstack UDP MSG_ERRQUEUE control = %x, want %x", canonicalControl, message[0].OOB[:message[0].NN])
			}
			var roundTripError mipstack.SocketErrorControlMessage
			if err = roundTripError.Parse(canonicalControl); err != nil || roundTripError != socketError {
				t.Fatalf("reparse mipstack UDP MSG_ERRQUEUE control = %+v, %v, want %+v", roundTripError, err, socketError)
			}
		})
	}
}

func TestUDPUnconnectedClosedPortErrorInterop(t *testing.T) {
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
			packetConnection, err := network.mipstack.ListenUDP(context.Background(), family.udpNetwork, netipAddrPort(family.mipstackAddress, 0))
			if err != nil {
				t.Fatal(err)
			}
			connection := packetConnection.(*mipstack.UDPConn)
			defer connection.Close()
			if err = connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			local := connection.LocalAddr().(*net.UDPAddr).AddrPort()
			closed := netipAddrPort(family.gvisorAddress, 44996)
			if _, err = connection.WriteTo([]byte{1}, net.UDPAddrFromAddrPort(closed)); err != nil {
				t.Fatal(err)
			}
			var wire []byte
			select {
			case wire = <-observed:
			case <-time.After(3 * time.Second):
				t.Fatal("gVisor did not emit Port Unreachable")
			}
			packet, err := mipstack.ParseIPPacket(wire)
			if err != nil || packet.Source != family.gvisorAddress || packet.Destination != family.mipstackAddress {
				t.Fatalf("gVisor ICMP packet = %+v, %v", packet, err)
			}
			message, err := packet.ICMPMessage()
			if err != nil {
				t.Fatal(err)
			}
			networkError, err := message.ICMPError()
			if err != nil || networkError.QuotedSource != local.Addr() || networkError.QuotedTarget != closed.Addr() ||
				networkError.QuotedSourcePort != local.Port() || networkError.QuotedTargetPort != closed.Port() {
				t.Fatalf("gVisor Port Unreachable quote = %+v, %v", networkError, err)
			}
			if family.mipstackAddress.Is4() {
				if networkError.Type != mipstack.ICMPv4TypeDestinationUnreachable || networkError.Code != mipstack.ICMPv4DestinationUnreachableCodePort {
					t.Fatalf("gVisor IPv4 error type/code = %d/%d", networkError.Type, networkError.Code)
				}
			} else if networkError.Type != mipstack.ICMPv6TypeDestinationUnreachable || networkError.Code != mipstack.ICMPv6DestinationUnreachableCodePort {
				t.Fatalf("gVisor IPv6 error type/code = %d/%d", networkError.Type, networkError.Code)
			}

			peer := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, 44997), func(tcpip.Endpoint) {})
			defer peer.Close()
			if _, err = peer.WriteTo([]byte{2}, net.UDPAddrFromAddrPort(local)); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 1)
			if n, source, readErr := connection.ReadFrom(payload); readErr != nil || n != 1 || payload[0] != 2 ||
				requireAddrPort(t, source) != netipAddrPort(family.gvisorAddress, 44997) {
				t.Fatalf("UDP read after gVisor ICMP = %d, %v, %x, %v", n, source, payload, readErr)
			}
			if count, readErr := connection.ReadBatch([]mipstack.SocketMessage{{Buffers: [][]byte{payload}}}, mipstack.MessageFlagDontWait); count != 0 || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("UDP read after payload = %d, %v", count, readErr)
			}
			if queued, readErr := connection.ReadError(); queued != nil || !errors.Is(readErr, syscall.EAGAIN) {
				t.Fatalf("default UDP error queue = %+v, %v", queued, readErr)
			}
			if info := connection.Info(); info.ErrorQueueEntries != 0 || info.ICMPErrors != 0 || info.LastError != nil {
				t.Fatalf("default unconnected UDP retained ICMP error: %+v", info)
			}

			if err = connection.SetReceiveErrors(true); err != nil {
				t.Fatal(err)
			}
			enabledClosed := netipAddrPort(family.gvisorAddress, 44999)
			if _, err = connection.WriteTo([]byte{3}, net.UDPAddrFromAddrPort(enabledClosed)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-observed:
			case <-time.After(3 * time.Second):
				t.Fatal("gVisor did not emit Port Unreachable with UDP error reception enabled")
			}
			if err = connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, _, readErr := connection.ReadFrom(payload); n != 0 || readErr == nil {
				t.Fatalf("UDP ordinary pending error = %d, %v", n, readErr)
			} else {
				var pending mipstack.ICMPError
				if !errors.Is(readErr, syscall.ECONNREFUSED) || !errors.As(readErr, &pending) || pending.QuotedTarget != enabledClosed.Addr() || pending.QuotedTargetPort != enabledClosed.Port() {
					t.Fatalf("UDP ordinary error lost its quote: %v", readErr)
				}
			}
			if _, err = peer.WriteTo([]byte{4}, net.UDPAddrFromAddrPort(local)); err != nil {
				t.Fatal(err)
			}
			if n, source, readErr := connection.ReadFrom(payload); readErr != nil || n != 1 || payload[0] != 4 ||
				requireAddrPort(t, source) != netipAddrPort(family.gvisorAddress, 44997) {
				t.Fatalf("UDP read with error reception enabled = %d, %v, %x, %v", n, source, payload, readErr)
			}
			reported, readErr := connection.ReadError()
			var reportedError mipstack.ICMPError
			if readErr != nil || !errors.Is(reported, syscall.ECONNREFUSED) || !errors.As(reported, &reportedError) ||
				reportedError.QuotedSource != local.Addr() || reportedError.QuotedTarget != enabledClosed.Addr() ||
				reportedError.QuotedSourcePort != local.Port() || reportedError.QuotedTargetPort != enabledClosed.Port() ||
				reportedError.Type != networkError.Type || reportedError.Code != networkError.Code {
				t.Fatalf("enabled unconnected UDP error = %+v, %v", reported, readErr)
			}
		})
	}
}

func TestUDPControlMessageInterop(t *testing.T) {
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
			const (
				mipstackPort = 45001
				gvisorPort   = 45002
			)
			packetConnection, err := network.mipstack.ListenUDP(ctx, family.udpNetwork, netipAddrPort(family.mipstackAddress, mipstackPort))
			if err != nil {
				t.Fatalf("listen with mipstack UDP: %v", err)
			}
			connection := packetConnection.(*mipstack.UDPConn)
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
				t.Fatalf("set mipstack UDP deadline: %v", err)
			}

			var queue waiter.Queue
			endpoint, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor UDP endpoint: %s", tcpipErr.String())
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
				t.Fatalf("configure gVisor UDP header options: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, gvisorPort)); tcpipErr != nil {
				t.Fatalf("bind gVisor UDP endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, mipstackPort)); tcpipErr != nil {
				t.Fatalf("connect gVisor UDP endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := []byte("control-request")
			written, tcpipErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if tcpipErr != nil || written != int64(len(request)) {
				t.Fatalf("write gVisor UDP control request: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
			}
			payload := make([]byte, 256)
			control := make([]byte, 256)
			read, controlRead, flags, source, err := connection.ReadMsgUDPAddrPort(payload, control)
			if err != nil || flags != 0 || source != netipAddrPort(family.gvisorAddress, gvisorPort) || !bytes.Equal(payload[:read], request) {
				t.Fatalf("read mipstack UDP control request: n=%d, oob=%d, flags=%#x, source=%v, error=%v", read, controlRead, flags, source, err)
			}
			if family.mipstackAddress.Is4() {
				var message mipstack.IPv4ControlMessage
				if err = message.Parse(control[:controlRead]); err != nil {
					t.Fatalf("parse mipstack IPv4 control message: %v", err)
				}
				if message.Dst != family.mipstackAddress || message.TTL != 37 || message.TOS != 0x2e || message.IfIndex != 0 {
					t.Fatalf("mipstack IPv4 control message = %+v", message)
				}
				if controlRead < 28 || !bytes.Equal(control[20:24], family.mipstackAddress.AsSlice()) || !bytes.Equal(control[24:28], family.mipstackAddress.AsSlice()) {
					t.Fatalf("mipstack IPv4 packet-info fields = %x/%x, want %s/%s", control[20:24], control[24:28], family.mipstackAddress, family.mipstackAddress)
				}
				control, err = (&mipstack.IPv4ControlMessage{TTL: 41, TOS: 0xb8}).Marshal()
			} else {
				var message mipstack.IPv6ControlMessage
				if err = message.Parse(control[:controlRead]); err != nil {
					t.Fatalf("parse mipstack IPv6 control message: %v", err)
				}
				if message.Dst != family.mipstackAddress || message.HopLimit != 37 || message.TrafficClass != 0x2e || message.IfIndex != 0 {
					t.Fatalf("mipstack IPv6 control message = %+v", message)
				}
				control, err = (&mipstack.IPv6ControlMessage{HopLimit: 41, TrafficClass: 0xb8, FlowLabel: 0x34567}).Marshal()
			}
			if err != nil {
				t.Fatalf("marshal mipstack UDP control message: %v", err)
			}

			response := []byte("control-response")
			writtenInt, controlWritten, err := connection.WriteMsgUDPAddrPort(response, control, source)
			if err != nil || writtenInt != len(response) || controlWritten != len(control) {
				t.Fatalf("write mipstack UDP control response: n=%d, oob=%d, error=%v", writtenInt, controlWritten, err)
			}
			select {
			case packet := <-outbound:
				validateControlledIPHeader(t, family, packet, 41)
			case <-ctx.Done():
				t.Fatalf("capture mipstack UDP control response: %v", ctx.Err())
			}
			received, result, readErr := readGVisorEndpointResult(ctx, endpoint, notifications, 256)
			if readErr != nil || result.RemoteAddr.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(received, response) {
				t.Fatalf("read gVisor UDP control response: n=%d, source=%v, error=%v", len(received), result.RemoteAddr, readErr)
			}
			messages := result.ControlMessages
			if family.mipstackAddress.Is4() {
				if !messages.HasTTL || messages.TTL != 41 || !messages.HasTOS || messages.TOS != 0xb8 || !messages.HasIPPacketInfo ||
					messages.PacketInfo.LocalAddr != gvisorAddress(family.gvisorAddress) || messages.PacketInfo.DestinationAddr != gvisorAddress(family.gvisorAddress) {
					t.Fatalf("gVisor IPv4 control messages = %+v", messages)
				}
			} else if !messages.HasHopLimit || messages.HopLimit != 41 || !messages.HasTClass || messages.TClass != 0xb8 || !messages.HasIPv6PacketInfo ||
				messages.IPv6PacketInfo.Addr != gvisorAddress(family.gvisorAddress) {
				t.Fatalf("gVisor IPv6 control messages = %+v", messages)
			}
		})
	}
}

func validateControlledIPHeader(t *testing.T, family interopFamily, packet []byte, hopLimit uint8) {
	t.Helper()
	if family.mipstackAddress.Is4() {
		if len(packet) < header.IPv4MinimumSize {
			t.Fatalf("short controlled IPv4 packet: %d bytes", len(packet))
		}
		ipHeader := header.IPv4(packet)
		tos, _ := ipHeader.TOS()
		if ipHeader.TTL() != hopLimit || tos != 0xb8 {
			t.Fatalf("controlled IPv4 header TTL/TOS = %d/%#x", ipHeader.TTL(), tos)
		}
		return
	}
	if len(packet) < header.IPv6MinimumSize {
		t.Fatalf("short controlled IPv6 packet: %d bytes", len(packet))
	}
	ipHeader := header.IPv6(packet)
	trafficClass, flowLabel := ipHeader.TOS()
	if ipHeader.HopLimit() != hopLimit || trafficClass != 0xb8 || flowLabel != 0x34567 {
		t.Fatalf("controlled IPv6 header hop/class/label = %d/%#x/%#x", ipHeader.HopLimit(), trafficClass, flowLabel)
	}
}

func TestUDPClosedPortFairnessInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			sourceA, sourceB := netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")
			if family.mipstackAddress.Is6() {
				sourceA, sourceB = netip.MustParseAddr("2001:db8::3"), netip.MustParseAddr("2001:db8::4")
			}
			for _, source := range []netip.Addr{sourceA, sourceB} {
				if tcpipErr := network.gvisor.AddProtocolAddress(interopNIC, tcpip.ProtocolAddress{
					Protocol: family.networkProtocol,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address: gvisorAddress(source), PrefixLen: family.prefixBits,
					},
				}, stack.AddressProperties{}); tcpipErr != nil {
					t.Fatalf("add gVisor fairness source address %s: %s", source, tcpipErr.String())
				}
			}

			type monitor struct {
				address       netip.Addr
				endpoint      tcpip.Endpoint
				notifications <-chan struct{}
				sourcePort    uint16
			}
			monitors := make([]monitor, 0, 2)
			for _, source := range []netip.Addr{sourceA, sourceB} {
				var queue waiter.Queue
				endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor raw ICMP monitor for %s: %s", source, tcpipErr.String())
				}
				if tcpipErr = endpoint.Bind(gvisorFullAddress(source, 0)); tcpipErr != nil {
					endpoint.Close()
					t.Fatalf("bind gVisor raw ICMP monitor for %s: %s", source, tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				t.Cleanup(func() {
					queue.EventUnregister(&entry)
					endpoint.Close()
				})
				monitors = append(monitors, monitor{address: source, endpoint: endpoint, notifications: notifications})
			}

			connections := make([]*gonet.UDPConn, 0, 2)
			for _, source := range []netip.Addr{sourceA, sourceB} {
				connection := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(source, 0), func(tcpip.Endpoint) {})
				connections = append(connections, connection)
				t.Cleanup(func() { _ = connection.Close() })
			}
			for index := range monitors {
				monitors[index].sourcePort = requireAddrPort(t, connections[index].LocalAddr()).Port()
			}

			type result struct {
				monitor monitor
				packet  []byte
				remote  tcpip.FullAddress
				err     error
			}
			results := make(chan result, len(monitors))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for _, current := range monitors {
				go func(current monitor) {
					packet, remote, err := readGVisorEndpoint(ctx, current.endpoint, current.notifications, 65535)
					results <- result{monitor: current, packet: packet, remote: remote, err: err}
				}(current)
			}

			target := net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, 53000))
			payload := []byte("fairness")
			const floodPackets = 2048
			for index := 0; index < floodPackets; index++ {
				if written, err := connections[0].WriteTo(payload, target); err != nil || written != len(payload) {
					t.Fatalf("gVisor source A closed-port flood packet %d: n=%d, error=%v", index, written, err)
				}
			}
			if written, err := connections[1].WriteTo(payload, target); err != nil || written != len(payload) {
				t.Fatalf("gVisor source B closed-port probe: n=%d, error=%v", written, err)
			}

			for range monitors {
				current := <-results
				if current.err != nil {
					t.Fatalf("read gVisor ICMP response for %s: %v", current.monitor.address, current.err)
				}
				validateGVisorClosedPortError(t, family, current.packet, current.remote, current.monitor.address, current.monitor.sourcePort)
			}
			if rateLimited := network.mipstack.Stats().RateLimitedControlResponses; rateLimited == 0 {
				t.Fatal("closed-port flood did not exercise ICMP response rate limiting")
			}
		})
	}
}

func TestUDPClosedPortMultiSourceFairnessInterop(t *testing.T) {
	const (
		attackerCount = 4
		attackerBurst = 256
		victimCount   = 16
	)
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			sources := make([]netip.Addr, attackerCount+victimCount)
			for index := range sources {
				if family.mipstackAddress.Is4() {
					sources[index] = netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 3)})
				} else {
					address := [16]byte{0x20, 0x01, 0x0d, 0xb8}
					address[15] = byte(index + 3)
					sources[index] = netip.AddrFrom16(address)
				}
				if tcpipErr := network.gvisor.AddProtocolAddress(interopNIC, tcpip.ProtocolAddress{
					Protocol: family.networkProtocol,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address: gvisorAddress(sources[index]), PrefixLen: family.prefixBits,
					},
				}, stack.AddressProperties{}); tcpipErr != nil {
					t.Fatalf("add gVisor multi-source address %s: %s", sources[index], tcpipErr.String())
				}
			}

			type monitor struct {
				address       netip.Addr
				endpoint      tcpip.Endpoint
				notifications <-chan struct{}
				sourcePort    uint16
			}
			monitors := make([]monitor, 0, victimCount)
			for _, source := range sources[attackerCount:] {
				var queue waiter.Queue
				endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor raw ICMP monitor for %s: %s", source, tcpipErr.String())
				}
				if tcpipErr = endpoint.Bind(gvisorFullAddress(source, 0)); tcpipErr != nil {
					endpoint.Close()
					t.Fatalf("bind gVisor raw ICMP monitor for %s: %s", source, tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				t.Cleanup(func() {
					queue.EventUnregister(&entry)
					endpoint.Close()
				})
				monitors = append(monitors, monitor{address: source, endpoint: endpoint, notifications: notifications})
			}

			connections := make([]*gonet.UDPConn, 0, len(sources))
			for _, source := range sources {
				connection := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(source, 0), func(tcpip.Endpoint) {})
				connections = append(connections, connection)
				t.Cleanup(func() { _ = connection.Close() })
			}
			for index := range monitors {
				monitors[index].sourcePort = requireAddrPort(t, connections[attackerCount+index].LocalAddr()).Port()
			}

			type result struct {
				monitor monitor
				packet  []byte
				remote  tcpip.FullAddress
				err     error
			}
			results := make(chan result, len(monitors))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for _, current := range monitors {
				go func(current monitor) {
					packet, remote, err := readGVisorEndpoint(ctx, current.endpoint, current.notifications, 65535)
					results <- result{monitor: current, packet: packet, remote: remote, err: err}
				}(current)
			}

			target := net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, 53000))
			payload := []byte("multi-source-fairness")
			for packet := 0; packet < attackerBurst; packet++ {
				for source := 0; source < attackerCount; source++ {
					if written, err := connections[source].WriteTo(payload, target); err != nil || written != len(payload) {
						t.Fatalf("gVisor attacker %d packet %d: n=%d, error=%v", source, packet, written, err)
					}
				}
			}
			for index := range monitors {
				if written, err := connections[attackerCount+index].WriteTo(payload, target); err != nil || written != len(payload) {
					t.Fatalf("gVisor victim %d probe: n=%d, error=%v", index, written, err)
				}
			}

			admitted := false
			for range monitors {
				current := <-results
				if current.err != nil {
					continue
				}
				if !admitted {
					validateGVisorClosedPortError(t, family, current.packet, current.remote, current.monitor.address, current.monitor.sourcePort)
					admitted = true
					cancel()
				}
			}
			if !admitted {
				t.Fatal("multi-source flood starved every unrelated gVisor source")
			}
			if rateLimited := network.mipstack.Stats().RateLimitedControlResponses; rateLimited == 0 {
				t.Fatal("multi-source flood did not exercise ICMP response rate limiting")
			}
		})
	}
}

func validateGVisorClosedPortError(t *testing.T, family interopFamily, packet []byte, remote tcpip.FullAddress, destination netip.Addr, sourcePort uint16) {
	t.Helper()
	if family.mipstackAddress.Is4() {
		if len(packet) < header.IPv4MinimumSize {
			t.Fatalf("short gVisor IPv4 packet: %d bytes", len(packet))
		}
		outer := header.IPv4(packet)
		headerSize := int(outer.HeaderLength())
		if headerSize < header.IPv4MinimumSize || len(packet) < headerSize+header.ICMPv4MinimumSize {
			t.Fatalf("short gVisor IPv4 ICMP packet: %d bytes", len(packet))
		}
		if outer.SourceAddress() != gvisorAddress(family.mipstackAddress) || outer.DestinationAddress() != gvisorAddress(destination) || outer.TransportProtocol() != header.ICMPv4ProtocolNumber {
			t.Fatalf("gVisor IPv4 ICMP outer packet = %v -> %v, protocol %d", outer.SourceAddress(), outer.DestinationAddress(), outer.TransportProtocol())
		}
		if checksum.Checksum(packet[:headerSize], 0) != 0xffff {
			t.Fatal("gVisor IPv4 outer header checksum is invalid")
		}
	}
	message, err := stripGVisorRawHeader(family, packet)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Addr != gvisorAddress(family.mipstackAddress) {
		t.Fatalf("gVisor ICMP response source = %v, want %v", remote.Addr, family.mipstackAddress)
	}
	if family.mipstackAddress.Is4() {
		if len(message) < header.ICMPv4MinimumSize || checksum.Checksum(message, 0) != 0xffff {
			t.Fatalf("invalid gVisor ICMPv4 response checksum or length: %d bytes", len(message))
		}
		icmpMessage := header.ICMPv4(message)
		if icmpMessage.Type() != header.ICMPv4DstUnreachable || icmpMessage.Code() != header.ICMPv4PortUnreachable {
			t.Fatalf("gVisor ICMPv4 response type/code = %d/%d", icmpMessage.Type(), icmpMessage.Code())
		}
	} else {
		if len(message) < header.ICMPv6MinimumSize || !validIPv6RawChecksum(message, family.mipstackAddress, destination, mipstack.ProtocolICMPv6) {
			t.Fatalf("invalid gVisor ICMPv6 response checksum or length: %d bytes", len(message))
		}
		icmpMessage := header.ICMPv6(message)
		if icmpMessage.Type() != header.ICMPv6DstUnreachable || icmpMessage.Code() != header.ICMPv6PortUnreachable {
			t.Fatalf("gVisor ICMPv6 response type/code = %d/%d", icmpMessage.Type(), icmpMessage.Code())
		}
	}
	quote := message[8:]
	if destination.Is4() {
		if len(quote) < header.IPv4MinimumSize {
			t.Fatalf("short quoted IPv4 UDP packet: %d bytes", len(quote))
		}
		quoted := header.IPv4(quote)
		if quoted.SourceAddress() != gvisorAddress(destination) || quoted.DestinationAddress() != gvisorAddress(family.mipstackAddress) || quoted.TransportProtocol() != header.UDPProtocolNumber {
			t.Fatalf("quoted IPv4 UDP packet = %v -> %v, protocol %d", quoted.SourceAddress(), quoted.DestinationAddress(), quoted.TransportProtocol())
		}
		if len(quote) < int(quoted.HeaderLength())+header.UDPMinimumSize {
			t.Fatalf("short quoted IPv4 UDP header: %d bytes", len(quote))
		}
		quotedUDP := header.UDP(quote[quoted.HeaderLength():])
		if quotedUDP.SourcePort() != sourcePort || quotedUDP.DestinationPort() != 53000 {
			t.Fatalf("quoted IPv4 UDP ports = %d -> %d, want %d -> 53000", quotedUDP.SourcePort(), quotedUDP.DestinationPort(), sourcePort)
		}
	} else {
		if len(quote) < header.IPv6MinimumSize+header.UDPMinimumSize {
			t.Fatalf("short quoted IPv6 UDP packet: %d bytes", len(quote))
		}
		quoted := header.IPv6(quote)
		if quoted.SourceAddress() != gvisorAddress(destination) || quoted.DestinationAddress() != gvisorAddress(family.mipstackAddress) || quoted.TransportProtocol() != header.UDPProtocolNumber {
			t.Fatalf("quoted IPv6 UDP packet = %v -> %v, protocol %d", quoted.SourceAddress(), quoted.DestinationAddress(), quoted.TransportProtocol())
		}
		quotedUDP := header.UDP(quote[header.IPv6MinimumSize:])
		if quotedUDP.SourcePort() != sourcePort || quotedUDP.DestinationPort() != 53000 {
			t.Fatalf("quoted IPv6 UDP ports = %d -> %d, want %d -> 53000", quotedUDP.SourcePort(), quotedUDP.DestinationPort(), sourcePort)
		}
	}
}

func validatePortUnreachable(t *testing.T, family interopFamily, packet []byte, source, target netip.AddrPort) {
	t.Helper()
	var quote []byte
	if family.mipstackAddress.Is4() {
		if len(packet) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
			t.Fatalf("short IPv4 Port Unreachable: %d bytes", len(packet))
		}
		outer := header.IPv4(packet)
		if outer.SourceAddress() != gvisorAddress(family.mipstackAddress) || outer.DestinationAddress() != gvisorAddress(family.gvisorAddress) {
			t.Fatalf("IPv4 Port Unreachable outer addresses = %v -> %v", outer.SourceAddress(), outer.DestinationAddress())
		}
		icmp := header.ICMPv4(packet[outer.HeaderLength():])
		if icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable {
			t.Fatalf("IPv4 Port Unreachable type/code = %d/%d", icmp.Type(), icmp.Code())
		}
		quote = icmp[header.ICMPv4MinimumSize:]
	} else {
		if len(packet) < header.IPv6MinimumSize+header.ICMPv6MinimumSize {
			t.Fatalf("short IPv6 Port Unreachable: %d bytes", len(packet))
		}
		outer := header.IPv6(packet)
		if outer.SourceAddress() != gvisorAddress(family.mipstackAddress) || outer.DestinationAddress() != gvisorAddress(family.gvisorAddress) {
			t.Fatalf("IPv6 Port Unreachable outer addresses = %v -> %v", outer.SourceAddress(), outer.DestinationAddress())
		}
		icmp := header.ICMPv6(packet[header.IPv6MinimumSize:])
		if icmp.Type() != header.ICMPv6DstUnreachable || icmp.Code() != header.ICMPv6PortUnreachable {
			t.Fatalf("IPv6 Port Unreachable type/code = %d/%d", icmp.Type(), icmp.Code())
		}
		quote = icmp[header.ICMPv6MinimumSize:]
	}
	if len(quote) < header.IPv4MinimumSize+header.UDPMinimumSize {
		t.Fatalf("short Port Unreachable quote: %d bytes", len(quote))
	}
	transportOffset := header.IPv6MinimumSize
	if source.Addr().Is4() {
		inner := header.IPv4(quote)
		if inner.SourceAddress() != gvisorAddress(source.Addr()) || inner.DestinationAddress() != gvisorAddress(target.Addr()) {
			t.Fatalf("quoted IPv4 addresses = %v -> %v", inner.SourceAddress(), inner.DestinationAddress())
		}
		transportOffset = int(inner.HeaderLength())
	} else {
		inner := header.IPv6(quote)
		if inner.SourceAddress() != gvisorAddress(source.Addr()) || inner.DestinationAddress() != gvisorAddress(target.Addr()) {
			t.Fatalf("quoted IPv6 addresses = %v -> %v", inner.SourceAddress(), inner.DestinationAddress())
		}
	}
	if len(quote) < transportOffset+header.UDPMinimumSize {
		t.Fatalf("Port Unreachable quote lacks UDP header: %d bytes", len(quote))
	}
	if sourcePort, targetPort := binary.BigEndian.Uint16(quote[transportOffset:]), binary.BigEndian.Uint16(quote[transportOffset+2:]); sourcePort != source.Port() || targetPort != target.Port() {
		t.Fatalf("quoted UDP ports = %d -> %d, want %d -> %d", sourcePort, targetPort, source.Port(), target.Port())
	}
}

func udpHeaderOffset(packet []byte) (int, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	var offset int
	switch packet[0] >> 4 {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return 0, false
		}
		ipHeader := header.IPv4(packet)
		if ipHeader.TransportProtocol() != header.UDPProtocolNumber {
			return 0, false
		}
		offset = int(ipHeader.HeaderLength())
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize || header.IPv6(packet).TransportProtocol() != header.UDPProtocolNumber {
			return 0, false
		}
		offset = header.IPv6MinimumSize
	default:
		return 0, false
	}
	return offset, len(packet) >= offset+header.UDPMinimumSize
}

func openUDPPair(t *testing.T, ctx context.Context, network *interopNetwork, family interopFamily, mipstackConnected bool) (net.Conn, net.PacketConn) {
	t.Helper()
	return openUDPPairAt(t, ctx, network, family, mipstackConnected, 42001, 42002)
}

func openUDPPairAt(t *testing.T, ctx context.Context, network *interopNetwork, family interopFamily, mipstackConnected bool, mipstackPort, gvisorPort uint16) (net.Conn, net.PacketConn) {
	t.Helper()

	if mipstackConnected {
		gvisorLocal := gvisorFullAddress(family.gvisorAddress, gvisorPort)
		gvisorConnection, err := gonet.DialUDP(
			network.gvisor,
			&gvisorLocal,
			nil,
			family.networkProtocol,
		)
		if err != nil {
			t.Fatalf("listen with gVisor UDP: %v", err)
		}
		mipstackConnection, err := network.mipstack.DialUDP(
			ctx,
			family.udpNetwork,
			netipAddrPort(family.mipstackAddress, mipstackPort),
			netipAddrPort(family.gvisorAddress, gvisorPort),
		)
		if err != nil {
			_ = gvisorConnection.Close()
			t.Fatalf("dial with mipstack UDP: %v", err)
		}
		return mipstackConnection, gvisorConnection
	}

	mipstackConnection, err := network.mipstack.ListenUDP(
		ctx,
		family.udpNetwork,
		netipAddrPort(family.mipstackAddress, mipstackPort),
	)
	if err != nil {
		t.Fatalf("listen with mipstack UDP: %v", err)
	}
	gvisorLocal := gvisorFullAddress(family.gvisorAddress, gvisorPort)
	mipstackRemote := gvisorFullAddress(family.mipstackAddress, mipstackPort)
	gvisorConnection, err := gonet.DialUDP(
		network.gvisor,
		&gvisorLocal,
		&mipstackRemote,
		family.networkProtocol,
	)
	if err != nil {
		_ = mipstackConnection.Close()
		t.Fatalf("dial with gVisor UDP: %v", err)
	}
	return gvisorConnection, mipstackConnection
}

func exerciseUDP(t *testing.T, connected net.Conn, unconnected net.PacketConn, mtu uint32) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	if err := connected.SetDeadline(deadline); err != nil {
		t.Fatalf("set connected UDP deadline: %v", err)
	}
	if err := unconnected.SetDeadline(deadline); err != nil {
		t.Fatalf("set unconnected UDP deadline: %v", err)
	}

	buffer := make([]byte, 65535)
	for index, size := range []int{0, 37, fragmentedInteropPayloadSize(mtu, 12_000)} {
		request := patternedPayload(size, byte(31+index))
		response := patternedPayload(size+19, byte(97+index))
		written, err := connected.Write(request)
		if err != nil || written != len(request) {
			t.Fatalf("connected UDP write %d bytes: n=%d, error=%v", size, written, err)
		}
		read, source, err := unconnected.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("unconnected UDP read %d bytes: %v", size, err)
		}
		if !bytes.Equal(buffer[:read], request) {
			t.Fatalf("unconnected UDP request mismatch: got %d bytes, want %d", read, len(request))
		}
		written, err = unconnected.WriteTo(response, source)
		if err != nil || written != len(response) {
			t.Fatalf("unconnected UDP write %d bytes: n=%d, error=%v", len(response), written, err)
		}
		read, err = connected.Read(buffer)
		if err != nil {
			t.Fatalf("connected UDP read %d bytes: %v", len(response), err)
		}
		if !bytes.Equal(buffer[:read], response) {
			t.Fatalf("connected UDP response mismatch: got %d bytes, want %d", read, len(response))
		}
	}
}
