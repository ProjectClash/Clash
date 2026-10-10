package gvisorinterop_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

func TestTCPSocketOptionsInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			role := "active"
			if mipstackListens {
				role = "passive"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				outbound := make(chan []byte, 1)
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					mipstackToGVisor: func(packet []byte) bool {
						select {
						case outbound <- append([]byte(nil), packet...):
						default:
						}
						return true
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				options := []mipstack.SocketOption{
					mipstack.SocketOptions.ReadBuffer(32 * 1024), mipstack.SocketOptions.WriteBuffer(48 * 1024),
					mipstack.SocketOptions.KeepAlive(true),
					mipstack.SocketOptions.KeepAliveConfig(mipstack.KeepAliveConfig{Idle: time.Minute, Interval: time.Second, Count: 3}),
					mipstack.SocketOptions.NoDelay(false), mipstack.SocketOptions.CongestionControl(mipstack.CongestionControlReno),
					mipstack.SocketOptions.MaximumPacingRate(8 * 1024 * 1024), mipstack.SocketOptions.TrafficClass(0xba),
				}
				flowLabel := uint32(0)
				if family.mipstackAddress.Is6() {
					flowLabel = 0x34567
					options = append(options, mipstack.SocketOptions.FlowLabel(flowLabel))
				}

				var listener net.Listener
				var err error
				const port = 41121
				if mipstackListens {
					options = append(options, mipstack.SocketOptions.AcceptQueue(4), mipstack.SocketOptions.SYNBacklog(4))
					listener, err = (&mipstack.ListenConfig{Options: options}).ListenTCP(ctx, network.mipstack, family.tcpNetwork, netipAddrPort(family.mipstackAddress, port))
				} else {
					listener, err = gonet.ListenTCP(network.gvisor, gvisorFullAddress(family.gvisorAddress, port), family.networkProtocol)
				}
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				defer listener.Close()
				type acceptResult struct {
					connection net.Conn
					err        error
				}
				accepted := make(chan acceptResult, 1)
				go func() {
					connection, acceptErr := listener.Accept()
					accepted <- acceptResult{connection: connection, err: acceptErr}
				}()

				var client net.Conn
				if mipstackListens {
					client, err = gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.mipstackAddress, port), family.networkProtocol)
				} else {
					client, err = (&mipstack.Dialer{Options: options}).DialTCP(ctx, network.mipstack, family.tcpNetwork,
						netipAddrPort(family.mipstackAddress, 0), netipAddrPort(family.gvisorAddress, port))
				}
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				defer client.Close()
				var server net.Conn
				select {
				case result := <-accepted:
					if result.err != nil {
						t.Fatalf("accept: %v", result.err)
					}
					server = result.connection
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 128*1024)
				var connection *mipstack.TCPConn
				if mipstackListens {
					connection = server.(*mipstack.TCPConn)
				} else {
					connection = client.(*mipstack.TCPConn)
				}
				info := connection.Info()
				if info.ReceiveBufferCapacity != 32*1024 || info.MaximumReceiveBuffer != 32*1024 ||
					info.SendBufferCapacity != 48*1024 || info.MaximumSendBuffer != 48*1024 ||
					!info.KeepAlive || info.NoDelay || info.CongestionControl != mipstack.CongestionControlReno ||
					info.MaximumPacingRate != 8*1024*1024 || info.TrafficClass != 0xb8 || info.FlowLabel != flowLabel {
					t.Fatalf("mipstack TCP creation policy = %+v", info)
				}
				select {
				case packet := <-outbound:
					validateControlledIPHeader(t, family, packet, 64)
				case <-ctx.Done():
					t.Fatalf("capture socket-option TCP handshake: %v", ctx.Err())
				}
			})
		}
	}
}

func TestUDPSocketOptionsInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			outbound := make(chan []byte, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: func(packet []byte) bool {
					select {
					case outbound <- append([]byte(nil), packet...):
					default:
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			gvisorLocal := gvisorFullAddress(family.gvisorAddress, 42121)
			peer, err := gonet.DialUDP(network.gvisor, &gvisorLocal, nil, family.networkProtocol)
			if err != nil {
				t.Fatalf("listen with gVisor UDP: %v", err)
			}
			defer peer.Close()
			options := []mipstack.SocketOption{
				mipstack.SocketOptions.ReadBuffer(64 * 1024), mipstack.SocketOptions.ReceiveErrors(true),
				mipstack.SocketOptions.PathMTUDiscovery(mipstack.PathMTUDiscoveryWant), mipstack.SocketOptions.HopLimit(41),
				mipstack.SocketOptions.Broadcast(false), mipstack.SocketOptions.MulticastHopLimit(4),
				mipstack.SocketOptions.MulticastLoopback(false), mipstack.SocketOptions.TrafficClass(0xb8),
			}
			flowLabel := uint32(0)
			if family.mipstackAddress.Is6() {
				flowLabel = 0x34567
				options = append(options, mipstack.SocketOptions.FlowLabel(flowLabel))
			}
			connectionNet, err := (&mipstack.Dialer{Options: options}).DialUDP(ctx, network.mipstack, family.udpNetwork,
				netipAddrPort(family.mipstackAddress, 42120), netipAddrPort(family.gvisorAddress, 42121))
			if err != nil {
				t.Fatalf("dial with mipstack UDP: %v", err)
			}
			connection := connectionNet.(*mipstack.UDPConn)
			defer connection.Close()
			exerciseUDP(t, connection, peer, 1500)
			select {
			case packet := <-outbound:
				validateControlledIPHeader(t, family, packet, 41)
			default:
				t.Fatal("socket-option UDP test observed no mipstack output")
			}
			info := connection.Info()
			if info.ReceiveQueueCapacity != 64*1024 || !info.ReceiveErrors || info.PathMTUDiscovery != mipstack.PathMTUDiscoveryWant ||
				info.HopLimit != 41 || info.Broadcast || info.MulticastHopLimit != 4 || info.MulticastLoopback ||
				info.TrafficClass != 0xb8 || info.FlowLabel != flowLabel {
				t.Fatalf("mipstack UDP creation policy = %+v", info)
			}
		})
	}
}

func TestIPSocketOptionsInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			outbound := make(chan []byte, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: func(packet []byte) bool {
					select {
					case outbound <- append([]byte(nil), packet...):
					default:
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			options := []mipstack.SocketOption{
				mipstack.SocketOptions.ReadBuffer(24 * 1024), mipstack.SocketOptions.ReceiveErrors(true),
				mipstack.SocketOptions.PathMTUDiscovery(mipstack.PathMTUDiscoveryWant), mipstack.SocketOptions.HopLimit(41),
				mipstack.SocketOptions.Broadcast(false), mipstack.SocketOptions.MulticastHopLimit(3),
				mipstack.SocketOptions.MulticastLoopback(false), mipstack.SocketOptions.TrafficClass(0xb8),
			}
			flowLabel := uint32(0)
			if family.mipstackAddress.Is6() {
				flowLabel = 0x34567
				options = append(options, mipstack.SocketOptions.FlowLabel(flowLabel))
			}
			connection, err := (&mipstack.ListenConfig{Options: options}).ListenIP(ctx, network.mipstack, family.rawNetwork, family.mipstackAddress)
			if err != nil {
				t.Fatalf("listen with mipstack raw IP: %v", err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatal(err)
			}

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

			request := []byte("socket-option-raw-request")
			if written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write gVisor raw request: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			storage := make([]byte, 256)
			read, source, err := connection.ReadFrom(storage)
			if err != nil || !bytes.Equal(storage[:read], request) {
				t.Fatalf("read mipstack raw request: n=%d source=%v error=%v", read, source, err)
			}
			response := []byte("socket-option-raw-response")
			if written, writeErr := connection.WriteTo(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || written != len(response) {
				t.Fatalf("write mipstack raw response: n=%d error=%v", written, writeErr)
			}
			select {
			case packet := <-outbound:
				validateControlledIPHeader(t, family, packet, 41)
			case <-ctx.Done():
				t.Fatalf("capture socket-option raw IP output: %v", ctx.Err())
			}
			packet, _, err := readGVisorEndpoint(ctx, endpoint, notifications, 512)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := stripGVisorRawHeader(family, packet)
			if err != nil || !bytes.Equal(payload, response) {
				t.Fatalf("read gVisor raw response: payload=%x error=%v", payload, err)
			}
			info := connection.(*mipstack.IPConn).Info()
			if info.ReceiveQueueCapacity != 24*1024 || !info.ReceiveErrors || info.PathMTUDiscovery != mipstack.PathMTUDiscoveryWant ||
				info.HopLimit != 41 || info.Broadcast || info.MulticastHopLimit != 3 || info.MulticastLoopback ||
				info.TrafficClass != 0xb8 || info.FlowLabel != flowLabel {
				t.Fatalf("mipstack IP creation policy = %+v", info)
			}
		})
	}
}

func TestForwarderSocketOptionsInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name+"/tcp", func(t *testing.T) {
			network := newConfiguredForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			accepted := make(chan *mipstack.TCPConn, 1)
			failures := make(chan error, 1)
			forwarder, err := mipstack.NewTCPForwarder(network.mipstack, mipstack.TCPForwarderOptions{}, func(request *mipstack.TCPForwarderRequest) {
				connection, acceptErr := request.Accept(ctx,
					mipstack.SocketOptions.ReadBuffer(20*1024), mipstack.SocketOptions.WriteBuffer(28*1024),
					mipstack.SocketOptions.NoDelay(false), mipstack.SocketOptions.CongestionControl(mipstack.CongestionControlReno),
				)
				if acceptErr != nil {
					failures <- acceptErr
					return
				}
				accepted <- connection
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			client, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.forwardAddress, 44121), family.networkProtocol)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var server *mipstack.TCPConn
			select {
			case server = <-accepted:
			case err = <-failures:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer server.Close()
			exerciseFullDuplexTCP(t, client, server, 64*1024)
			if info := server.Info(); info.ReceiveBufferCapacity != 20*1024 || info.SendBufferCapacity != 28*1024 || info.NoDelay || info.CongestionControl != mipstack.CongestionControlReno {
				t.Fatalf("forwarded TCP creation policy = %+v", info)
			}
		})

		t.Run(family.name+"/udp", func(t *testing.T) {
			network := newConfiguredForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			accepted := make(chan *mipstack.UDPConn, 1)
			failures := make(chan error, 1)
			forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
				connection, acceptErr := request.Accept(
					mipstack.SocketOptions.ReadBuffer(12*1024), mipstack.SocketOptions.ReceiveErrors(true),
					mipstack.SocketOptions.HopLimit(33), mipstack.SocketOptions.TrafficClass(0x2e),
				)
				if acceptErr != nil {
					failures <- acceptErr
					return
				}
				accepted <- connection
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			local := gvisorFullAddress(family.gvisorAddress, 44122)
			remote := gvisorFullAddress(family.forwardAddress, 44123)
			client, err := gonet.DialUDP(network.gvisor, &local, &remote, family.networkProtocol)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err = client.Write([]byte("forwarded-options")); err != nil {
				t.Fatal(err)
			}
			var server *mipstack.UDPConn
			select {
			case server = <-accepted:
			case err = <-failures:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			payload := make([]byte, 64)
			if read, readErr := server.Read(payload); readErr != nil || string(payload[:read]) != "forwarded-options" {
				t.Fatalf("read forwarded UDP request: %q, %v", payload[:read], readErr)
			}
			if _, err = server.Write([]byte("forwarded-reply")); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if read, readErr := client.Read(payload); readErr != nil || string(payload[:read]) != "forwarded-reply" {
				t.Fatalf("read forwarded UDP reply: %q, %v", payload[:read], readErr)
			}
			if info := server.Info(); info.ReceiveQueueCapacity != 12*1024 || !info.ReceiveErrors || info.HopLimit != 33 || info.TrafficClass != 0x2e {
				t.Fatalf("forwarded UDP creation policy = %+v", info)
			}
		})
	}
}
