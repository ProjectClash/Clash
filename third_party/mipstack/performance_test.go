package mipstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func benchmarkTCPControllerConnection(b *testing.B, algorithm string, mtu uint32, ipv6 bool, offload RXChecksumOffload) (net.Conn, *Stack, *stackBridge) {
	return benchmarkTCPProfileConnection(b, TCPSocketDefaults{CongestionControl: algorithm}, mtu, ipv6, offload)
}

func benchmarkTCPProfileConnection(b *testing.B, defaults TCPSocketDefaults, mtu uint32, ipv6 bool, offload RXChecksumOffload) (net.Conn, *Stack, *stackBridge) {
	b.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.201")
	serverAddress := netip.MustParseAddr("192.0.2.202")
	network := "tcp4"
	if ipv6 {
		clientAddress = netip.MustParseAddr("2001:db8::201")
		serverAddress = netip.MustParseAddr("2001:db8::202")
		network = "tcp6"
	}
	client, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(clientAddress, clientAddress.BitLen())},
		MTU:            mtu,
		TCP:            defaults,
	})
	if err != nil {
		b.Fatal(err)
	}
	server, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, serverAddress.BitLen())},
		MTU:            mtu,
		TCP:            defaults,
	})
	if err != nil {
		b.Fatal(err)
	}
	client.SetRXChecksumOffload(offload)
	server.SetRXChecksumOffload(offload)
	if err = client.Start(); err != nil {
		b.Fatal(err)
	}
	if err = server.Start(); err != nil {
		b.Fatal(err)
	}
	bridge := &stackBridge{client: client, peer: server, done: make(chan struct{}, 2)}
	go bridge.run(client, server, true)
	go bridge.run(server, client, false)
	listener, err := server.ListenTCP(context.Background(), network, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		b.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- connection
		_, _ = io.Copy(connection, connection)
		_ = connection.Close()
	}()
	connection, err := client.DialTCP(context.Background(), network, netip.AddrPort{}, netip.AddrPortFrom(serverAddress, listener.Addr().(*net.TCPAddr).AddrPort().Port()))
	if err != nil {
		b.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		b.Fatal("benchmark accept failed")
	}
	b.Cleanup(func() {
		_ = connection.Close()
		_ = serverConnection.Close()
		_ = listener.Close()
		_ = client.Close()
		_ = server.Close()
		<-bridge.done
		<-bridge.done
	})
	return connection, server, bridge
}

func BenchmarkTCPControllerThroughput(b *testing.B) {
	const size = 4 * 1024 * 1024
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(string(algorithm), func(b *testing.B) {
			connection, peer, bridge := benchmarkTCPControllerConnection(b, algorithm, defaultMTU, false, RXChecksumOffload{})
			payload := bytes.Repeat([]byte{0x5a}, size)
			received := make([]byte, size)
			b.SetBytes(2 * size)
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				writeDone := make(chan error, 1)
				go func() {
					_, writeErr := connection.Write(payload)
					writeDone <- writeErr
				}()
				if _, err := io.ReadFull(connection, received); err != nil {
					b.Fatal(err)
				}
				if err := <-writeDone; err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(received, payload) {
					b.Fatal("echo payload mismatch")
				}
			}
			if tcp, ok := connection.(*TCPConn); ok {
				info := tcp.Info()
				stats := tcp.stack.Stats()
				peerStats := peer.Stats()
				b.ReportMetric(float64(info.CongestionWindow), "cwnd-B")
				b.ReportMetric(float64(info.DeliveryRate), "delivery-B/s")
				b.ReportMetric(float64(info.BytesInFlight), "flight-B")
				b.ReportMetric(float64(info.PacingRate), "pacing-B/s")
				b.ReportMetric(float64(info.SchedulerLimitedEvents), "scheduler-limited-events")
				b.ReportMetric(float64(info.SlowStartThreshold), "ssthresh-B")
				b.ReportMetric(float64(info.RTT)/float64(time.Microsecond), "rtt-us")
				b.ReportMetric(float64(info.Retransmissions), "retransmissions")
				b.ReportMetric(float64(info.InboundQueueDrops), "connection-queue-drops")
				b.ReportMetric(float64(stats.InboundDroppedPackets), "rx-drops")
				b.ReportMetric(float64(stats.TCPInboundQueueDrops), "queue-drops")
				b.ReportMetric(float64(peerStats.InboundDroppedPackets), "peer-rx-drops")
				b.ReportMetric(float64(peerStats.TCPInboundQueueDrops), "peer-queue-drops")
				b.ReportMetric(float64(stats.TCPSACKRetransmissions), "sack-retransmissions")
				b.ReportMetric(float64(stats.TCPRACKRetransmissions), "rack-retransmissions")
				b.ReportMetric(float64(stats.TCPTailLossProbes), "tail-loss-probes")
				b.ReportMetric(float64(info.SendBufferCapacity), "send-buffer-B")
				b.ReportMetric(float64(info.InboundQueuePeak), "inbound-queue-peak-B")
				bridge.mu.Lock()
				b.ReportMetric(float64(bridge.clientGaps), "wire-gaps")
				b.ReportMetric(float64(bridge.clientRepeats), "wire-repeats")
				b.ReportMetric(float64(bridge.peerSACKs), "peer-sack-acks")
				b.ReportMetric(float64(bridge.peerDSACKs), "peer-dsack-acks")
				bridge.mu.Unlock()
			}
		})
	}
}

func BenchmarkTCPControllerJumboStream(b *testing.B) {
	const size = 4 * 1024 * 1024
	for _, mtu := range []uint32{1500, 9000, 65535} {
		b.Run(fmt.Sprintf("mtu-%d", mtu), func(b *testing.B) {
			connection, peer, _ := benchmarkTCPControllerConnection(b, CongestionControlCUBIC, mtu, false, RXChecksumOffload{})
			payload := bytes.Repeat([]byte{0x6a}, size)
			received := make([]byte, size)
			b.SetBytes(2 * size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				writeDone := make(chan error, 1)
				go func() {
					_, writeErr := connection.Write(payload)
					writeDone <- writeErr
				}()
				if _, err := io.ReadFull(connection, received); err != nil {
					b.Fatal(err)
				}
				if err := <-writeDone; err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if !bytes.Equal(received, payload) {
				b.Fatal("echo payload mismatch")
			}
			if tcp, ok := connection.(*TCPConn); ok {
				info := tcp.Info()
				stats, peerStats := tcp.stack.Stats(), peer.Stats()
				b.ReportMetric(float64(info.Retransmissions), "retransmissions")
				b.ReportMetric(float64(info.RTT)/float64(time.Microsecond), "rtt-us")
				b.ReportMetric(float64(info.InboundQueueDrops), "connection-queue-drops")
				b.ReportMetric(float64(info.InboundQueuePeak), "inbound-queue-peak-B")
				b.ReportMetric(float64(stats.TCPTailLossProbes), "tail-loss-probes")
				b.ReportMetric(float64(stats.TCPInboundQueueDrops), "queue-drops")
				b.ReportMetric(float64(peerStats.TCPInboundQueueDrops), "peer-queue-drops")
			}
		})
	}
}

func BenchmarkTCPControllerLatency(b *testing.B) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(string(algorithm), func(b *testing.B) {
			for _, requestSize := range []int{64, 512, 1200, 2400, 16 * 1024} {
				b.Run(fmt.Sprintf("%dB", requestSize), func(b *testing.B) {
					connection, _, _ := benchmarkTCPControllerConnection(b, algorithm, defaultMTU, false, RXChecksumOffload{})
					_ = connection.SetDeadline(time.Now().Add(time.Minute))
					request := bytes.Repeat([]byte{0x5a}, requestSize)
					response := make([]byte, requestSize)
					b.SetBytes(int64(2 * requestSize))
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						if _, err := connection.Write(request); err != nil {
							b.Fatal(err)
						}
						if _, err := io.ReadFull(connection, response); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func benchmarkTCPControllerConnections(b *testing.B, algorithm string, count int) []net.Conn {
	b.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.211")
	serverAddress := netip.MustParseAddr("192.0.2.212")
	client, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(clientAddress, 32)}, TCP: TCPSocketDefaults{CongestionControl: algorithm}})
	if err != nil {
		b.Fatal(err)
	}
	server, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
		TCP: TCPSocketDefaults{
			CongestionControl: algorithm,
			AcceptQueue: count,
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = client.Start(); err != nil {
		b.Fatal(err)
	}
	if err = server.Start(); err != nil {
		b.Fatal(err)
	}
	bridge := &stackBridge{client: client, peer: server, done: make(chan struct{}, 2)}
	go bridge.run(client, server, true)
	go bridge.run(server, client, false)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		b.Fatal(err)
	}
	accepted := make(chan net.Conn, count)
	acceptErrors := make(chan error, 1)
	go func() {
		for index := 0; index < count; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				acceptErrors <- acceptErr
				return
			}
			accepted <- connection
			go func(connection net.Conn) { _, _ = io.Copy(connection, connection) }(connection)
		}
		acceptErrors <- nil
	}()
	endpoint := netip.AddrPortFrom(serverAddress, listener.Addr().(*net.TCPAddr).AddrPort().Port())
	connections := make([]net.Conn, count)
	dialErrors := make(chan error, count)
	dialLimit := make(chan struct{}, 32)
	for index := range connections {
		go func(index int) {
			dialLimit <- struct{}{}
			connection, dialErr := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, endpoint)
			<-dialLimit
			connections[index] = connection
			dialErrors <- dialErr
		}(index)
	}
	for range connections {
		if err = <-dialErrors; err != nil {
			b.Fatal(err)
		}
	}
	serverConnections := make([]net.Conn, 0, count)
	for len(serverConnections) < count {
		select {
		case connection := <-accepted:
			serverConnections = append(serverConnections, connection)
		case err = <-acceptErrors:
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Cleanup(func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
		for _, connection := range serverConnections {
			_ = connection.Close()
		}
		_ = listener.Close()
		_ = client.Close()
		_ = server.Close()
		<-bridge.done
		<-bridge.done
	})
	return connections
}

func BenchmarkTCPControllerConcurrency(b *testing.B) {
	const size = 128 * 1024
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, count := range []int{16, 64, 256, 512, 1024, 2048, 4096, 8192} {
			b.Run(fmt.Sprintf("%s-%d", algorithm, count), func(b *testing.B) {
				connections := benchmarkTCPControllerConnections(b, algorithm, count)
				payload := bytes.Repeat([]byte{0x6b}, size)
				b.SetBytes(int64(2 * size * count))
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					results := make(chan error, count)
					for _, connection := range connections {
						go func(connection net.Conn) {
							_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
							writeDone := make(chan error, 1)
							go func() {
								_, writeErr := connection.Write(payload)
								writeDone <- writeErr
							}()
							received := make([]byte, size)
							_, readErr := io.ReadFull(connection, received)
							if writeErr := <-writeDone; readErr == nil {
								readErr = writeErr
							}
							if readErr == nil && !bytes.Equal(received, payload) {
								readErr = errors.New("echo payload mismatch")
							}
							results <- readErr
						}(connection)
					}
					for range connections {
						if err := <-results; err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func BenchmarkPacketDeviceBatchRead(b *testing.B) {
	for _, mtu := range []int{1500, 2048, 2049, 9000, 16384, 32768, 65535} {
		payloadSize := 1200
		if mtu > 1500 {
			payloadSize = mtu - 20 - udpHeaderSize
		}
		b.Run(fmt.Sprintf("mtu-%d", mtu), func(b *testing.B) {
			for _, burst := range []int{deviceBatchSize, outboundPacketQueue} {
				b.Run(fmt.Sprintf("burst-%d", burst), func(b *testing.B) {
					for _, batch := range []int{1, deviceBatchSize} {
						b.Run(fmt.Sprintf("read-%d", batch), func(b *testing.B) {
							local := netip.MustParseAddr("192.0.2.221")
							remote := netip.MustParseAddrPort("192.0.2.222:9000")
							stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: uint32(mtu)})
							if err != nil {
								b.Fatal(err)
							}
							if err = stack.Start(); err != nil {
								b.Fatal(err)
							}
							connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
							if err != nil {
								b.Fatal(err)
							}
							b.Cleanup(func() {
								_ = connection.Close()
								_ = stack.Close()
							})
							payload := make([]byte, payloadSize)
							buffers := make([][]byte, batch)
							for index := range buffers {
								buffers[index] = make([]byte, mtu)
							}
							sizes := make([]int, batch)
							b.SetBytes(int64(payloadSize * burst))
							b.ReportAllocs()
							b.ResetTimer()
							for iteration := 0; iteration < b.N; iteration++ {
								for packet := 0; packet < burst; packet++ {
									if _, err = connection.Write(payload); err != nil {
										b.Fatal(err)
									}
								}
								read := 0
								for read < burst {
									count, readErr := stack.Read(buffers, sizes, 0)
									if readErr != nil {
										b.Fatal(readErr)
									}
									read += count
								}
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkTCPLocalLoopback(b *testing.B) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, mtu := range []uint32{1500, 9000, 65535} {
			b.Run(fmt.Sprintf("%s/mtu-%d", algorithm, mtu), func(b *testing.B) {
				local := netip.MustParseAddr("192.0.2.223")
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: mtu,
					TCP: TCPSocketDefaults{CongestionControl: algorithm}})
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = stack.Close() })
				if err = stack.Start(); err != nil {
					b.Fatal(err)
				}
				listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 0))
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = listener.Close() })
				client, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = client.Close() })
				server, err := listener.Accept()
				if err != nil {
					b.Fatal(err)
				}
				if err = client.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
					b.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(server, server)
					close(done)
				}()
				b.Cleanup(func() { _ = server.Close(); <-done })
				payload := bytes.Repeat([]byte{0x5a}, 32*1024)
				received := make([]byte, len(payload))
				b.SetBytes(int64(2 * len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					if _, err = client.Write(payload); err != nil {
						b.Fatal(err)
					}
					if _, err = io.ReadFull(client, received); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				stats := stack.Stats()
				if !bytes.Equal(received, payload) || stats.LoopbackPackets == 0 {
					b.Fatal("local TCP did not deliver the expected payload through loopback")
				}
				clientInfo, serverInfo := client.(*TCPConn).Info(), server.(*TCPConn).Info()
				b.ReportMetric(float64(clientInfo.InboundQueuePeak), "client-inbound-queue-peak-B")
				b.ReportMetric(float64(serverInfo.InboundQueuePeak), "server-inbound-queue-peak-B")
				b.ReportMetric(float64(stats.LoopbackPackets)/float64(b.N), "loopback-packets/op")
				b.ReportMetric(float64(stats.TCPRetransmissions), "retransmissions")
				b.ReportMetric(float64(stats.TCPTailLossProbes), "tail-loss-probes")
				b.ReportMetric(float64(stats.LoopbackQueueDrops), "loopback-queue-drops")
				b.ReportMetric(float64(stats.TCPInboundQueueDrops), "queue-drops")
			})
		}
	}
}

func BenchmarkUDPLocalLoopback(b *testing.B) {
	for _, mtu := range []uint32{1500, 4064, 9000, 65535} {
		for _, size := range []int{64, int(mtu) - 28} {
			b.Run(fmt.Sprintf("mtu-%d/%dB", mtu, size), func(b *testing.B) {
				local := netip.MustParseAddr("192.0.2.224")
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: mtu})
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = stack.Close() })
				if err = stack.Start(); err != nil {
					b.Fatal(err)
				}
				server, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 0))
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = server.Close() })
				client, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, server.LocalAddr().(*net.UDPAddr).AddrPort())
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = client.Close() })
				if err = server.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
					b.Fatal(err)
				}
				payload := bytes.Repeat([]byte{0x5a}, size)
				received := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					if _, err = client.Write(payload); err != nil {
						b.Fatal(err)
					}
					if n, _, readErr := server.ReadFrom(received); readErr != nil || n != size {
						b.Fatalf("local UDP read = %d, %v", n, readErr)
					}
				}
				b.StopTimer()
				if !bytes.Equal(received, payload) || stack.Stats().LoopbackPackets == 0 {
					b.Fatal("local UDP did not deliver the expected payload through loopback")
				}
			})
		}
	}
}

type rxChecksumBenchmarkPolicy struct {
	name    string
	offload RXChecksumOffload
}

func benchmarkRXChecksumPolicies(ipv4 bool, setProtocol func(*RXChecksumOffload, bool) *RXChecksumOffload) []rxChecksumBenchmarkPolicy {
	policies := []rxChecksumBenchmarkPolicy{{name: "none"}}
	for _, category := range []struct {
		name string
		set  func(*RXChecksumOffload, bool) *RXChecksumOffload
	}{
		{"ipv4-header", (*RXChecksumOffload).SetIPv4Header},
		{"tcp", (*RXChecksumOffload).SetTCP},
		{"udp", (*RXChecksumOffload).SetUDP},
		{"icmpv4", (*RXChecksumOffload).SetICMPv4},
		{"icmpv6", (*RXChecksumOffload).SetICMPv6},
		{"igmp", (*RXChecksumOffload).SetIGMP},
	} {
		policy := rxChecksumBenchmarkPolicy{name: category.name}
		category.set(&policy.offload, true)
		policies = append(policies, policy)
	}
	if ipv4 {
		policy := rxChecksumBenchmarkPolicy{name: "header-and-protocol"}
		policy.offload.SetIPv4Header(true)
		setProtocol(&policy.offload, true)
		policies = append(policies, policy)
	}
	all := rxChecksumBenchmarkPolicy{name: "all"}
	all.offload.SetIPv4Header(true).SetTCP(true).SetUDP(true).SetICMPv4(true).SetICMPv6(true).SetIGMP(true)
	return append(policies, all)
}

func BenchmarkRXChecksumOffload(b *testing.B) {
	local4, remote4 := netip.MustParseAddr("192.0.2.225"), netip.MustParseAddr("192.0.2.226")
	local6, remote6 := netip.MustParseAddr("2001:db8::225"), netip.MustParseAddr("2001:db8::226")
	for _, traffic := range []struct {
		name, family, network string
		local, remote         netip.Addr
		protocol              byte
		sizes                 []int
		set                   func(*RXChecksumOffload, bool) *RXChecksumOffload
		vector                string
	}{
		{"udp", "ipv4", "udp4", local4, remote4, ProtocolUDP, []int{64, 1400, 8900, 65400}, (*RXChecksumOffload).SetUDP, ""},
		{"udp", "ipv6", "udp6", local6, remote6, ProtocolUDP, []int{64, 1400, 8900, 65400}, (*RXChecksumOffload).SetUDP, ""},
		{"icmp", "ipv4", "ip4:icmp", local4, remote4, ProtocolICMPv4, []int{64, 1400, 8900, 65400}, (*RXChecksumOffload).SetICMPv4, ""},
		{"icmp", "ipv6", "ip6:ipv6-icmp", local6, remote6, ProtocolICMPv6, []int{64, 1400, 8900, 65400}, (*RXChecksumOffload).SetICMPv6, ""},
		{"igmp", "ipv4", "ip4:2", local4, remote4, ProtocolIGMP, []int{8}, (*RXChecksumOffload).SetIGMP,
			"4500001c00000000010217ddc0000202e00000011100eeff00000000"},
		{"mld", "ipv6", "ip6:ipv6-icmp", netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2"), ProtocolICMPv6, []int{24}, (*RXChecksumOffload).SetICMPv6,
			"6000000000200001fe800000000000000000000000000002ff020000000000000000000000000001" +
				"3a0005020000010082007c3e03e8000000000000000000000000000000000000"},
	} {
		for _, size := range traffic.sizes {
			var packet, payload []byte
			if traffic.vector != "" {
				packet = mustCodecVector(b, traffic.vector)
				parsed, err := ParseIPPacket(packet)
				if err != nil {
					b.Fatal(err)
				}
				_, payload, err = parsed.UpperLayer()
				if err != nil || len(payload) != size {
					b.Fatalf("control vector payload = %d, %v", len(payload), err)
				}
			} else if traffic.protocol == ProtocolUDP {
				payload = bytes.Repeat([]byte{0x5a}, size)
				packet = buildTestUDP(traffic.remote, traffic.local, 49000, 49001, payload)
			} else {
				message := ICMPMessage{Source: traffic.remote, Destination: traffic.local}
				if err := message.SetEchoReply(1, 1, bytes.Repeat([]byte{0x5a}, size-8)); err != nil {
					b.Fatal(err)
				}
				payload = mustTestWire(message.MarshalBinary())
				packet = mustTestWire((IPPacket{
					Source: traffic.remote, Destination: traffic.local, Protocol: int(traffic.protocol), HopLimit: 64, Payload: payload,
				}).MarshalBinary())
			}
			for _, batch := range []int{1, 8, deviceBatchSize} {
				for _, policy := range benchmarkRXChecksumPolicies(traffic.local.Is4(), traffic.set) {
					b.Run(fmt.Sprintf("%s/%s/%dB/batch-%d/%s", traffic.name, traffic.family, size, batch, policy.name), func(b *testing.B) {
						stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(traffic.local, traffic.local.BitLen())}, MTU: 65535})
						if err != nil {
							b.Fatal(err)
						}
						b.Cleanup(func() { _ = stack.Close() })
						stack.SetRXChecksumOffload(policy.offload)
						if err = stack.Start(); err != nil {
							b.Fatal(err)
						}
						var receiver net.PacketConn
						if traffic.protocol == ProtocolUDP {
							receiver, err = stack.ListenUDP(context.Background(), traffic.network, netip.AddrPortFrom(traffic.local, 49001))
						} else {
							receiver, err = stack.ListenIP(context.Background(), traffic.network, netip.Addr{})
						}
						if err != nil {
							b.Fatal(err)
						}
						b.Cleanup(func() { _ = receiver.Close() })
						_ = receiver.SetReadDeadline(time.Now().Add(10 * time.Minute))
						packets := make([][]byte, batch)
						for index := range packets {
							packets[index] = packet
						}
						buffer := make([]byte, size)
						b.SetBytes(int64(size * batch))
						b.ReportAllocs()
						b.ResetTimer()
						for iteration := 0; iteration < b.N; iteration++ {
							if n, err := stack.Write(packets, 0); err != nil || n != batch {
								b.Fatalf("Write = %d, %v", n, err)
							}
							for index := 0; index < batch; index++ {
								if n, _, err := receiver.ReadFrom(buffer); err != nil || n != size {
									b.Fatalf("ReadFrom = %d, %v", n, err)
								}
							}
						}
						b.StopTimer()
						if !bytes.Equal(buffer, payload) || stack.Stats().InboundDroppedPackets != 0 {
							b.Fatal("valid input was lost or changed")
						}
						if traffic.vector != "" && stack.multicastSeed == nil {
							b.Fatal("control input did not reach querier tracking")
						}
					})
				}
			}
		}
	}
}

func BenchmarkTCPRXChecksumOffload(b *testing.B) {
	const size = 4 * 1024 * 1024
	for _, ipv6 := range []bool{false, true} {
		family := "ipv4"
		if ipv6 {
			family = "ipv6"
		}
		for _, mtu := range []uint32{1500, 9000, 65535} {
			for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
				for _, policy := range benchmarkRXChecksumPolicies(!ipv6, (*RXChecksumOffload).SetTCP) {
					b.Run(fmt.Sprintf("%s/mtu-%d/%s/%s", family, mtu, algorithm, policy.name), func(b *testing.B) {
						connection, peer, _ := benchmarkTCPControllerConnection(b, algorithm, mtu, ipv6, policy.offload)
						_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))
						payload := bytes.Repeat([]byte{0x5a}, size)
						received := make([]byte, size)
						b.SetBytes(2 * size)
						b.ReportAllocs()
						b.ResetTimer()
						for iteration := 0; iteration < b.N; iteration++ {
							writeDone := make(chan error, 1)
							go func() {
								_, writeErr := connection.Write(payload)
								writeDone <- writeErr
							}()
							if _, err := io.ReadFull(connection, received); err != nil {
								b.Fatal(err)
							}
							if err := <-writeDone; err != nil {
								b.Fatal(err)
							}
						}
						b.StopTimer()
						if !bytes.Equal(received, payload) {
							b.Fatal("echo payload mismatch")
						}
						tcp := connection.(*TCPConn)
						info := tcp.Info()
						stats, peerStats := tcp.stack.Stats(), peer.Stats()
						b.ReportMetric(float64(info.Retransmissions), "retransmissions")
						b.ReportMetric(float64(stats.InboundDroppedPackets+peerStats.InboundDroppedPackets), "rx-drops")
						b.ReportMetric(float64(stats.TCPInboundQueueDrops+peerStats.TCPInboundQueueDrops), "queue-drops")
						b.ReportMetric(float64(stats.TCPTailLossProbes+peerStats.TCPTailLossProbes), "tail-loss-probes")
					})
				}
			}
		}
	}
}
