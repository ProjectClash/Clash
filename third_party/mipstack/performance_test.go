package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type benchmarkRTOController struct {
	algorithm       CongestionController
	window          uint32
	recoveryEntries atomic.Uint32
	timeoutAt       chan time.Time
}

func (c *benchmarkRTOController) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventInitialize {
		event.State.CongestionWindow = c.window
	}
	c.algorithm.HandleCongestionEvent(event)
	if event.Type == CongestionEventTimeout {
		if c.recoveryEntries.Add(1) == 1 {
			c.timeoutAt <- event.Time
		}
	}
}

func BenchmarkTCPRTORecovery(b *testing.B) {
	const mss = 1280
	local := netip.MustParseAddr("192.0.2.211")
	remote := netip.MustParseAddr("192.0.2.212")
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, count := range []int{16, 128, 1024, 8192} {
			b.Run(fmt.Sprintf("%s/segments-%d", algorithm, count), func(b *testing.B) {
				payload := bytes.Repeat([]byte{0x5a}, count*mss)
				var recoveryTime time.Duration
				b.SetBytes(int64(len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				b.StopTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					base, _ := registeredCongestionControlFactory(algorithm)
					definition := base.definition
					var observer *benchmarkRTOController
					definition.New = func(context CongestionControlContext) CongestionController {
						observer = &benchmarkRTOController{
							algorithm: base.definition.New(context), window: uint32(len(payload)),
							timeoutAt: make(chan time.Time, 1),
						}
						return observer
					}
					factory, err := NewCongestionControlFactory(definition)
					if err != nil {
						b.Fatal(err)
					}
					stack, err := New(Config{
						LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
						TCP: TCPSocketDefaults{CongestionControlFactory: factory, SendBuffer: len(payload), MaximumSendBuffer: len(payload)},
					})
					if err != nil {
						b.Fatal(err)
					}
					if err = stack.Start(); err != nil {
						_ = stack.Close()
						b.Fatal(err)
					}
					peerDone := make(chan error, 1)
					go func() {
						peerDone <- func() error {
							buffer := make([]byte, 65535)
							original := make([]bool, count)
							received := make([]bool, count)
							originalCount, prefix := 0, 0
							firstRecoveryACK := true
							synLost := false
							var first uint32
							for {
								sizes := []int{0}
								if _, readErr := stack.Read([][]byte{buffer}, sizes, 0); readErr != nil {
									return readErr
								}
								packet, ok := parseIPPacket(buffer[:sizes[0]], false)
								if !ok || packet.protocol != ProtocolTCP || len(packet.payload) < tcpHeaderSize {
									return fmt.Errorf("invalid outbound TCP packet")
								}
								tcp := packet.payload
								sequence := binary.BigEndian.Uint32(tcp[4:8])
								flags := tcp[13]
								data := tcp[int(tcp[12]>>4)*4:]
								if flags&TCPFlagSYN != 0 {
									if !synLost {
										synLost = true
										continue
									}
									first = sequence + 1
									options := []byte{2, 4, 5, 0, 4, 2, 1, 3, 3, 8}
									if writeErr := writeTestPacket(stack, buildTestTCP(remote, local, 8080, binary.BigEndian.Uint16(tcp[:2]), 100, first, TCPFlagSYN|TCPFlagACK, 65535, options, nil)); writeErr != nil {
										return writeErr
									}
									continue
								}
								if flags&TCPFlagRST != 0 {
									return fmt.Errorf("connection reset during RTO recovery")
								}
								if len(data) != 0 {
									offset := int(sequence - first)
									if offset < 0 || offset >= len(payload) || offset%mss != 0 || len(data) != mss || !bytes.Equal(data, payload[offset:offset+mss]) {
										return fmt.Errorf("invalid recovery payload at offset %d, length %d", offset, len(data))
									}
									index := offset / mss
									if observer.recoveryEntries.Load() == 0 || firstRecoveryACK && index != 0 {
										if !original[index] {
											original[index] = true
											originalCount++
										}
										continue
									}
									if originalCount != count {
										return fmt.Errorf("RTO started after only %d/%d original segments departed", originalCount, count)
									}
									if firstRecoveryACK {
										time.Sleep(time.Millisecond)
										firstRecoveryACK = false
									}
									received[index] = true
									for prefix < count && received[prefix] {
										prefix++
									}
								}
								ackFlags := uint8(TCPFlagACK)
								if prefix == count {
									ackFlags |= TCPFlagFIN
								}
								if writeErr := writeTestPacket(stack, buildTestTCP(remote, local, 8080, binary.BigEndian.Uint16(tcp[:2]), 101, first+uint32(prefix*mss), ackFlags, 65535, nil, nil)); writeErr != nil {
									return writeErr
								}
								if prefix == count {
									return nil
								}
							}
						}()
					}()
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					connection, err := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
					if err != nil {
						cancel()
						_ = stack.Close()
						<-peerDone
						b.Fatal(err)
					}
					deadline, _ := ctx.Deadline()
					_ = connection.SetDeadline(deadline)
					for connection.(*TCPConn).Info().PeerWindow < uint32(len(payload)) {
						select {
						case <-ctx.Done():
							_ = stack.Close()
							<-peerDone
							cancel()
							b.Fatal("scaled peer window was not installed")
						default:
							runtime.Gosched()
						}
					}
					setup := connection.(*TCPConn).Info()
					if setup.RTT != 0 || setup.MinimumRTT != 0 || setup.RetransmissionTimeout != 3*time.Second {
						_ = stack.Close()
						<-peerDone
						cancel()
						b.Fatalf("unexpected initial RTT/RTO: %v/%v, minimum %v", setup.RTT, setup.RetransmissionTimeout, setup.MinimumRTT)
					}
					b.StartTimer()
					written, writeErr := connection.Write(payload)
					select {
					case err = <-peerDone:
						peerDone = nil
					case <-ctx.Done():
						err = ctx.Err()
					}
					if err == nil {
						var buffer [1]byte
						if n, readErr := connection.Read(buffer[:]); n != 0 || readErr != io.EOF {
							err = fmt.Errorf("recovery completion read = %d, %v; want 0, EOF", n, readErr)
						}
					}
					completed := time.Now()
					b.StopTimer()
					info := connection.(*TCPConn).Info()
					_ = stack.Close()
					if peerDone != nil {
						if peerErr := <-peerDone; err == nil {
							err = peerErr
						}
					}
					cancel()
					if err != nil || writeErr != nil || written != len(payload) {
						b.Fatalf("recovery failed: peer %v, write %d/%d: %v, recovery entries %d, info %+v", err, written, len(payload), writeErr, observer.recoveryEntries.Load(), info)
					}
					if observer.recoveryEntries.Load() != 1 || info.BytesAcknowledged != uint64(len(payload)) || info.RetransmissionRecovery || info.FastRecovery || info.SpuriousRecoveryUndos != 0 || info.State != TCPStateCloseWait {
						b.Fatalf("incomplete RTO recovery: recovery entries %d, info %+v", observer.recoveryEntries.Load(), info)
					}
					recoveryTime += completed.Sub(<-observer.timeoutAt)
				}
				if recoveryTime > 0 {
					b.ReportMetric(float64(recoveryTime.Nanoseconds())/float64(b.N)/1e6, "recovery-ms/op")
					b.ReportMetric(float64(len(payload))*float64(b.N)/recoveryTime.Seconds()/(1024*1024), "recovery-MiB/s")
				}
			})
		}
	}
}

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

func BenchmarkTCPFastRecovery(b *testing.B) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, test := range []struct {
			name     string
			segments int
			drops    map[int]bool
		}{
			{name: "SACK", segments: 64, drops: map[int]bool{1: true, 2: true}},
			{name: "RACK", segments: 2, drops: map[int]bool{1: true}},
		} {
			b.Run(algorithm+"/"+test.name, func(b *testing.B) {
				link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.221"), netip.MustParseAddr("192.0.2.222"))
				link.mu.Lock()
				link.echoTCP, link.sackTCP, link.dropTCPOrdinals = true, true, test.drops
				link.mu.Unlock()
				payload := bytes.Repeat([]byte{0x5a}, test.segments*1280)
				received := make([]byte, len(payload))
				var retransmissions, sackRetransmissions, rackRetransmissions uint64
				var handshakeRTT time.Duration
				b.SetBytes(int64(2 * len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					opened, err := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
					if err != nil {
						cancel()
						b.Fatal(err)
					}
					connection := opened.(*TCPConn)
					if err = connection.SetCongestionControl(algorithm); err != nil {
						b.Fatal(err)
					}
					if err = connection.SetLinger(0); err != nil {
						b.Fatal(err)
					}
					deadline, _ := ctx.Deadline()
					_ = connection.SetDeadline(deadline)
					setup := connection.Info()
					if setup.CongestionControl != algorithm || setup.MaximumSegmentSize != 1280 {
						b.Fatalf("unexpected initial connection: %+v", setup)
					}
					handshakeRTT += setup.MinimumRTT
					before := stack.Stats()
					written := make(chan error, 1)
					go func() {
						n, writeErr := connection.Write(payload)
						if writeErr == nil && n != len(payload) {
							writeErr = io.ErrShortWrite
						}
						written <- writeErr
					}()
					_, readErr := io.ReadFull(connection, received)
					writeErr := <-written
					info, after := connection.Info(), stack.Stats()
					_ = connection.Close()
					select {
					case <-connection.done:
					case <-ctx.Done():
						b.Fatal("connection cleanup timed out")
					}
					cancel()
					link.mu.Lock()
					delete(link.tcp, connection.key.local.Port())
					link.mu.Unlock()
					if readErr != nil || writeErr != nil || !bytes.Equal(received, payload) {
						b.Fatalf("stream transfer: read %v, write %v", readErr, writeErr)
					}
					retries := after.TCPRetransmissions - before.TCPRetransmissions
					sack := after.TCPSACKRetransmissions - before.TCPSACKRetransmissions
					rack := after.TCPRACKRetransmissions - before.TCPRACKRetransmissions
					tlp := after.TCPTailLossProbes - before.TCPTailLossProbes
					if retries != uint64(len(test.drops)) || sack != retries || test.name == "RACK" && rack != retries || tlp != 0 || info.FastRecovery || info.RetransmissionRecovery || info.BytesAcknowledged != uint64(len(payload)) {
						b.Fatalf("unexpected recovery: retransmissions %d, SACK %d, RACK %d, TLP %d, info %+v", retries, sack, rack, tlp, info)
					}
					retransmissions += retries
					sackRetransmissions += sack
					rackRetransmissions += rack
				}
				b.StopTimer()
				b.ReportMetric(float64(handshakeRTT.Nanoseconds())/float64(b.N), "handshake-rtt-ns/op")
				b.ReportMetric(float64(retransmissions)/float64(b.N), "retransmissions/op")
				b.ReportMetric(float64(sackRetransmissions)/float64(b.N), "sack-retransmissions/op")
				b.ReportMetric(float64(rackRetransmissions)/float64(b.N), "rack-retransmissions/op")
				b.ReportMetric(0, "tail-loss-probes/op")
			})
		}
	}
}

func BenchmarkTCPRACKRecovery(b *testing.B) {
	responseDelay := time.Millisecond
	version := runtime.Version()
	if runtime.GOOS == "windows" && (strings.HasPrefix(version, "go1.20") || strings.HasPrefix(version, "go1.21") || strings.HasPrefix(version, "go1.22")) {
		responseDelay = 20 * time.Millisecond
	}
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(algorithm, func(b *testing.B) {
			link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.223"), netip.MustParseAddr("192.0.2.224"))
			link.mu.Lock()
			link.echoTCP, link.sackTCP = true, true
			link.delayTCPResponse = responseDelay
			link.dropTCPOrdinals = map[int]bool{1: true}
			link.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			opened, err := stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
			if err != nil {
				b.Fatal(err)
			}
			connection := opened.(*TCPConn)
			defer connection.Close()
			if err = connection.SetCongestionControl(algorithm); err != nil {
				b.Fatal(err)
			}
			if err = connection.SetLinger(0); err != nil {
				b.Fatal(err)
			}
			if err = connection.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
				b.Fatal(err)
			}
			setup := connection.Info()
			if setup.CongestionControl != algorithm || setup.MaximumSegmentSize != 1280 || setup.MinimumRTT < responseDelay {
				b.Fatalf("unexpected RACK connection: %+v", setup)
			}
			payload := bytes.Repeat([]byte{0x6b}, 2*setup.MaximumSegmentSize)
			received := make([]byte, len(payload))
			before := stack.Stats()
			b.SetBytes(int64(2 * len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
					b.Fatalf("RACK write = %d, %v", n, writeErr)
				}
				if _, err = io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
					b.Fatalf("RACK echo = %v", err)
				}
				info := connection.Info()
				if info.FastRecovery || info.RetransmissionRecovery || info.BytesAcknowledged != uint64(i+1)*uint64(len(payload)) {
					b.Fatalf("incomplete RACK recovery: %+v", info)
				}
				link.mu.Lock()
				peer := link.tcp[connection.key.local.Port()]
				peer.dataSegments = 0
				for sequence := range peer.seenData {
					delete(peer.seenData, sequence)
				}
				link.mu.Unlock()
			}
			b.StopTimer()
			after := stack.Stats()
			retries := after.TCPRetransmissions - before.TCPRetransmissions
			rack := after.TCPRACKRetransmissions - before.TCPRACKRetransmissions
			if retries != uint64(b.N) || rack != retries || after.TCPTailLossProbes != before.TCPTailLossProbes {
				b.Fatalf("recovery count = retransmissions:%d RACK:%d TLP:%d, want %d RACK retransmissions only", retries, rack, after.TCPTailLossProbes-before.TCPTailLossProbes, b.N)
			}
			b.ReportMetric(float64(rack)/float64(b.N), "rack-retransmissions/op")
			b.ReportMetric(float64(setup.MinimumRTT.Nanoseconds()), "handshake-rtt-ns")
			b.ReportMetric(float64(responseDelay.Nanoseconds()), "response-delay-ns")
		})
	}
}

func BenchmarkTCPPRREntryAcknowledgment(b *testing.B) {
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(algorithm, func(b *testing.B) {
			fixture := newTCPRecoveryACKFixture(b, algorithm, 64)
			fixture.initial.fastRecovery = false
			fixture.initial.recoveryPoint, fixture.initial.prrPriorFlight = 0, 0
			fixture.initial.controller.state.Phase = CongestionPhaseOpen
			fixture.original[1].state = sentTCPSegmentTransmitted
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fixture.reset()
				fixture.state.processAcknowledgment(&fixture.segment, fixture.ackTime, 0)
			}
			b.StopTimer()
			b.ReportMetric(float64(fixture.state.prrDelivered), "credit-B")
		})
	}
}

func BenchmarkICMPv6ErrorInput(b *testing.B) {
	local, remote := netip.MustParseAddr("2001:db8::31"), netip.MustParseAddr("2001:db8::32")
	for _, input := range []struct{ messageType, code byte }{{2, 0}, {2, 1}, {100, 255}} {
		b.Run(fmt.Sprintf("type-%d/code-%d", input.messageType, input.code), func(b *testing.B) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1500})
			if err != nil {
				b.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			opened, err := stack.DialUDP(context.Background(), "udp6", netip.AddrPort{}, netip.AddrPortFrom(remote, 13000))
			if err != nil {
				b.Fatal(err)
			}
			connection := opened.(*UDPConn)
			defer connection.Close()
			if err = connection.SetReceiveErrors(true); err != nil {
				b.Fatal(err)
			}
			quote := buildTestUDP(local, remote, connection.LocalAddr().(*net.UDPAddr).AddrPort().Port(), 13000, []byte("quote"))
			body := make([]byte, 4+len(quote))
			binary.BigEndian.PutUint32(body[:4], 1280)
			copy(body[4:], quote)
			wire := mustTestWire((ICMPMessage{Source: remote, Destination: local, Type: input.messageType, Code: input.code, Body: body}).MarshalBinary())
			packet := buildIPPacket(remote, local, ProtocolICMPv6, wire, 1, true)
			packets := [][]byte{packet}
			delivered := 0
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if n, err := stack.Write(packets, 0); err != nil || n != 1 {
					b.Fatalf("ICMPv6 input = %d, %v", n, err)
				}
				if reported, err := connection.ReadError(); err == nil && reported != nil {
					delivered++
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(delivered)/float64(b.N), "errors/op")
		})
	}
}

func BenchmarkTCPEstablishedStateAllocation(b *testing.B) {
	states := make([]*tcpEstablishedState, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		states[i%len(states)] = &tcpEstablishedState{}
	}
	runtime.KeepAlive(states)
}

func BenchmarkTCPEstablishedLivenessAllocation(b *testing.B) {
	states := make([]*tcpEstablishedLivenessState, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		states[i%len(states)] = &tcpEstablishedLivenessState{}
	}
	runtime.KeepAlive(states)
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
			b.StopTimer()
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
				b.ReportMetric(float64(stats.OutboundPackets+peerStats.OutboundPackets)/float64(b.N), "wire-packets/op")
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

func BenchmarkTCPControllerFixedBufferThroughput(b *testing.B) {
	const size = 4 * 1024 * 1024
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(algorithm, func(b *testing.B) {
			connection, peer, _ := benchmarkTCPControllerConnection(b, algorithm, defaultMTU, false, RXChecksumOffload{})
			sender := connection.(*TCPConn)
			peer.mu.Lock()
			receiver := peer.tcp[tcpKey{local: sender.key.remote, remote: sender.key.local}]
			peer.mu.Unlock()
			if receiver == nil {
				b.Fatal("fixed-buffer benchmark has no peer connection")
			}
			for _, c := range []*TCPConn{sender, receiver} {
				if err := c.SetReadBuffer(tcpReceiveCapacity); err != nil {
					b.Fatal(err)
				}
				if err := c.SetWriteBuffer(tcpSendCapacity); err != nil {
					b.Fatal(err)
				}
			}
			payload := bytes.Repeat([]byte{0x5a}, size)
			received := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(2 * size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				written := make(chan error, 1)
				go func() {
					n, err := connection.Write(payload)
					if err == nil && n != len(payload) {
						err = io.ErrShortWrite
					}
					written <- err
				}()
				if _, err := io.ReadFull(connection, received); err != nil {
					b.Fatal(err)
				}
				if err := <-written; err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(received, payload) {
					b.Fatal("fixed-buffer echo payload mismatch")
				}
			}
			b.StopTimer()
			for _, c := range []*TCPConn{sender, receiver} {
				info := c.Info()
				if info.SendBufferCapacity != tcpSendCapacity || info.ReceiveBufferCapacity != tcpReceiveCapacity {
					b.Fatalf("fixed socket buffers changed: %+v", info)
				}
			}
			clientStats, peerStats := sender.stack.Stats(), peer.Stats()
			b.ReportMetric(float64(clientStats.OutboundPackets+peerStats.OutboundPackets)/float64(b.N), "wire-packets/op")
			b.ReportMetric(float64(sender.inbound.peakBytes()), "client-inbound-queue-peak-B")
			b.ReportMetric(float64(receiver.inbound.peakBytes()), "peer-inbound-queue-peak-B")
			b.ReportMetric(float64(sender.Info().Retransmissions+receiver.Info().Retransmissions), "retransmissions")
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

func benchmarkTCPControllerConnections(b *testing.B, algorithm string, count int) ([]net.Conn, []net.Conn) {
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
	return connections, serverConnections
}

func BenchmarkTCPControllerConcurrency(b *testing.B) {
	const size = 128 * 1024
	for _, algorithm := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, count := range []int{16, 64, 256, 512, 1024, 2048, 4096, 8192} {
			b.Run(fmt.Sprintf("%s-%d", algorithm, count), func(b *testing.B) {
				connections, peerConnections := benchmarkTCPControllerConnections(b, algorithm, count)
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
				b.StopTimer()
				var retransmissions, queueDrops, window, sendCapacity uint64
				for _, connection := range connections {
					info := connection.(*TCPConn).Info()
					retransmissions += info.Retransmissions
					queueDrops += info.InboundQueueDrops
					window += uint64(info.CongestionWindow)
					sendCapacity += uint64(info.SendBufferCapacity)
				}
				var peerRetransmissions, peerQueueDrops, peerWindow, peerSendCapacity uint64
				for _, connection := range peerConnections {
					info := connection.(*TCPConn).Info()
					peerRetransmissions += info.Retransmissions
					peerQueueDrops += info.InboundQueueDrops
					peerWindow += uint64(info.CongestionWindow)
					peerSendCapacity += uint64(info.SendBufferCapacity)
				}
				stats := connections[0].(*TCPConn).stack.Stats()
				peerStats := peerConnections[0].(*TCPConn).stack.Stats()
				b.ReportMetric(float64(retransmissions), "retransmissions")
				b.ReportMetric(float64(queueDrops), "connection-queue-drops")
				b.ReportMetric(float64(window)/float64(count), "cwnd-B/flow")
				b.ReportMetric(float64(sendCapacity)/float64(count), "send-buffer-B/flow")
				b.ReportMetric(float64(stats.TCPTailLossProbes), "tail-loss-probes")
				b.ReportMetric(float64(stats.TCPSACKRetransmissions), "sack-retransmissions")
				b.ReportMetric(float64(stats.TCPRACKRetransmissions), "rack-retransmissions")
				b.ReportMetric(float64(stats.InboundDroppedPackets), "rx-drops")
				b.ReportMetric(float64(stats.TCPInboundQueueDrops), "queue-drops")
				b.ReportMetric(float64(peerRetransmissions), "peer-retransmissions")
				b.ReportMetric(float64(peerQueueDrops), "peer-connection-queue-drops")
				b.ReportMetric(float64(peerWindow)/float64(count), "peer-cwnd-B/flow")
				b.ReportMetric(float64(peerSendCapacity)/float64(count), "peer-send-buffer-B/flow")
				b.ReportMetric(float64(peerStats.TCPTailLossProbes), "peer-tail-loss-probes")
				b.ReportMetric(float64(peerStats.TCPSACKRetransmissions), "peer-sack-retransmissions")
				b.ReportMetric(float64(peerStats.TCPRACKRetransmissions), "peer-rack-retransmissions")
				b.ReportMetric(float64(peerStats.InboundDroppedPackets), "peer-rx-drops")
				b.ReportMetric(float64(peerStats.TCPInboundQueueDrops), "peer-queue-drops")
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
