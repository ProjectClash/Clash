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
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

type interopCongestionController struct{}

func (*interopCongestionController) HandleCongestionEvent(*mipstack.CongestionEvent) {}

func TestTCPInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, mipstackListens := range []bool{true, false} {
				mipstackListens := mipstackListens
				direction := "gvisor-listens"
				if mipstackListens {
					direction = "mipstack-listens"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+direction, func(t *testing.T) {
					network := newFamilyInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					exerciseFullDuplexTCP(t, client, server, tcpInteropStreamSize(mtu))
					var mipstackConnection *mipstack.TCPConn
					if mipstackListens {
						mipstackConnection = server.(*mipstack.TCPConn)
					} else {
						mipstackConnection = client.(*mipstack.TCPConn)
					}
					validateTCPMTUInfo(t, mipstackConnection.Info(), family, mtu)
				})
			}
		}
	}
}

func TestTCPRXChecksumOffloadInterop(t *testing.T) {
	for _, family := range interopFamilies {
		for _, mipstackListens := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/listens-%t", family.name, mipstackListens), func(t *testing.T) {
				var network *interopNetwork
				var mutations atomic.Uint64
				network = newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 9000,
					gvisorToMipstack: func(packet []byte) bool {
						if _, _, ok := tcpSegment(packet); !ok {
							return true
						}
						modified := append([]byte(nil), packet...)
						segment, _, _ := tcpSegment(modified)
						segment.SetChecksum(segment.Checksum() ^ 1)
						mutations.Add(1)
						if err := network.deliverToMipstack(modified); err != nil {
							network.reportBridgeError(err)
						}
						return false
					},
				})
				var offload mipstack.RXChecksumOffload
				offload.SetTCP(true)
				network.mipstack.SetRXChecksumOffload(offload)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 512*1024)
				if mutations.Load() < 3 {
					t.Fatal("offload did not cover both handshake and established traffic")
				}
			})
		}
	}
}

func TestTCPPeerMSSWithTimestampInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var maximumPayload atomic.Int32
			var timestampedPayloads atomic.Int32
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family},
				mtu:      1500,
				mipstackToGVisor: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if !ok || payloadLength == 0 {
						return true
					}
					for {
						current := maximumPayload.Load()
						if payloadLength <= int(current) || maximumPayload.CompareAndSwap(current, int32(payloadLength)) {
							break
						}
					}
					if tcpHeader.ParsedOptions().TS {
						timestampedPayloads.Add(1)
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			const (
				port        = 41003
				peerMSS     = 1200
				wantSendMSS = peerMSS - 12
			)
			var queue waiter.Queue
			endpoint, tcpipErr := network.gvisor.NewEndpoint(tcp.ProtocolNumber, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create native gVisor TCP listener: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.SetSockOptInt(tcpip.MaxSegOption, peerMSS); tcpipErr != nil {
				t.Fatalf("set gVisor TCP_MAXSEG: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, port)); tcpipErr != nil {
				t.Fatalf("bind native gVisor TCP listener: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Listen(1); tcpipErr != nil {
				t.Fatalf("listen with native gVisor TCP endpoint: %s", tcpipErr.String())
			}
			listener := gonet.NewTCPListener(network.gvisor, &queue, endpoint)
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- connection
			}()

			client, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, port))
			if err != nil {
				t.Fatalf("mipstack dial with gVisor TCP_MAXSEG peer: %v", err)
			}
			defer client.Close()
			var server net.Conn
			select {
			case server = <-accepted:
			case err = <-acceptErr:
				t.Fatalf("accept native gVisor TCP connection: %v", err)
			case <-ctx.Done():
				t.Fatalf("accept native gVisor TCP connection: %v", ctx.Err())
			}
			defer server.Close()

			info := client.(*mipstack.TCPConn).Info()
			if info.MaximumSegmentSize != wantSendMSS || !info.Timestamps {
				t.Fatalf("mipstack TCP info = MSS:%d timestamps:%v, want MSS:%d timestamps:true", info.MaximumSegmentSize, info.Timestamps, wantSendMSS)
			}
			deadline := time.Now().Add(8 * time.Second)
			if err = client.SetDeadline(deadline); err != nil {
				t.Fatalf("set mipstack TCP deadline: %v", err)
			}
			if err = server.SetDeadline(deadline); err != nil {
				t.Fatalf("set gVisor TCP deadline: %v", err)
			}
			payload := patternedPayload(64*1024+137, 211)
			writeResult := make(chan error, 1)
			go func() {
				n, writeErr := client.Write(payload)
				if writeErr == nil && n != len(payload) {
					writeErr = io.ErrShortWrite
				}
				writeResult <- writeErr
			}()
			received := make([]byte, len(payload))
			if _, err = io.ReadFull(server, received); err != nil {
				t.Fatalf("read low-MSS gVisor payload: %v", err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("low-MSS gVisor payload mismatch")
			}
			if err = <-writeResult; err != nil {
				t.Fatalf("write low-MSS mipstack payload: %v", err)
			}
			if got := maximumPayload.Load(); got != wantSendMSS || timestampedPayloads.Load() == 0 {
				t.Fatalf("mipstack wire payload = %d, timestamped segments = %d; want max %d and timestamp coverage", got, timestampedPayloads.Load(), wantSendMSS)
			}
		})
	}
}

func TestTCPReadWithBufferInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			role := "gvisor-listens"
			if mipstackListens {
				role = "mipstack-listens"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, 1500)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				var connection *mipstack.TCPConn
				var peer net.Conn
				if mipstackListens {
					connection = server.(*mipstack.TCPConn)
					peer = client
				} else {
					connection = client.(*mipstack.TCPConn)
					peer = server
				}
				deadline := time.Now().Add(8 * time.Second)
				if err := connection.SetReadDeadline(deadline); err != nil {
					t.Fatalf("set mipstack read deadline: %v", err)
				}
				if err := peer.SetWriteDeadline(deadline); err != nil {
					t.Fatalf("set gVisor write deadline: %v", err)
				}

				payload := patternedPayload(64*1024+137, 59)
				written := make(chan error, 1)
				go func() {
					n, err := peer.Write(payload)
					if err == nil && n != len(payload) {
						err = io.ErrShortWrite
					}
					written <- err
				}()
				readTCPPayloadWithBuffer(t, connection, payload)
				if err := <-written; err != nil {
					t.Fatalf("write gVisor TCP payload: %v", err)
				}
				exchangeTCPPayload(t, connection, peer, patternedPayload(8*1024+73, 137))
			})
		}
	}
}

func TestTCPOldACKTimestampInterop(t *testing.T) {
	for _, family := range interopFamilies {
		t.Run(family.name, func(t *testing.T) {
			var armed, translated atomic.Bool
			var expectedEcho, expectedACK atomic.Uint32
			echoed := make(chan uint32, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					segment, size, ok := tcpSegment(packet)
					if !ok || !armed.Load() || segment.Flags().Contains(header.TCPFlagSyn) {
						return true
					}
					if size != 0 {
						segment.SetAckNumber(segment.AckNumber() - 1)
						expectedACK.Store(segment.SequenceNumber() + uint32(size))
					}
					if !rewriteTCPTimestamps(packet, func(value, echo uint32) (uint32, uint32) {
						if size != 0 {
							expectedEcho.Store(value + 1000)
						}
						return value + 1000, echo
					}) {
						return false
					}
					translated.Store(true)
					return true
				},
				mipstackToGVisor: func(packet []byte) bool {
					segment, size, ok := tcpSegment(packet)
					if !ok || !translated.Load() || segment.Flags().Contains(header.TCPFlagSyn) {
						return true
					}
					if size == 0 && segment.AckNumber() == expectedACK.Load() {
						select {
						case echoed <- segment.ParsedOptions().TSEcr:
						default:
						}
					}
					return rewriteTCPTimestamps(packet, func(value, echo uint32) (uint32, uint32) { return value, echo - 1000 })
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			exchangeTCPPayload(t, client, server, []byte("seed"))
			connection := client.(*mipstack.TCPConn)
			deadline := time.Now().Add(5 * time.Second)
			for connection.Info().BytesInFlight != 0 {
				if time.Now().After(deadline) {
					t.Fatal("seed was not cumulatively acknowledged")
				}
				time.Sleep(time.Millisecond)
			}
			armed.Store(true)
			exchangeTCPPayload(t, server, client, []byte("old ACK timestamp"))
			select {
			case echo := <-echoed:
				if want := expectedEcho.Load(); echo != want {
					t.Fatalf("old ACK timestamp echo = %d, want %d", echo, want)
				}
			case <-ctx.Done():
				t.Fatal("mipstack did not acknowledge native gVisor data")
			}
			if err := server.(*gonet.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			if n, err := client.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("native gVisor half-close = %d, %v, want EOF", n, err)
			}
		})
	}
}

func TestTCPOldACKSACKRecoveryInterop(t *testing.T) {
	for _, family := range interopFamilies {
		for _, algorithm := range []string{mipstack.CongestionControlReno, mipstack.CongestionControlCUBIC, mipstack.CongestionControlBBR, mipstack.CongestionControlBBR3} {
			t.Run(family.name+"/"+algorithm, func(t *testing.T) {
				var armed, dropped atomic.Bool
				var gap, rewritten atomic.Uint32
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					tcp: mipstack.TCPSocketDefaults{CongestionControl: algorithm},
					mipstackToGVisor: func(packet []byte) bool {
						segment, size, ok := tcpSegment(packet)
						if ok && size != 0 && armed.Load() && dropped.CompareAndSwap(false, true) {
							gap.Store(segment.SequenceNumber())
							return false
						}
						return true
					},
					gvisorToMipstack: func(packet []byte) bool {
						segment, _, ok := tcpSegment(packet)
						if !ok || !dropped.Load() || segment.AckNumber() != gap.Load() || !tcpHasSACKOption(segment) {
							return true
						}
						segment.SetAckNumber(segment.AckNumber() - 1)
						segment.SetChecksum(0)
						partial := header.PseudoHeaderChecksum(tcp.ProtocolNumber, gvisorAddress(family.gvisorAddress), gvisorAddress(family.mipstackAddress), uint16(len(segment)))
						segment.SetChecksum(^checksum.Checksum(segment, partial))
						rewritten.Add(1)
						return true
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, false)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exchangeTCPPayload(t, client, server, []byte("seed"))
				connection := client.(*mipstack.TCPConn)
				deadline := time.Now().Add(5 * time.Second)
				for connection.Info().BytesInFlight != 0 {
					if time.Now().After(deadline) {
						t.Fatal("seed was not cumulatively acknowledged")
					}
					time.Sleep(time.Millisecond)
				}
				before := network.mipstack.Stats()
				armed.Store(true)
				exchangeTCPPayload(t, client, server, patternedPayload(128*1024, 71))
				stats := network.mipstack.Stats()
				retransmissions := stats.TCPRetransmissions - before.TCPRetransmissions
				selective := stats.TCPSACKRetransmissions - before.TCPSACKRetransmissions
				if !dropped.Load() || rewritten.Load() == 0 || selective == 0 || retransmissions != selective {
					t.Fatalf("old ACK selective recovery = dropped %t rewritten %d total retransmissions %d SACK retransmissions %d RACK retransmissions %d", dropped.Load(), rewritten.Load(), retransmissions, selective, stats.TCPRACKRetransmissions-before.TCPRACKRetransmissions)
				}
			})
		}
	}
}

func TestTCPMissingTimestampInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			role := "gvisor-listens"
			if mipstackListens {
				role = "mipstack-listens"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				var stripped atomic.Uint32
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					gvisorToMipstack: func(packet []byte) bool {
						tcpHeader, _, ok := tcpSegment(packet)
						if !ok || tcpHeader.Flags().Contains(header.TCPFlagSyn) || !tcpHeader.ParsedOptions().TS {
							return true
						}
						if stripTCPTimestamp(packet) {
							stripped.Add(1)
						}
						return true
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 32*1024)
				if stripped.Load() == 0 {
					t.Fatal("gVisor-to-mipstack hook did not strip a negotiated Timestamp")
				}
			})
		}
	}
}

func TestTCPHighFrequencyTimestampInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			t.Run(fmt.Sprintf("%s/listens-%t", family.name, mipstackListens), func(t *testing.T) {
				var mu sync.Mutex
				var initial, last, stale uint32
				var initialized, rejectData bool
				var wraps, stalePackets, rewriteFailures int
				originals := make(map[uint32]uint32)
				staleSent := make(chan struct{}, 1)
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					gvisorToMipstack: func(packet []byte) bool {
						tcpHeader, payloadLength, ok := tcpSegment(packet)
						if !ok || !tcpHeader.ParsedOptions().TS {
							return true
						}
						mu.Lock()
						defer mu.Unlock()
						if rejectData && payloadLength != 0 && stalePackets != 0 {
							return false
						}
						if rejectData && payloadLength != 0 {
							tcpHeader.Payload()[0] ^= 0x80
						}
						if !rewriteTCPTimestamps(packet, func(value, echo uint32) (uint32, uint32) {
							if !initialized {
								initial = value
								initialized = true
							}
							mapped := ^uint32(0) - 999 + (value-initial)*1000
							if int32(mapped-last) > 0 && mapped < last {
								wraps++
							}
							last = mapped
							if rejectData && payloadLength != 0 {
								mapped = stale
								stalePackets++
								select {
								case staleSent <- struct{}{}:
								default:
								}
							}
							originals[mapped] = value
							return mapped, echo
						}) {
							rewriteFailures++
						}
						return true
					},
					mipstackToGVisor: func(packet []byte) bool {
						tcpHeader, _, ok := tcpSegment(packet)
						if !ok || !tcpHeader.ParsedOptions().TS {
							return true
						}
						mu.Lock()
						defer mu.Unlock()
						if !rewriteTCPTimestamps(packet, func(value, echo uint32) (uint32, uint32) {
							if original, ok := originals[echo]; ok {
								echo = original
							} else if echo != 0 {
								rewriteFailures++
							}
							return value, echo
						}) {
							rewriteFailures++
						}
						return true
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				mipstackConnection, gvisorConnection := client, server
				if mipstackListens {
					mipstackConnection, gvisorConnection = server, client
				}
				exchangeTCPPayload(t, gvisorConnection, mipstackConnection, []byte("before wrap"))
				time.Sleep(3 * time.Millisecond)
				exchangeTCPPayload(t, gvisorConnection, mipstackConnection, []byte("after wrap"))
				mu.Lock()
				stale, rejectData = last-1_000_000, true
				mu.Unlock()
				payload := []byte("retransmitted after PAWS rejection")
				_ = gvisorConnection.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if n, err := gvisorConnection.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("gVisor write = %d, %v", n, err)
				}
				select {
				case <-staleSent:
				case <-ctx.Done():
					t.Fatal("gVisor data did not reach the timestamp translator")
				}
				_ = mipstackConnection.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				buffer := make([]byte, len(payload))
				if n, err := mipstackConnection.Read(buffer); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("stale gVisor data delivered %q, %v", buffer[:n], err)
				}
				mu.Lock()
				rejectData = false
				mu.Unlock()
				_ = mipstackConnection.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(mipstackConnection, buffer); err != nil || !bytes.Equal(buffer, payload) {
					t.Fatalf("gVisor retransmission delivered %q, %v", buffer, err)
				}
				exerciseFullDuplexTCP(t, client, server, 32*1024)
				mu.Lock()
				defer mu.Unlock()
				if wraps == 0 || stalePackets == 0 || rewriteFailures != 0 {
					t.Fatalf("timestamp translation: wraps=%d, stale packets=%d, failures=%d", wraps, stalePackets, rewriteFailures)
				}
			})
		}
	}
}

func TestTCPSYNCookieOptionRecoveryInterop(t *testing.T) {
	scenarios := []struct {
		name             string
		rewrite          func([]byte) bool
		wantTimestamp    bool
		wantWindowScale  bool
		wantPeerScale    uint8
		wantSACK         bool
		wantReceiveScale bool
		stripSYN         bool
	}{
		{name: "no-timestamp-syn", rewrite: stripTCPTimestamp, stripSYN: true},
		{name: "missing-timestamp", rewrite: stripTCPTimestamp},
		{name: "zero-tsecr", rewrite: func(packet []byte) bool {
			return rewriteTCPTimestamps(packet, func(value, _ uint32) (uint32, uint32) { return value, 0 })
		}, wantTimestamp: true, wantWindowScale: true, wantPeerScale: 7, wantSACK: true, wantReceiveScale: true},
	}
	for scenarioIndex, scenario := range scenarios {
		scenarioIndex, scenario := scenarioIndex, scenario
		t.Run(scenario.name, func(t *testing.T) {
			for _, family := range interopFamilies {
				family := family
				t.Run(family.name, func(t *testing.T) {
					serverPort := uint16(41015 + scenarioIndex*10)
					firstClientPort := serverPort + 1
					secondClientPort := serverPort + 2
					var (
						firstACKDropped     atomic.Bool
						rewrittenHandshake  atomic.Bool
						cookieSYNACKChecked atomic.Bool
						cookieSYNACKInvalid atomic.Bool
					)
					network := newInteropNetworkWithOptions(t, interopNetworkOptions{
						families: []interopFamily{family},
						mtu:      1500,
						gvisorToMipstack: func(packet []byte) bool {
							tcpHeader, _, ok := tcpSegment(packet)
							if !ok || tcpHeader.DestinationPort() != serverPort {
								return true
							}
							if tcpHeader.Flags().Contains(header.TCPFlagSyn) {
								if scenario.stripSYN && tcpHeader.SourcePort() == secondClientPort && scenario.rewrite(packet) {
									rewrittenHandshake.Store(true)
								}
								return true
							}
							if !tcpHeader.Flags().Contains(header.TCPFlagAck) {
								return true
							}
							switch tcpHeader.SourcePort() {
							case firstClientPort:
								firstACKDropped.Store(true)
								return false
							case secondClientPort:
								if !scenario.stripSYN && rewrittenHandshake.CompareAndSwap(false, true) {
									if !scenario.rewrite(packet) {
										rewrittenHandshake.Store(false)
									}
								}
							}
							return true
						},
						mipstackToGVisor: func(packet []byte) bool {
							tcpHeader, _, ok := tcpSegment(packet)
							if !ok || tcpHeader.DestinationPort() != secondClientPort || !tcpHeader.Flags().Contains(header.TCPFlagSyn|header.TCPFlagAck) {
								return true
							}
							options := header.ParseSynOptions(tcpHeader.Options(), true)
							if scenario.stripSYN {
								if options.TS || options.WS != -1 || options.SACKPermitted {
									cookieSYNACKInvalid.Store(true)
								}
							} else if !options.TS || options.TSVal == 0 {
								cookieSYNACKInvalid.Store(true)
							}
							cookieSYNACKChecked.Store(true)
							return true
						},
					})
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					listener, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{
						mipstack.SocketOptions.AcceptQueue(1), mipstack.SocketOptions.SYNBacklog(1),
					}}).ListenTCP(ctx, network.mipstack, family.tcpNetwork, netipAddrPort(family.mipstackAddress, serverPort))
					if err != nil {
						t.Fatalf("listen for SYN-cookie interop: %v", err)
					}
					defer listener.Close()

					firstResult := make(chan net.Conn, 1)
					firstErr := make(chan error, 1)
					go func() {
						connection, dialErr := gonet.DialTCPWithBind(ctx, network.gvisor,
							gvisorFullAddress(family.gvisorAddress, firstClientPort),
							gvisorFullAddress(family.mipstackAddress, serverPort), family.networkProtocol)
						if dialErr != nil {
							firstErr <- dialErr
							return
						}
						firstResult <- connection
					}()

					backlogDeadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(backlogDeadline) {
						info := listener.(*mipstack.TCPListener).Info()
						if info.SYNBacklogConnections == 1 && firstACKDropped.Load() {
							break
						}
						time.Sleep(time.Millisecond)
					}
					if info := listener.(*mipstack.TCPListener).Info(); info.SYNBacklogConnections != 1 || !firstACKDropped.Load() {
						t.Fatalf("first handshake did not occupy SYN backlog: %+v, final-ACK dropped:%v", info, firstACKDropped.Load())
					}

					second, err := gonet.DialTCPWithBind(ctx, network.gvisor,
						gvisorFullAddress(family.gvisorAddress, secondClientPort),
						gvisorFullAddress(family.mipstackAddress, serverPort), family.networkProtocol)
					if err != nil {
						t.Fatalf("second gVisor cookie dial: %v", err)
					}
					defer second.Close()
					rewriteDeadline := time.Now().Add(2 * time.Second)
					for !rewrittenHandshake.Load() && time.Now().Before(rewriteDeadline) {
						time.Sleep(time.Millisecond)
					}
					if !rewrittenHandshake.Load() {
						t.Fatalf("SYN-cookie handshake was not rewritten for %s", scenario.name)
					}
					if !cookieSYNACKChecked.Load() || cookieSYNACKInvalid.Load() {
						t.Fatalf("invalid cookie SYN-ACK options for %s", scenario.name)
					}
					accepted, err := listener.Accept()
					if err != nil {
						t.Fatalf("accept SYN-cookie connection: %v", err)
					}
					defer accepted.Close()
					connection := accepted.(*mipstack.TCPConn)
					info := connection.Info()
					if info.State != mipstack.TCPStateEstablished || info.Timestamps != scenario.wantTimestamp || info.SACK != scenario.wantSACK ||
						info.WindowScaling != scenario.wantWindowScale || info.PeerWindowScale != scenario.wantPeerScale ||
						(!scenario.wantReceiveScale && info.ReceiveWindowScale != 0) ||
						(scenario.wantReceiveScale && info.ReceiveWindowScale == 0) {
						t.Fatalf("SYN-cookie %s options = %+v", scenario.name, info)
					}
					listenerInfo := listener.(*mipstack.TCPListener).Info()
					if listenerInfo.SYNCookiesSent == 0 || listenerInfo.SYNCookiesAccepted == 0 {
						t.Fatalf("SYN-cookie counters = sent:%d accepted:%d", listenerInfo.SYNCookiesSent, listenerInfo.SYNCookiesAccepted)
					}
					payloadSize := 4096
					if scenario.stripSYN {
						payloadSize = 128 * 1024
					}
					exchangeTCPPayload(t, second, accepted, patternedPayload(payloadSize, 43))
					exchangeTCPPayload(t, accepted, second, patternedPayload(payloadSize, 47))

					select {
					case connection := <-firstResult:
						_ = connection.Close()
					case <-firstErr:
					case <-time.After(time.Second):
					}
				})
			}
		})
	}
}

func TestTCPActiveInvalidTimestampEchoInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var rewritten atomic.Bool
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family},
				mtu:      1500,
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, _, ok := tcpSegment(packet)
					if !ok || !tcpHeader.Flags().Contains(header.TCPFlagSyn) || !tcpHeader.Flags().Contains(header.TCPFlagAck) {
						return true
					}
					if rewriteTCPTimestamps(packet, func(value, _ uint32) (uint32, uint32) { return value, 1 << 30 }) {
						rewritten.Store(true)
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			listener, err := gonet.ListenTCP(network.gvisor, gvisorFullAddress(family.gvisorAddress, 41018), family.networkProtocol)
			if err != nil {
				t.Fatalf("listen with gVisor TCP: %v", err)
			}
			defer listener.Close()
			if _, err = network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, 41018)); err == nil {
				t.Fatal("mipstack accepted SYN-ACK with invalid nonzero TSecr")
			}
			if !rewritten.Load() {
				t.Fatal("gVisor SYN-ACK was not rewritten")
			}
		})
	}
}

func TestTCPPassiveInvalidTimestampEchoInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			const (
				serverPort = 41019
				clientPort = 41020
			)
			var rewritten atomic.Uint32
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family},
				mtu:      1500,
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, _, ok := tcpSegment(packet)
					if !ok || tcpHeader.DestinationPort() != serverPort ||
						tcpHeader.SourcePort() != clientPort ||
						tcpHeader.Flags().Contains(header.TCPFlagSyn) ||
						!tcpHeader.Flags().Contains(header.TCPFlagAck) {
						return true
					}
					if rewriteTCPTimestamps(packet, func(value, _ uint32) (uint32, uint32) { return value, 1 << 30 }) {
						rewritten.Add(1)
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			listener, err := network.mipstack.ListenTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, serverPort))
			if err != nil {
				t.Fatalf("listen for invalid passive timestamp interop: %v", err)
			}
			defer listener.Close()

			type dialResult struct {
				connection net.Conn
				err        error
			}
			result := make(chan dialResult, 1)
			go func() {
				connection, dialErr := gonet.DialTCPWithBind(ctx, network.gvisor,
					gvisorFullAddress(family.gvisorAddress, clientPort),
					gvisorFullAddress(family.mipstackAddress, serverPort), family.networkProtocol)
				result <- dialResult{connection: connection, err: dialErr}
			}()

			if err = listener.(*mipstack.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatalf("set invalid passive timestamp deadline: %v", err)
			}
			if connection, acceptErr := listener.Accept(); acceptErr == nil {
				_ = connection.Close()
				t.Fatal("mipstack accepted a final ACK with invalid nonzero TSecr")
			} else if timeout, ok := acceptErr.(net.Error); !ok || !timeout.Timeout() {
				t.Fatalf("invalid passive timestamp Accept error = %v", acceptErr)
			}
			if rewritten.Load() == 0 {
				t.Fatal("gVisor final ACK was not rewritten")
			}
			select {
			case outcome := <-result:
				if outcome.connection != nil {
					_ = outcome.connection.Close()
				}
			case <-time.After(time.Second):
			}
		})
	}
}

func TestTCPTimeWaitReuseInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			const (
				serverPort = 41011
				clientPort = 41012
			)
			listener, err := network.mipstack.ListenTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, serverPort))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accept := func() net.Conn {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					t.Fatalf("Accept: %v", acceptErr)
				}
				return connection
			}
			local := gvisorFullAddress(family.gvisorAddress, clientPort)
			remote := gvisorFullAddress(family.mipstackAddress, serverPort)
			first, err := gonet.DialTCPWithBind(ctx, network.gvisor, local, remote, family.networkProtocol)
			if err != nil {
				t.Fatalf("first gVisor DialTCPWithBind: %v", err)
			}
			firstServer := accept()
			if err = firstServer.(*mipstack.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = first.SetReadDeadline(time.Now().Add(time.Second))
			if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
				t.Fatalf("first gVisor FIN read = %d, %v", n, readErr)
			}
			if err = first.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
			if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
				t.Fatalf("first mipstack FIN read = %d, %v", n, readErr)
			}
			deadline := time.Now().Add(time.Second)
			for firstServer.(*mipstack.TCPConn).Info().State != mipstack.TCPStateTimeWait && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if state := firstServer.(*mipstack.TCPConn).Info().State; state != mipstack.TCPStateTimeWait {
				t.Fatalf("first mipstack state = %v, want TIME-WAIT", state)
			}
			_ = first.Close()
			_ = firstServer.Close()
			time.Sleep(2 * time.Millisecond)

			second, err := gonet.DialTCPWithBind(ctx, network.gvisor, local, remote, family.networkProtocol)
			if err != nil {
				t.Fatalf("same-tuple gVisor DialTCPWithBind: %v", err)
			}
			defer second.Close()
			secondServer := accept()
			defer secondServer.Close()
			if got := second.LocalAddr().(*net.TCPAddr).Port; got != clientPort {
				t.Fatalf("replacement gVisor local port = %d, want %d", got, clientPort)
			}
		})
	}
}

func TestTCPTimeWaitMissingTimestampInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var (
				firstFINSequence atomic.Uint32
				firstFINSeen     atomic.Bool
				ackDropped       atomic.Bool
				ackAfterDrop     atomic.Uint32
				strippedFIN      atomic.Uint32
				timeWaitReady    atomic.Bool
				earlyDuplicate   atomic.Bool
			)
			firstFIN := make(chan struct{})
			ackWasDropped := make(chan struct{})
			stripped := make(chan struct{})
			ackAfterWasSent := make(chan struct{})
			var firstFINOnce, ackDropOnce, strippedOnce, ackAfterOnce sync.Once
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if !ok || payloadLength != 0 || !tcpHeader.Flags().Contains(header.TCPFlagFin) || tcpHeader.Flags().Contains(header.TCPFlagSyn) {
						return true
					}
					sequence := tcpHeader.SequenceNumber()
					if firstFINSeen.CompareAndSwap(false, true) {
						firstFINSequence.Store(sequence)
						firstFINOnce.Do(func() { close(firstFIN) })
						return true
					}
					if sequence != firstFINSequence.Load() || !tcpHeader.ParsedOptions().TS {
						return true
					}
					if !timeWaitReady.Load() {
						earlyDuplicate.Store(true)
					}
					if stripTCPTimestamp(packet) {
						strippedFIN.Add(1)
						strippedOnce.Do(func() { close(stripped) })
					}
					return true
				},
				mipstackToGVisor: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if !ok || payloadLength != 0 || tcpHeader.Flags() != header.TCPFlagAck || !firstFINSeen.Load() {
						return true
					}
					if tcpHeader.AckNumber() != firstFINSequence.Load()+1 {
						return true
					}
					if ackDropped.CompareAndSwap(false, true) {
						ackDropOnce.Do(func() { close(ackWasDropped) })
						return false
					}
					if strippedFIN.Load() == 0 {
						return true
					}
					ackAfterDrop.Add(1)
					ackAfterOnce.Do(func() { close(ackAfterWasSent) })
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			const (
				serverPort = 41013
				clientPort = 41014
			)
			listener, err := network.mipstack.ListenTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, serverPort))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			local := gvisorFullAddress(family.gvisorAddress, clientPort)
			remote := gvisorFullAddress(family.mipstackAddress, serverPort)
			first, err := gonet.DialTCPWithBind(ctx, network.gvisor, local, remote, family.networkProtocol)
			if err != nil {
				t.Fatalf("gVisor DialTCPWithBind: %v", err)
			}
			defer first.Close()
			firstServer, err := listener.Accept()
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			defer firstServer.Close()
			if err = firstServer.(*mipstack.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			if err = first.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
				t.Fatalf("gVisor FIN read = %d, %v", n, readErr)
			}
			if err = first.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-firstFIN:
			case <-time.After(2 * time.Second):
				t.Fatal("gVisor FIN was not observed")
			}
			select {
			case <-ackWasDropped:
			case <-time.After(2 * time.Second):
				t.Fatal("mipstack FIN acknowledgement was not dropped")
			}
			stateDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(stateDeadline) && firstServer.(*mipstack.TCPConn).Info().State != mipstack.TCPStateTimeWait {
				time.Sleep(5 * time.Millisecond)
			}
			if state := firstServer.(*mipstack.TCPConn).Info().State; state != mipstack.TCPStateTimeWait {
				t.Fatalf("mipstack state after dropped FIN ACK = %v, want TIME-WAIT", state)
			}
			timeWaitReady.Store(true)
			select {
			case <-stripped:
			case <-time.After(5 * time.Second):
				t.Fatal("gVisor did not retransmit a Timestamp-stripped FIN")
			}
			select {
			case <-ackAfterWasSent:
			case <-time.After(2 * time.Second):
				t.Fatal("mipstack did not acknowledge the Timestamp-stripped FIN")
			}
			if earlyDuplicate.Load() || strippedFIN.Load() != 1 || ackAfterDrop.Load() == 0 {
				t.Fatalf("TIME-WAIT missing-Timestamp FIN = early:%v stripped:%d ACKs-after-drop:%d", earlyDuplicate.Load(), strippedFIN.Load(), ackAfterDrop.Load())
			}
		})
	}
}

func TestTCPStoppedDeviceReadInterop(t *testing.T) {
	family := interopFamilies[0]
	bridgeStopped := make(chan struct{})
	releaseBridge := make(chan struct{})
	var bridgeArmed atomic.Bool
	var stopOnce, releaseOnce sync.Once
	network := newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: 1500,
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
	gvisorTCP, mipstackTCP, listener := openTCPPair(t, ctx, network, family, true)
	defer listener.Close()
	defer gvisorTCP.Close()
	defer mipstackTCP.Close()
	mipstackUDP, gvisorUDP := openUDPPair(t, ctx, network, family, true)
	defer mipstackUDP.Close()
	defer gvisorUDP.Close()
	udpConnection := mipstackUDP.(*mipstack.UDPConn)
	if err := udpConnection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}

	bridgeArmed.Store(true)
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

	outbound := patternedPayload(4096, 43)
	tcpWrite := make(chan error, 1)
	go func() {
		written, err := mipstackTCP.Write(outbound)
		if err == nil && written != len(outbound) {
			err = io.ErrShortWrite
		}
		tcpWrite <- err
	}()
	select {
	case err := <-tcpWrite:
		if err != nil {
			t.Fatalf("buffer TCP output while Stack.Read was stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("TCP Write blocked on the stopped device reader")
	}

	infoResult := make(chan mipstack.TCPConnInfo, 1)
	go func() { infoResult <- mipstackTCP.(*mipstack.TCPConn).Info() }()
	select {
	case info := <-infoResult:
		if info.SendBufferSize != len(outbound) || info.BytesSent != 0 {
			t.Fatalf("TCP output escaped a full device queue: buffered=%d sent=%d", info.SendBufferSize, info.BytesSent)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("TCP Info blocked on the stopped device reader")
	}

	inbound := patternedPayload(4096, 97)
	peerWrite := make(chan error, 1)
	go func() {
		written, err := gvisorTCP.Write(inbound)
		if err == nil && written != len(inbound) {
			err = io.ErrShortWrite
		}
		peerWrite <- err
	}()
	receivedInbound := make(chan error, 1)
	go func() {
		storage := make([]byte, len(inbound))
		_, err := io.ReadFull(mipstackTCP, storage)
		if err == nil && !bytes.Equal(storage, inbound) {
			err = errors.New("inbound TCP payload mismatch")
		}
		receivedInbound <- err
	}()
	select {
	case err := <-receivedInbound:
		if err != nil {
			t.Fatalf("receive TCP input while Stack.Read was stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("TCP input processing blocked on the stopped device reader")
	}
	select {
	case err := <-peerWrite:
		if err != nil {
			t.Fatalf("write gVisor TCP input while Stack.Read was stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("gVisor TCP input write did not complete")
	}

	releaseOnce.Do(func() { close(releaseBridge) })
	if err := gvisorTCP.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	receivedOutbound := make([]byte, len(outbound))
	if _, err := io.ReadFull(gvisorTCP, receivedOutbound); err != nil {
		t.Fatalf("read TCP output after device-read recovery: %v", err)
	}
	if !bytes.Equal(receivedOutbound, outbound) {
		t.Fatal("recovered outbound TCP payload mismatch")
	}
	exchangeTCPPayload(t, mipstackTCP, gvisorTCP, patternedPayload(32*1024, 151))
	exchangeTCPPayload(t, gvisorTCP, mipstackTCP, patternedPayload(32*1024, 211))
}

func TestTCPQuickACKInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{true, false} {
			mipstackListens := mipstackListens
			role := "gvisor-listens"
			if mipstackListens {
				role = "mipstack-listens"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, 1500)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				connection, peer := client, server
				if mipstackListens {
					connection, peer = server, client
				}
				quick := connection.(*mipstack.TCPConn)
				if err := quick.SetQuickACK(false); err != nil {
					t.Fatalf("disable quick ACK: %v", err)
				}
				exchangeTCPPayload(t, peer, connection, patternedPayload(4096, 31))
				if err := quick.SetQuickACK(true); err != nil {
					t.Fatalf("enable quick ACK: %v", err)
				}
				exchangeTCPPayload(t, peer, connection, patternedPayload(4096, 79))
				exchangeTCPPayload(t, connection, peer, patternedPayload(4096, 113))
			})
		}
	}
}

func TestPublicTCPSegmentCodecInterop(t *testing.T) {
	const (
		mipstackPort = 44011
		gvisorPort   = 44012
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
			listener, err := gonet.ListenTCP(network.gvisor, gvisorFullAddress(family.gvisorAddress, gvisorPort), family.networkProtocol)
			if err != nil {
				t.Fatalf("listen with gVisor TCP: %v", err)
			}
			defer listener.Close()

			var maximumSegmentSize, windowScale, sackPermitted, timestamp mipstack.TCPHeaderOption
			maximumSegmentSize.SetMaximumSegmentSize(1460)
			windowScale.SetWindowScale(7)
			sackPermitted.SetSACKPermitted()
			timestamp.SetTimestamp(0x10203040, 0)
			segment := mipstack.TCPSegment{
				Source:         netipAddrPort(family.mipstackAddress, mipstackPort),
				Destination:    netipAddrPort(family.gvisorAddress, gvisorPort),
				SequenceNumber: 1000, Flags: mipstack.TCPFlagSYN, WindowSize: 65535,
			}
			if err := segment.SetHeaderOptions([]mipstack.TCPHeaderOption{
				maximumSegmentSize, sackPermitted, timestamp,
				{Kind: mipstack.TCPHeaderOptionNOP}, windowScale,
			}); err != nil {
				t.Fatalf("construct public TCP SYN options: %v", err)
			}
			tcpWire, err := segment.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public TCP SYN: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolTCP, HopLimit: 64, Payload: tcpWire,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public TCP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public TCP SYN: %v", err)
			}
			select {
			case responseWire := <-captured:
				parsedPacket, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor SYN-ACK packet: %v", parseErr)
				}
				parsed, parseErr := parsedPacket.TCPSegment()
				if parseErr != nil || parsed.Source != segment.Destination || parsed.Destination != segment.Source || parsed.Flags&(mipstack.TCPFlagSYN|mipstack.TCPFlagACK) != mipstack.TCPFlagSYN|mipstack.TCPFlagACK || parsed.Flags&mipstack.TCPFlagRST != 0 || parsed.AcknowledgmentNumber != segment.SequenceNumber+1 {
					t.Fatalf("parsed gVisor SYN-ACK = %+v, %v", parsed, parseErr)
				}
				options, optionsErr := parsed.HeaderOptions()
				if optionsErr != nil {
					t.Fatalf("parse gVisor SYN-ACK options: %v", optionsErr)
				}
				var foundMSS, foundWindowScale, foundSACK, foundTimestamp bool
				for _, option := range options {
					if value, ok := option.MaximumSegmentSize(); ok {
						foundMSS = value != 0
					}
					if value, ok := option.WindowScale(); ok {
						foundWindowScale = value <= 14
					}
					foundSACK = foundSACK || option.IsSACKPermitted()
					if _, _, ok := option.Timestamp(); ok {
						foundTimestamp = true
					}
				}
				if !foundMSS || !foundWindowScale || !foundSACK || !foundTimestamp {
					t.Fatalf("gVisor SYN-ACK options did not negotiate the offered features: %+v", options)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for gVisor SYN-ACK")
			}
		})
	}
}

func TestTCPCongestionControlInterop(t *testing.T) {
	controllers := mipstack.AvailableCongestionControls()
	for _, family := range interopFamilies {
		family := family
		for _, controller := range controllers {
			controller := controller
			for _, mipstackListens := range []bool{false, true} {
				mipstackListens := mipstackListens
				direction := "active"
				if mipstackListens {
					direction = "passive"
				}
				t.Run(family.name+"/"+string(controller)+"/"+direction, func(t *testing.T) {
					var dropped atomic.Bool
					network := newInteropNetworkWithOptions(t, interopNetworkOptions{
						families: []interopFamily{family}, mtu: 1500,
						tcp:              mipstack.TCPSocketDefaults{CongestionControl: controller},
						mipstackToGVisor: newTCPDropHook(&dropped),
					})
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()

					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					exerciseFullDuplexTCP(t, client, server, 256*1024)
					if !dropped.Load() {
						t.Fatal("mipstack TCP data-loss hook did not match a segment")
					}
					connection := client
					if mipstackListens {
						connection = server
					}
					info := connection.(*mipstack.TCPConn).Info()
					if info.CongestionControl != controller || info.Retransmissions == 0 {
						t.Fatalf("mipstack TCP controller/retransmissions = %s/%d, want %s/nonzero", info.CongestionControl, info.Retransmissions, controller)
					}
				})
			}
		}
	}
}

func TestTCPACKClockedFlightReplacementInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var dataSegments, acknowledgments atomic.Uint32
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: func(packet []byte) bool {
					if _, data := tcpDataSequence(packet); data {
						dataSegments.Add(1)
					}
					return true
				},
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if ok && payloadLength == 0 && tcpHeader.Flags() == header.TCPFlagAck {
						acknowledgments.Add(1)
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(8 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)

			exchangeTCPPayload(t, client, server, patternedPayload(256*1024, 211))
			connection := client.(*mipstack.TCPConn)
			for connection.Info().BytesAcknowledged < 256*1024 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			info := connection.Info()
			if info.BytesAcknowledged < 256*1024 || info.Retransmissions != 0 || dataSegments.Load() <= 10 || acknowledgments.Load() <= 2 {
				t.Fatalf("ACK-clocked flight = acknowledged:%d retransmissions:%d data-segments:%d ACKs:%d", info.BytesAcknowledged, info.Retransmissions, dataSegments.Load(), acknowledgments.Load())
			}
			if err := connection.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := server.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("gVisor read after mipstack FIN = %d, %v", n, err)
			}
			if err := server.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("mipstack read after gVisor FIN = %d, %v", n, err)
			}
		})
	}
}

func TestTCPLocalCongestionControlFactoryInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			role := "active"
			if mipstackListens {
				role = "passive"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				contexts := make(chan mipstack.CongestionControlContext, 1)
				name := "interop-local-" + family.name + "-" + role
				factory, err := mipstack.NewCongestionControlFactory(mipstack.CongestionControlDefinition{
					Name: name,
					New: func(context mipstack.CongestionControlContext) mipstack.CongestionController {
						contexts <- context
						return &interopCongestionController{}
					},
					Features: mipstack.CongestionControlFeatureTransmissionEvents,
				})
				if err != nil {
					t.Fatal(err)
				}
				var dropped atomic.Bool
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					tcp:              mipstack.TCPSocketDefaults{CongestionControlFactory: factory},
					mipstackToGVisor: newTCPDropHook(&dropped),
				})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 256*1024)
				if !dropped.Load() {
					t.Fatal("mipstack local-controller data-loss hook did not match a segment")
				}
				connection := client
				if mipstackListens {
					connection = server
				}
				info := connection.(*mipstack.TCPConn).Info()
				if info.CongestionControl != name || info.Retransmissions == 0 {
					t.Fatalf("local controller/retransmissions = %s/%d, want %s/nonzero", info.CongestionControl, info.Retransmissions, name)
				}
				select {
				case factoryContext := <-contexts:
					if factoryContext.LocalAddress.Addr() != family.mipstackAddress || factoryContext.RemoteAddress.Addr() != family.gvisorAddress ||
						factoryContext.Passive != mipstackListens || factoryContext.Forwarded {
						t.Fatalf("local factory context = %+v", factoryContext)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
}

func TestTCPControlLossInterop(t *testing.T) {
	type controlLoss struct {
		name        string
		flags       header.TCPFlags
		clientSends bool
	}
	for _, family := range interopFamilies {
		family := family
		for _, loss := range []controlLoss{
			{name: "syn", flags: header.TCPFlagSyn, clientSends: true},
			{name: "syn-ack", flags: header.TCPFlagSyn | header.TCPFlagAck},
			{name: "final-ack", flags: header.TCPFlagAck, clientSends: true},
		} {
			loss := loss
			for _, mipstackListens := range []bool{false, true} {
				mipstackListens := mipstackListens
				direction := "mipstack-listens"
				if !mipstackListens {
					direction = "gvisor-listens"
				}
				t.Run(family.name+"/"+loss.name+"/"+direction, func(t *testing.T) {
					var dropped atomic.Bool
					options := interopNetworkOptions{families: []interopFamily{family}, mtu: 1500}
					mipstackSends := loss.clientSends != mipstackListens
					if mipstackSends {
						options.mipstackToGVisor = newTCPControlDropHook(loss.flags, &dropped)
					} else {
						options.gvisorToMipstack = newTCPControlDropHook(loss.flags, &dropped)
					}
					network := newInteropNetworkWithOptions(t, options)
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					exerciseFullDuplexTCP(t, client, server, 32*1024)
					if !dropped.Load() {
						t.Fatalf("TCP %s loss hook did not match a segment", loss.name)
					}
				})
			}
		}

		t.Run(family.name+"/fin", func(t *testing.T) {
			var mipstackDropped, gvisorDropped atomic.Bool
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: newTCPControlDropHook(header.TCPFlagFin, &mipstackDropped),
				gvisorToMipstack: newTCPControlDropHook(header.TCPFlagFin, &gvisorDropped),
			})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			exerciseFullDuplexTCP(t, client, server, 32*1024)
			if !mipstackDropped.Load() || !gvisorDropped.Load() {
				t.Fatalf("TCP FIN loss coverage = mipstack:%v gVisor:%v", mipstackDropped.Load(), gvisorDropped.Load())
			}
		})
	}
}

func TestTCPDualStackWildcardInterop(t *testing.T) {
	network := newInteropNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listener, err := network.mipstack.ListenTCP(ctx, "tcp", netip.AddrPort{})
	if err != nil {
		t.Fatalf("listen on dual-stack TCP wildcard: %v", err)
	}
	defer listener.Close()
	port := requireAddrPort(t, listener.Addr()).Port()

	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			type acceptResult struct {
				connection net.Conn
				err        error
			}
			accepted := make(chan acceptResult, 1)
			go func() {
				connection, acceptErr := listener.Accept()
				accepted <- acceptResult{connection: connection, err: acceptErr}
			}()

			client, dialErr := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.mipstackAddress, port), family.networkProtocol)
			if dialErr != nil {
				t.Fatalf("dial dual-stack TCP listener: %v", dialErr)
			}
			defer client.Close()
			var result acceptResult
			select {
			case result = <-accepted:
			case <-ctx.Done():
				t.Fatalf("accept dual-stack TCP connection: %v", ctx.Err())
			}
			if result.err != nil {
				t.Fatalf("accept dual-stack TCP connection: %v", result.err)
			}
			defer result.connection.Close()
			wantLocal := netipAddrPort(family.mipstackAddress, port)
			if local := requireAddrPort(t, result.connection.LocalAddr()); local != wantLocal {
				t.Fatalf("accepted dual-stack TCP local endpoint = %v, want %v", local, wantLocal)
			}
			exerciseFullDuplexTCP(t, client, result.connection, 64*1024)
		})
	}
}

func TestTCPClosedPortInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				connection, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.mipstackAddress, 44991), family.networkProtocol)
				if connection != nil {
					_ = connection.Close()
				}
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("gVisor dial to closed mipstack port = %v, want ECONNREFUSED", err)
				}

				mipstackConnection, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, 44992))
				if mipstackConnection != nil {
					_ = mipstackConnection.Close()
				}
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("mipstack dial to closed gVisor port = %v, want ECONNREFUSED", err)
				}
			})
		}
	}
}

func TestTCPEstablishedResetInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu)+"/mipstack-resets", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, true)
				defer listener.Close()
				defer client.Close()
				connection := server.(*mipstack.TCPConn)
				if err := connection.SetLinger(0); err != nil {
					t.Fatalf("set mipstack abortive linger: %v", err)
				}
				if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatalf("set gVisor reset deadline: %v", err)
				}
				if err := connection.Close(); err != nil {
					t.Fatalf("abort mipstack TCP connection: %v", err)
				}
				if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("gVisor read after mipstack abort = %v, want ECONNRESET", err)
				}
			})

			t.Run(family.name+"/"+interopMTUName(mtu)+"/gvisor-resets", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				const port = 44981
				var queue waiter.Queue
				listener, tcpipErr := network.gvisor.NewEndpoint(tcp.ProtocolNumber, family.networkProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create native gVisor TCP listener: %s", tcpipErr.String())
				}
				defer listener.Close()
				if tcpipErr = listener.Bind(gvisorFullAddress(family.gvisorAddress, port)); tcpipErr != nil {
					t.Fatalf("bind native gVisor TCP listener: %s", tcpipErr.String())
				}
				if tcpipErr = listener.Listen(1); tcpipErr != nil {
					t.Fatalf("listen with native gVisor TCP endpoint: %s", tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)
				type dialResult struct {
					connection net.Conn
					err        error
				}
				dialed := make(chan dialResult, 1)
				go func() {
					connection, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, port))
					dialed <- dialResult{connection: connection, err: err}
				}()
				accepted, _, err := acceptGVisorTCP(ctx, listener, notifications)
				if err != nil {
					t.Fatalf("accept native gVisor TCP connection: %v", err)
				}
				defer accepted.Close()
				result := <-dialed
				if result.err != nil {
					t.Fatalf("dial native gVisor TCP listener: %v", result.err)
				}
				connection := result.connection.(*mipstack.TCPConn)
				defer connection.Close()
				if err = connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatalf("set mipstack reset deadline: %v", err)
				}
				accepted.SocketOptions().SetLinger(tcpip.LingerOption{Enabled: true})
				accepted.Close()
				if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("mipstack read after gVisor abort = %v, want ECONNRESET", err)
				}
			})
		}
	}
}

func TestTCPReceiveBoundaryResetInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, scenario := range []string{"consumed-FIN", "receive-SACK"} {
			scenario := scenario
			t.Run(family.name+"/"+scenario, func(t *testing.T) {
				firstData := make(chan uint32, 1)
				sackEnds := make(chan uint32, 32)
				resets := make(chan uint32, 1)
				var firstSequence, finSequence uint32
				var haveData, haveFIN, resetDelivered bool
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					gvisorToMipstack: func(packet []byte) bool {
						segment, payloadLength, ok := tcpSegment(packet)
						if !ok {
							return true
						}
						if segment.Flags()&header.TCPFlagFin != 0 {
							finSequence = segment.SequenceNumber() + uint32(payloadLength)
							haveFIN = true
						}
						if segment.Flags()&header.TCPFlagRst != 0 {
							if resetDelivered {
								return false
							}
							resetDelivered = true
							if scenario == "consumed-FIN" && haveFIN {
								segment.SetSequenceNumber(finSequence)
								segment.SetChecksum(0)
								partial := header.PseudoHeaderChecksum(header.TCPProtocolNumber, gvisorAddress(family.gvisorAddress), gvisorAddress(family.mipstackAddress), uint16(len(segment)))
								segment.SetChecksum(^checksum.Checksum(segment, partial))
							}
							select {
							case resets <- segment.SequenceNumber():
							default:
							}
						}
						if scenario == "receive-SACK" && payloadLength != 0 {
							if !haveData {
								firstSequence, haveData = segment.SequenceNumber(), true
								firstData <- firstSequence
							}
							return segment.SequenceNumber() != firstSequence
						}
						return true
					},
					mipstackToGVisor: func(packet []byte) bool {
						segment, _, ok := tcpSegment(packet)
						if ok {
							for _, block := range header.ParseTCPOptions(segment.Options()).SACKBlocks {
								select {
								case sackEnds <- uint32(block.End):
								default:
								}
							}
						}
						return true
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				const port = 44982
				var queue waiter.Queue
				listener, tcpipErr := network.gvisor.NewEndpoint(tcp.ProtocolNumber, family.networkProtocol, &queue)
				if tcpipErr != nil {
					t.Fatal(tcpipErr.String())
				}
				defer listener.Close()
				if tcpipErr = listener.Bind(gvisorFullAddress(family.gvisorAddress, port)); tcpipErr != nil {
					t.Fatal(tcpipErr.String())
				}
				if tcpipErr = listener.Listen(16); tcpipErr != nil {
					t.Fatal(tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)
				type dialResult struct {
					connection net.Conn
					err        error
				}
				dialed := make(chan dialResult, 1)
				go func() {
					connection, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, port))
					dialed <- dialResult{connection, err}
				}()
				accepted, acceptedQueue, err := acceptGVisorTCP(ctx, listener, notifications)
				if err != nil {
					t.Fatal(err)
				}
				defer accepted.Close()
				result := <-dialed
				if result.err != nil {
					t.Fatal(result.err)
				}
				connection := result.connection.(*mipstack.TCPConn)
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				var resetSequence uint32
				if scenario == "consumed-FIN" {
					if tcpipErr = accepted.Shutdown(tcpip.ShutdownWrite); tcpipErr != nil {
						t.Fatal(tcpipErr.String())
					}
					if n, err := connection.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						t.Fatalf("Read after native FIN = %d, %v, want EOF", n, err)
					}
					if info := connection.Info(); info.State != mipstack.TCPStateCloseWait {
						t.Fatalf("state after peer FIN = %s, want CLOSE-WAIT", info.State)
					}
				} else {
					accepted.SocketOptions().SetDelayOption(false)
					peer := gonet.NewTCPConn(acceptedQueue, accepted)
					_ = peer.SetWriteDeadline(time.Now().Add(3 * time.Second))
					payload := patternedPayload(6000, 137)
					if n, err := peer.Write(payload); n != len(payload) || err != nil {
						t.Fatalf("native data Write = %d, %v", n, err)
					}
					select {
					case sequence := <-firstData:
						resetSequence = sequence + uint32(len(payload))
					case <-ctx.Done():
						t.Fatal("gVisor emitted no data")
					}
					observed := false
					var observedEnds []uint32
					for !observed {
						select {
						case end := <-sackEnds:
							observedEnds = append(observedEnds, end)
							observed = end == resetSequence
						case <-ctx.Done():
							t.Fatalf("mipstack did not SACK end %d: observed %v, info %+v", resetSequence, observedEnds, connection.Info())
						}
					}
				}
				accepted.SocketOptions().SetLinger(tcpip.LingerOption{Enabled: true})
				accepted.Close()
				if scenario == "receive-SACK" {
					if n, err := connection.Read(make([]byte, 1)); n != 0 || !errors.Is(err, syscall.ECONNRESET) {
						t.Fatalf("Read after native SACK-edge abort = %d, %v, want ECONNRESET", n, err)
					}
				}
				deadline := time.Now().Add(time.Second)
				for {
					info := connection.Info()
					if info.State == mipstack.TCPStateClosed && errors.Is(info.LastError, syscall.ECONNRESET) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("state after peer abort = %+v, want ECONNRESET", info)
					}
					time.Sleep(time.Millisecond)
				}
				select {
				case sequence := <-resets:
					if scenario == "receive-SACK" && sequence != resetSequence {
						t.Fatalf("native RST sequence = %d, want SACK end %d", sequence, resetSequence)
					}
				case <-ctx.Done():
					t.Fatal("native abort emitted no reset")
				}
			})
		}
	}
}

func TestTCPImpairedLinkInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, impairment := range []string{"loss", "reorder"} {
			impairment := impairment
			t.Run(family.name+"/"+impairment, func(t *testing.T) {
				var network *interopNetwork
				var mipstackImpaired, gvisorImpaired atomic.Bool
				bridgeErrors := make(chan error, 2)
				options := interopNetworkOptions{families: []interopFamily{family}, mtu: 1500}
				if impairment == "loss" {
					options.mipstackToGVisor = newTCPDropHook(&mipstackImpaired)
					options.gvisorToMipstack = newTCPDropHook(&gvisorImpaired)
				} else {
					options.mipstackToGVisor = newTCPReorderHook(func(packet []byte) error {
						return network.deliverToGVisor(packet)
					}, &mipstackImpaired, bridgeErrors)
					options.gvisorToMipstack = newTCPReorderHook(func(packet []byte) error {
						return network.deliverToMipstack(packet)
					}, &gvisorImpaired, bridgeErrors)
				}
				network = newInteropNetworkWithOptions(t, options)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()

				client, server, listener := openTCPPair(t, ctx, network, family, true)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 256*1024)
				if impairment == "loss" {
					if info := server.(*mipstack.TCPConn).Info(); info.Retransmissions == 0 {
						t.Fatalf("mipstack TCP retransmissions = 0 after an outbound data loss")
					}
				}
				if !mipstackImpaired.Load() || !gvisorImpaired.Load() {
					t.Fatalf("TCP impairment coverage = mipstack:%v gVisor:%v", mipstackImpaired.Load(), gvisorImpaired.Load())
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

func TestTCPCompressedSACKInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var network *interopNetwork
			var dropped, released atomic.Bool
			var sackACKs atomic.Uint32
			bridgeErrors := make(chan error, 1)
			var heldACKs [][]byte
			network = newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					_, data := tcpDataSequence(packet)
					return !data || !dropped.CompareAndSwap(false, true)
				},
				mipstackToGVisor: func(packet []byte) bool {
					if !dropped.Load() || released.Load() {
						return true
					}
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if !ok || payloadLength != 0 || tcpHeader.Flags() != header.TCPFlagAck || !tcpHasSACKOption(tcpHeader) {
						return true
					}
					heldACKs = append(heldACKs, append([]byte(nil), packet...))
					if sackACKs.Add(1) < 4 {
						return false
					}
					released.Store(true)
					for _, acknowledgement := range heldACKs {
						if err := network.deliverToGVisor(acknowledgement); err != nil {
							select {
							case bridgeErrors <- err:
							default:
							}
						}
					}
					return false
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			exchangeTCPPayload(t, client, server, patternedPayload(256*1024, 149))
			if !dropped.Load() || !released.Load() || sackACKs.Load() != 4 {
				t.Fatalf("compressed SACK coverage = dropped:%v released:%v ACKs:%d", dropped.Load(), released.Load(), sackACKs.Load())
			}
			select {
			case err := <-bridgeErrors:
				t.Fatal(err)
			default:
			}
		})
	}
}

func TestTCPFRTOInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var armed, delayed atomic.Bool
			var delayNanos atomic.Int64
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if ok && payloadLength == 0 && tcpHeader.Flags() == header.TCPFlagAck && armed.Load() && delayed.CompareAndSwap(false, true) {
						time.Sleep(time.Duration(delayNanos.Load()))
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			tcpConnection := client.(*mipstack.TCPConn)
			delayNanos.Store(int64(4*tcpConnection.Info().RetransmissionTimeout + time.Second))
			armed.Store(true)
			deadline := time.Now().Add(6 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)
			payload := patternedPayload(128*1024, 191)
			result := make(chan error, 1)
			go writeTCPPayload(client, payload, "mipstack F-RTO sender", result)
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(server, received); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("F-RTO interop payload mismatch")
			}
			if !delayed.Load() {
				t.Fatal("gVisor ACK delay hook did not match")
			}
			info := tcpConnection.Info()
			if info.Retransmissions == 0 || info.SpuriousRecoveryUndos == 0 {
				t.Fatalf("mipstack F-RTO diagnostics = retransmissions:%d undos:%d", info.Retransmissions, info.SpuriousRecoveryUndos)
			}
		})
	}
}

func TestTCPKeepAliveInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			keepAlive := mipstack.KeepAliveConfig{Idle: 200 * time.Millisecond, Interval: 20 * time.Millisecond, Count: 20}
			observer := newTCPKeepAliveObserver()
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				tcp:              mipstack.TCPSocketDefaults{KeepAlive: true, KeepAliveConfig: keepAlive},
				mipstackToGVisor: observer.observeOutbound,
				gvisorToMipstack: observer.observeInbound,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()

			select {
			case <-observer.probes:
			case <-time.After(2 * time.Second):
				t.Fatalf("mipstack did not emit the initial TCP keepalive probe; info=%+v", client.(*mipstack.TCPConn).Info())
			}
			activityStartedAt := observer.elapsed()
			exchangeTCPPayload(t, client, server, patternedPayload(32*1024, 29))
			exchangeTCPPayload(t, server, client, patternedPayload(32*1024, 71))
			lastActivity := time.Duration(observer.lastInboundData.Load())
			if lastActivity < activityStartedAt {
				t.Fatalf("bidirectional transfer produced no inbound TCP data after %v; last inbound data at %v", activityStartedAt, lastActivity)
			}

			var laterProbe tcpKeepAliveObservation
			probeDeadline := time.NewTimer(2 * time.Second)
			defer probeDeadline.Stop()
			for laterProbe.lastInbound < lastActivity {
				select {
				case observation := <-observer.probes:
					laterProbe = observation
				case <-probeDeadline.C:
					t.Fatalf("mipstack did not emit a TCP keepalive probe after bidirectional activity; info=%+v", client.(*mipstack.TCPConn).Info())
				}
			}
			minimumRestart := (keepAlive.Idle + keepAlive.Interval) / 2
			if elapsed := laterProbe.sentAt - laterProbe.lastInbound; elapsed < minimumRestart {
				t.Fatalf("mipstack emitted a TCP keepalive probe %v after inbound activity; want the restarted idle period (at least %v)", elapsed, minimumRestart)
			}
			if observer.dropped.Load() {
				t.Fatal("TCP keepalive observation queue overflowed")
			}
			info := client.(*mipstack.TCPConn).Info()
			if !info.KeepAlive || info.KeepAliveConfig != keepAlive || info.State != mipstack.TCPStateEstablished {
				t.Fatalf("mipstack TCP keepalive state = enabled:%v config:%+v state:%v", info.KeepAlive, info.KeepAliveConfig, info.State)
			}
			exerciseFullDuplexTCP(t, client, server, 32*1024)
		})
	}
}

func TestTCPKeepAliveUserTimeoutInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			for _, response := range []string{"acknowledged", "silent", "silent option update", "silent keepalive restart", "silent delayed keepalive restart", "silent coalesced keepalive restart"} {
				response := response
				silent := response != "acknowledged"
				direction := "gvisor-listens"
				if mipstackListens {
					direction = "mipstack-listens"
				}
				t.Run(family.name+"/"+direction+"/"+response, func(t *testing.T) {
					keepAlive := mipstack.KeepAliveConfig{Idle: 150 * time.Millisecond, Interval: 500 * time.Millisecond, Count: 1}
					observer := newTCPKeepAliveObserver()
					ackHeld, release := make(chan struct{}), make(chan struct{})
					var releaseOnce sync.Once
					held := false
					var probe tcpKeepAliveObservation
					network := newInteropNetworkWithOptions(t, interopNetworkOptions{
						families: []interopFamily{family}, mtu: 1500,
						tcp:              mipstack.TCPSocketDefaults{KeepAlive: true, KeepAliveConfig: keepAlive, UserTimeout: 100 * time.Millisecond},
						mipstackToGVisor: observer.observeOutbound,
						gvisorToMipstack: func(packet []byte) bool {
							tcpHeader, size, ok := tcpSegment(packet)
							if ok && size == 0 && tcpHeader.Flags() == header.TCPFlagAck && !held {
								select {
								case probe = <-observer.probes:
									held = true
									close(ackHeld)
									if silent {
										return false
									}
									<-release
								default:
								}
							}
							return observer.observeInbound(packet)
						},
					})
					t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					connection, ok := client.(*mipstack.TCPConn)
					if !ok {
						connection = server.(*mipstack.TCPConn)
					}
					select {
					case <-ackHeld:
					case <-time.After(2 * time.Second):
						t.Fatalf("gVisor did not acknowledge the keepalive probe; info=%+v", connection.Info())
					}
					if response == "silent option update" {
						if err := connection.SetNoDelay(false); err != nil {
							t.Fatal(err)
						}
					}
					var reenabledAt time.Time
					switch response {
					case "silent keepalive restart", "silent delayed keepalive restart", "silent coalesced keepalive restart":
						if err := connection.SetKeepAlive(false); err != nil {
							t.Fatal(err)
						}
						if response != "silent coalesced keepalive restart" && connection.Info().KeepAlive {
							t.Fatal("keepalive was not disabled")
						}
						if response == "silent delayed keepalive restart" {
							time.Sleep(keepAlive.Interval + keepAlive.Interval/4)
						}
						reenabledAt = time.Now()
						if err := connection.SetKeepAlive(true); err != nil {
							t.Fatal(err)
						}
					}
					delay := keepAlive.Interval / 5
					if !reenabledAt.IsZero() {
						delay = keepAlive.Idle / 5
					}
					time.Sleep(delay)
					if info := connection.Info(); info.State != mipstack.TCPStateEstablished || info.LastError != nil {
						t.Fatalf("connection closed before the next keepalive check: %+v", info)
					}
					if silent {
						_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
						var buffer [1]byte
						if n, err := connection.Read(buffer[:]); n != 0 || !errors.Is(err, syscall.ETIMEDOUT) {
							t.Fatalf("silent keepalive Read = %d, %v, want ETIMEDOUT", n, err)
						}
						elapsed, minimum := observer.elapsed()-probe.sentAt, keepAlive.Interval*3/4
						if !reenabledAt.IsZero() {
							elapsed, minimum = time.Since(reenabledAt), keepAlive.Idle*3/4
						}
						if elapsed < minimum {
							t.Fatalf("silent peer closed after %v, before the keepalive check's %v minimum", elapsed, minimum)
						}
						if probes := network.mipstack.Stats().TCPKeepAliveProbes; probes != 1 {
							t.Fatalf("published keepalive probes = %d, want 1", probes)
						}
						return
					}
					releaseOnce.Do(func() { close(release) })
					select {
					case <-observer.probes:
					case <-time.After((keepAlive.Idle + keepAlive.Interval) / 2):
						t.Fatalf("gVisor ACK did not restart the probe series with Idle; info=%+v", connection.Info())
					}
					exchangeTCPPayload(t, client, server, patternedPayload(32*1024, 29))
					exchangeTCPPayload(t, server, client, patternedPayload(32*1024, 71))
					exerciseFullDuplexTCP(t, client, server, 16*1024)
				})
			}
		}
	}
}

func TestTCPCloseWriteBlockedWriterInterop(t *testing.T) {
	for _, family := range interopFamilies {
		for _, mipstackListens := range []bool{false, true} {
			for _, mode := range []string{"Write", "ReadFrom", "Reader", "StoppedStackRead", "ReadFromStoppedStackRead"} {
				direction := "gvisor-listens"
				if mipstackListens {
					direction = "mipstack-listens"
				}
				t.Run(family.name+"/"+direction+"/"+mode, func(t *testing.T) {
					const capacity = 4096
					paused, resume := make(chan struct{}), make(chan struct{})
					var pauseOnce, resumeOnce sync.Once
					network := newInteropNetworkWithOptions(t, interopNetworkOptions{
						families: []interopFamily{family}, mtu: 1500,
						tcp: mipstack.TCPSocketDefaults{ReceiveBuffer: capacity, MaximumReceiveBuffer: capacity, SendBuffer: capacity, MaximumSendBuffer: capacity},
						mipstackToGVisor: func(packet []byte) bool {
							if mode == "StoppedStackRead" || mode == "ReadFromStoppedStackRead" {
								_, size, ok := tcpSegment(packet)
								if ok && size > 0 {
									pauseOnce.Do(func() { close(paused); <-resume })
								}
							}
							return true
						},
					})
					resumeRead := func() { resumeOnce.Do(func() { close(resume) }) }
					t.Cleanup(resumeRead)
					if err := network.gvisor.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
						Min: capacity, Default: capacity, Max: capacity,
					}); err != nil {
						t.Fatalf("gVisor receive buffer: %s", err.String())
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					connection, peer := client, server
					if mipstackListens {
						connection, peer = server, client
					}
					sender := connection.(*mipstack.TCPConn)
					payload := patternedPayload(64*1024, 173)
					type writeResult struct {
						n   int64
						err error
					}
					written := make(chan writeResult, 1)
					var pipeWriter *io.PipeWriter
					if mode == "Reader" {
						reader, writer := io.Pipe()
						pipeWriter = writer
						t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
						go func() {
							n, err := sender.ReadFrom(reader)
							written <- writeResult{n, err}
						}()
						payload = []byte("queued before the blocked source")
						if n, err := writer.Write(payload); err != nil || n != len(payload) {
							t.Fatalf("source Write = %d, %v", n, err)
						}
					} else {
						go func() {
							if mode == "ReadFrom" || mode == "ReadFromStoppedStackRead" {
								n, err := sender.ReadFrom(bytes.NewReader(payload))
								written <- writeResult{n, err}
							} else {
								n, err := sender.Write(payload)
								written <- writeResult{int64(n), err}
							}
						}()
					}
					if mode == "StoppedStackRead" || mode == "ReadFromStoppedStackRead" {
						select {
						case <-paused:
						case <-time.After(2 * time.Second):
							t.Fatal("external packet reader did not stop")
						}
					}
					ready := false
					for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
						info := sender.Info()
						if mode == "Reader" {
							ready = info.BytesAcknowledged == uint64(len(payload))
						} else {
							ready = info.SendBufferSize == capacity &&
								(info.PeerWindow == 0 || mode == "StoppedStackRead" || mode == "ReadFromStoppedStackRead")
						}
						if ready {
							break
						}
						time.Sleep(time.Millisecond)
					}
					if !ready {
						t.Fatalf("sender did not reach blocked state: %+v", sender.Info())
					}
					select {
					case result := <-written:
						t.Fatalf("writer returned before half-close: %+v", result)
					default:
					}
					closed := make(chan error, 1)
					go func() { closed <- sender.CloseWrite() }()
					select {
					case err := <-closed:
						if err != nil {
							t.Fatalf("CloseWrite: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("CloseWrite waited for the writer")
					}
					var result writeResult
					expected := payload
					if pipeWriter == nil {
						select {
						case result = <-written:
						case <-time.After(2 * time.Second):
							t.Fatal("writer did not observe half-close")
						}
						if result.n <= 0 || result.n >= int64(len(payload)) || !errors.Is(result.err, net.ErrClosed) {
							t.Fatalf("interrupted write = %d, %v", result.n, result.err)
						}
						expected = payload[:int(result.n)]
					}
					resumeRead()
					_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
					received, err := io.ReadAll(peer)
					if err != nil || !bytes.Equal(received, expected) {
						t.Fatalf("gVisor accepted prefix before EOF = %d bytes, %v; want %d matching bytes", len(received), err, len(expected))
					}
					response := patternedPayload(512, 179)
					if n, err := peer.Write(response); err != nil || n != len(response) {
						t.Fatalf("gVisor reverse Write = %d, %v", n, err)
					}
					if err := peer.(*gonet.TCPConn).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					_ = sender.SetReadDeadline(time.Now().Add(5 * time.Second))
					received, err = io.ReadAll(sender)
					if err != nil || !bytes.Equal(received, response) {
						t.Fatalf("mipstack reverse stream before EOF = %d bytes, %v", len(received), err)
					}
					if pipeWriter != nil {
						select {
						case result := <-written:
							t.Fatalf("ReadFrom returned before source EOF: %+v", result)
						default:
						}
						_ = pipeWriter.Close()
						select {
						case result = <-written:
						case <-time.After(2 * time.Second):
							t.Fatal("ReadFrom did not return after source EOF")
						}
						if result.n != int64(len(payload)) || result.err != nil {
							t.Fatalf("ReadFrom after source EOF = %d, %v", result.n, result.err)
						}
					}
				})
			}
		}
	}
}

func TestTCPReceiveWindowReopenInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			const receiveCapacity = 4 * 1024
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				tcp: mipstack.TCPSocketDefaults{ReceiveBuffer: receiveCapacity, MaximumReceiveBuffer: receiveCapacity},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(8 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatalf("set gVisor zero-window deadline: %v", err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatalf("set mipstack zero-window deadline: %v", err)
			}

			payload := patternedPayload(256*1024, 157)
			writeResult := make(chan error, 1)
			go writeTCPPayload(client, payload, "gVisor zero-window sender", writeResult)
			connection := server.(*mipstack.TCPConn)
			windowDeadline := time.Now().Add(2 * time.Second)
			var windowClosed bool
			for time.Now().Before(windowDeadline) {
				info := connection.Info()
				if info.ReceiveWindow == 0 && info.ReceiveBufferSize == receiveCapacity {
					windowClosed = true
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !windowClosed {
				info := connection.Info()
				t.Fatalf("mipstack receive window did not close: window=%d buffered=%d capacity=%d", info.ReceiveWindow, info.ReceiveBufferSize, info.ReceiveBufferCapacity)
			}
			received, err := io.ReadAll(server)
			if err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("read after reopening mipstack receive window: bytes=%d, error=%v", len(received), err)
			}
			if err = <-writeResult; err != nil {
				t.Fatal(err)
			}
			if info := connection.Info(); info.BytesReceived != uint64(len(payload)) || info.ReceiveBufferSize != 0 {
				t.Fatalf("mipstack post-window TCP info = received:%d buffered:%d", info.BytesReceived, info.ReceiveBufferSize)
			}
		})
	}
}

func TestTCPPersistProbeResponseInterop(t *testing.T) {
	for _, family := range interopFamilies {
		t.Run(family.name, func(t *testing.T) {
			var probes, responses atomic.Uint32
			var peerACK, probeSequence atomic.Uint32
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					segment, _, ok := tcpSegment(packet)
					if ok && segment.Flags().Contains(header.TCPFlagAck) && !segment.Flags().Contains(header.TCPFlagSyn) {
						peerACK.Store(segment.AckNumber())
						if probes.Load() != 0 && segment.WindowSize() == 0 && segment.AckNumber() == probeSequence.Load()+1 {
							responses.Add(1)
						}
					}
					return true
				},
				mipstackToGVisor: func(packet []byte) bool {
					segment, size, ok := tcpSegment(packet)
					if ok && size == 1 && segment.Flags() == header.TCPFlagAck && segment.SequenceNumber()+1 == peerACK.Load() {
						probeSequence.Store(segment.SequenceNumber())
						probes.Add(1)
					}
					return true
				},
			})
			limits := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 4096, Max: 4096}
			if err := network.gvisor.SetTransportProtocolOption(tcp.ProtocolNumber, &limits); err != nil {
				t.Fatalf("set gVisor receive limits: %s", err.String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer server.Close()
			defer client.Close()
			deadline := time.Now().Add(15 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			payload := patternedPayload(256*1024, 159)
			written := make(chan error, 1)
			go func() {
				n, err := client.Write(payload)
				if err == nil && n != len(payload) {
					err = io.ErrShortWrite
				}
				written <- err
			}()
			probeDeadline := time.Now().Add(10 * time.Second)
			for (probes.Load() < 2 || responses.Load() < 2) && time.Now().Before(probeDeadline) {
				time.Sleep(5 * time.Millisecond)
			}
			connection := client.(*mipstack.TCPConn)
			if info := connection.Info(); probes.Load() < 2 || responses.Load() < 2 || info.PeerWindow != 0 || info.State != mipstack.TCPStateEstablished {
				t.Fatalf("zero-window replies: probes=%d responses=%d info=%+v", probes.Load(), responses.Load(), info)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(server, received); err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("read after reopening gVisor window: %v", err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			exchangeTCPPayload(t, server, client, patternedPayload(4096, 161))
		})
	}
}

func TestTCPZeroWindowOutstandingResponseInterop(t *testing.T) {
	for _, family := range interopFamilies {
		t.Run(family.name, func(t *testing.T) {
			var widened atomic.Bool
			var captured atomic.Bool
			var zeroACK, responses atomic.Uint32
			retryPacket := make(chan []byte, 1)
			zeroReplies := make(chan uint32, 16)
			seen := make(map[uint32]bool)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					segment, _, ok := tcpSegment(packet)
					if !ok {
						return true
					}
					if segment.Flags() == header.TCPFlagSyn|header.TCPFlagAck {
						segment.SetWindowSize(65535)
						segment.SetChecksum(0)
						partial := header.PseudoHeaderChecksum(tcp.ProtocolNumber, gvisorAddress(family.gvisorAddress), gvisorAddress(family.mipstackAddress), uint16(len(segment)))
						segment.SetChecksum(^checksum.Checksum(segment, partial))
						widened.Store(true)
					} else if segment.Flags() == header.TCPFlagAck && segment.WindowSize() == 0 {
						zeroACK.Store(segment.AckNumber())
						responses.Add(1)
						select {
						case zeroReplies <- segment.AckNumber():
						default:
						}
					}
					return true
				},
				mipstackToGVisor: func(packet []byte) bool {
					segment, size, ok := tcpSegment(packet)
					if !ok || size == 0 {
						return true
					}
					sequence := segment.SequenceNumber()
					repeated := seen[sequence]
					seen[sequence] = true
					if repeated && responses.Load() != 0 && sequence == zeroACK.Load() && !captured.Swap(true) {
						retryPacket <- append([]byte(nil), packet...)
						return false
					}
					return true
				},
			})
			limits := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 4096, Max: 4096}
			if err := network.gvisor.SetTransportProtocolOption(tcp.ProtocolNumber, &limits); err != nil {
				t.Fatalf("set gVisor receive limits: %s", err.String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer server.Close()
			defer client.Close()
			deadline := time.Now().Add(8 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			connection := client.(*mipstack.TCPConn)
			payload := patternedPayload(3*connection.Info().MaximumSegmentSize, 163)
			if n, err := client.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("mipstack outstanding Write = %d, %v", n, err)
			}
			for until := time.Now().Add(time.Second); time.Now().Before(until); {
				if info := connection.Info(); info.PeerWindow == 0 && info.BytesSent > info.BytesAcknowledged {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if info := connection.Info(); info.PeerWindow != 0 || info.BytesSent <= info.BytesAcknowledged {
				t.Fatalf("gVisor did not close its window with outstanding data: %+v", info)
			}
			received := make([]byte, len(payload))
			prefix := connection.Info().MaximumSegmentSize
			if n, err := io.ReadFull(server, received[:prefix]); err != nil || n != prefix {
				t.Fatalf("gVisor partial read = %d/%d bytes, %v", n, prefix, err)
			}
			var retry []byte
			select {
			case retry = <-retryPacket:
			case <-time.After(3 * time.Second):
				t.Fatalf("outstanding zero-window retry was not observed: %+v", connection.Info())
			}
			for len(zeroReplies) != 0 {
				<-zeroReplies
			}
			select {
			case ack := <-zeroReplies:
				t.Fatalf("unexpected zero-window ACK %d before retry delivery", ack)
			case <-time.After(100 * time.Millisecond):
			}
			segment, _, ok := tcpSegment(retry)
			if !ok {
				t.Fatal("invalid held retry packet")
			}
			if err := network.deliverToGVisor(retry); err != nil {
				t.Fatal(err)
			}
			select {
			case ack := <-zeroReplies:
				if ack != segment.SequenceNumber() {
					t.Fatalf("native zero-window response ACK = %d, want %d", ack, segment.SequenceNumber())
				}
			case <-time.After(time.Second):
				t.Fatal("gVisor did not respond to the delivered RTO packet")
			}
			if info := connection.Info(); !widened.Load() || info.PeerWindow != 0 || info.BytesSent <= info.BytesAcknowledged || info.Retransmissions == 0 {
				t.Fatalf("outstanding zero-window response = widened:%t replies:%d info:%+v", widened.Load(), responses.Load(), info)
			}
			if stats := network.mipstack.Stats(); stats.TCPZeroWindowProbes != 0 || stats.TCPTailLossProbes != 0 {
				t.Fatalf("outstanding flight used a persist or tail-loss probe: %+v", stats)
			}
			if n, err := io.ReadFull(server, received[prefix:]); err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("gVisor read after reopening = %d/%d bytes, %v; %+v", n+prefix, len(payload), err, connection.Info())
			}
			exchangeTCPPayload(t, server, client, patternedPayload(4096, 165))
			if info := connection.Info(); info.LastError != nil || info.State != mipstack.TCPStateEstablished {
				t.Fatalf("resumed outstanding connection = %+v", info)
			}
		})
	}
}

func TestTCPZeroWindowFINInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			const receiveCapacity = 1
			var finCount atomic.Int32
			finObserved := make(chan struct{}, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				tcp: mipstack.TCPSocketDefaults{ReceiveBuffer: receiveCapacity, MaximumReceiveBuffer: receiveCapacity},
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if ok && payloadLength == 0 && tcpHeader.Flags().Contains(header.TCPFlagFin) &&
						!tcpHeader.Flags().Contains(header.TCPFlagSyn) {
						if finCount.Add(1) == 1 {
							select {
							case finObserved <- struct{}{}:
							default:
							}
						}
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			connection := server.(*mipstack.TCPConn)
			deadline := time.Now().Add(5 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if written, err := client.Write([]byte{'x'}); err != nil || written != 1 {
				t.Fatalf("gVisor one-byte write = %d, %v", written, err)
			}
			windowDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(windowDeadline) {
				info := connection.Info()
				if info.ReceiveWindow == 0 && info.ReceiveBufferSize == receiveCapacity {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if info := connection.Info(); info.ReceiveWindow != 0 || info.ReceiveBufferSize != receiveCapacity {
				t.Fatalf("mipstack receive window did not close: window=%d buffered=%d", info.ReceiveWindow, info.ReceiveBufferSize)
			}
			closeWriter, ok := client.(interface{ CloseWrite() error })
			if !ok {
				t.Fatal("gVisor TCP connection has no CloseWrite")
			}
			if err := closeWriter.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-finObserved:
			case <-time.After(2 * time.Second):
				t.Fatal("gVisor FIN was not observed")
			}
			stateDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(stateDeadline) && connection.Info().State != mipstack.TCPStateCloseWait {
				time.Sleep(5 * time.Millisecond)
			}
			if info := connection.Info(); info.State != mipstack.TCPStateCloseWait || finCount.Load() != 1 {
				t.Fatalf("mipstack close after first FIN = state:%v FINs:%d", info.State, finCount.Load())
			}
			if n, err := server.Read(make([]byte, 1)); n != 1 || err != nil {
				t.Fatalf("buffered byte before EOF = %d, %v", n, err)
			}
			if n, err := server.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("zero-window FIN read = %d, %v; want 0, EOF", n, err)
			}
		})
	}
}

func validateTCPMTUInfo(t *testing.T, info mipstack.TCPConnInfo, family interopFamily, mtu uint32) {
	t.Helper()
	maximumSegmentSize := int(mtu) - header.IPv4MinimumSize - header.TCPMinimumSize
	if family.mipstackAddress.Is6() {
		maximumSegmentSize = int(mtu) - header.IPv6MinimumSize - header.TCPMinimumSize
	}
	if info.PathMTU != int(mtu) || info.MaximumSegmentSize <= 0 || info.MaximumSegmentSize > maximumSegmentSize {
		t.Fatalf("mipstack TCP MTU info = path %d, MSS %d; want path %d and MSS 1..%d", info.PathMTU, info.MaximumSegmentSize, mtu, maximumSegmentSize)
	}
	if !info.SACK || !info.Timestamps || !info.WindowScaling {
		t.Fatalf("mipstack TCP negotiated options = SACK:%v timestamps:%v window-scaling:%v", info.SACK, info.Timestamps, info.WindowScaling)
	}
}

func newTCPDropHook(dropped *atomic.Bool) interopPacketHook {
	return func(packet []byte) bool {
		_, data := tcpDataSequence(packet)
		return !data || !dropped.CompareAndSwap(false, true)
	}
}

func newTCPControlDropHook(want header.TCPFlags, dropped *atomic.Bool) interopPacketHook {
	return func(packet []byte) bool {
		tcpHeader, payloadLength, ok := tcpSegment(packet)
		if !ok {
			return true
		}
		flags := tcpHeader.Flags()
		matched := flags.Contains(want)
		if want == header.TCPFlagSyn {
			matched = matched && !flags.Contains(header.TCPFlagAck)
		} else if want == header.TCPFlagAck {
			matched = flags == header.TCPFlagAck && payloadLength == 0
		}
		return !matched || !dropped.CompareAndSwap(false, true)
	}
}

func newTCPReorderHook(deliver func([]byte) error, reordered *atomic.Bool, bridgeErrors chan<- error) interopPacketHook {
	var held []byte
	var heldSequence uint32
	return func(packet []byte) bool {
		sequence, data := tcpDataSequence(packet)
		if !data || reordered.Load() {
			return true
		}
		if held == nil {
			held = append([]byte(nil), packet...)
			heldSequence = sequence
			return false
		}
		if sequence == heldSequence {
			return true
		}
		if err := deliver(packet); err != nil {
			select {
			case bridgeErrors <- err:
			default:
			}
		}
		if err := deliver(held); err != nil {
			select {
			case bridgeErrors <- err:
			default:
			}
		}
		held = nil
		reordered.Store(true)
		return false
	}
}

func tcpDataSequence(packet []byte) (uint32, bool) {
	tcpHeader, payloadLength, ok := tcpSegment(packet)
	if !ok || payloadLength == 0 {
		return 0, false
	}
	return tcpHeader.SequenceNumber(), true
}

type tcpKeepAliveObservation struct {
	sentAt, lastInbound time.Duration
}

type tcpKeepAliveObserver struct {
	origin       time.Time
	haveSendNext bool
	sendNext     uint32
	lastInboundData atomic.Int64
	probes          chan tcpKeepAliveObservation
	dropped         atomic.Bool
}

func newTCPKeepAliveObserver() *tcpKeepAliveObserver {
	return &tcpKeepAliveObserver{origin: time.Now(), probes: make(chan tcpKeepAliveObservation, 16)}
}

func (o *tcpKeepAliveObserver) elapsed() time.Duration {
	elapsed := time.Since(o.origin)
	if elapsed <= 0 {
		return 1
	}
	return elapsed
}

func (o *tcpKeepAliveObserver) observeInbound(packet []byte) bool {
	if _, payloadLength, ok := tcpSegment(packet); ok && payloadLength != 0 {
		o.lastInboundData.Store(int64(o.elapsed()))
	}
	return true
}

func (o *tcpKeepAliveObserver) observeOutbound(packet []byte) bool {
	tcpHeader, payloadLength, ok := tcpSegment(packet)
	if !ok {
		return true
	}
	flags := tcpHeader.Flags()
	sequence := tcpHeader.SequenceNumber()
	if flags.Contains(header.TCPFlagSyn) {
		o.sendNext = sequence + 1
		o.haveSendNext = true
	} else if o.haveSendNext && sequence == o.sendNext {
		o.sendNext += uint32(payloadLength)
		if flags.Contains(header.TCPFlagFin) {
			o.sendNext++
		}
	}
	control := header.TCPFlagSyn | header.TCPFlagFin | header.TCPFlagRst
	if o.haveSendNext && payloadLength == 0 && flags.Contains(header.TCPFlagAck) && flags&control == 0 && sequence == o.sendNext-1 {
		observation := tcpKeepAliveObservation{
			sentAt: o.elapsed(), lastInbound: time.Duration(o.lastInboundData.Load()),
		}
		select {
		case o.probes <- observation:
		default:
			o.dropped.Store(true)
		}
	}
	return true
}

func tcpHasSACKOption(tcpHeader header.TCP) bool {
	headerLength := int(tcpHeader.DataOffset())
	if headerLength < header.TCPMinimumSize || headerLength > len(tcpHeader) {
		return false
	}
	for options := tcpHeader[header.TCPMinimumSize:headerLength]; len(options) != 0; {
		kind := options[0]
		if kind == header.TCPOptionEOL {
			return false
		}
		if kind == header.TCPOptionNOP {
			options = options[1:]
			continue
		}
		if len(options) < 2 || int(options[1]) > len(options) || options[1] < 2 {
			return false
		}
		if kind == header.TCPOptionSACK && options[1] >= 10 && (options[1]-2)%8 == 0 {
			return true
		}
		options = options[options[1]:]
	}
	return false
}

func tcpSegment(packet []byte) (header.TCP, int, bool) {
	if len(packet) == 0 {
		return nil, 0, false
	}
	transportOffset := 0
	switch packet[0] >> 4 {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return nil, 0, false
		}
		ipHeader := header.IPv4(packet)
		if ipHeader.TransportProtocol() != header.TCPProtocolNumber {
			return nil, 0, false
		}
		transportOffset = int(ipHeader.HeaderLength())
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize || header.IPv6(packet).TransportProtocol() != header.TCPProtocolNumber {
			return nil, 0, false
		}
		transportOffset = header.IPv6MinimumSize
	default:
		return nil, 0, false
	}
	if len(packet) < transportOffset+header.TCPMinimumSize {
		return nil, 0, false
	}
	tcpHeader := header.TCP(packet[transportOffset:])
	headerSize := int(tcpHeader.DataOffset())
	if headerSize < header.TCPMinimumSize || len(packet) < transportOffset+headerSize {
		return nil, 0, false
	}
	return tcpHeader, len(packet) - transportOffset - headerSize, true
}

func stripTCPTimestamp(packet []byte) bool {
	const timestampOptionLength = header.TCPOptionTSLength
	if len(packet) == 0 {
		return false
	}
	transportOffset := 0
	wireEnd := len(packet)
	var source, target tcpip.Address
	var ipv4Header header.IPv4
	var ipv6Header header.IPv6
	switch packet[0] >> 4 {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return false
		}
		ipv4Header = header.IPv4(packet)
		if ipv4Header.TransportProtocol() != header.TCPProtocolNumber || int(ipv4Header.TotalLength()) > len(packet) {
			return false
		}
		transportOffset = int(ipv4Header.HeaderLength())
		wireEnd = int(ipv4Header.TotalLength())
		source, target = ipv4Header.SourceAddress(), ipv4Header.DestinationAddress()
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize || header.IPv6(packet).TransportProtocol() != header.TCPProtocolNumber {
			return false
		}
		ipv6Header = header.IPv6(packet)
		wireEnd = header.IPv6MinimumSize + int(ipv6Header.PayloadLength())
		if wireEnd > len(packet) {
			return false
		}
		transportOffset = header.IPv6MinimumSize
		source, target = ipv6Header.SourceAddress(), ipv6Header.DestinationAddress()
	default:
		return false
	}
	if wireEnd < transportOffset+header.TCPMinimumSize {
		return false
	}
	tcpHeader := header.TCP(packet[transportOffset:wireEnd])
	oldHeaderSize := int(tcpHeader.DataOffset())
	if oldHeaderSize < header.TCPMinimumSize || oldHeaderSize > len(tcpHeader) {
		return false
	}
	var compact [40]byte
	writeOffset := 0
	removed := false
	for options := tcpHeader.Options(); len(options) != 0; {
		kind := options[0]
		if kind == header.TCPOptionEOL {
			break
		}
		if kind == header.TCPOptionNOP {
			if writeOffset >= len(compact) {
				return false
			}
			compact[writeOffset] = kind
			writeOffset++
			options = options[1:]
			continue
		}
		if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
			return false
		}
		length := int(options[1])
		if kind == header.TCPOptionTS && length == timestampOptionLength {
			removed = true
			options = options[length:]
			continue
		}
		if writeOffset+length > len(compact) {
			return false
		}
		copy(compact[writeOffset:], options[:length])
		writeOffset += length
		options = options[length:]
	}
	if !removed {
		return false
	}
	newOptionsSize := (writeOffset + 3) &^ 3
	if newOptionsSize > len(compact) {
		return false
	}
	for writeOffset < newOptionsSize {
		compact[writeOffset] = header.TCPOptionNOP
		writeOffset++
	}
	newHeaderSize := header.TCPMinimumSize + newOptionsSize
	if newHeaderSize >= oldHeaderSize {
		return false
	}
	removedBytes := oldHeaderSize - newHeaderSize
	newWireEnd := wireEnd - removedBytes
	copy(packet[transportOffset+newHeaderSize:newWireEnd], packet[transportOffset+oldHeaderSize:wireEnd])
	copy(packet[transportOffset+header.TCPMinimumSize:transportOffset+newHeaderSize], compact[:newOptionsSize])
	tcpHeader = header.TCP(packet[transportOffset:newWireEnd])
	tcpHeader.SetDataOffset(uint8(newHeaderSize))
	tcpHeader.SetChecksum(0)
	partial := header.PseudoHeaderChecksum(header.TCPProtocolNumber, source, target, uint16(newWireEnd-transportOffset))
	tcpHeader.SetChecksum(^checksum.Checksum(tcpHeader, partial))
	if ipv4Header != nil {
		ipv4Header.SetTotalLength(uint16(newWireEnd))
		ipv4Header.SetChecksum(0)
		ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())
	} else {
		ipv6Header.SetPayloadLength(uint16(newWireEnd - header.IPv6MinimumSize))
	}
	return true
}

func rewriteTCPTimestamps(packet []byte, rewrite func(value, echo uint32) (uint32, uint32)) bool {
	if len(packet) == 0 {
		return false
	}
	transportOffset := 0
	wireEnd := len(packet)
	var source, target tcpip.Address
	switch packet[0] >> 4 {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return false
		}
		ipHeader := header.IPv4(packet)
		if ipHeader.TransportProtocol() != header.TCPProtocolNumber || int(ipHeader.TotalLength()) > len(packet) {
			return false
		}
		transportOffset = int(ipHeader.HeaderLength())
		wireEnd = int(ipHeader.TotalLength())
		source, target = ipHeader.SourceAddress(), ipHeader.DestinationAddress()
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return false
		}
		ipHeader := header.IPv6(packet)
		if ipHeader.TransportProtocol() != header.TCPProtocolNumber {
			return false
		}
		wireEnd = header.IPv6MinimumSize + int(ipHeader.PayloadLength())
		if wireEnd > len(packet) {
			return false
		}
		transportOffset = header.IPv6MinimumSize
		source, target = ipHeader.SourceAddress(), ipHeader.DestinationAddress()
	default:
		return false
	}
	if wireEnd < transportOffset+header.TCPMinimumSize {
		return false
	}
	tcpHeader := header.TCP(packet[transportOffset:wireEnd])
	headerSize := int(tcpHeader.DataOffset())
	if headerSize < header.TCPMinimumSize || headerSize > len(tcpHeader) {
		return false
	}
	for options := tcpHeader.Options(); len(options) != 0; {
		kind := options[0]
		if kind == header.TCPOptionEOL {
			break
		}
		if kind == header.TCPOptionNOP {
			options = options[1:]
			continue
		}
		if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
			return false
		}
		length := int(options[1])
		if kind == header.TCPOptionTS && length == header.TCPOptionTSLength {
			oldValue := binary.BigEndian.Uint32(options[2:6])
			oldEcho := binary.BigEndian.Uint32(options[6:10])
			oldChecksum := tcpHeader.Checksum()
			value, echo := rewrite(oldValue, oldEcho)
			binary.BigEndian.PutUint32(options[2:6], value)
			binary.BigEndian.PutUint32(options[6:10], echo)
			tcpHeader.SetChecksum(0)
			partial := header.PseudoHeaderChecksum(header.TCPProtocolNumber, source, target, uint16(wireEnd-transportOffset))
			tcpHeader.SetChecksum(^checksum.Checksum(tcpHeader, partial))
			if checksum.Checksum(tcpHeader, partial) != 0xffff {
				binary.BigEndian.PutUint32(options[2:6], oldValue)
				binary.BigEndian.PutUint32(options[6:10], oldEcho)
				tcpHeader.SetChecksum(oldChecksum)
				return false
			}
			return true
		}
		options = options[length:]
	}
	return false
}

func acceptGVisorTCP(ctx context.Context, listener tcpip.Endpoint, notifications <-chan struct{}) (tcpip.Endpoint, *waiter.Queue, error) {
	for {
		endpoint, queue, tcpipErr := listener.Accept(nil)
		if tcpipErr == nil {
			return endpoint, queue, nil
		}
		if _, wouldBlock := tcpipErr.(*tcpip.ErrWouldBlock); !wouldBlock {
			return nil, nil, errors.New(tcpipErr.String())
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-notifications:
		}
	}
}

func openTCPPair(t *testing.T, ctx context.Context, network *interopNetwork, family interopFamily, mipstackListens bool) (net.Conn, net.Conn, net.Listener) {
	t.Helper()
	const port = 41001

	var listener net.Listener
	var err error
	if mipstackListens {
		listener, err = network.mipstack.ListenTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, port))
	} else {
		listener, err = gonet.ListenTCP(network.gvisor, gvisorFullAddress(family.gvisorAddress, port), family.networkProtocol)
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

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
		client, err = network.mipstack.DialTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, 0), netipAddrPort(family.gvisorAddress, port))
	}
	if err != nil {
		_ = listener.Close()
		t.Fatalf("dial: %v", err)
	}

	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			_ = listener.Close()
			t.Fatalf("accept: %v", result.err)
		}
		return client, result.connection, listener
	case <-ctx.Done():
		_ = client.Close()
		_ = listener.Close()
		t.Fatalf("accept: %v", ctx.Err())
		return nil, nil, nil
	}
}

func exerciseFullDuplexTCP(t *testing.T, client, server net.Conn, payloadSize int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}

	clientPayload := patternedPayload(payloadSize, 17)
	serverPayload := patternedPayload(payloadSize, 83)
	results := make(chan error, 4)
	go writeTCPPayload(client, clientPayload, "client", results)
	go writeTCPPayload(server, serverPayload, "server", results)
	go readTCPPayload(client, serverPayload, "client", results)
	go readTCPPayload(server, clientPayload, "server", results)
	for index := 0; index < 4; index++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

func exchangeTCPPayload(t *testing.T, sender, receiver net.Conn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if err := sender.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set sender write deadline: %v", err)
	}
	if err := receiver.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set receiver read deadline: %v", err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(sender, bytes.NewReader(payload))
		written <- err
	}()
	received := make([]byte, len(payload))
	_, readErr := io.ReadFull(receiver, received)
	writeErr := <-written
	if writeErr != nil {
		t.Fatalf("write payload: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("read payload: %v", readErr)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("payload mismatch")
	}
}

func readTCPPayloadWithBuffer(t *testing.T, connection *mipstack.TCPConn, expected []byte) {
	t.Helper()
	storage := make([]byte, 4*1024)
	received := make([]byte, 0, len(expected))
	for len(received) < len(expected) {
		remaining := len(expected) - len(received)
		var provided []byte
		n, err := connection.ReadWithBuffer(func(sizeHint int) []byte {
			if sizeHint <= 0 {
				t.Fatalf("ReadWithBuffer reported non-positive size hint %d", sizeHint)
			}
			provided = storage
			if sizeHint < len(provided) {
				provided = provided[:sizeHint]
			}
			if remaining < len(provided) {
				provided = provided[:remaining]
			}
			return provided
		})
		if n < 0 || n > len(provided) {
			t.Fatalf("ReadWithBuffer returned %d bytes for a %d-byte buffer", n, len(provided))
		}
		if n != 0 {
			received = append(received, provided[:n]...)
		}
		if err != nil {
			t.Fatalf("ReadWithBuffer after %d bytes: %v", len(received), err)
		}
		if n == 0 {
			t.Fatal("ReadWithBuffer returned no data and no error")
		}
	}
	if !bytes.Equal(received, expected) {
		t.Fatal("ReadWithBuffer payload mismatch")
	}
}

func writeTCPPayload(connection net.Conn, payload []byte, side string, result chan<- error) {
	written, err := io.Copy(connection, bytes.NewReader(payload))
	if err == nil && written != int64(len(payload)) {
		err = io.ErrShortWrite
	}
	if err == nil {
		if closeWriter, ok := connection.(interface{ CloseWrite() error }); ok {
			err = closeWriter.CloseWrite()
		} else {
			err = errors.New("connection does not implement CloseWrite")
		}
	}
	if err != nil {
		err = fmt.Errorf("%s write: %w", side, err)
	}
	result <- err
}

func readTCPPayload(connection net.Conn, expected []byte, side string, result chan<- error) {
	payload, err := io.ReadAll(connection)
	if err == nil && !bytes.Equal(payload, expected) {
		err = fmt.Errorf("payload mismatch: got %d bytes, want %d", len(payload), len(expected))
	}
	if err != nil {
		err = fmt.Errorf("%s read: %w", side, err)
	}
	result <- err
}
