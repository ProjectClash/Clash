package gvisorinterop_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

const (
	forwardTCPPort = 44001
	forwardUDPPort = 44002
)

func TestTCPForwarderInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newForwarderInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()

				type acceptResult struct {
					connection *mipstack.TCPConn
					flow       mipstack.ForwarderFlow
					err        error
				}
				accepted := make(chan acceptResult, 1)
				forwarder, err := mipstack.NewTCPForwarder(network.mipstack, mipstack.TCPForwarderOptions{}, func(request *mipstack.TCPForwarderRequest) {
					flow := request.Flow()
					connection, acceptErr := request.Accept(ctx)
					accepted <- acceptResult{connection: connection, flow: flow, err: acceptErr}
				})
				if err != nil {
					t.Fatalf("create TCP forwarder: %v", err)
				}
				defer forwarder.Close()

				target := netipAddrPort(family.forwardAddress, forwardTCPPort)
				client, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(target.Addr(), target.Port()), family.networkProtocol)
				if err != nil {
					t.Fatalf("dial forwarded TCP destination: %v", err)
				}
				defer client.Close()

				var result acceptResult
				select {
				case result = <-accepted:
				case <-ctx.Done():
					t.Fatalf("accept forwarded TCP connection: %v", ctx.Err())
				}
				if result.err != nil {
					t.Fatalf("accept forwarded TCP connection: %v", result.err)
				}
				defer result.connection.Close()
				wantSource := requireAddrPort(t, client.LocalAddr())
				if result.flow.Source != wantSource || result.flow.Destination != target {
					t.Fatalf("forwarded TCP flow = %+v, want %v -> %v", result.flow, wantSource, target)
				}
				if local, remote := requireAddrPort(t, result.connection.LocalAddr()), requireAddrPort(t, result.connection.RemoteAddr()); local != target || remote != wantSource {
					t.Fatalf("forwarded TCP endpoints = %v -> %v, want %v -> %v", remote, local, wantSource, target)
				}

				exerciseFullDuplexTCP(t, client, result.connection, tcpInteropStreamSize(mtu))
				validateTCPMTUInfo(t, result.connection.Info(), family, mtu)
				if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
					t.Fatalf("TCP forwarder info = %+v", info)
				}
			})
		}
	}
}

func TestTCPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newConfiguredForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type rejectResult struct {
				flow mipstack.ForwarderFlow
				err  error
			}
			results := make(chan rejectResult, 1)
			forwarder, err := mipstack.NewTCPForwarder(network.mipstack, mipstack.TCPForwarderOptions{}, func(request *mipstack.TCPForwarderRequest) {
				results <- rejectResult{flow: request.Flow(), err: request.Reject()}
			})
			if err != nil {
				t.Fatalf("create TCP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			target := netipAddrPort(family.forwardAddress, forwardTCPPort)
			connection, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(target.Addr(), target.Port()), family.networkProtocol)
			if connection != nil {
				_ = connection.Close()
			}
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("gVisor dial after TCP Forwarder Reject = %v, want ECONNREFUSED", err)
			}
			select {
			case result := <-results:
				if result.err != nil || result.flow.Destination != target || result.flow.Source.Addr() != family.gvisorAddress {
					t.Fatalf("TCP Forwarder Reject = flow %+v, error=%v", result.flow, result.err)
				}
			case <-ctx.Done():
				t.Fatalf("receive TCP Forwarder Reject result: %v", ctx.Err())
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("TCP reject forwarder info = %+v", info)
			}
		})
	}
}

func TestUDPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newConfiguredForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type rejectResult struct {
				flow mipstack.ForwarderFlow
				err  error
			}
			replied := make(chan rejectResult, 1)
			reject := make(chan struct{})
			results := make(chan rejectResult, 1)
			forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
				flow := request.Flow()
				if written, replyErr := request.Reply([]byte("reply-before-reject")); replyErr != nil || written != len("reply-before-reject") {
					if replyErr == nil {
						replyErr = io.ErrShortWrite
					}
					results <- rejectResult{flow: flow, err: replyErr}
					return
				}
				replied <- rejectResult{flow: flow}
				select {
				case <-reject:
				case <-ctx.Done():
					results <- rejectResult{flow: flow, err: ctx.Err()}
					return
				}
				results <- rejectResult{flow: flow, err: request.Reject()}
			})
			if err != nil {
				t.Fatalf("create UDP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			var queue waiter.Queue
			endpoint, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor UDP endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor UDP endpoint: %s", tcpipErr.String())
			}
			target := netipAddrPort(family.forwardAddress, forwardUDPPort)
			if tcpipErr = endpoint.Connect(gvisorFullAddress(target.Addr(), target.Port())); tcpipErr != nil {
				t.Fatalf("connect gVisor UDP endpoint: %s", tcpipErr.String())
			}
			readEntry, readable := registerReadable(&queue)
			defer queue.EventUnregister(&readEntry)
			errorEntry, errorsReady := waiter.NewChannelEntry(waiter.EventErr)
			queue.EventRegister(&errorEntry)
			defer queue.EventUnregister(&errorEntry)
			written, tcpipErr := endpoint.Write(bytes.NewReader([]byte("reject")), tcpip.WriteOptions{})
			if tcpipErr != nil || written != 6 {
				t.Fatalf("write gVisor rejected UDP datagram: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
			}

			select {
			case result := <-replied:
				if result.err != nil || result.flow.Destination != target || result.flow.Source.Addr() != family.gvisorAddress {
					t.Fatalf("UDP Forwarder Reply = flow %+v, error=%v", result.flow, result.err)
				}
			case result := <-results:
				t.Fatalf("UDP Forwarder Reply failed before synchronization: flow %+v, error=%v", result.flow, result.err)
			case <-ctx.Done():
				t.Fatalf("receive UDP Forwarder Reply result: %v", ctx.Err())
			}
			reply, _, readErr := readGVisorEndpoint(ctx, endpoint, readable, 64)
			if readErr != nil || string(reply) != "reply-before-reject" {
				t.Fatalf("read UDP reply before Reject = %q, %v", reply, readErr)
			}
			close(reject)
			select {
			case result := <-results:
				if result.err != nil {
					t.Fatalf("UDP Forwarder Reject = flow %+v, error=%v", result.flow, result.err)
				}
			case <-ctx.Done():
				t.Fatalf("receive UDP Forwarder Reject result: %v", ctx.Err())
			}
			select {
			case <-errorsReady:
			case <-ctx.Done():
				t.Fatalf("wait for gVisor UDP rejection: %v", ctx.Err())
			}
			if lastError := endpoint.LastError(); lastError == nil {
				t.Fatal("gVisor UDP endpoint signaled rejection without LastError")
			} else if _, refused := lastError.(*tcpip.ErrConnectionRefused); !refused {
				t.Fatalf("gVisor UDP rejection = %T %s, want ErrConnectionRefused", lastError, lastError.String())
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("UDP reject forwarder info = %+v", info)
			}
		})
	}
}

func TestIPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newConfiguredForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			replied := make(chan error, 1)
			reject := make(chan struct{})
			results := make(chan error, 1)
			forwarder, err := mipstack.NewIPForwarder(network.mipstack, mipstack.IPForwarderOptions{}, func(request *mipstack.IPForwarderRequest) {
				if replyErr := request.Reply([]byte("reply-before-reject")); replyErr != nil {
					results <- replyErr
					return
				}
				replied <- nil
				select {
				case <-reject:
				case <-ctx.Done():
					results <- ctx.Err()
					return
				}
				results <- request.Reject()
			})
			if err != nil {
				t.Fatalf("create IP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			monitor, notifications := newGVisorRawICMPMonitor(t, network, family)
			var queue waiter.Queue
			sender, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw IP sender: %s", tcpipErr.String())
			}
			defer sender.Close()
			if tcpipErr = sender.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw IP sender: %s", tcpipErr.String())
			}
			if tcpipErr = sender.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw IP sender: %s", tcpipErr.String())
			}
			replyEntry, replyReady := registerReadable(&queue)
			defer queue.EventUnregister(&replyEntry)
			payload := []byte("reject-raw-protocol")
			if written, writeErr := sender.Write(bytes.NewReader(payload), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(payload)) {
				t.Fatalf("write rejected gVisor raw IP payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			select {
			case replyErr := <-replied:
				if replyErr != nil {
					t.Fatalf("reply before IP Forwarder Reject: %v", replyErr)
				}
			case rejectErr := <-results:
				t.Fatalf("IP Forwarder Reply failed before synchronization: %v", rejectErr)
			case <-ctx.Done():
				t.Fatalf("wait for IP Forwarder Reply: %v", ctx.Err())
			}
			replyPacket, replyRemote, readErr := readGVisorEndpoint(ctx, sender, replyReady, 128)
			if readErr != nil {
				t.Fatalf("read reply before IP Forwarder Reject: %v", readErr)
			}
			replyPayload, stripErr := stripGVisorRawHeader(family, replyPacket)
			if stripErr != nil || replyRemote.Addr != gvisorAddress(family.forwardAddress) || string(replyPayload) != "reply-before-reject" {
				t.Fatalf("IP Forwarder Reply before Reject = %q from %v, error=%v", replyPayload, replyRemote.Addr, stripErr)
			}
			close(reject)
			select {
			case rejectErr := <-results:
				if rejectErr != nil {
					t.Fatalf("reject IP Forwarder request: %v", rejectErr)
				}
			case <-ctx.Done():
				t.Fatalf("wait for IP Forwarder Reject: %v", ctx.Err())
			}
			packet, remote, readErr := readGVisorEndpoint(ctx, monitor, notifications, 2048)
			if readErr != nil {
				t.Fatalf("read gVisor IP Forwarder rejection: %v", readErr)
			}
			message, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			wantType, wantCode := byte(header.ICMPv4DstUnreachable), byte(header.ICMPv4ProtoUnreachable)
			wantPointer, checkPointer := uint32(0), false
			if family.mipstackAddress.Is6() {
				wantType, wantCode = byte(header.ICMPv6ParamProblem), 1
				wantPointer, checkPointer = 6, true
			}
			validateForwarderICMPError(t, family, message, remote, uint8(interopRawIPProtocol), wantType, wantCode, wantPointer, checkPointer)
			if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("IP reject forwarder info = %+v", info)
			}
		})
	}
}

func TestICMPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newConfiguredForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			replied := make(chan error, 1)
			reject := make(chan struct{})
			results := make(chan error, 1)
			forwarder, err := mipstack.NewICMPForwarder(network.mipstack, mipstack.ICMPForwarderOptions{}, func(request *mipstack.ICMPForwarderRequest) {
				if replyErr := request.ReplyEcho(); replyErr != nil {
					results <- replyErr
					return
				}
				replied <- nil
				select {
				case <-reject:
				case <-ctx.Done():
					results <- ctx.Err()
					return
				}
				results <- request.Reject()
			})
			if err != nil {
				t.Fatalf("create ICMP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			monitor, notifications := newGVisorRawICMPMonitor(t, network, family)
			var queue waiter.Queue
			sender, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor ICMP sender: %s", tcpipErr.String())
			}
			defer sender.Close()
			const identifier = 0x6401
			if tcpipErr = sender.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
				t.Fatalf("bind gVisor ICMP sender: %s", tcpipErr.String())
			}
			if tcpipErr = sender.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor ICMP sender: %s", tcpipErr.String())
			}
			replyEntry, replyReady := registerReadable(&queue)
			defer queue.EventUnregister(&replyEntry)
			request := makeICMPEcho(family, false, identifier, 1, []byte("reject-echo"), family.gvisorAddress, family.forwardAddress)
			if written, writeErr := sender.Write(bytes.NewReader(request), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write rejected gVisor ICMP request: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			select {
			case replyErr := <-replied:
				if replyErr != nil {
					t.Fatalf("reply before ICMP Forwarder Reject: %v", replyErr)
				}
			case rejectErr := <-results:
				t.Fatalf("ICMP Forwarder Reply failed before synchronization: %v", rejectErr)
			case <-ctx.Done():
				t.Fatalf("wait for ICMP Forwarder Reply: %v", ctx.Err())
			}
			reply, remote, readErr := readGVisorEndpoint(ctx, sender, replyReady, 2048)
			if readErr != nil {
				t.Fatalf("read reply before ICMP Forwarder Reject: %v", readErr)
			}
			if remote.Addr != gvisorAddress(family.forwardAddress) {
				t.Fatalf("ICMP Forwarder Reply source = %v, want %v", remote.Addr, family.forwardAddress)
			}
			if validateErr := validateICMPEcho(family, reply, true, identifier, 1, []byte("reject-echo"), family.forwardAddress, family.gvisorAddress); validateErr != nil {
				t.Fatalf("ICMP Forwarder Reply before Reject: %v", validateErr)
			}
			observedReply, observedRemote, readErr := readGVisorEndpoint(ctx, monitor, notifications, 2048)
			if readErr != nil {
				t.Fatalf("read raw monitor copy before ICMP Forwarder Reject: %v", readErr)
			}
			observedMessage, stripErr := stripGVisorRawHeader(family, observedReply)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			if observedRemote.Addr != gvisorAddress(family.forwardAddress) {
				t.Fatalf("raw monitor ICMP Reply source = %v, want %v", observedRemote.Addr, family.forwardAddress)
			}
			if validateErr := validateICMPEcho(family, observedMessage, true, identifier, 1, []byte("reject-echo"), family.forwardAddress, family.gvisorAddress); validateErr != nil {
				t.Fatalf("raw monitor ICMP Reply before Reject: %v", validateErr)
			}
			close(reject)
			select {
			case rejectErr := <-results:
				if rejectErr != nil {
					t.Fatalf("reject ICMP Forwarder request: %v", rejectErr)
				}
			case <-ctx.Done():
				t.Fatalf("wait for ICMP Forwarder Reject: %v", ctx.Err())
			}
			packet, remote, readErr := readGVisorEndpoint(ctx, monitor, notifications, 2048)
			if readErr != nil {
				t.Fatalf("read gVisor ICMP Forwarder rejection: %v", readErr)
			}
			message, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			protocol := uint8(header.ICMPv4ProtocolNumber)
			wantType, wantCode := byte(header.ICMPv4DstUnreachable), byte(header.ICMPv4AdminProhibited)
			if family.mipstackAddress.Is6() {
				protocol = uint8(header.ICMPv6ProtocolNumber)
				wantType, wantCode = byte(header.ICMPv6DstUnreachable), byte(header.ICMPv6Prohibited)
			}
			validateForwarderICMPError(t, family, message, remote, protocol, wantType, wantCode, 0, false)
			if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("ICMP reject forwarder info = %+v", info)
			}
		})
	}
}

func TestUDPForwarderEndpointInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, listen := range []bool{false, true} {
				listen := listen
				mode := "accept"
				if listen {
					mode = "listen"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					type endpointResult struct {
						connection *mipstack.UDPConn
						flow       mipstack.ForwarderFlow
						err        error
					}
					endpoints := make(chan endpointResult, 1)
					forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
						flow := request.Flow()
						if _, replyErr := request.Reply([]byte("reply-before-endpoint")); replyErr != nil {
							endpoints <- endpointResult{flow: flow, err: replyErr}
							return
						}
						var connection *mipstack.UDPConn
						var endpointErr error
						if listen {
							connection, endpointErr = request.Listen()
						} else {
							connection, endpointErr = request.Accept()
						}
						endpoints <- endpointResult{connection: connection, flow: flow, err: endpointErr}
					})
					if err != nil {
						t.Fatalf("create UDP forwarder: %v", err)
					}
					defer forwarder.Close()

					target := netipAddrPort(family.forwardAddress, forwardUDPPort)
					firstClient := dialGVisorForwardUDP(t, network, family, target)
					defer firstClient.Close()
					clients := []*gonet.UDPConn{firstClient, firstClient}
					if listen {
						secondClient := dialGVisorForwardUDP(t, network, family, target)
						defer secondClient.Close()
						clients[1] = secondClient
					}

					var forwarded *mipstack.UDPConn
					buffer := make([]byte, 65535)
					for index, size := range []int{37, fragmentedInteropPayloadSize(mtu, 12_000)} {
						request := patternedPayload(size, byte(11+index))
						response := patternedPayload(size+19, byte(47+index))
						client := clients[index]
						written, writeErr := client.Write(request)
						if writeErr != nil || written != len(request) {
							t.Fatalf("write forwarded UDP request: n=%d, error=%v", written, writeErr)
						}
						if index == 0 {
							preReply := make([]byte, 64)
							read, readErr := client.Read(preReply)
							if readErr != nil || string(preReply[:read]) != "reply-before-endpoint" {
								t.Fatalf("read UDP reply before %s: n=%d error=%v", mode, read, readErr)
							}
							select {
							case result := <-endpoints:
								if result.err != nil {
									t.Fatalf("create forwarded UDP endpoint: %v", result.err)
								}
								forwarded = result.connection
								wantSource := requireAddrPort(t, client.LocalAddr())
								if result.flow.Source != wantSource || result.flow.Destination != target {
									t.Fatalf("forwarded UDP flow = %+v, want %v -> %v", result.flow, wantSource, target)
								}
								if local := requireAddrPort(t, forwarded.LocalAddr()); local != target {
									t.Fatalf("forwarded UDP local endpoint = %v, want %v", local, target)
								}
								if listen {
									if remote := forwarded.RemoteAddr(); remote != nil {
										t.Fatalf("listened UDP remote endpoint = %v, want nil", remote)
									}
								} else if remote := requireAddrPort(t, forwarded.RemoteAddr()); remote != wantSource {
									t.Fatalf("accepted UDP remote endpoint = %v, want %v", remote, wantSource)
								}
							case <-ctx.Done():
								t.Fatalf("receive forwarded UDP endpoint: %v", ctx.Err())
							}
							defer forwarded.Close()
							if err = forwarded.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
								t.Fatalf("set forwarded UDP deadline: %v", err)
							}
						}

						wantSource := requireAddrPort(t, client.LocalAddr())
						var read int
						var source netip.AddrPort
						if listen {
							read, source, err = forwarded.ReadFromUDPAddrPort(buffer)
						} else {
							read, err = forwarded.Read(buffer)
							source = wantSource
						}
						if err != nil || source != wantSource || !bytes.Equal(buffer[:read], request) {
							t.Fatalf("read forwarded UDP request: n=%d, source=%v, error=%v", read, source, err)
						}
						if listen {
							written, err = forwarded.WriteToUDPAddrPort(response, source)
						} else {
							written, err = forwarded.Write(response)
						}
						if err != nil || written != len(response) {
							t.Fatalf("write forwarded UDP response: n=%d, error=%v", written, err)
						}
						read, err = client.Read(buffer)
						if err != nil || !bytes.Equal(buffer[:read], response) {
							t.Fatalf("read gVisor UDP response: n=%d, error=%v", read, err)
						}
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Replies != 1 || info.Pending != 0 {
						t.Fatalf("UDP endpoint forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

func TestUDPForwarderReplyInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					type replyResult struct {
						flow      mipstack.ForwarderFlow
						request   []byte
						responses [][]byte
						responder *mipstack.UDPForwarderResponder
						err       error
					}
					results := make(chan replyResult, 1)
					forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
						payload := append([]byte(nil), request.Payload()...)
						response := append([]byte("udp-forward:"), payload...)
						result := replyResult{flow: request.Flow(), request: payload, responses: [][]byte{response}}
						if detached {
							callbackResponse := append([]byte("udp-callback:"), payload...)
							result.responses = [][]byte{callbackResponse, response}
							var written int
							written, result.err = request.Reply(callbackResponse)
							if result.err == nil && written != len(callbackResponse) {
								result.err = io.ErrShortWrite
							}
							if result.err == nil {
								result.responder, result.err = request.Detach()
							}
						} else {
							var written int
							written, result.err = request.Reply(response)
							if result.err == nil && written != len(response) {
								result.err = io.ErrShortWrite
							}
						}
						results <- result
					})
					if err != nil {
						t.Fatalf("create UDP reply forwarder: %v", err)
					}
					defer forwarder.Close()

					target := netipAddrPort(family.forwardAddress, forwardUDPPort)
					client := dialGVisorForwardUDP(t, network, family, target)
					defer client.Close()
					payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 12_000), 79)
					written, err := client.Write(payload)
					if err != nil || written != len(payload) {
						t.Fatalf("write gVisor UDP request: n=%d, error=%v", written, err)
					}

					var result replyResult
					select {
					case result = <-results:
					case <-ctx.Done():
						t.Fatalf("receive UDP reply request: %v", ctx.Err())
					}
					if result.err != nil {
						t.Fatalf("prepare UDP reply: %v", result.err)
					}
					wantSource := requireAddrPort(t, client.LocalAddr())
					if result.flow.Source != wantSource || result.flow.Destination != target || !bytes.Equal(result.request, payload) {
						t.Fatalf("UDP reply request = flow %+v, payload %d bytes", result.flow, len(result.request))
					}
					if detached {
						written, err = result.responder.Reply(result.responses[1])
						if err != nil || written != len(result.responses[1]) {
							t.Fatalf("write detached UDP reply: n=%d, error=%v", written, err)
						}
					}
					buffer := make([]byte, 65535)
					seen := make([]bool, len(result.responses))
					for received := range result.responses {
						read, readErr := client.Read(buffer)
						if readErr != nil {
							t.Fatalf("read gVisor UDP reply %d: n=%d, error=%v", received, read, readErr)
						}
						matched := -1
						for index, response := range result.responses {
							if !seen[index] && bytes.Equal(buffer[:read], response) {
								matched = index
								break
							}
						}
						if matched < 0 {
							t.Fatalf("read unexpected or duplicate gVisor UDP reply %d: n=%d", received, read)
						}
						seen[matched] = true
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Replies != uint64(len(result.responses)) || info.Pending != 0 {
						t.Fatalf("UDP reply forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

func TestUDPForwarderReplyFromInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, detached := range []bool{false, true} {
			detached := detached
			mode := "callback"
			if detached {
				mode = "detached"
			}
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				network := newForwarderInteropNetwork(t, family, 1280)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				type result struct {
					responder *mipstack.UDPForwarderResponder
					err       error
				}
				results := make(chan result, 1)
				forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
					if detached {
						if _, replyErr := request.ReplyFrom([]byte{0}, netipAddrPort(family.forwardAddress, 45010)); replyErr != nil {
							results <- result{err: replyErr}
							return
						}
						responder, detachErr := request.Detach()
						results <- result{responder: responder, err: detachErr}
						return
					}
					for index, port := range []uint16{45011, 45012} {
						if _, replyErr := request.ReplyFrom([]byte{byte(index + 1)}, netipAddrPort(family.forwardAddress, port)); replyErr != nil {
							results <- result{err: replyErr}
							return
						}
					}
					results <- result{}
				})
				if err != nil {
					t.Fatalf("create UDP ReplyFrom forwarder: %v", err)
				}
				defer forwarder.Close()
				target := netipAddrPort(family.forwardAddress, forwardUDPPort)
				client := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, 0), func(tcpip.Endpoint) {})
				defer client.Close()
				if err = client.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
					t.Fatalf("set gVisor UDP deadline: %v", err)
				}
				if _, err = client.WriteTo([]byte("sources"), net.UDPAddrFromAddrPort(target)); err != nil {
					t.Fatalf("write unconnected gVisor UDP request: %v", err)
				}
				var prepared result
				select {
				case prepared = <-results:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if prepared.err != nil {
					t.Fatal(prepared.err)
				}
				if detached {
					for index, port := range []uint16{45011, 45012} {
						if _, err = prepared.responder.ReplyFrom([]byte{byte(index + 1)}, netipAddrPort(family.forwardAddress, port)); err != nil {
							t.Fatal(err)
						}
					}
				}
				seen := map[uint16]byte{}
				buffer := make([]byte, 8)
				wantReplies := 2
				if detached {
					wantReplies = 3
				}
				for index := 0; index < wantReplies; index++ {
					n, sourceAddress, readErr := client.ReadFrom(buffer)
					source, ok := sourceAddress.(*net.UDPAddr)
					if readErr != nil || !ok || n != 1 || source.IP.String() != family.forwardAddress.String() {
						t.Fatalf("read gVisor ReplyFrom: n=%d source=%v error=%v", n, source, readErr)
					}
					seen[uint16(source.Port)] = buffer[0]
				}
				if detached && seen[45010] != 0 || seen[45011] != 1 || seen[45012] != 2 {
					t.Fatalf("ReplyFrom sources = %+v", seen)
				}
				if info := forwarder.Info(); info.Requests != 1 || info.Replies != uint64(wantReplies) || info.Pending != 0 {
					t.Fatalf("ReplyFrom forwarder info = %+v", info)
				}
			})
		}
	}
}

func TestICMPForwarderReplyIPPacketInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			if mtu < 576 {
				continue
			}
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096), 137)
					identifier := uint16(0x6800 + mtu%251)
					const sequence = 7
					type result struct {
						packet    []byte
						responder *mipstack.ICMPForwarderResponder
						err       error
					}
					results := make(chan result, 1)
					forwarder, err := mipstack.NewICMPForwarder(network.mipstack, mipstack.ICMPForwarderOptions{}, func(request *mipstack.ICMPForwarderRequest) {
						echo := makeICMPEcho(family, true, identifier, sequence, payload, family.forwardAddress, family.gvisorAddress)
						packet := makeInteropICMPPacket(family, family.forwardAddress, family.gvisorAddress, echo, true)
						result := result{packet: packet}
						if detached {
							result.err = request.ReplyIPPacket(packet)
							if result.err == nil {
								result.responder, result.err = request.Detach()
							}
						} else {
							result.err = request.ReplyIPPacket(packet)
						}
						results <- result
					})
					if err != nil {
						t.Fatal(err)
					}
					defer forwarder.Close()
					request := makeICMPEcho(family, false, identifier, 1, []byte("header included"), family.gvisorAddress, family.forwardAddress)
					var queue waiter.Queue
					endpoint, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
					if tcpipErr != nil {
						t.Fatal(tcpipErr.String())
					}
					defer endpoint.Close()
					if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
						t.Fatal(tcpipErr.String())
					}
					if tcpipErr = endpoint.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
						t.Fatal(tcpipErr.String())
					}
					entry, notifications := registerReadable(&queue)
					defer queue.EventUnregister(&entry)
					if written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(request)) {
						t.Fatalf("write forwarded ICMP request: n=%d err=%s", written, tcpipErrorString(writeErr))
					}
					var prepared result
					select {
					case prepared = <-results:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					if prepared.err != nil {
						t.Fatal(prepared.err)
					}
					if detached {
						if err = prepared.responder.ReplyIPPacket(prepared.packet); err != nil {
							t.Fatal(err)
						}
					}
					wantReplies := 1
					if detached {
						wantReplies = 2
					}
					for index := 0; index < wantReplies; index++ {
						message, remote, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
						if readErr != nil {
							t.Fatal(readErr)
						}
						if remote.Addr != gvisorAddress(family.forwardAddress) {
							t.Fatalf("ReplyIPPacket source = %v, want %v", remote.Addr, family.forwardAddress)
						}
						if err = validateICMPEcho(family, message, true, identifier, sequence, payload, family.forwardAddress, family.gvisorAddress); err != nil {
							t.Fatal(err)
						}
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Replies != uint64(wantReplies) || info.Pending != 0 {
						t.Fatalf("ReplyIPPacket forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

func TestICMPForwarderReplyIPPacketErrorInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, detached := range []bool{false, true} {
			detached := detached
			mode := "callback"
			if detached {
				mode = "detached"
			}
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				network := newForwarderInteropNetwork(t, family, 1500)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				type result struct {
					packet    []byte
					responder *mipstack.ICMPForwarderResponder
					err       error
				}
				results := make(chan result, 1)
				forwarder, err := mipstack.NewICMPForwarder(network.mipstack, mipstack.ICMPForwarderOptions{}, func(request *mipstack.ICMPForwarderRequest) {
					packet := makeInteropICMPErrorPacket(family, family.forwardAddress, family.gvisorAddress, request.IPPacket())
					result := result{packet: packet}
					if detached {
						result.responder, result.err = request.Detach()
					} else {
						result.err = request.ReplyIPPacket(packet)
					}
					results <- result
				})
				if err != nil {
					t.Fatal(err)
				}
				defer forwarder.Close()
				monitor, notifications := newGVisorRawICMPMonitor(t, network, family)
				var queue waiter.Queue
				endpoint, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
				if tcpipErr != nil {
					t.Fatal(tcpipErr.String())
				}
				defer endpoint.Close()
				const identifier = 0x6811
				if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
					t.Fatal(tcpipErr.String())
				}
				if tcpipErr = endpoint.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
					t.Fatal(tcpipErr.String())
				}
				request := makeICMPEcho(family, false, identifier, 1, []byte("quoted"), family.gvisorAddress, family.forwardAddress)
				if written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(request)) {
					t.Fatalf("write forwarded ICMP request: n=%d err=%s", written, tcpipErrorString(writeErr))
				}
				var prepared result
				select {
				case prepared = <-results:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if prepared.err != nil {
					t.Fatal(prepared.err)
				}
				if detached {
					if err = prepared.responder.ReplyIPPacket(prepared.packet); err != nil {
						t.Fatal(err)
					}
				}
				packet, remote, readErr := readGVisorEndpoint(ctx, monitor, notifications, 2048)
				if readErr != nil {
					t.Fatal(readErr)
				}
				message, stripErr := stripGVisorRawHeader(family, packet)
				if stripErr != nil {
					t.Fatal(stripErr)
				}
				protocol := byte(header.ICMPv4ProtocolNumber)
				wantType := byte(header.ICMPv4DstUnreachable)
				if family.mipstackAddress.Is6() {
					protocol = byte(header.ICMPv6ProtocolNumber)
					wantType = byte(header.ICMPv6DstUnreachable)
				}
				validateForwarderICMPError(t, family, message, remote, protocol, wantType, 1, 0, false)
			})
		}
	}
}

func makeInteropICMPErrorPacket(family interopFamily, source, target netip.Addr, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	copy(icmp[8:], payload)
	if source.Is4() {
		icmpHeader := header.ICMPv4(icmp[:8])
		icmpHeader.SetType(header.ICMPv4DstUnreachable)
		icmpHeader.SetCode(1)
		icmpHeader.SetChecksum(^checksum.Checksum(icmp, 0))
		return makeInteropICMPPacket(family, source, target, icmp, false)
	}
	icmpHeader := header.ICMPv6(icmp[:8])
	icmpHeader.SetType(header.ICMPv6DstUnreachable)
	icmpHeader.SetCode(1)
	icmpHeader.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmpHeader, Src: gvisorAddress(source), Dst: gvisorAddress(target), PayloadCsum: checksum.Checksum(icmp[8:], 0), PayloadLen: len(icmp) - 8}))
	return makeInteropICMPPacket(family, source, target, icmp, false)
}

func makeInteropICMPPacket(family interopFamily, source, target netip.Addr, message []byte, ipv6HopByHop bool) []byte {
	protocol := uint8(header.ICMPv6ProtocolNumber)
	headerSize := header.IPv6MinimumSize
	if ipv6HopByHop && source.Is6() {
		headerSize += 8
	}
	if source.Is4() {
		protocol = uint8(header.ICMPv4ProtocolNumber)
		headerSize = header.IPv4MinimumSize
	}
	packet := make([]byte, headerSize+len(message))
	if source.Is4() {
		ip := header.IPv4(packet[:headerSize])
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 37, Protocol: protocol, SrcAddr: gvisorAddress(source), DstAddr: gvisorAddress(target)})
		ip.SetChecksum(^ip.CalculateChecksum())
	} else if ipv6HopByHop {
		header.IPv6(packet[:header.IPv6MinimumSize]).Encode(&header.IPv6Fields{PayloadLength: uint16(8 + len(message)), TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier), HopLimit: 37, SrcAddr: gvisorAddress(source), DstAddr: gvisorAddress(target)})
		packet[header.IPv6MinimumSize] = protocol
	} else {
		header.IPv6(packet[:headerSize]).Encode(&header.IPv6Fields{PayloadLength: uint16(len(message)), TransportProtocol: tcpip.TransportProtocolNumber(protocol), HopLimit: 37, SrcAddr: gvisorAddress(source), DstAddr: gvisorAddress(target)})
	}
	copy(packet[headerSize:], message)
	return packet
}

func TestICMPForwarderInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					type echoResult struct {
						message, converted mipstack.ICMPForwarderMessage
						responder          *mipstack.ICMPForwarderResponder
						err                error
					}
					results := make(chan echoResult, 2)
					forwarder, err := mipstack.NewICMPForwarder(network.mipstack, mipstack.ICMPForwarderOptions{}, func(request *mipstack.ICMPForwarderRequest) {
						message := request.Message()
						semantic, conversionErr := message.ICMPMessage()
						result := echoResult{message: message, err: conversionErr}
						if result.err == nil {
							result.err = result.converted.SetICMPMessage(semantic)
						}
						message.Payload = append([]byte(nil), message.Payload...)
						result.message = message
						if result.err == nil && detached {
							result.err = request.ReplyEcho()
							if result.err == nil {
								result.responder, result.err = request.Detach()
							}
						} else if result.err == nil {
							result.err = request.ReplyEcho()
						}
						results <- result
					})
					if err != nil {
						t.Fatalf("create ICMP forwarder: %v", err)
					}
					defer forwarder.Close()

					var queue waiter.Queue
					endpoint, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
					if tcpipErr != nil {
						t.Fatalf("create gVisor ICMP endpoint: %s", tcpipErr.String())
					}
					defer endpoint.Close()
					identifier := uint16(0x6101)
					if detached {
						identifier = 0x6201
					}
					if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
						t.Fatalf("bind gVisor ICMP endpoint: %s", tcpipErr.String())
					}
					if tcpipErr = endpoint.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
						t.Fatalf("connect gVisor ICMP endpoint: %s", tcpipErr.String())
					}
					entry, notifications := registerReadable(&queue)
					defer queue.EventUnregister(&entry)

					for index, size := range []int{31, fragmentedInteropPayloadSize(mtu, 4096)} {
						payload := patternedPayload(size, byte(101+index))
						sequence := uint16(index + 1)
						request := makeICMPEcho(family, false, identifier, sequence, payload, family.gvisorAddress, family.forwardAddress)
						written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
						if writeErr != nil || written != int64(len(request)) {
							t.Fatalf("write gVisor forwarded ICMP echo: n=%d, error=%s", written, tcpipErrorString(writeErr))
						}

						var result echoResult
						select {
						case result = <-results:
						case <-ctx.Done():
							t.Fatalf("receive forwarded ICMP echo: %v", ctx.Err())
						}
						if result.err != nil {
							t.Fatalf("prepare ICMP echo reply: %v", result.err)
						}
						if result.message.Source != family.gvisorAddress || result.message.Destination != family.forwardAddress || !result.message.IsEchoRequest() || !bytes.Equal(result.message.Payload, request) {
							t.Fatalf("forwarded ICMP message = %+v", result.message)
						}
						if result.converted.Source != result.message.Source || result.converted.Destination != result.message.Destination ||
							result.converted.Type != result.message.Type || result.converted.Code != result.message.Code ||
							!bytes.Equal(result.converted.Payload, result.message.Payload) {
							t.Fatalf("converted ICMP message = %+v, want %+v", result.converted, result.message)
						}
						if detached {
							if err = result.responder.ReplyEcho(); err != nil {
								t.Fatalf("write detached ICMP echo reply: %v", err)
							}
						}
						wantReplies := 1
						if detached {
							wantReplies = 2
						}
						for replyIndex := 0; replyIndex < wantReplies; replyIndex++ {
							reply, remote, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
							if readErr != nil {
								t.Fatalf("read gVisor ICMP echo reply: %v", readErr)
							}
							if remote.Addr != gvisorAddress(family.forwardAddress) {
								t.Fatalf("ICMP echo reply source = %v, want %v", remote.Addr, family.forwardAddress)
							}
							if err = validateICMPEcho(family, reply, true, identifier, sequence, payload, family.forwardAddress, family.gvisorAddress); err != nil {
								t.Fatal(err)
							}
						}
					}
					wantReplies := uint64(2)
					if detached {
						wantReplies = 4
					}
					if info := forwarder.Info(); info.Requests != 2 || info.Replies != wantReplies || info.Pending != 0 {
						t.Fatalf("ICMP forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

func TestIPForwarderInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()

					type replyResult struct {
						message   mipstack.IPForwarderMessage
						response  []byte
						responder *mipstack.IPForwarderResponder
						err       error
					}
					results := make(chan replyResult, 1)
					forwarder, err := mipstack.NewIPForwarder(network.mipstack, mipstack.IPForwarderOptions{}, func(request *mipstack.IPForwarderRequest) {
						message := request.Message()
						message.Payload = append([]byte(nil), message.Payload...)
						result := replyResult{message: message, response: append([]byte("ip-forward:"), message.Payload...)}
						if detached {
							result.err = request.Reply(append([]byte("ip-request:"), message.Payload...))
							if result.err == nil {
								result.responder, result.err = request.Detach()
							}
						} else {
							result.err = request.Reply(result.response)
						}
						results <- result
					})
					if err != nil {
						t.Fatalf("create IP forwarder: %v", err)
					}
					defer forwarder.Close()

					var queue waiter.Queue
					endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
					if tcpipErr != nil {
						t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
					}
					defer endpoint.Close()
					if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
						t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
					}
					if tcpipErr = endpoint.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
						t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
					}
					entry, notifications := registerReadable(&queue)
					defer queue.EventUnregister(&entry)

					payloadSize := rawInteropPayloadCapacity(family, mtu) - len("ip-forward:")
					payload := patternedPayload(payloadSize, 137)
					written, writeErr := endpoint.Write(bytes.NewReader(payload), tcpip.WriteOptions{})
					if writeErr != nil || written != int64(len(payload)) {
						t.Fatalf("write gVisor forwarded IP payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
					}
					var result replyResult
					select {
					case result = <-results:
					case <-ctx.Done():
						t.Fatalf("receive forwarded IP payload: %v", ctx.Err())
					}
					if result.err != nil {
						t.Fatalf("prepare IP forwarder reply: %v", result.err)
					}
					if result.message.Source != family.gvisorAddress || result.message.Destination != family.forwardAddress || result.message.Protocol != uint8(interopRawIPProtocol) || !bytes.Equal(result.message.Payload, payload) {
						t.Fatalf("forwarded IP message = %+v", result.message)
					}
					if detached {
						if err = result.responder.Reply(result.response); err != nil {
							t.Fatalf("write detached IP reply: %v", err)
						}
					}
					responses := [][]byte{result.response}
					if detached {
						responses = [][]byte{append([]byte("ip-request:"), result.message.Payload...), result.response}
					}
					for index, wantResponse := range responses {
						packet, remote, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
						if readErr != nil {
							t.Fatalf("read gVisor IP forwarder reply: %v", readErr)
						}
						response, stripErr := stripGVisorRawHeader(family, packet)
						if stripErr != nil {
							t.Fatal(stripErr)
						}
						if remote.Addr != gvisorAddress(family.forwardAddress) || !bytes.Equal(response, wantResponse) {
							t.Fatalf("gVisor IP forwarder reply %d: source=%v, bytes=%d", index, remote.Addr, len(response))
						}
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Replies != uint64(len(responses)) || info.Pending != 0 {
						t.Fatalf("IP forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

func dialGVisorForwardUDP(t *testing.T, network *interopNetwork, family interopFamily, target netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	local := gvisorFullAddress(family.gvisorAddress, 0)
	remote := gvisorFullAddress(target.Addr(), target.Port())
	connection, err := gonet.DialUDP(network.gvisor, &local, &remote, family.networkProtocol)
	if err != nil {
		t.Fatalf("dial gVisor forwarded UDP destination: %v", err)
	}
	if err = connection.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		_ = connection.Close()
		t.Fatalf("set gVisor UDP deadline: %v", err)
	}
	return connection
}

func newGVisorRawICMPMonitor(t *testing.T, network *interopNetwork, family interopFamily) (tcpip.Endpoint, <-chan struct{}) {
	t.Helper()
	var queue waiter.Queue
	endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor raw ICMP monitor: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		endpoint.Close()
		t.Fatalf("bind gVisor raw ICMP monitor: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	t.Cleanup(func() {
		queue.EventUnregister(&entry)
		endpoint.Close()
	})
	return endpoint, notifications
}

func validateForwarderICMPError(t *testing.T, family interopFamily, message []byte, remote tcpip.FullAddress, quotedProtocol, wantType, wantCode byte, wantPointer uint32, checkPointer bool) {
	t.Helper()
	if remote.Addr != gvisorAddress(family.forwardAddress) {
		t.Fatalf("Forwarder ICMP rejection source = %v, want %v", remote.Addr, family.forwardAddress)
	}
	if len(message) < 8 {
		t.Fatalf("short Forwarder ICMP rejection: %d bytes", len(message))
	}
	if family.mipstackAddress.Is4() {
		icmpHeader := header.ICMPv4(message[:8])
		if byte(icmpHeader.Type()) != wantType || byte(icmpHeader.Code()) != wantCode {
			t.Fatalf("Forwarder ICMPv4 rejection type/code = %d/%d, want %d/%d", icmpHeader.Type(), icmpHeader.Code(), wantType, wantCode)
		}
		if checksum.Checksum(message, 0) != 0xffff {
			t.Fatal("Forwarder ICMPv4 rejection checksum is invalid")
		}
	} else {
		icmpHeader := header.ICMPv6(message[:8])
		if byte(icmpHeader.Type()) != wantType || byte(icmpHeader.Code()) != wantCode {
			t.Fatalf("Forwarder ICMPv6 rejection type/code = %d/%d, want %d/%d", icmpHeader.Type(), icmpHeader.Code(), wantType, wantCode)
		}
		if checkPointer && icmpHeader.TypeSpecific() != wantPointer {
			t.Fatalf("Forwarder ICMPv6 rejection pointer = %d, want %d", icmpHeader.TypeSpecific(), wantPointer)
		}
		actualChecksum := icmpHeader.Checksum()
		icmpHeader.SetChecksum(0)
		expectedChecksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHeader,
			Src:         gvisorAddress(family.forwardAddress),
			Dst:         gvisorAddress(family.gvisorAddress),
			PayloadCsum: checksum.Checksum(message[8:], 0),
			PayloadLen:  len(message) - 8,
		})
		icmpHeader.SetChecksum(actualChecksum)
		if actualChecksum != expectedChecksum {
			t.Fatalf("Forwarder ICMPv6 rejection checksum = %#04x, want %#04x", actualChecksum, expectedChecksum)
		}
	}

	quote := message[8:]
	if family.mipstackAddress.Is4() {
		if len(quote) < header.IPv4MinimumSize {
			t.Fatalf("short Forwarder ICMPv4 quote: %d bytes", len(quote))
		}
		inner := header.IPv4(quote)
		if inner.SourceAddress() != gvisorAddress(family.gvisorAddress) || inner.DestinationAddress() != gvisorAddress(family.forwardAddress) || byte(inner.TransportProtocol()) != quotedProtocol {
			t.Fatalf("Forwarder ICMPv4 quote = %v -> %v protocol %d", inner.SourceAddress(), inner.DestinationAddress(), inner.TransportProtocol())
		}
		return
	}
	if len(quote) < header.IPv6MinimumSize {
		t.Fatalf("short Forwarder ICMPv6 quote: %d bytes", len(quote))
	}
	inner := header.IPv6(quote)
	if inner.SourceAddress() != gvisorAddress(family.gvisorAddress) || inner.DestinationAddress() != gvisorAddress(family.forwardAddress) || byte(inner.TransportProtocol()) != quotedProtocol {
		t.Fatalf("Forwarder ICMPv6 quote = %v -> %v protocol %d", inner.SourceAddress(), inner.DestinationAddress(), inner.TransportProtocol())
	}
}

func requireAddrPort(t *testing.T, address net.Addr) netip.AddrPort {
	t.Helper()
	switch typed := address.(type) {
	case *net.TCPAddr:
		return typed.AddrPort()
	case *net.UDPAddr:
		return typed.AddrPort()
	default:
		t.Fatalf("unexpected network address %T (%v)", address, address)
		return netip.AddrPort{}
	}
}
