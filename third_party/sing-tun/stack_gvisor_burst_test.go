//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type burstHandler struct {
	doorHandler
	errs       sync.Map
	done       atomic.Int32
	undeferred atomic.Int32
	dialDelay time.Duration
}

func (h *burstHandler) DeferHandshake(network string, _, _ M.Socksaddr) bool {
	return network == N.NetworkTCP
}

func (h *burstHandler) NewConnection(_ context.Context, c net.Conn, m M.Metadata) error {
	go func() {
		var err error
		if h.dialDelay > 0 {
			time.Sleep(time.Duration(m.Source.Port%13) * h.dialDelay / 13)
		}
		if deferred, ok := c.(*deferredConn); ok {
			err = deferred.HandshakeSuccess()
		} else {
			h.undeferred.Add(1)
		}
		h.errs.Store(m.Source.Port, err)
		h.done.Add(1)
		if err != nil {
			_ = c.Close()
		}
	}()
	return nil
}

func injectSYNFrom(ep *channel.Endpoint, port uint16) {
	ipHdr, tcpHdr := ipv6TCP(doorClient, doorServer, header.TCPFlagSyn)
	tcpHdr.SetSourcePort(port)
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	ep.InjectInbound(tcpip.NetworkProtocolNumber(header.IPv6ProtocolNumber), stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte(ipHdr))}))
}

func injectACKFrom(ep *channel.Endpoint, port uint16, serverSeq uint32) {
	ipHdr, tcpHdr := ipv6TCP(doorClient, doorServer, header.TCPFlagAck)
	tcpHdr.SetSourcePort(port)
	tcpHdr.SetSequenceNumber(8)
	tcpHdr.SetAckNumber(serverSeq + 1)
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	ep.InjectInbound(tcpip.NetworkProtocolNumber(header.IPv6ProtocolNumber), stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte(ipHdr))}))
}

func TestGVisorABurstOfDeferredHandshakesAllComplete(t *testing.T) {
	for _, delay := range []time.Duration{0, 60 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) { gvisorBurst(t, 400, delay) })
	}
}

func gvisorBurst(t *testing.T, flows int, dialDelay time.Duration) {
	handler := &burstHandler{dialDelay: dialDelay}
	ep := channel.New(4096, 1500, "")
	s, err := NewGVisorStack(ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	forwarder := NewTCPForwarder(context.Background(), s, handler)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	var synAcks, resets atomic.Int32
	stop := make(chan struct{})
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			pkt := ep.ReadContext(ctx)
			cancel()
			if pkt == nil {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			tcpHdr := header.TCP(pkt.TransportHeader().Slice())
			flags, port, seq := tcpHdr.Flags(), tcpHdr.DestinationPort(), tcpHdr.SequenceNumber()
			pkt.DecRef()
			switch {
			case flags&header.TCPFlagRst != 0:
				resets.Add(1)
			case flags&header.TCPFlagSyn != 0 && flags&header.TCPFlagAck != 0:
				synAcks.Add(1)
				injectACKFrom(ep, port, seq)
			}
		}
	}()
	for i := 0; i < flows; i++ {
		injectSYNFrom(ep, uint16(20000+i))
	}
	deadline := time.Now().Add(10 * time.Second)
	for int(handler.done.Load()) < flows && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	var failed int
	var sample error
	handler.errs.Range(func(_, v any) bool {
		if e, _ := v.(error); e != nil {
			failed++
			sample = e
		}
		return true
	})
	t.Logf("completed=%d undeferred=%d syn-acks=%d resets=%d failed=%d sample=%v", handler.done.Load(), handler.undeferred.Load(), synAcks.Load(), resets.Load(), failed, sample)
	if failed != 0 || int(handler.done.Load()) != flows {
		t.Fatalf("%d of %d handshakes failed (%d never completed); sample: %v (EPIPE=%v)", failed, flows, flows-int(handler.done.Load()), sample, errors.Is(sample, syscall.EPIPE))
	}
}
