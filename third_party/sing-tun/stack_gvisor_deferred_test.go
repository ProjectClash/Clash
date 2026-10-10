//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type gvisorDeferHandler struct {
	doorHandler
	defers bool

	connMu sync.Mutex
	conns  chan net.Conn
}

func (h *gvisorDeferHandler) DeferHandshake(network string, _, _ M.Socksaddr) bool {
	return h.defers && network == N.NetworkTCP
}

func (h *gvisorDeferHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	h.connMu.Lock()
	ch := h.conns
	h.connMu.Unlock()
	if ch != nil {
		ch <- c
	}
	return nil
}

func newGVisorDeferHandler() *gvisorDeferHandler {
	return &gvisorDeferHandler{defers: true, conns: make(chan net.Conn, 1)}
}

func readReplyWithin(ep *channel.Endpoint, wait time.Duration) header.TCP {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	return header.TCP(pkt.TransportHeader().Slice())
}

func injectACK(t *testing.T, ep *channel.Endpoint, synAck header.TCP) {
	t.Helper()
	ipHdr, tcpHdr := ipv6TCP(doorClient, doorServer, header.TCPFlagAck)
	tcpHdr.SetSequenceNumber(8)
	tcpHdr.SetAckNumber(synAck.SequenceNumber() + 1)
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	ep.InjectInbound(tcpip.NetworkProtocolNumber(header.IPv6ProtocolNumber), stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte(ipHdr))}))
}

func TestGVisorDeferredHandshakeAnswersNothingUntilTheDialFails(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)

	var conn net.Conn
	select {
	case conn = <-h.conns:
	case <-time.After(3 * time.Second):
		t.Fatal("the tunnel was never offered the flow")
	}
	t.Cleanup(func() { _ = conn.Close() })
	if reply := readReplyWithin(ep, 300*time.Millisecond); reply != nil {
		t.Fatalf("the SYN was answered before the dial had an answer: flags %v", reply.Flags())
	}

	deferred, ok := conn.(*deferredConn)
	if !ok {
		t.Fatalf("expected the deferred connection, got %T", conn)
	}
	if !deferred.HandshakeDeferred() {
		t.Fatal("the flow is undecided, so it is pending")
	}
	if err := deferred.HandshakeFailure(errors.New("dial: i/o timeout")); err != nil {
		t.Fatal(err)
	}
	reply := readReply(t, ep)
	if reply.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("a flow the tunnel cannot carry must be reset, got flags %v", reply.Flags())
	}
	if reply.Flags()&header.TCPFlagSyn != 0 {
		t.Fatalf("the app was told it connected: flags %v", reply.Flags())
	}
	if err := deferred.HandshakeFailure(errors.New("again")); err != nil {
		t.Fatal(err)
	}
	if err := deferred.HandshakeSuccess(); err == nil {
		t.Fatal("a decided flow cannot be undecided")
	}
}

func TestGVisorDeferredHandshakeCompletesWhenTheDialSucceeds(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	conn := <-h.conns
	t.Cleanup(func() { _ = conn.Close() })
	if reply := readReplyWithin(ep, 300*time.Millisecond); reply != nil {
		t.Fatalf("answered before the dial: flags %v", reply.Flags())
	}
	go func() { _ = conn.(*deferredConn).HandshakeSuccess() }()
	reply := readReply(t, ep)
	if reply.Flags()&header.TCPFlagSyn == 0 || reply.Flags()&header.TCPFlagAck == 0 {
		t.Fatalf("expected the SYN-ACK once the dial succeeded, got flags %v", reply.Flags())
	}
	_ = conn.Close()
}

func TestGVisorUndeferredFlowsAreAnsweredImmediatelyAsBefore(t *testing.T) {
	h := &gvisorDeferHandler{defers: false}
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	reply := readReply(t, ep)
	if reply.Flags()&header.TCPFlagSyn == 0 || reply.Flags()&header.TCPFlagAck == 0 {
		t.Fatalf("an undeferred flow must still be answered at once, got flags %v", reply.Flags())
	}
}

func TestGVisorDeferredHandshakeClosedWithoutAVerdictResetsTheApp(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	conn := <-h.conns
	_ = conn.Close()
	reply := readReply(t, ep)
	if reply.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("a closed-before-verdict flow must be reset, got flags %v", reply.Flags())
	}
}

func TestGVisorDeferredHandshakeSpendsTheRequestOnlyOnce(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	deferred := (<-h.conns).(*deferredConn)
	t.Cleanup(func() { _ = deferred.Close() })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_ = deferred.HandshakeFailure(errors.New("dial failed"))
			} else {
				_ = deferred.Close()
			}
		}(i)
	}
	wg.Wait()
	if reply := readReply(t, ep); reply.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("expected one reset, got flags %v", reply.Flags())
	}
	if deferred.HandshakeDeferred() {
		t.Fatal("the flow is decided")
	}
}

func TestGVisorDeferredAcceptedFlowCanStillBeAborted(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	conn := <-h.conns
	t.Cleanup(func() { _ = conn.Close() })
	deferred := conn.(*deferredConn)
	accepted := make(chan error, 1)
	go func() { accepted <- deferred.HandshakeSuccess() }()
	synAck := readReply(t, ep)
	if synAck.Flags()&header.TCPFlagSyn == 0 {
		t.Fatalf("setup: expected the SYN-ACK, got flags %v", synAck.Flags())
	}
	injectACK(t, ep, synAck)
	if err := <-accepted; err != nil {
		t.Fatalf("the handshake must complete once the app acknowledges: %v", err)
	}
	if _, ok := deferred.Upstream().(interface{ SetLinger(int) error }); !ok {
		t.Fatalf("an accepted gVisor flow must be able to abort, got %T", deferred.Upstream())
	}
	if err := deferred.SetLinger(0); err != nil {
		t.Fatalf("aborting an accepted flow must work: %v", err)
	}
	_ = deferred.Close()
}

func TestGVisorCloseWriteOnAnUndecidedFlowDoesNotResetIt(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	deferred := (<-h.conns).(*deferredConn)
	t.Cleanup(func() { _ = deferred.Close() })
	if err := deferred.CloseWrite(); err == nil {
		t.Fatal("there is nothing to half-close on a flow that has not been decided")
	}
	if !deferred.HandshakeDeferred() {
		t.Fatal("asking for a half-close must not have decided the flow")
	}
	if reply := readReplyWithin(ep, 200*time.Millisecond); reply != nil {
		t.Fatalf("nothing should have gone to the app, got flags %v", reply.Flags())
	}
}

func TestGVisorCloseDuringTheHandshakeReportsTheClosure(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	deferred := (<-h.conns).(*deferredConn)

	accepted := make(chan error, 1)
	go func() { accepted <- deferred.HandshakeSuccess() }()
	synAck := readReply(t, ep)
	if synAck.Flags()&header.TCPFlagSyn == 0 {
		t.Fatalf("setup: expected the SYN-ACK, got flags %v", synAck.Flags())
	}
	closed := make(chan struct{})
	go func() { _ = deferred.Close(); close(closed) }()
	injectACK(t, ep, synAck)

	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("a flow closed under the handshake must report that, not success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the accept must finish")
	}
	<-closed
	if deferred.HandshakeDeferred() {
		t.Fatal("the flow is decided")
	}
	if up := deferred.Upstream(); up != nil {
		t.Fatalf("a closed flow must not hand out a live connection, got %T", up)
	}
}

func TestGVisorADeadlineArmedBeforeTheVerdictSurvivesTheHandshake(t *testing.T) {
	h := newGVisorDeferHandler()
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	deferred := (<-h.conns).(*deferredConn)
	t.Cleanup(func() { _ = deferred.Close() })

	if err := deferred.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() { accepted <- deferred.HandshakeSuccess() }()
	synAck := readReply(t, ep)
	time.Sleep(600 * time.Millisecond)
	injectACK(t, ep, synAck)
	if err := <-accepted; err != nil {
		t.Fatalf("the handshake must complete: %v", err)
	}

	started := time.Now()
	_, err := deferred.Read(make([]byte, 1))
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("no data was sent, so the read must time out")
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("the caller's window was spent on the handshake: the read failed after %s", elapsed)
	}
}
