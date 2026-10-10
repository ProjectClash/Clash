package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)


const (
	tcpFlagSYN uint8 = 0x02
	tcpFlagRST uint8 = 0x04
)

func ipHeaderLen(addr netip.Addr) int {
	if addr.Is6() {
		return 40
	}
	return 20
}

func tcpFlagsOf(packet []byte, source netip.Addr) uint8 {
	return packet[ipHeaderLen(source)+13]
}

func readPacketWithin(d *memoryTun, wait time.Duration) []byte {
	select {
	case p := <-d.out:
		return p
	case <-time.After(wait):
		return nil
	}
}

func TestDeferredHandshakeAnswersNothingUntilTheDialFails(t *testing.T) {
	for _, pair := range [][2]string{{"198.18.0.1", "8.8.8.8"}, {"fd00::1", "2001:4860:4860::8888"}} {
		t.Run(pair[0], func(t *testing.T) {
			d := newMemoryTun()
			source, target := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
			dialing := make(chan net.Conn, 1)
			h := &testHandler{
				deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
				tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
					dialing <- c
					return nil
				},
			}
			testStack(t, d, h, nil)
			d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)

			var conn net.Conn
			select {
			case conn = <-dialing:
			case <-time.After(3 * time.Second):
				t.Fatal("the tunnel was never offered the flow")
			}
			if p := readPacketWithin(d, 300*time.Millisecond); p != nil {
				t.Fatalf("the SYN was answered before the dial had an answer: flags=%x", tcpFlagsOf(p, source))
			}

			dialErr := errors.New("dial: i/o timeout")
			if got := N.ReportHandshakeFailure(conn, dialErr); !errors.Is(got, dialErr) {
				t.Fatalf("the reporting helper returns the dial error it was given, got %v", got)
			}
			p := readPacket(t, d)
			flags := tcpFlagsOf(p, source)
			if flags&tcpFlagRST == 0 {
				t.Fatalf("a flow the tunnel cannot carry must be reset, got flags=%x", flags)
			}
			if flags&tcpFlagSYN != 0 && flags&tcpFlagACK != 0 {
				t.Fatalf("the app was told it connected: flags=%x", flags)
			}
		})
	}
}

func TestDeferredHandshakeCompletesWhenTheDialSucceeds(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)

	conn := <-dialing
	if p := readPacketWithin(d, 300*time.Millisecond); p != nil {
		t.Fatalf("answered before the dial: flags=%x", tcpFlagsOf(p, source))
	}
	reported := make(chan error, 1)
	go func() { reported <- N.ReportHandshakeSuccess(conn) }()
	synAck := readPacket(t, d)
	if flags := tcpFlagsOf(synAck, source); flags&(tcpFlagSYN|tcpFlagACK) != (tcpFlagSYN | tcpFlagACK) {
		t.Fatalf("expected SYN ACK once the dial succeeded, got flags=%x", flags)
	}
	offset := ipHeaderLen(source)
	ack := binary.BigEndian.Uint32(synAck[offset+4:]) + 1
	d.in <- tcpPacket(source, target, 101, ack, tcpFlagACK, nil)
	if err := <-reported; err != nil {
		t.Fatalf("the handshake must complete once the app acknowledges: %v", err)
	}
	d.in <- tcpPacket(source, target, 101, ack, tcpFlagACK|tcpFlagPSH, []byte("hello"))
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	p := make([]byte, 5)
	if _, err := conn.Read(p); err != nil {
		t.Fatalf("the connection must carry data after a deferred handshake: %v", err)
	}
	if string(p) != "hello" {
		t.Fatalf("wrong payload %q", p)
	}
	_ = conn.Close()
}

func TestUndeferredFlowsAreAnsweredImmediatelyAsBefore(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	h := &testHandler{tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error { return nil }}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	p := readPacket(t, d)
	if flags := tcpFlagsOf(p, source); flags&(tcpFlagSYN|tcpFlagACK) != (tcpFlagSYN | tcpFlagACK) {
		t.Fatalf("an undeferred flow must still be answered at once, got flags=%x", flags)
	}
}

func TestDeferredHandshakeClosedWithoutAVerdictResetsTheApp(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing
	_ = conn.Close()
	p := readPacket(t, d)
	if flags := tcpFlagsOf(p, source); flags&tcpFlagRST == 0 {
		t.Fatalf("a closed-before-verdict flow must be reset, got flags=%x", flags)
	}
}

func TestDeferredHandshakeBudgetFallsBackInsteadOfStarvingTheStack(t *testing.T) {
	before := deferredHandshakesPending()
	taken := 0
	t.Cleanup(func() {
		for i := 0; i < taken; i++ {
			releaseDeferredHandshake()
		}
	})
	for acquireDeferredHandshake() {
		taken++
		if int32(taken)+before > deferredHandshakeBudget {
			t.Fatalf("the budget must be a ceiling, not a suggestion: took %d on top of %d", taken, before)
		}
	}
	if acquireDeferredHandshake() {
		releaseDeferredHandshake()
		t.Fatal("a spent budget must keep refusing")
	}
	if pending := deferredHandshakesPending(); pending != int32(taken)+before {
		t.Fatalf("a refused permit must not be counted, pending=%d want=%d", pending, int32(taken)+before)
	}
	for i := 0; i < taken; i++ {
		releaseDeferredHandshake()
	}
	taken = 0
	if pending := deferredHandshakesPending(); pending != before {
		t.Fatalf("every permit taken must come back, pending=%d want=%d", pending, before)
	}
}

func TestASpentBudgetSaysSoOncePerStretch(t *testing.T) {
	h := &testHandler{errors: make(chan error, 8)}
	deferredBudgetSpentReported.Store(false)
	t.Cleanup(func() { deferredBudgetSpentReported.Store(false) })

	noteDeferredBudgetSpent(context.Background(), h)
	noteDeferredBudgetSpent(context.Background(), h)
	if len(h.errors) != 1 {
		t.Fatalf("a crowd of refused permits is one line, got %d", len(h.errors))
	}
	if !acquireDeferredHandshake() {
		t.Skip("the budget is saturated by another test")
	}
	releaseDeferredHandshake()
	if deferredHandshakesPending() <= deferredHandshakeBudget/2 {
		noteDeferredBudgetSpent(context.Background(), h)
		if len(h.errors) != 2 {
			t.Fatalf("a second stretch must be reported too, got %d lines", len(h.errors))
		}
	}
}

func TestDeferredHandshakeBackstopResetsAFlowNobodyDecided(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	held := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			held <- c
			return nil
		},
	}
	before := deferredHandshakesPending()
	s := testStack(t, d, h, nil)
	restore := deferredHandshakeVerdictForTest(200 * time.Millisecond)
	defer restore()
	_ = s
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	<-held
	p := readPacket(t, d)
	if flags := tcpFlagsOf(p, source); flags&tcpFlagRST == 0 {
		t.Fatalf("an undecided flow must be reset by the backstop, got flags=%x", flags)
	}
	deadline := time.Now().Add(2 * time.Second)
	for deferredHandshakesPending() > before {
		if time.Now().After(deadline) {
			t.Fatalf("the backstop must give the permit back, pending=%d want<=%d", deferredHandshakesPending(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDeferredHandshakeKeepsHalfCloseOnceAccepted(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing

	lazy, ok := conn.(*deferredConn)
	if !ok {
		t.Fatalf("expected the deferred connection, got %T", conn)
	}
	if !lazy.HandshakeDeferred() {
		t.Fatal("the flow is undecided, so it is pending")
	}
	if up := lazy.Upstream(); up != nil {
		t.Fatalf("nothing may reach past an undecided flow, got %T", up)
	}

	reported := make(chan error, 1)
	go func() { reported <- N.ReportHandshakeSuccess(conn) }()
	synAck := readPacket(t, d)
	offset := ipHeaderLen(source)
	ack := binary.BigEndian.Uint32(synAck[offset+4:]) + 1
	d.in <- tcpPacket(source, target, 101, ack, tcpFlagACK, nil)
	if err := <-reported; err != nil {
		t.Fatal(err)
	}
	if lazy.HandshakeDeferred() {
		t.Fatal("the flow was decided; nothing is pending any more")
	}
	if up := lazy.Upstream(); up == nil {
		t.Fatal("an accepted flow must expose the real connection, or it loses half-close and ReadFrom/WriteTo")
	}
	if err := lazy.CloseWrite(); err != nil {
		t.Fatalf("half-close must work on a deferred flow: %v", err)
	}
	_ = conn.Close()
}

func TestArmingADeadlineDoesNotCompleteTheHandshake(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if p := readPacketWithin(d, 300*time.Millisecond); p != nil {
		t.Fatalf("a deadline put the SYN-ACK on the wire: flags=%x", tcpFlagsOf(p, source))
	}
	_ = conn.Close()
}

func TestDeferredHandshakeResetsWhenTheStackGoesAway(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	s := testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing
	lazy := conn.(*deferredConn)

	go func() { _ = s.Close() }()
	select {
	case <-lazy.Settled():
	case <-time.After(3 * time.Second):
		t.Fatal("a flow the stack abandoned must be decided, not left pending")
	}
	if lazy.HandshakeDeferred() {
		t.Fatal("the flow is decided, so nothing is pending")
	}
}

func TestDeferredHandshakeCloseDuringAcceptDoesNotLeak(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing
	lazy := conn.(*deferredConn)

	accepted := make(chan error, 1)
	go func() { accepted <- lazy.HandshakeSuccess() }()
	synAck := readPacket(t, d)
	go func() { _ = lazy.Close() }()
	offset := ipHeaderLen(source)
	ack := binary.BigEndian.Uint32(synAck[offset+4:]) + 1
	d.in <- tcpPacket(source, target, 101, ack, tcpFlagACK, nil)
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("the accept must finish")
	}
	_ = lazy.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := lazy.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection was closed; reads must not succeed on it")
	}
}

func TestAReadOnAnUnfinishedHandshakeEndsInTheCompletionWindow(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing

	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	started := time.Now()
	_, err := conn.Read(make([]byte, 1))
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a read on a flow whose handshake never completed must fail")
	}
	if elapsed > deferredHandshakeCompletion+time.Second {
		t.Fatalf("the completion window must bound the read, took %s", elapsed)
	}
	_ = conn.Close()
}

func TestTheCompletionWindowOutlastsARetransmission(t *testing.T) {
	const initialRTO = time.Second
	if deferredHandshakeCompletion <= initialRTO {
		t.Fatalf("a window of one RTO (%s) ends the flow on the first loss; got %s", initialRTO, deferredHandshakeCompletion)
	}
	if deferredHandshakeCompletion <= initialRTO+2*initialRTO+4*initialRTO {
		t.Fatalf("the window must outlast the third retransmission (1+2+4 RTO), got %s", deferredHandshakeCompletion)
	}
}

func TestADeadlineOnADecidedButUnacceptedFlowReportsTheFailure(t *testing.T) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	dialing := make(chan net.Conn, 1)
	h := &testHandler{
		deferHandshake: func(network string, _, _ M.Socksaddr) bool { return network == N.NetworkTCP },
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			dialing <- c
			return nil
		},
	}
	testStack(t, d, h, nil)
	d.in <- tcpPacket(source, target, 100, 0, tcpFlagSYN, nil)
	conn := <-dialing
	if err := conn.(*deferredConn).HandshakeFailure(errors.New("dial: no route")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		t.Fatal("arming a deadline on a flow that will never have a connection must report the failure")
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err == nil {
		t.Fatal("same for the combined deadline")
	}
}
