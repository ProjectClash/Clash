package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/pause"
	"github.com/ProjectClash/Clash/component/sniffer"
	C "github.com/ProjectClash/Clash/constant"
	CS "github.com/ProjectClash/Clash/constant/sniffer"
	icontext "github.com/ProjectClash/Clash/context"
	R "github.com/ProjectClash/Clash/rules"
)

type verdictConn struct {
	pending  atomic.Bool
	once     sync.Once
	closed   chan struct{}
	verdicts chan error
	firstBytes []byte
	left     error
	payload  chan []byte
	deadline atomic.Pointer[time.Time]
	events   *eventLog
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func newVerdictConn(pending bool) *verdictConn {
	c := &verdictConn{closed: make(chan struct{}), verdicts: make(chan error, 4), payload: make(chan []byte, 1)}
	c.pending.Store(pending)
	return c
}

func (c *verdictConn) HandshakeDeferred() bool { return c.pending.Load() }

func (c *verdictConn) HandshakeSuccess() error {
	if !c.pending.CompareAndSwap(true, false) {
		return nil
	}
	if c.left != nil {
		return c.left
	}
	if c.events != nil {
		c.events.add("answered")
	}
	c.verdicts <- nil
	if c.firstBytes != nil {
		c.payload <- c.firstBytes
		close(c.payload)
	}
	return nil
}

func (c *verdictConn) HandshakeFailure(err error) error {
	if c.pending.CompareAndSwap(true, false) {
		c.verdicts <- err
	}
	return nil
}

func (c *verdictConn) Read(b []byte) (int, error) {
	if c.pending.CompareAndSwap(true, false) {
		if c.events != nil {
			c.events.add("answered-by-a-read")
		}
		c.verdicts <- nil
	}
	wait := 2 * time.Second
	if deadline := c.deadline.Load(); deadline != nil && !deadline.IsZero() {
		wait = time.Until(*deadline)
	}
	select {
	case <-c.closed:
		return 0, io.EOF
	case payload, ok := <-c.payload:
		if !ok {
			return 0, io.EOF
		}
		return copy(b, payload), nil
	case <-time.After(wait):
		return 0, os.ErrDeadlineExceeded
	}
}
func (c *verdictConn) Write(b []byte) (int, error)       { return len(b), nil }
func (c *verdictConn) Close() error                      { c.once.Do(func() { close(c.closed) }); return nil }
func (c *verdictConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *verdictConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *verdictConn) SetDeadline(time.Time) error       { return nil }
func (c *verdictConn) SetReadDeadline(t time.Time) error { c.deadline.Store(&t); return nil }
func (c *verdictConn) SetWriteDeadline(time.Time) error  { return nil }

func (c *verdictConn) verdict(t *testing.T) (err error, told bool) {
	t.Helper()
	select {
	case err = <-c.verdicts:
		return err, true
	default:
		return nil, false
	}
}

type dialProxy struct {
	doorProxy
	dials   atomic.Int32
	dial    func() (C.Conn, error)
	dialCtx func(ctx context.Context)
	listen  func() (C.PacketConn, error)
}

func (p *dialProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.dials.Add(1)
	if p.dialCtx != nil {
		p.dialCtx(ctx)
	}
	return p.dial()
}

func (p *dialProxy) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return p.listen()
}

func (p *dialProxy) IsL3Protocol(*C.Metadata) bool { return false }

type eofConn struct{}

func (eofConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (eofConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (eofConn) Close() error                     { return nil }
func (eofConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (eofConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (eofConn) SetDeadline(time.Time) error      { return nil }
func (eofConn) SetReadDeadline(time.Time) error  { return nil }
func (eofConn) SetWriteDeadline(time.Time) error { return nil }

type nothingConn struct{ N.ExtendedConn }

func (nothingConn) Chains() C.Chain               { return C.Chain{"REJECT"} }
func (nothingConn) ProviderChains() C.Chain       { return nil }
func (nothingConn) AppendToChains(C.ProxyAdapter) {}
func (nothingConn) RemoteDestination() string     { return "" }

type nothingPacketConn struct{ nothingConn }

func (nothingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (nothingPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (nothingPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, io.EOF
}
func (nothingPacketConn) Close() error                                  { return nil }
func (nothingPacketConn) LocalAddr() net.Addr                           { return &net.UDPAddr{} }
func (nothingPacketConn) SetDeadline(time.Time) error                   { return nil }
func (nothingPacketConn) SetReadDeadline(time.Time) error               { return nil }
func (nothingPacketConn) SetWriteDeadline(time.Time) error              { return nil }
func (nothingPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func withVerdictTunnel(t *testing.T, target string, proxy C.Proxy) {
	t.Helper()
	prevMode, prevProxies, prevRules, prevStatus := Mode(), loadProxies(), rules_(), status.Load()
	t.Cleanup(func() {
		SetMode(prevMode)
		UpdateProxies(prevProxies, nil)
		UpdateRules(prevRules, nil, nil)
		status.Store(prevStatus)
	})
	UpdateProxies(map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT": doorProxy{name: "REJECT", typ: C.Reject},
		target:   proxy,
	}, nil)
	match, err := R.ParseRule("MATCH", "", target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateRules([]C.Rule{match}, nil, nil)
	SetMode(Rule)
	OnRunning()
}

var errRefused = &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}

func TestARejectedFlowIsResetBeforeItsHandshake(t *testing.T) {
	reject := &dialProxy{doorProxy: doorProxy{name: "REJECT", typ: C.Reject}, dial: func() (C.Conn, error) {
		return nothingConn{N.NewExtendedConn(eofConn{})}, nil
	}}
	withVerdictTunnel(t, "REJECT", reject)

	conn := newVerdictConn(true)
	handleTCPConn(icontext.NewConnContext(conn, tunFlowTo("192.0.2.1")))
	err, told := conn.verdict(t)
	if !told || !errors.Is(err, errRejectedByRule) {
		t.Fatalf("a rejected flow must be refused before its handshake, told=%v err=%v", told, err)
	}
}

func TestARefusedPhysicalDialIsNotRetriedWhileTheAppWaits(t *testing.T) {
	direct := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) { return nil, errRefused }}
	withVerdictTunnel(t, "DIRECT", direct)

	conn := newVerdictConn(true)
	started := time.Now()
	handleTCPConn(icontext.NewConnContext(conn, tunFlowTo("192.0.2.1")))
	if direct.dials.Load() != 1 {
		t.Fatalf("the destination said no once; it was asked %d times", direct.dials.Load())
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("the refusal reached the app after %v", took)
	}
	if err, told := conn.verdict(t); !told || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("the app must be refused with the destination's own answer, told=%v err=%v", told, err)
	}
}

func TestOtherFailedDialsAreStillRetried(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     C.AdapterType
		pending bool
	}{
		{"a proxy server that refuses", C.Shadowsocks, true},
		{"a flow already answered", C.Direct, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: tc.typ}, dial: func() (C.Conn, error) { return nil, errRefused }}
			withVerdictTunnel(t, "out", proxy)
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			handleTCPConnContext(ctx, icontext.NewConnContext(newVerdictConn(tc.pending), tunFlowTo("192.0.2.1")))
			if proxy.dials.Load() < 2 {
				t.Fatalf("dialled %d time(s); this failure is still worth retrying", proxy.dials.Load())
			}
		})
	}
}

func TestARejectedUDPFlowIsAnsweredUnreachable(t *testing.T) {
	reject := &dialProxy{doorProxy: doorProxy{name: "REJECT", typ: C.Reject}, listen: func() (C.PacketConn, error) {
		return nothingPacketConn{}, nil
	}}
	withVerdictTunnel(t, "REJECT", reject)

	packet := newReportingPacket()
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	select {
	case <-packet.reported:
	case <-time.After(3 * time.Second):
		t.Fatal("a rejected UDP flow must be answered unreachable")
	}
	packet.settled(t)
}

func TestNothingIsAnsweredUnreachableWhileThereIsNoNetwork(t *testing.T) {
	withVerdictTunnel(t, "out", doorProxy{name: "out", typ: C.Shadowsocks})
	UpdateProxies(map[string]C.Proxy{}, nil)
	pause.NetworkPause()
	t.Cleanup(pause.NetworkWake)

	packet := newReportingPacket()
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	metadata.SrcPort = 40001
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	packet.settled(t)
	select {
	case <-packet.reported:
		t.Fatal("no network is not the flow's verdict; the app must not be told port unreachable")
	default:
	}
}

type lazyHeaderConn struct {
	nothingConn
	events    *eventLog
	written   atomic.Bool
	closes    atomic.Int32
	unconnect bool
}

func (c *lazyHeaderConn) Close() error           { c.closes.Add(1); return nil }
func (c *lazyHeaderConn) NeedHandshake() bool    { return !c.written.Load() }
func (c *lazyHeaderConn) TransportPending() bool { return c.unconnect && !c.written.Load() }
func (c *lazyHeaderConn) Write(b []byte) (int, error) {
	if c.written.CompareAndSwap(false, true) {
		c.events.add("header+" + string(b))
	}
	return len(b), nil
}

func runLazyHeaderFlow(t *testing.T, port uint16, firstBytes []byte, unconnected bool) ([]string, time.Duration) {
	t.Helper()
	events := &eventLog{}
	out := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, dial: func() (C.Conn, error) {
		return &lazyHeaderConn{nothingConn: nothingConn{N.NewExtendedConn(eofConn{})}, events: events, unconnect: unconnected}, nil
	}}
	withVerdictTunnel(t, "out", out)
	conn := newVerdictConn(true)
	conn.firstBytes, conn.events = firstBytes, events
	metadata := tunFlowTo("192.0.2.1")
	metadata.DstPort = port
	started := time.Now()
	handleTCPConn(icontext.NewConnContext(conn, metadata))
	return events.all(), time.Since(started)
}

func sameEvents(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestTheOutboundsHeaderLeavesWithTheClientsFirstBytes(t *testing.T) {
	events, _ := runLazyHeaderFlow(t, 443, []byte("ClientHello"), false)
	if !sameEvents(events, "answered", "header+ClientHello") {
		t.Fatalf("want the client answered, then header and first bytes in one write; got %q", events)
	}
}

func TestAServerFirstPortDoesNotWaitForTheClient(t *testing.T) {
	events, took := runLazyHeaderFlow(t, 22, nil, false)
	if !sameEvents(events, "answered", "header+") {
		t.Fatalf("want the client answered and the header sent alone; got %q", events)
	}
	if took >= 2*time.Second {
		t.Fatalf("a server-first port took %v", took)
	}
}

func TestASilentClientCostsOnlyTheWait(t *testing.T) {
	events, _ := runLazyHeaderFlow(t, 443, nil, false)
	if !sameEvents(events, "answered", "header+") {
		t.Fatalf("want the client answered and, nothing arriving, the header sent alone; got %q", events)
	}
}

func TestAFastOpenTransportConnectsBeforeTheClientIsAnswered(t *testing.T) {
	events, _ := runLazyHeaderFlow(t, 443, []byte("ClientHello"), true)
	if len(events) < 2 || events[0] != "header+" || events[1] != "answered" {
		t.Fatalf("want the connect first and the answer after it; got %q", events)
	}
}

func TestAClientThatLeftIsNotDialledForAgain(t *testing.T) {
	events := &eventLog{}
	var remote *lazyHeaderConn
	out := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, dial: func() (C.Conn, error) {
		remote = &lazyHeaderConn{nothingConn: nothingConn{N.NewExtendedConn(eofConn{})}, events: events}
		return remote, nil
	}}
	withVerdictTunnel(t, "out", out)
	conn := newVerdictConn(true)
	conn.left = syscall.ECONNRESET
	handleTCPConn(icontext.NewConnContext(conn, tunFlowTo("192.0.2.1")))
	if out.dials.Load() != 1 {
		t.Fatalf("dialled %d times for a client that had gone", out.dials.Load())
	}
	if len(events.all()) != 0 {
		t.Fatalf("nothing may be written for a client that had gone, got %q", events.all())
	}
	if remote.closes.Load() == 0 {
		t.Fatal("the outbound dialled for it must be closed")
	}
}

func withSnifferOn(t *testing.T) {
	t.Helper()
	ports, err := utils.NewUnsignedRanges[uint16]("80,443")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable:      true,
		ParsePureIp: true,
		Sniffers: map[CS.Type]sniffer.SnifferConfig{
			CS.TLS:  {Ports: ports},
			CS.HTTP: {Ports: ports},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	previous := snifferDispatcher.Load()
	UpdateSniffer(dispatcher)
	t.Cleanup(func() { UpdateSniffer(previous) })
}

func TestTheSnifferStandsAsideForABareGlobalIPv6FlowDialledPhysically(t *testing.T) {
	for _, tc := range []struct {
		name        string
		destination string
		target      string
		typ         C.AdapterType
		wantFirst   string
	}{
		{"global IPv6, dialled physically", "2001:db8::10", "DIRECT", C.Direct, "dialled"},
		{"global IPv6, carried by a proxy", "2001:db8::10", "out", C.Shadowsocks, "answered-by-a-read"},
		{"IPv4, dialled physically", "192.0.2.10", "DIRECT", C.Direct, "answered-by-a-read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := &eventLog{}
			proxy := &dialProxy{doorProxy: doorProxy{name: tc.target, typ: tc.typ}, dial: func() (C.Conn, error) {
				events.add("dialled")
				return nil, errRefused
			}}
			withVerdictTunnel(t, tc.target, proxy)
			withSnifferOn(t)
			conn := newVerdictConn(true)
			conn.events = events
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			handleTCPConnContext(ctx, icontext.NewConnContext(conn, tunFlowTo(tc.destination)))
			if got := events.all(); len(got) == 0 || got[0] != tc.wantFirst {
				t.Fatalf("want %q first, got %q", tc.wantFirst, got)
			}
		})
	}
}

func TestTheTunnelLabelsEachFlowsSocketsWithTheirKind(t *testing.T) {
	var mu sync.Mutex
	var kinds []string
	record := func(ctx context.Context) {
		mu.Lock()
		kinds = append(kinds, dialer.DialKindOf(ctx))
		mu.Unlock()
	}

	direct := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) { return nil, errRefused }}
	direct.dialCtx = func(ctx context.Context) { record(ctx) }
	withVerdictTunnel(t, "DIRECT", direct)
	handleTCPConn(icontext.NewConnContext(newVerdictConn(true), tunFlowTo("192.0.2.1")))

	relay := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, dial: func() (C.Conn, error) {
		return nothingConn{N.NewExtendedConn(eofConn{})}, nil
	}}
	relay.dialCtx = func(ctx context.Context) { record(ctx) }
	withVerdictTunnel(t, "out", relay)
	handleTCPConn(icontext.NewConnContext(newVerdictConn(true), tunFlowTo("192.0.2.1")))

	mu.Lock()
	defer mu.Unlock()
	if len(kinds) < 2 || kinds[0] != dialer.DialKindDirect || kinds[len(kinds)-1] != dialer.DialKindProxy {
		t.Fatalf("want the direct flow's sockets labelled %q and the relayed flow's %q, got %v", dialer.DialKindDirect, dialer.DialKindProxy, kinds)
	}
}
