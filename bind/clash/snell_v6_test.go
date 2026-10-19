package clash

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/inbound"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const snellV6TestPSK = "clash-k9-v6-psk-0123456789"

func withSnellV6Tunnel(t *testing.T, node C.ProxyAdapter) {
	t.Helper()
	previousProxies, previousProviders, previousStatus := tunnel.Proxies(), tunnel.Providers(), tunnel.Status()
	proxies := map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}
	if node != nil {
		proxies["v6"] = adapter.NewProxy(node)
	}
	tunnel.UpdateProxies(proxies, nil)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.UpdateProxies(previousProxies, previousProviders)
		switch previousStatus {
		case tunnel.Suspend:
			tunnel.OnSuspend()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		}
	})
}

func snellV6Listener(t *testing.T, mode string, udp bool) (*inbound.Snell, int) {
	t.Helper()
	listener, err := inbound.NewSnell(&inbound.SnellOption{
		BaseOption: inbound.BaseOption{NameStr: "snell-v6-in", Listen: "127.0.0.1", Port: "0", SpecialProxy: "DIRECT"},
		Psk:        snellV6TestPSK, Version: 6, UDP: udp, Mode: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Listen(tunnel.Tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_, port, _ := net.SplitHostPort(listener.Address())
	p, _ := strconv.Atoi(port)
	return listener, p
}

func snellV6Node(t *testing.T, port int, mode string, reuse bool) *outbound.Snell {
	t.Helper()
	node, err := outbound.NewSnell(outbound.SnellOption{
		Name: "v6", Server: "127.0.0.1", Port: port, Psk: snellV6TestPSK, UDP: true, Version: 6, Mode: mode, Reuse: reuse,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func forwardThroughV6(t *testing.T, target string) string {
	t.Helper()
	forward, err := inbound.NewTunnel(&inbound.TunnelOption{
		BaseOption: inbound.BaseOption{NameStr: "to-v6", Listen: "127.0.0.1", Port: "0", SpecialProxy: "v6"},
		Network:    []string{"tcp", "udp"},
		Target:     target,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := forward.Listen(tunnel.Tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	return forward.Address()
}

func forwardAddress(t *testing.T, address, network string) string {
	t.Helper()
	for _, part := range strings.Split(address, ",") {
		if rest, ok := strings.CutPrefix(part, network+"://"); ok {
			return rest
		}
	}
	t.Fatalf("no %s address in %q", network, address)
	return ""
}

func tcpEcho(t *testing.T, banner []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if banner != nil {
					_, _ = c.Write(banner)
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func udpEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func roundTrip(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the echo came back different")
	}
}

func countingForward(t *testing.T, listenerPort int) (int, func() int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				upstream, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenerPort)))
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, c); _ = upstream.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(c, upstream)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted.Load
}

func dialThrough(t *testing.T, local string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestASnellV6NodeAndListenerCarryTCPThroughTheTunnel(t *testing.T) {
	echo := tcpEcho(t, nil)
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reuse=%v", mode, reuse), func(t *testing.T) {
				_, port := snellV6Listener(t, mode, false)
				forwardPort, sessions := countingForward(t, port)
				withSnellV6Tunnel(t, snellV6Node(t, forwardPort, mode, reuse))
				local := forwardAddress(t, forwardThroughV6(t, echo), "tcp")
				for i := 0; i < 3; i++ {
					conn := dialThrough(t, local)
					roundTrip(t, conn, 256<<10)
					_ = conn.Close()
					time.Sleep(50 * time.Millisecond)
				}
				want := int64(3)
				if reuse {
					want = 1
				}
				if got := sessions(); got != want {
					t.Fatalf("three flows opened %d sessions, want %d", got, want)
				}
			})
		}
	}
}

func TestASnellV6FlowToADestinationThatSpeaksFirst(t *testing.T) {
	banner := []byte("220 ready\r\n")
	serverFirst, err := net.Listen("tcp", "127.0.0.1:3306")
	if err == nil {
		go func() {
			for {
				c, err := serverFirst.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write(banner)
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		t.Cleanup(func() { _ = serverFirst.Close() })
	}
	ordinary := tcpEcho(t, banner)
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reuse=%v", mode, reuse), func(t *testing.T) {
				_, port := snellV6Listener(t, mode, false)
				withSnellV6Tunnel(t, snellV6Node(t, port, mode, reuse))
				read := func(t *testing.T, conn net.Conn) {
					t.Helper()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					got := make([]byte, len(banner))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, banner) {
						t.Fatalf("the banner: %q (%v)", got, err)
					}
				}
				read(t, dialThrough(t, forwardAddress(t, forwardThroughV6(t, ordinary), "tcp")))
				targets := []string{ordinary}
				if serverFirst != nil {
					targets = append(targets, serverFirst.Addr().String())
				}
				for _, target := range targets {
					host, p, _ := net.SplitHostPort(target)
					portNumber, _ := strconv.Atoi(p)
					app, flow := net.Pipe()
					t.Cleanup(func() { _ = app.Close(); _ = flow.Close() })
					metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUN, SrcIP: netip.MustParseAddr("127.0.0.1"), SrcPort: 40000, DstIP: netip.MustParseAddr(host), DstPort: uint16(portNumber), SpecialProxy: "v6"}
					go tunnel.Tunnel.HandleTCPConn(flow, metadata)
					read(t, app)
				}
			})
		}
	}
	if serverFirst == nil {
		t.Log("port 3306 is taken here: the listed server-first port was not exercised")
	}
}

func TestClosingAReusedV6FlowDoesNotWaitForItsStalledUpload(t *testing.T) {
	stalled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	go func() {
		for {
			c, err := stalled.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte{'x'})
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	_, port := snellV6Listener(t, "default", false)
	forwardPort, sessions := countingForward(t, port)
	withSnellV6Tunnel(t, snellV6Node(t, forwardPort, "default", true))
	local := forwardAddress(t, forwardThroughV6(t, stalled.Addr().String()), "tcp")
	app := dialThrough(t, local)
	var written atomic.Int64
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			n, err := app.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	waitStalled(t, &written)

	done := make(chan struct{})
	go func() {
		defer close(done)
		statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
			if c.Info().Metadata.Type != C.SNELL {
				_ = c.Close()
			}
			return true
		})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the flow waited for its stalled upload")
	}
	conn := dialThrough(t, forwardAddress(t, forwardThroughV6(t, tcpEcho(t, nil)), "tcp"))
	roundTrip(t, conn, 1024)
	if got := sessions(); got != 2 {
		t.Fatalf("%d sessions, want the stalled one and a new one", got)
	}
}

func waitStalled(t *testing.T, written *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := written.Load()
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		now := written.Load()
		if now == last && now > 0 {
			return
		}
		last = now
	}
	t.Fatal("the flood never stalled")
}

func TestClosingAV6ListenerFlowWhoseClientStoppedReadingReturns(t *testing.T) {
	flood, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = flood.Close() })
	var served atomic.Int64
	go func() {
		for {
			c, err := flood.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				chunk := make([]byte, 64<<10)
				for {
					n, err := c.Write(chunk)
					served.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse=%v", reuse), func(t *testing.T) {
			_, port := snellV6Listener(t, "default", false)
			withSnellV6Tunnel(t, snellV6Node(t, port, "default", reuse))
			app := dialThrough(t, forwardAddress(t, forwardThroughV6(t, flood.Addr().String()), "tcp"))
			_, _ = app.Write([]byte("go"))
			waitStalled(t, &served)
			done := make(chan struct{})
			go func() {
				defer close(done)
				statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
					if c.Info().Metadata.Type == C.SNELL {
						if inbound, ok := c.(interface{ CloseInbound() error }); ok {
							_ = inbound.CloseInbound()
						}
					}
					return true
				})
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("closing the listener's flow waited for its stalled download")
			}
			statistic.DefaultManager.Range(func(c statistic.Tracker) bool { _ = c.Close(); return true })
		})
	}
}

func TestANetworkResetLeavesNoReusedSessionOnTheOldPath(t *testing.T) {
	reused, plain := snellV6Node(t, 1, "default", true), snellV6Node(t, 1, "default", false)
	reusedWrapper, plainWrapper := outbound.NewAutoCloseProxyAdapter(reused), outbound.NewAutoCloseProxyAdapter(plain)
	if _, keeps := outbound.AsNetworkResetter(reusedWrapper); !keeps {
		t.Fatal("a v6 node with reuse is not reset on a network change")
	}
	if _, keeps := outbound.AsNetworkResetter(plainWrapper); keeps {
		t.Fatal("a v6 node without reuse claims sessions to reset")
	}
	runtime.KeepAlive(reusedWrapper)
	runtime.KeepAlive(plainWrapper)

	var failedDials atomic.Int64
	tunnel.SetDialOutcomeObserver(func(err error) {
		if err != nil {
			failedDials.Add(1)
		}
	})
	t.Cleanup(func() { tunnel.SetDialOutcomeObserver(observeDialOutcomeForNotice) })

	echo := tcpEcho(t, nil)
	_, port := snellV6Listener(t, "default", false)
	forwardPort, sessions := countingForward(t, port)
	node := snellV6Node(t, forwardPort, "default", true)
	withSnellV6Tunnel(t, node)
	local := forwardAddress(t, forwardThroughV6(t, echo), "tcp")
	flow := func() net.Conn {
		conn := dialThrough(t, local)
		roundTrip(t, conn, 4096)
		return conn
	}

	_ = flow().Close()
	time.Sleep(50 * time.Millisecond)
	node.ResetNetwork()
	open := flow()
	if got := sessions(); got != 2 {
		t.Fatalf("after a reset with a pooled session: %d sessions, want 2", got)
	}
	node.ResetNetwork()
	_ = open.Close()
	time.Sleep(50 * time.Millisecond)
	_ = flow().Close()
	if got := sessions(); got != 3 {
		t.Fatalf("a session in use at the reset came back to the pool: %d sessions, want 3", got)
	}
	time.Sleep(50 * time.Millisecond)
	_ = flow().Close()
	if got := sessions(); got != 3 {
		t.Fatalf("with no reset the session was not reused: %d sessions, want 3", got)
	}
	if n := failedDials.Load(); n != 0 {
		t.Fatalf("%d dial(s) failed on the way", n)
	}
}

type fakeRecordConn struct {
	net.Conn
	deadline  chan struct{}
	once      sync.Once
	closeOnce sync.Once
	ended     chan struct{}
}

func (c *fakeRecordConn) SetWriteDeadline(time.Time) error {
	c.once.Do(func() { close(c.deadline) })
	return nil
}

func (c *fakeRecordConn) CloseWrite() error {
	c.closeOnce.Do(func() {
		<-c.deadline
		close(c.ended)
	})
	<-c.ended
	return errors.New("end record: write deadline exceeded")
}

func (c *fakeRecordConn) Close() error { return c.CloseWrite() }

func TestAGuardedFlowsCloseDoesNotWaitBehindABlockedHalfClose(t *testing.T) {
	inner := &fakeRecordConn{deadline: make(chan struct{}), ended: make(chan struct{})}
	flow := &snellV6ServerConn{guardedConn{Conn: inner}}
	halfClosed := make(chan struct{})
	go func() { _ = flow.CloseWrite(); close(halfClosed) }()
	deadline := time.Now().Add(time.Second)
	for flow.writing.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { _ = flow.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited behind the blocked half-close")
	}
	<-halfClosed
}

func TestAHalfClosedV6FlowEndsAndItsSessionCarriesTheNext(t *testing.T) {
	answerAfterEOF, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = answerAfterEOF.Close() })
	go func() {
		for {
			c, err := answerAfterEOF.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				_, _ = fmt.Fprintf(c, "got %d", n)
			}()
		}
	}()
	_, port := snellV6Listener(t, "default", false)
	forwardPort, sessions := countingForward(t, port)
	withSnellV6Tunnel(t, snellV6Node(t, forwardPort, "default", true))
	local := forwardAddress(t, forwardThroughV6(t, answerAfterEOF.Addr().String()), "tcp")
	for i := 0; i < 2; i++ {
		conn := dialThrough(t, local).(*net.TCPConn)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(make([]byte, 100000)); err != nil {
			t.Fatal(err)
		}
		_ = conn.CloseWrite()
		answer, err := io.ReadAll(conn)
		if err != nil || string(answer) != "got 100000" {
			t.Fatalf("flow %d: the answer after the half-close: %q (%v)", i, answer, err)
		}
		_ = conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	if got := sessions(); got != 1 {
		t.Fatalf("two half-closed flows opened %d sessions, want 1", got)
	}
}

func TestASnellV6NodeAndListenerCarryUDPThroughTheTunnel(t *testing.T) {
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		t.Run(mode, func(t *testing.T) {
			echo := udpEcho(t)
			_, port := snellV6Listener(t, mode, true)
			withSnellV6Tunnel(t, snellV6Node(t, port, mode, false))
			local := forwardAddress(t, forwardThroughV6(t, echo), "udp")
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for session := 0; session < 8; session++ {
				wg.Add(1)
				go func(session int) {
					defer wg.Done()
					conn, err := net.Dial("udp", local)
					if err != nil {
						errs <- err
						return
					}
					defer conn.Close()
					for i := 0; i < 20; i++ {
						size := 1200
						if i%2 == 1 {
							size = 8000
						}
						payload := make([]byte, size)
						_, _ = rand.Read(payload)
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := conn.Write(payload); err != nil {
							errs <- err
							return
						}
						got := make([]byte, 65535)
						n, err := conn.Read(got)
						if err != nil || !bytes.Equal(got[:n], payload) {
							errs <- fmt.Errorf("session %d datagram %d (%d B): %d B back (%v)", session, i, size, n, err)
							return
						}
					}
				}(session)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

func TestASnellV6ListenerWithUDPOffEndsTheSession(t *testing.T) {
	_, port := snellV6Listener(t, "default", false)
	node := snellV6Node(t, port, "default", false)
	withSnellV6Tunnel(t, node)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	echo := udpEcho(t)
	host, p, _ := net.SplitHostPort(echo)
	portNumber, _ := strconv.Atoi(p)
	pc, err := node.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, Host: host, DstPort: uint16(portNumber)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr, _ := net.ResolveUDPAddr("udp", echo)
	_, _ = pc.WriteTo([]byte("x"), addr)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(make([]byte, 16))
	if err == nil {
		t.Fatalf("a listener with udp off answered a datagram (%d B)", n)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the session stayed open with udp off: it should end")
	}
}

func TestSnellV6RefusesWhatTheOfficialServerRefuses(t *testing.T) {
	for name, option := range map[string]outbound.SnellOption{
		"a short psk": {Name: "v6", Server: "127.0.0.1", Port: 1, Psk: "short", Version: 6},
		"an obfs":     {Name: "v6", Server: "127.0.0.1", Port: 1, Psk: snellV6TestPSK, Version: 6, ObfsOpts: map[string]any{"mode": "http"}},
		"an odd mode": {Name: "v6", Server: "127.0.0.1", Port: 1, Psk: snellV6TestPSK, Version: 6, Mode: "shaped"},
	} {
		if _, err := outbound.NewSnell(option); err == nil {
			t.Errorf("%s: a node was built", name)
		}
	}
	if _, err := outbound.NewSnell(outbound.SnellOption{Name: "v4", Server: "127.0.0.1", Port: 1, Psk: snellV6TestPSK, Version: 4, Mode: "unshaped", UserKey: "u"}); err != nil {
		t.Errorf("a version-4 node with a mode was refused: %v", err)
	}
	if l, err := inbound.NewSnell(&inbound.SnellOption{BaseOption: inbound.BaseOption{NameStr: "x", Listen: "127.0.0.1", Port: "0"}, Psk: "short", Version: 6}); err == nil {
		if err := l.Listen(tunnel.Tunnel); err == nil {
			_ = l.Close()
			t.Error("a listener with a short psk listened")
		}
	}
	if _, err := inbound.NewSnell(&inbound.SnellOption{BaseOption: inbound.BaseOption{NameStr: "x", Listen: "127.0.0.1", Port: "0"}, Psk: snellV6TestPSK, Version: 4, Mode: "unshaped"}); err != nil {
		t.Errorf("a version-4 listener with a mode was refused: %v", err)
	}
}

func TestTheFieldCatalogOffersEverySnellVersionAndModeTheKernelBuilds(t *testing.T) {
	catalog := map[string]syntaxField{}
	for _, field := range fieldList() {
		catalog[field.Path] = field
	}
	selectOf := func(path string, want []string, byDefault string) []string {
		field := catalog[path]
		if field.Kind != "select" || strings.Join(field.Values, ",") != strings.Join(want, ",") || field.Default != byDefault || field.UnknownValue != "refused" {
			t.Fatalf("%s: %+v, want a select of %v defaulting to %s that refuses others", path, field, want, byDefault)
		}
		return field.Values
	}
	versions := []string{"1", "2", "3", "4", "5", "6"}
	modes := []string{"default", "unshaped", "unsafe-raw"}
	listen := func(option inbound.SnellOption) error {
		option.BaseOption = inbound.BaseOption{NameStr: "in", Listen: "127.0.0.1", Port: "0", SpecialProxy: "DIRECT"}
		option.Psk = snellV6TestPSK
		listener, err := inbound.NewSnell(&option)
		if err == nil {
			if err = listener.Listen(tunnel.Tunnel); err == nil {
				_ = listener.Close()
			}
		}
		return err
	}
	build := func(option outbound.SnellOption) error {
		option.Name, option.Server, option.Port, option.Psk = "node", "127.0.0.1", 1, snellV6TestPSK
		node, err := outbound.NewSnell(option)
		if err == nil {
			_ = node.Close()
		}
		return err
	}
	for _, value := range selectOf("proxies[snell].version", versions, "1") {
		version, _ := strconv.Atoi(value)
		if err := build(outbound.SnellOption{Version: version, UDP: version >= 3}); err != nil {
			t.Errorf("a version-%s node: %v", value, err)
		}
	}
	for _, value := range selectOf("listeners[snell].version", versions, "4") {
		version, _ := strconv.Atoi(value)
		if err := listen(inbound.SnellOption{Version: version}); err != nil {
			t.Errorf("a version-%s listener: %v", value, err)
		}
	}
	for _, mode := range selectOf("proxies[snell].mode", modes, "default") {
		if err := build(outbound.SnellOption{Version: 6, Mode: mode}); err != nil {
			t.Errorf("a version-6 node in mode %s: %v", mode, err)
		}
	}
	for _, mode := range selectOf("listeners[snell].mode", modes, "default") {
		if err := listen(inbound.SnellOption{Version: 6, Mode: mode}); err != nil {
			t.Errorf("a version-6 listener in mode %s: %v", mode, err)
		}
	}
	if field := catalog["proxies[snell].user-key"]; field.Kind != "text" || field.Format != "password" {
		t.Errorf("proxies[snell].user-key: %+v, want a text kept as a password", field)
	}
}

func TestASnellV6NodeImportsFromASurgeLineAndALink(t *testing.T) {
	for name, tc := range map[string]struct {
		payload, context string
		want             map[string]string
	}{
		"the manual's line": {"[Proxy]\nV6 = snell, v6.example.com, 443, psk=" + snellV6TestPSK + ", version=6, reuse=true, mode=unshaped\n", "subscriptionBody",
			map[string]string{"type": "snell", "version": "6", "reuse": "true", "udp": "true", "mode": "unshaped"}},
		"udp turned off": {"[Proxy]\nV6 = snell, v6.example.com, 443, psk=" + snellV6TestPSK + ", version=6, udp-relay=false\n", "subscriptionBody",
			map[string]string{"type": "snell", "version": "6", "udp": ""}},
		"udp=false": {"[Proxy]\nV4 = snell, v4.example.com, 443, psk=" + snellV6TestPSK + ", version=4, udp=false\n", "subscriptionBody",
			map[string]string{"type": "snell", "version": "4", "udp": ""}},
		"version 2": {"[Proxy]\nV2 = snell, v2.example.com, 443, psk=" + snellV6TestPSK + ", version=2\n", "subscriptionBody",
			map[string]string{"type": "snell", "version": "2", "udp": ""}},
		"udp-relay on version 2": {"[Proxy]\nV2 = snell, v2.example.com, 443, psk=" + snellV6TestPSK + ", version=2, udp-relay=true\n", "subscriptionBody",
			map[string]string{"type": "snell", "version": "2", "udp": ""}},
		"a snell link": {"snell://" + snellV6TestPSK + "@v6.example.com:443?version=6&mode=unsafe-raw&reuse=1&udp=1&user-key=u1#v6-link", "singleNode",
			map[string]string{"type": "snell", "version": "6", "reuse": "true", "udp": "true", "mode": "unsafe-raw", "user-key": "u1"}},
	} {
		report := inspectProxyPayloadReport(t, tc.payload, tc.context)
		if len(report.Proxies) != 1 || len(report.NotHonoured) != 0 {
			t.Fatalf("%s: proxies %d, skipped %v, notHonoured %v", name, len(report.Proxies), report.Skipped, report.NotHonoured)
		}
		proxy := report.Proxies[0]
		for path, value := range tc.want {
			if got := shadowrocketField(proxy, path); got != value {
				t.Errorf("%s: %s = %q, want %q", name, path, got, value)
			}
		}
		if _, err := adapter.ParseProxy(proxy); err != nil {
			t.Errorf("%s does not build: %v", name, err)
		}
	}
	for name, payload := range map[string]string{
		"a mode on a version-4 line": "[Proxy]\nV4 = snell, v4.example.com, 443, psk=" + snellV6TestPSK + ", version=4, mode=unshaped\n",
		"a mode on a version-4 link": "snell://" + snellV6TestPSK + "@v4.example.com:443?version=4&mode=unshaped#v4",
	} {
		if report := inspectProxyPayloadReport(t, payload, "subscriptionBody"); len(report.Proxies) != 0 {
			t.Errorf("%s: imported %v", name, report.Proxies)
		}
	}
}

func TestSnellV6Footprint(t *testing.T) {
	type sample struct {
		heap, stack uint64
		goroutines  int
	}
	measure := func() sample {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return sample{m.HeapAlloc, m.StackInuse, runtime.NumGoroutine()}
	}
	delta := func(a, b sample, n int64) string {
		return fmt.Sprintf("heap %+d B, stacks %+d B, goroutines %+.1f", (int64(b.heap)-int64(a.heap))/n, (int64(b.stack)-int64(a.stack))/n, float64(b.goroutines-a.goroutines)/float64(n))
	}
	for _, version := range []int{4, 6} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			mode := ""
			if version == 6 {
				mode = "default"
			}
			listen := func(udp bool) int {
				listener, err := inbound.NewSnell(&inbound.SnellOption{
					BaseOption: inbound.BaseOption{NameStr: "snell-in", Listen: "127.0.0.1", Port: "0", SpecialProxy: "DIRECT"},
					Psk:        snellV6TestPSK, Version: version, UDP: udp, Mode: mode,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := listener.Listen(tunnel.Tunnel); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				_, port, _ := net.SplitHostPort(listener.Address())
				p, _ := strconv.Atoi(port)
				return p
			}
			port := listen(false)
			node, err := outbound.NewSnell(outbound.SnellOption{Name: "v6", Server: "127.0.0.1", Port: port, Psk: snellV6TestPSK, Version: version, Mode: mode})
			if err != nil {
				t.Fatal(err)
			}
			withSnellV6Tunnel(t, node)
			local := forwardAddress(t, forwardThroughV6(t, tcpEcho(t, nil)), "tcp")
			roundTrip(t, dialThrough(t, local), 1024)
			time.Sleep(300 * time.Millisecond)

			before := measure()
			const listeners = 20
			for i := 0; i < listeners; i++ {
				listen(true)
			}
			time.Sleep(100 * time.Millisecond)
			perListener := delta(before, measure(), listeners)

			before = measure()
			const flows = 50
			conns := make([]net.Conn, 0, flows)
			for i := 0; i < flows; i++ {
				conn := dialThrough(t, local)
				roundTrip(t, conn, 16)
				conns = append(conns, conn)
			}
			time.Sleep(300 * time.Millisecond)
			perFlow := delta(before, measure(), flows)
			for _, conn := range conns {
				_ = conn.Close()
			}

			conn := dialThrough(t, local)
			const size = 64 << 20
			start := time.Now()
			roundTrip(t, conn, size)
			elapsed := time.Since(start)
			mbps := float64(size) / elapsed.Seconds() / (1 << 20)
			t.Logf("version %d: an idle listener: %s; an idle flow (both ends, through the tunnel twice): %s; 64 MiB echoed in %v (%.0f MiB/s each way)", version, perListener, perFlow, elapsed.Round(time.Millisecond), mbps)
			if mbps < 5 {
				t.Errorf("version %d: %.1f MiB/s, far below any working build", version, mbps)
			}
		})
	}
}
