package tunnel

import (
	"net"
	"sync"
	"syscall"
	"testing"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	icontext "github.com/ProjectClash/Clash/context"
)

type cleanupOrderConn struct {
	net.Conn
	name  string
	order *[]string
	check func()
}

func (c *cleanupOrderConn) Close() error {
	if c.check != nil {
		c.check()
	}
	*c.order = append(*c.order, c.name)
	return nil
}

type cleanupOrderRemote struct {
	C.Conn
	cleanupOrderConn
}

func (c *cleanupOrderRemote) Close() error { return c.cleanupOrderConn.Close() }

func TestTheFlowCleanupRunsInTheOrderTheDefersRan(t *testing.T) {
	var order []string
	var peek sync.Mutex
	peek.Lock()
	remote := &cleanupOrderRemote{cleanupOrderConn: cleanupOrderConn{name: "remote", order: &order, check: func() {
		if !peek.TryLock() {
			t.Error("the outbound closed while the peek lock was still held")
			return
		}
		peek.Unlock()
	}}}
	held := TCPConnectionAdmissionSnapshot().Active
	if !admitTCPConnection() {
		t.Fatal("no connection slot to take")
	}
	taken := TCPConnectionAdmissionSnapshot().Active
	cleanup := tcpFlowCleanup{
		slot: true,
		conn: &cleanupOrderConn{name: "conn", order: &order, check: func() {
			if now := TCPConnectionAdmissionSnapshot().Active; now != taken {
				t.Errorf("the slot was given back before the application's side closed (%d, holding %d)", now, taken)
			}
		}},
		cancel: func() { order = append(order, "cancel") },
		remote: remote,
		peek:   &peek,
	}
	cleanup.run()
	if now := TCPConnectionAdmissionSnapshot().Active; now != held {
		t.Errorf("the slot was not given back: %d active, %d before", now, held)
	}
	want := []string{"remote", "cancel", "conn"}
	if len(order) != len(want) {
		t.Fatalf("cleanup ran %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("cleanup ran %v, want %v", order, want)
		}
	}
	if !peek.TryLock() {
		t.Fatal("the peek lock is still held after the cleanup")
	}

	order = nil
	early := tcpFlowCleanup{conn: &cleanupOrderConn{name: "conn", order: &order}}
	early.run()
	if len(order) != 1 || order[0] != "conn" {
		t.Fatalf("an early cleanup ran %v, want [conn]", order)
	}
}

func TestAFlowClosesItsOutboundNoMoreThanBefore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		left   bool
		closes int32
	}{{"relayed", false, 3}, {"client left before the answer", true, 4}} {
		t.Run(tc.name, func(t *testing.T) {
			events := &eventLog{}
			var remote *lazyHeaderConn
			out := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, dial: func() (C.Conn, error) {
				remote = &lazyHeaderConn{nothingConn: nothingConn{N.NewExtendedConn(eofConn{})}, events: events}
				return remote, nil
			}}
			withVerdictTunnel(t, "out", out)
			conn := newVerdictConn(true)
			if tc.left {
				conn.left = syscall.ECONNRESET
			} else {
				conn.firstBytes, conn.events = []byte("ClientHello"), events
			}
			handleTCPConn(icontext.NewConnContext(conn, tunFlowTo("192.0.2.1")))
			if remote == nil {
				t.Fatal("the flow never dialled")
			}
			if n := remote.closes.Load(); n > tc.closes {
				t.Fatalf("the outbound was closed %d times, %d before the cleanup left the preparation", n, tc.closes)
			}
		})
	}
}

func TestTheFlowCleanupRunsEveryStepPastAPanic(t *testing.T) {
	var order []string
	cleanup := tcpFlowCleanup{
		conn:   &cleanupOrderConn{name: "conn", order: &order},
		cancel: func() { order = append(order, "cancel") },
		remote: &cleanupOrderRemote{cleanupOrderConn: cleanupOrderConn{name: "remote", order: &order, check: func() { panic("remote") }}},
	}
	func() {
		defer func() { _ = recover() }()
		cleanup.run()
	}()
	if len(order) != 2 || order[0] != "cancel" || order[1] != "conn" {
		t.Fatalf("after the outbound's close panicked the cleanup ran %v, want [cancel conn]", order)
	}
}
