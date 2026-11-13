package inbound_test


import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/inbound"
)

const mib = 1 << 20

type floodTunnel struct {
	*TestTunnel
	sent  atomic.Int64
	flows atomic.Int64
	conns sync.Map
}

func newFloodTunnel(t *testing.T) *floodTunnel {
	tunnel := &floodTunnel{TestTunnel: NewHttpTestTunnel()}
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		tunnel.flows.Add(1)
		tunnel.conns.Store(conn, struct{}{})
		defer conn.Close()
		block := make([]byte, 16<<10)
		for {
			n, err := conn.Write(block)
			tunnel.sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}
	t.Cleanup(func() {
		tunnel.conns.Range(func(conn, _ any) bool { _ = conn.(net.Conn).Close(); return true })
		_ = tunnel.Close()
	})
	return tunnel
}

func (f *floodTunnel) settled(t *testing.T, flows int64) int64 {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	last, still := int64(-1), 0
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		now := f.sent.Load()
		if f.flows.Load() >= flows && now == last {
			if still++; still >= 15 {
				return now
			}
		} else {
			still = 0
		}
		last = now
	}
	t.Fatalf("the server never stopped sending: %d bytes over %d of %d flows", f.sent.Load(), f.flows.Load(), flows)
	return 0
}

func openUnread(t *testing.T, out C.ProxyAdapter, flows int) {
	t.Helper()
	for i := 0; i < flows; i++ {
		conn, err := out.DialContext(context.Background(), &C.Metadata{
			NetWork: C.TCP, Host: "video.test", DstPort: uint16(8000 + i),
		})
		if err != nil {
			t.Fatalf("dial flow %d: %v", i, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if _, err := conn.Write([]byte("GET")); err != nil {
			t.Fatalf("write flow %d: %v", i, err)
		}
	}
}

func withTunnelReceiveWindows(t *testing.T, windows *outbound.QUICReceiveWindows) {
	t.Helper()
	before := outbound.QUICDefaultReceiveWindows()
	outbound.SetQUICDefaultReceiveWindows(windows)
	t.Cleanup(func() { outbound.SetQUICDefaultReceiveWindows(before) })
}

func newFloodHysteria2(t *testing.T, tunnel *floodTunnel, options outbound.Hysteria2Option) C.ProxyAdapter {
	t.Helper()
	in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
		BaseOption:  inbound.BaseOption{NameStr: "hysteria2_flood", Listen: "127.0.0.1", Port: "0"},
		Users:       map[string]string{"test": userUUID},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	addrPort, err := netip.ParseAddrPort(in.Address())
	if err != nil {
		t.Fatal(err)
	}
	options.Name = "hysteria2_flood"
	options.Server = addrPort.Addr().String()
	options.Port = int(addrPort.Port())
	options.Password = userUUID
	options.Fingerprint = tlsFingerprint
	options.DialerForAPI = tunnel.NewDialer()
	options.TunnelForAPI = tunnel
	out, err := outbound.NewHysteria2(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func newFloodTuic(t *testing.T, tunnel *floodTunnel, options outbound.TuicOption) C.ProxyAdapter {
	t.Helper()
	in, err := inbound.NewTuic(&inbound.TuicOption{
		BaseOption:            inbound.BaseOption{NameStr: "tuic_flood", Listen: "127.0.0.1", Port: "0"},
		Users:                 map[string]string{userUUID: userUUID},
		Certificate:           tlsCertificate,
		PrivateKey:            tlsPrivateKey,
		AuthenticationTimeout: 5000,
		CongestionController:  "bbr",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	addrPort, err := netip.ParseAddrPort(in.Address())
	if err != nil {
		t.Fatal(err)
	}
	options.Name = "tuic_flood"
	options.Server = addrPort.Addr().String()
	options.Port = int(addrPort.Port())
	options.UUID = userUUID
	options.Password = userUUID
	options.CongestionController = "bbr"
	options.Fingerprint = tlsFingerprint
	options.DialerForAPI = tunnel.NewDialer()
	options.TunnelForAPI = tunnel
	out, err := outbound.NewTuic(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

const slack = 64 << 10

func TestAHysteria2FlowTheAppStopsReadingHoldsOneStreamWindow(t *testing.T) {
	withTunnelReceiveWindows(t, outbound.QUICTunnelReceiveWindows())
	tunnel := newFloodTunnel(t)
	openUnread(t, newFloodHysteria2(t, tunnel, outbound.Hysteria2Option{}), 1)
	if sent := tunnel.settled(t, 1); sent > 1*mib+slack {
		t.Fatalf("the server sent %d bytes to a flow nobody reads, past its 1 MiB window", sent)
	}
}

func TestHysteria2FlowsTheAppStopsReadingHoldOneConnectionWindow(t *testing.T) {
	withTunnelReceiveWindows(t, outbound.QUICTunnelReceiveWindows())
	tunnel := newFloodTunnel(t)
	openUnread(t, newFloodHysteria2(t, tunnel, outbound.Hysteria2Option{}), 20)
	sent := tunnel.settled(t, 20)
	if sent > 12*mib+20*slack {
		t.Fatalf("twenty flows nobody reads took %d bytes, past the 12 MiB the connection's window starts at", sent)
	}
	if sent < 11*mib {
		t.Fatalf("twenty flows nobody reads took %d bytes, short of the 12 MiB the connection's window starts at", sent)
	}
}

func TestAHysteria2NodeThatWritesItsWindowsRunsThem(t *testing.T) {
	withTunnelReceiveWindows(t, outbound.QUICTunnelReceiveWindows())
	tunnel := newFloodTunnel(t)
	openUnread(t, newFloodHysteria2(t, tunnel, outbound.Hysteria2Option{
		InitialStreamReceiveWindow: 3 * mib, MaxStreamReceiveWindow: 3 * mib,
	}), 1)
	if sent := tunnel.settled(t, 1); sent < 3*mib-slack || sent > 3*mib+slack {
		t.Fatalf("a node that writes a 3 MiB stream window had %d bytes sent to a flow nobody reads", sent)
	}
}

func TestWithoutTheTunnelsDefaultAHysteria2FlowHoldsItsProtocolsWindow(t *testing.T) {
	withTunnelReceiveWindows(t, nil)
	tunnel := newFloodTunnel(t)
	openUnread(t, newFloodHysteria2(t, tunnel, outbound.Hysteria2Option{}), 1)
	if sent := tunnel.settled(t, 1); sent < 8*mib-slack {
		t.Fatalf("upstream's default let the server send %d bytes, want Hysteria2's 8 MiB", sent)
	}
}

func TestATuicFlowTheAppStopsReadingHoldsItsProtocolsStreamWindow(t *testing.T) {
	withTunnelReceiveWindows(t, outbound.QUICTunnelReceiveWindows())
	tunnel := newFloodTunnel(t)
	openUnread(t, newFloodTuic(t, tunnel, outbound.TuicOption{}), 1)
	const own = 15728640 / 10
	if sent := tunnel.settled(t, 1); sent < own-slack || sent > own+slack {
		t.Fatalf("the server sent %d bytes to a TUIC flow nobody reads, want its own %d", sent, own)
	}
}

func TestATuicNodeThatWritesItsStreamWindowRunsIt(t *testing.T) {
	withTunnelReceiveWindows(t, outbound.QUICTunnelReceiveWindows())
	tunnel := newFloodTunnel(t)
	openUnread(t, newFloodTuic(t, tunnel, outbound.TuicOption{ReceiveWindowConn: 3 * mib}), 1)
	if sent := tunnel.settled(t, 1); sent < 3*mib-slack || sent > 3*mib+slack {
		t.Fatalf("a TUIC node that writes recv-window-conn 3 MiB had %d bytes sent to a flow nobody reads", sent)
	}
}
