package clash

import (
	"net/netip"
	"testing"
	"time"

	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

func withIPRewrite(t *testing.T, rules ...tun.IPRewriteRule) {
	t.Helper()
	tun.SetIPRewrite(rules)
	t.Cleanup(func() { tun.SetIPRewrite(nil) })
}

func (e *goStackThroughTheListener) nextPacket(t *testing.T) ([]byte, bool) {
	t.Helper()
	select {
	case packet := <-e.toApp:
		return packet, true
	case <-time.After(time.Second):
		return nil, false
	}
}

func TestIPRewriteTakesAPacketBeforeTheGoStack(t *testing.T) {
	withIPRewrite(t,
		tun.IPRewriteRule{Prefix: netip.MustParsePrefix("10.9.0.0/16"), Action: tun.IPRewriteReflect},
		tun.IPRewriteRule{Prefix: netip.MustParsePrefix("10.8.0.0/16"), Action: tun.IPRewriteReject},
		tun.IPRewriteRule{Prefix: netip.MustParsePrefix("10.7.0.0/16"), Action: tun.IPRewriteDrop},
	)
	entry := startGoStackThroughTheListener(t, 1500)
	app := netip.MustParseAddrPort("198.18.0.2:5000")

	reflected := netip.MustParseAddrPort("10.9.0.1:53")
	entry.send(t, app, reflected, []byte("reflect"))
	packet, ok := entry.nextPacket(t)
	if !ok {
		t.Fatal("a packet to a reflect line did not come back")
	}
	if from, to := netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])); from != reflected.Addr() || to != app.Addr() || string(packet[28:]) != "reflect" {
		t.Fatalf("the reflected packet went from %v to %v carrying %q", from, to, packet[28:])
	}

	entry.send(t, app, netip.MustParseAddrPort("10.8.0.1:443"), []byte("reject"))
	packet, ok = entry.nextPacket(t)
	if !ok {
		t.Fatal("a datagram to a reject line was not answered")
	}
	if packet[9] != unix.IPPROTO_ICMP || packet[20] != 3 || packet[21] != 13 || netip.AddrFrom4([4]byte(packet[16:20])) != app.Addr() {
		t.Fatalf("a rejected datagram was answered with % x, want ICMP administratively prohibited to the app", packet[:min(len(packet), 24)])
	}

	entry.send(t, app, netip.MustParseAddrPort("10.7.0.1:443"), []byte("drop"))
	if packet, ok := entry.nextPacket(t); ok {
		t.Fatalf("a dropped datagram was answered with % x", packet[:min(len(packet), 24)])
	}
	if got := entry.tunnel.waitFor(t, 0); len(got) != 0 {
		t.Fatalf("the tunnel was handed what IP Rewrite took: %+v", got)
	}

	entry.send(t, app, netip.MustParseAddrPort("192.0.2.1:443"), []byte("carried"))
	if got := entry.tunnel.waitFor(t, 1); len(got) != 1 || got[0].destination != "192.0.2.1:443" {
		t.Fatalf("a datagram no line covers reached the tunnel as %+v", got)
	}
}

func TestADatagramToALoopbackAddressGoesBackToTheApp(t *testing.T) {
	loopback := netip.MustParseAddr("198.18.0.100")
	entry := startGoStackThroughTheListenerWith(t, 1500, []netip.Addr{loopback})
	app := netip.MustParseAddrPort("198.18.0.2:5000")
	entry.send(t, app, netip.AddrPortFrom(loopback, 8080), []byte("loopback"))
	packet, ok := entry.nextPacket(t)
	if !ok {
		t.Fatal("a datagram to a loopback address did not come back")
	}
	if from, to := netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])); from != loopback || to != app.Addr() {
		t.Fatalf("the datagram came back from %v to %v", from, to)
	}
	if got := entry.tunnel.waitFor(t, 0); len(got) != 0 {
		t.Fatalf("a datagram to a loopback address reached the tunnel: %+v", got)
	}
}
