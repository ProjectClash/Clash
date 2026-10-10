package sing_tun

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/sing"
	"github.com/ProjectClash/Clash/tunnel"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)


type doorTunnel struct {
	physical bool
	asked    []*C.Metadata
}

func (d *doorTunnel) HandleTCPConn(net.Conn, *C.Metadata)      {}
func (d *doorTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (d *doorTunnel) NatTable() C.NatTable                     { return nil }
func (d *doorTunnel) WouldDialPhysically(m *C.Metadata) bool {
	d.asked = append(d.asked, m)
	return d.physical
}

func newDoorHandler(t *testing.T, physical bool) (*ListenerHandler, *doorTunnel) {
	t.Helper()
	tun := &doorTunnel{physical: physical}
	base, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: tun, Type: C.TUN})
	if err != nil {
		t.Fatal(err)
	}
	return &ListenerHandler{ListenerHandler: base}, tun
}

func prepare(h *ListenerHandler, network, dst string) error {
	_, err := h.PrepareConnection(network,
		M.SocksaddrFrom(netip.MustParseAddr("fdfe:dcba:9876::1"), 40000),
		M.SocksaddrFrom(netip.MustParseAddr(dst), 443), nil, time.Second)
	return err
}

func withPathWithoutIPv6(t *testing.T) {
	t.Helper()
	prev := dialer.DefaultAddressTransform
	dialer.DefaultAddressTransform = func(_ string, dst netip.Addr) (netip.Addr, error) {
		if dialer.IsPhysicalGlobalIPv6(dst) {
			return netip.Addr{}, dialer.ErrPhysicalIPv6Unavailable
		}
		return dst, nil
	}
	t.Cleanup(func() { dialer.DefaultAddressTransform = prev })
}

func TestDoorHonoursThePathWitnessBeforeTheHandshake(t *testing.T) {
	withPathWithoutIPv6(t)
	h, _ := newDoorHandler(t, true)
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if err := prepare(h, network, "2001:db8::10"); !errors.Is(err, dialer.ErrPhysicalIPv6Unavailable) {
			t.Fatalf("%s to a global v6 destination on a path without IPv6 must be refused at the door, got %v", network, err)
		}
	}
	for _, dst := range []string{"192.0.2.10", "fd00::1"} {
		if err := prepare(h, N.NetworkTCP, dst); err != nil {
			t.Fatalf("%s is not global IPv6; refused with %v", dst, err)
		}
	}
}

func TestDoorLeavesProxiedFlowsAloneEvenWithoutPathIPv6(t *testing.T) {
	withPathWithoutIPv6(t)
	h, _ := newDoorHandler(t, false)
	if err := prepare(h, N.NetworkTCP, "2001:db8::10"); err != nil {
		t.Fatalf("a proxy carries this peer over whatever the proxy server has: %v", err)
	}
}

func TestDoorSaysNothingAboutAPathThatHasIPv6(t *testing.T) {
	h, tun := newDoorHandler(t, true)
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if err := prepare(h, network, "2001:db8::10"); err != nil {
			t.Fatalf("%s: nothing here knows this flow will fail, so nothing may refuse it: %v", network, err)
		}
	}
	if len(tun.asked) != 0 {
		t.Fatalf("the door must not even ask which way a flow goes on a path with IPv6, asked %d times", len(tun.asked))
	}
}

func TestTheProductionTunnelIsTheDoorsOracle(t *testing.T) {
	var production interface{} = tunnel.Tunnel
	if _, ok := production.(physicalDialOracle); !ok {
		t.Fatal("tunnel.Tunnel does not implement WouldDialPhysically; the door would silently admit every flow")
	}
}

func TestTheDoorsLogGateReopensWhenThePathCarriesIPv6Again(t *testing.T) {
	pathRefusalLogged.Store(false)
	t.Cleanup(func() { pathRefusalLogged.Store(false) })

	withPathWithoutIPv6(t)
	h, _ := newDoorHandler(t, true)
	if err := prepare(h, N.NetworkTCP, "2001:db8::10"); !errors.Is(err, dialer.ErrPhysicalIPv6Unavailable) {
		t.Fatalf("setup: refused, got %v", err)
	}
	if !pathRefusalLogged.Load() {
		t.Fatal("the first refusal of a stretch is the one worth reading")
	}

	dialer.DefaultAddressTransform = nil
	if err := prepare(h, N.NetworkTCP, "2001:db8::10"); err != nil {
		t.Fatalf("a path with IPv6 refuses nothing: %v", err)
	}
	if pathRefusalLogged.Load() {
		t.Fatal("a later stretch without IPv6 must get its own line, not be silently swallowed")
	}
}

func TestDoorLeavesAHijackedDNSQueryAlone(t *testing.T) {
	withPathWithoutIPv6(t)
	h, tun := newDoorHandler(t, true)
	h.DnsAddrPorts = []netip.AddrPort{netip.MustParseAddrPort("[::]:53")}
	resolver6 := M.SocksaddrFrom(netip.MustParseAddr("2001:4860:4860::8888"), 53)
	source := M.SocksaddrFrom(netip.MustParseAddr("fdfe:dcba:9876::1"), 40000)
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if _, err := h.PrepareConnection(network, source, resolver6, nil, time.Second); err != nil {
			t.Fatalf("%s: a hijacked query must pass the door, refused with %v", network, err)
		}
	}
	if len(tun.asked) != 0 {
		t.Fatal("a hijacked query is settled before the rules are consulted")
	}
	if _, err := h.PrepareConnection(N.NetworkTCP, source, M.SocksaddrFrom(resolver6.Addr, 443), nil, time.Second); !errors.Is(err, dialer.ErrPhysicalIPv6Unavailable) {
		t.Fatalf("port 443 to the same host is dialled physically and must still be refused, got %v", err)
	}
}
