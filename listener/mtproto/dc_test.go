package mtproto

import (
	"net/netip"
	"testing"
)

func useDCTable(t *testing.T, table []dataCenter) {
	t.Helper()
	saved := dcTableOverride.Load()
	dcTableOverride.Store(&table)
	t.Cleanup(func() { dcTableOverride.Store(saved) })
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestProductionDCTableShape(t *testing.T) {
	if len(productionDCs) != 5 {
		t.Fatalf("%d production DCs, want 5", len(productionDCs))
	}
	for i := range productionDCs {
		dc := &productionDCs[i]
		for _, f := range []struct {
			name   string
			family *dcFamily
			is4    bool
		}{{"IPv4", &dc.v4, true}, {"IPv6", &dc.v6, false}} {
			if len(f.family.general) == 0 {
				t.Errorf("DC %d has no general %s endpoint", i+1, f.name)
			}
			if n := len(f.family.general) + len(f.family.media); n > maxFamilyEndpoints {
				t.Errorf("DC %d %s: %d endpoints, at most %d fit the failure marks", i+1, f.name, n, maxFamilyEndpoints)
			}
			seen := map[netip.AddrPort]bool{}
			for _, list := range [][]netip.AddrPort{f.family.general, f.family.media} {
				for _, addr := range list {
					if addr.Port() != 443 || addr.Addr().Is4() != f.is4 || (!f.is4 && !addr.Addr().Is6()) {
						t.Errorf("DC %d %s: endpoint %s", i+1, f.name, addr)
					}
					if seen[addr] {
						t.Errorf("DC %d %s: %s twice", i+1, f.name, addr)
					}
					seen[addr] = true
				}
			}
		}
	}
}

func TestPickProductionEndpoints(t *testing.T) {
	useDCTable(t, productionDCs[:])
	for _, c := range []struct {
		dc   int16
		ipv6 bool
		want string
	}{
		{1, false, "149.154.175.54:443"},
		{2, false, "149.154.167.41:443"},
		{3, false, "149.154.175.100:443"},
		{4, false, "149.154.167.92:443"},
		{5, false, "91.108.56.191:443"},
		{-2, false, "149.154.167.222:443"},
		{-4, false, "149.154.165.111:443"},
		{-1, false, "149.154.175.54:443"},
		{-3, false, "149.154.175.100:443"},
		{-5, false, "91.108.56.191:443"},
		{1, true, "[2001:b28:f23d:f001::a]:443"},
		{2, true, "[2001:67c:4e8:f002::a]:443"},
		{-2, true, "[2001:67c:4e8:f002::b]:443"},
		{-4, true, "[2001:67c:4e8:f004::b]:443"},
		{-5, true, "[2001:b28:f23f:f005::a]:443"},
	} {
		p, ok := pickEndpoint(c.dc, c.ipv6)
		if !ok {
			t.Errorf("dc %d ipv6 %v: no endpoint", c.dc, c.ipv6)
			continue
		}
		if p.addr != ap(c.want) {
			t.Errorf("dc %d ipv6 %v: %s, want %s", c.dc, c.ipv6, p.addr, c.want)
		}
	}
	for _, dc := range []int16{0, 6, -6, 203, -203, 10002, 32767, -32768} {
		if p, ok := pickEndpoint(dc, false); ok {
			t.Errorf("dc %d: %s, want no endpoint", dc, p.addr)
		}
	}
}

func TestPickSkipsFailedEndpoints(t *testing.T) {
	useDCTable(t, []dataCenter{
		{},
		{v4: dcFamily{
			general: []netip.AddrPort{ap("10.0.0.1:443"), ap("10.0.0.2:443")},
			media:   []netip.AddrPort{ap("10.0.0.3:443")},
		}},
	})
	pick := func(dc int16) string {
		t.Helper()
		p, ok := pickEndpoint(dc, false)
		if !ok {
			t.Fatalf("dc %d: no endpoint", dc)
		}
		return p.addr.String()
	}
	mark := func(dc int16) {
		t.Helper()
		p, ok := pickEndpoint(dc, false)
		if !ok {
			t.Fatalf("dc %d: no endpoint", dc)
		}
		p.markFailed()
	}

	if _, ok := pickEndpoint(1, false); ok {
		t.Fatal("a DC without endpoints gave one")
	}
	if _, ok := pickEndpoint(2, true); ok {
		t.Fatal("a DC without IPv6 endpoints gave one")
	}
	if got := pick(2); got != "10.0.0.1:443" {
		t.Fatalf("first pick %s", got)
	}
	if got := pick(-2); got != "10.0.0.3:443" {
		t.Fatalf("first media pick %s", got)
	}

	mark(2)
	if got := pick(2); got != "10.0.0.2:443" {
		t.Fatalf("after one failure %s", got)
	}
	if got := pick(-2); got != "10.0.0.3:443" {
		t.Fatalf("a general failure moved media to %s", got)
	}

	mark(-2)
	if got := pick(-2); got != "10.0.0.2:443" {
		t.Fatalf("media after its endpoint failed %s", got)
	}

	mark(2)
	if got := pick(2); got != "10.0.0.1:443" {
		t.Fatalf("after every general endpoint failed %s", got)
	}
	if got := pick(-2); got != "10.0.0.3:443" {
		t.Fatalf("media after the marks started over %s", got)
	}
}

func TestListenAddressOnApple(t *testing.T) {
	for _, c := range []struct {
		in       string
		apple    bool
		expected string
	}{
		{"0.0.0.0:5753", true, "127.0.0.1:5753"},
		{"0.0.0.0:5753", false, "0.0.0.0:5753"},
		{"127.0.0.1:5753", true, "127.0.0.1:5753"},
		{"192.168.1.2:5753", true, "192.168.1.2:5753"},
		{"[::]:5753", true, "[::1]:5753"},
		{"[::]:5753", false, "[::]:5753"},
		{"[::ffff:0.0.0.0]:5753", true, "127.0.0.1:5753"},
		{"[::1]:5753", true, "[::1]:5753"},
	} {
		if got := listenAddress(c.in, c.apple); got != c.expected {
			t.Errorf("listenAddress(%q, %v) = %q, want %q", c.in, c.apple, got, c.expected)
		}
	}
}
