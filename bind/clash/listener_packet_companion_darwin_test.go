//go:build darwin

package clash

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	"github.com/ProjectClash/Clash/dns"

	D "github.com/miekg/dns"
)

func TestAWildcardDNSListenGetsLoopbackPacketCompanions(t *testing.T) {
	installListenerScopeHooks(true)
	t.Cleanup(func() { installListenerScopeHooks(false) })
	var lc inbound.ListenConfig
	for _, tc := range []struct {
		host string
		want []string
	}{
		{"0.0.0.0", []string{"127.0.0.1", "::1"}},
		{"::", []string{"127.0.0.1", "::1"}},
		{"", []string{"127.0.0.1", "::1"}},
		{"127.0.0.1", nil},
		{"192.0.2.1", nil},
	} {
		t.Run("host="+tc.host, func(t *testing.T) {
			primary, err := lc.ListenPacket(context.Background(), "udp", net.JoinHostPort(tc.host, "0"))
			if err != nil {
				if tc.host == "192.0.2.1" {
					t.Skip("the documentation address is not this host's")
				}
				t.Fatal(err)
			}
			defer primary.Close()
			port := primary.LocalAddr().(*net.UDPAddr).Port
			address := net.JoinHostPort(tc.host, strconv.Itoa(port))
			companions, err := listenerLoopbackPacketCompanions("udp", address, primary, lc.ListenPacket)
			if err != nil {
				t.Fatalf("companions for %s: %v", address, err)
			}
			defer func() {
				for _, c := range companions {
					_ = c.Close()
				}
			}()
			var got []string
			for _, c := range companions {
				local := c.LocalAddr().(*net.UDPAddr)
				if local.Port != port {
					t.Fatalf("a companion listens on port %d, not the primary's %d", local.Port, port)
				}
				addr, _ := netip.AddrFromSlice(local.IP)
				got = append(got, addr.Unmap().String())
			}
			if len(got) != len(tc.want) {
				t.Fatalf("companions on %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("companions on %v, want %v", got, tc.want)
				}
			}
		})
	}
}

type answeringDNS struct{}

func (answeringDNS) ServeMsg(_ context.Context, r *D.Msg) (*D.Msg, error) {
	m := new(D.Msg)
	m.SetReply(r)
	return m, nil
}

func TestADNSListenOnTheWildcardAnswersLoopbackAndReleasesIt(t *testing.T) {
	installListenerScopeHooks(true)
	t.Cleanup(func() { installListenerScopeHooks(false) })

	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	_ = free.Close()
	dns.ReCreateServer(net.JoinHostPort("0.0.0.0", strconv.Itoa(port)), inbound.NewListenConfig(), answeringDNS{})
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			dns.ReCreateServer("", nil, nil)
		}
	})

	client := &D.Client{Net: "udp", Timeout: time.Second}
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	for _, host := range []string{"127.0.0.1", "::1"} {
		deadline := time.Now().Add(3 * time.Second)
		for {
			reply, _, err := client.Exchange(query, net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil && reply != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s:%d was never answered: %v", host, port, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	dns.ReCreateServer("", nil, nil)
	stopped = true
	deadline := time.Now().Add(3 * time.Second)
	for _, host := range []string{"127.0.0.1", "::1"} {
		for {
			conn, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				_ = conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s:%d is still held after the DNS server stopped: %v", host, port, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestOneFamilysCompanionFailingKeepsTheOther(t *testing.T) {
	installListenerScopeHooks(true)
	t.Cleanup(func() { installListenerScopeHooks(false) })
	var lc inbound.ListenConfig
	primary, err := lc.ListenPacket(context.Background(), "udp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	port := strconv.Itoa(primary.LocalAddr().(*net.UDPAddr).Port)
	squatter, err := (&net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var e error
		_ = c.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1) })
		return e
	}}).ListenPacket(context.Background(), "udp6", net.JoinHostPort("::1", port))
	if err != nil {
		t.Skipf("could not take [::1]:%s for the test: %v", port, err)
	}
	defer squatter.Close()
	companions, err := listenerLoopbackPacketCompanions("udp", net.JoinHostPort("::", port), primary, lc.ListenPacket)
	defer func() {
		for _, c := range companions {
			_ = c.Close()
		}
	}()
	if err == nil {
		t.Fatal("a companion that could not be made is reported")
	}
	if len(companions) != 1 || companions[0].LocalAddr().(*net.UDPAddr).IP.To4() == nil {
		t.Fatalf("the v4 companion is kept when v6 fails, got %v", companions)
	}
}
