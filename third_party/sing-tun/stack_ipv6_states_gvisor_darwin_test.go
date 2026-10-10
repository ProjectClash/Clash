//go:build darwin && with_gvisor

package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing/common/logger"
)

type statesTun struct {
	mtu    uint32
	closed chan struct{}
	once   sync.Once
}

func (t *statesTun) Read([]byte) (int, error)    { <-t.closed; return 0, net.ErrClosed }
func (t *statesTun) Write(p []byte) (int, error) { return len(p), nil }
func (t *statesTun) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}
func (t *statesTun) WritePacket(*stack.PacketBuffer) (int, error) { return 0, nil }
func (t *statesTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return channel.New(128, t.mtu, ""), stack.NICOptions{}, nil
}

func TestEveryStackStartsInEveryTunIPv6StateTheTunnelCanPresent(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 on this host:", err)
	}
	states := []struct {
		name       string
		offersIPv6 bool
		declared   bool
	}{
		{"disabled: no IPv6 address", false, false},
		{"enabled, or automatic on a path with IPv6: address declared", true, true},
		{"automatic on an IPv4-only path: address undeclared", true, false},
	}
	for _, stackName := range []string{"system", "mixed", "gvisor"} {
		for _, state := range states {
			t.Run(stackName+"/"+state.name, func(t *testing.T) {
				carried := []net.Addr{mustCIDR(t, "127.0.0.1/8")}
				if state.declared {
					carried = append(carried, mustCIDR(t, "::1/128"))
				}
				withInterfaceTable(t, []net.Interface{*lo}, map[string][]net.Addr{"lo0": carried})
				tunOptions := Options{
					Name:         "utun-test",
					MTU:          1500,
					Inet4Address: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/30")},
				}
				if state.offersIPv6 {
					tunOptions.Inet6Address = []netip.Prefix{netip.MustParsePrefix("::1/126")}
				}
				tun := &statesTun{mtu: 1500, closed: make(chan struct{})}
				s, err := NewStack(stackName, StackOptions{
					Context:     context.Background(),
					Tun:         tun,
					TunOptions:  tunOptions,
					UDPTimeout:  time.Minute,
					ICMPTimeout: time.Minute,
					Logger:      logger.NOP(),
				})
				if err != nil {
					t.Fatalf("NewStack(%q): %v", stackName, err)
				}
				start := time.Now()
				if err := s.Start(); err != nil {
					t.Fatalf("%s stack must start with the IPv6 address %s, got %v", stackName, state.name, err)
				}
				t.Cleanup(func() { _ = s.Close(); _ = tun.Close() })
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("%s stack took %v to start; no state may ride the retry loop", stackName, elapsed)
				}
				switch typed := s.(type) {
				case *System:
					assertForwarders(t, typed, state.offersIPv6 && state.declared)
				case *Mixed:
					assertForwarders(t, typed.System, state.offersIPv6 && state.declared)
				}
			})
		}
	}
}

func assertForwarders(t *testing.T, s *System, wantV6Up bool) {
	t.Helper()
	if s.tcpListener == nil {
		t.Fatal("the v4 forwarder is up in every state")
	}
	if up := s.tcpListener6 != nil && s.tcpPort6 != 0; up != wantV6Up {
		t.Fatalf("v6 forwarder up=%v, want %v", up, wantV6Up)
	}
}
