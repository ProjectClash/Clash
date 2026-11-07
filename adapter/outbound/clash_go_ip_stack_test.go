package outbound

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound/ipstacktest"
)

func init() {
	SetGoIPStackFactory(func(options GoIPStackOptions) (IPStack, error) { return ipstacktest.New(options.MTU), nil })
}

func TestEveryIPStackModeBuildsTheRegisteredStack(t *testing.T) {
	previous := goIPStackFactory.Load()
	t.Cleanup(func() { goIPStackFactory.Store(previous) })
	var got GoIPStackOptions
	built := 0
	SetGoIPStackFactory(func(options GoIPStackOptions) (IPStack, error) {
		got, built = options, built+1
		return ipstacktest.New(options.MTU), nil
	})
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.7.0.2/32")}
	for _, mode := range []string{"", ipStackAuto, ipStackGVisor, ipStackMips, "GVisor"} {
		option := IPStackOption{Mode: mode, CongestionController: "BBR"}
		option.normalize()
		if err := option.validate(); err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		stack, err := newIPStack(option, prefixes, 1420)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		_ = stack.Close()
		if got.MTU != 1420 || len(got.LocalAddresses) != 1 || got.LocalAddresses[0] != prefixes[0] || got.CongestionController != "bbr" {
			t.Fatalf("mode %q built the stack with %+v", mode, got)
		}
	}
	if built != 5 {
		t.Fatalf("%d stacks built for 5 nodes", built)
	}
	SetGoIPStackFactory(nil)
	if _, err := newIPStack(IPStackOption{Mode: ipStackAuto}, prefixes, 1420); !errors.Is(err, errNoIPStack) {
		t.Fatalf("with no stack registered a node got %v", err)
	}
}
