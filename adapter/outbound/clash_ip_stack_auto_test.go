package outbound

import (
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/constant/features"
	"github.com/metacubex/mipstack"
)

func TestIPStackAutoKeepsGVisorWhereItIsCompiledIn(t *testing.T) {
	for _, mode := range []string{"", ipStackAuto} {
		option := IPStackOption{Mode: mode}
		option.normalize()
		if err := option.validate(); err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		stack, err := newIPStack(option, []netip.Prefix{netip.MustParsePrefix("10.7.0.2/32")}, 1420)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		_, isMips := stack.(*mipstack.Stack)
		_ = stack.Close()
		if features.WithGVisor == isMips {
			t.Fatalf("mode %q with gVisor compiled in=%v built mips=%v", mode, features.WithGVisor, isMips)
		}
	}
}
