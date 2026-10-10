package dns

import (
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
)

func TestSystemResolverDefaultsFollowTheSeed(t *testing.T) {
	t.Cleanup(func() { SetSystemResolverDefaults(nil) })
	SetSystemResolverDefaults([]string{"9.9.9.9", "", "[2620:fe::fe]:53"})
	got := SystemResolverDefaultAddresses()
	if len(got) != 2 || got[0] != "9.9.9.9:53" || got[1] != "[2620:fe::fe]:53" {
		t.Fatalf("seeded defaults = %v", got)
	}
	if resolver.SystemResolver == nil {
		t.Fatal("no system resolver")
	}
	SetSystemResolverDefaults(nil)
	got = SystemResolverDefaultAddresses()
	if len(got) != 2 || got[0] != "114.114.114.114:53" {
		t.Fatalf("upstream defaults = %v", got)
	}
}
