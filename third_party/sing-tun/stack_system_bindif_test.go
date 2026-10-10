package tun

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/sing/common/logger"
)

func TestInterfaceIndexCarryingFindsTheInterfaceByAddress(t *testing.T) {
	index, carriers, lookupErr := interfaceIndexCarrying(netip.MustParseAddr("127.0.0.1"))
	if lookupErr != nil {
		t.Fatalf("loopback lookup must not error: %v", lookupErr)
	}
	if bindListenerSupported {
		loopback, err := net.InterfaceByName(loopbackInterfaceName(t))
		if err != nil {
			t.Fatalf("resolve the loopback interface: %v", err)
		}
		if index != loopback.Index {
			t.Errorf("interfaceIndexCarrying(127.0.0.1) = %d, want the loopback index %d", index, loopback.Index)
		}
		if carriers < 1 {
			t.Errorf("loopback carries 127.0.0.1 but carriers = %d", carriers)
		}
	} else {
		if index != -1 || carriers != 0 {
			t.Errorf("off darwin the stub must report -1/0, got %d/%d", index, carriers)
		}
	}
}

func TestInterfaceIndexCarryingReportsNotFoundForAnUnownedAddress(t *testing.T) {
	if index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("203.0.113.201")); index != -1 || carriers != 0 || err != nil {
		t.Errorf("interfaceIndexCarrying(unowned) = %d/%d/%v, want -1/0/nil", index, carriers, err)
	}
	if index, carriers, err := interfaceIndexCarrying(netip.Addr{}); index != -1 || carriers != 0 || err != nil {
		t.Errorf("interfaceIndexCarrying(invalid) = %d/%d/%v, want -1/0/nil", index, carriers, err)
	}
}

func TestBindControlIsNilWhenTheIndexIsNotFound(t *testing.T) {
	if bindListenerToInterfaceControl(-1, logger.NOP()) != nil {
		t.Error("a not-found index (-1) must produce no bind hook")
	}
}

func loopbackInterfaceName(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface on this host")
	return ""
}
