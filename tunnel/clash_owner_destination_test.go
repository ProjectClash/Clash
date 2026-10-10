package tunnel

import (
	"net"
	"net/netip"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestTheOwnerIsAskedForWithTheDestinationTheSocketHas(t *testing.T) {
	m := &C.Metadata{
		NetWork:    C.TCP,
		DstIP:      netip.MustParseAddr("203.0.113.47"),
		DstPort:    443,
		RawDstAddr: &net.TCPAddr{IP: net.IPv4(198, 18, 0, 20), Port: 443},
	}
	ip, port := ownerDestination(m)
	if ip != netip.MustParseAddr("198.18.0.20") || port != 443 {
		t.Fatalf("asked with %v:%d, want the socket's 198.18.0.20:443", ip, port)
	}
}

func TestAFakeIPFlowWhoseDstIPWasClearedStillHasADestination(t *testing.T) {
	m := &C.Metadata{
		NetWork:    C.UDP,
		DstPort:    443,
		RawDstAddr: &net.UDPAddr{IP: net.ParseIP("fdfe:dcba:9876::14"), Port: 443},
	}
	ip, port := ownerDestination(m)
	if ip != netip.MustParseAddr("fdfe:dcba:9876::14") || port != 443 {
		t.Fatalf("asked with %v:%d", ip, port)
	}
}

func TestWithoutARecordedDestinationTheMetadatasIsUsed(t *testing.T) {
	m := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("203.0.113.9"), DstPort: 8443}
	ip, port := ownerDestination(m)
	if ip != netip.MustParseAddr("203.0.113.9") || port != 8443 {
		t.Fatalf("asked with %v:%d", ip, port)
	}
}
