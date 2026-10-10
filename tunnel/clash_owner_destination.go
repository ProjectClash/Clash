package tunnel

import (
	"net"
	"net/netip"

	C "github.com/ProjectClash/Clash/constant"
)

func ownerDestination(metadata *C.Metadata) (netip.Addr, int) {
	switch raw := metadata.RawDstAddr.(type) {
	case *net.TCPAddr:
		if addr := raw.AddrPort(); addr.Addr().IsValid() {
			return addr.Addr().Unmap(), int(addr.Port())
		}
	case *net.UDPAddr:
		if addr := raw.AddrPort(); addr.Addr().IsValid() {
			return addr.Addr().Unmap(), int(addr.Port())
		}
	}
	return metadata.DstIP, int(metadata.DstPort)
}
