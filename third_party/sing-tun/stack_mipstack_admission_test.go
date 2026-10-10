package tun

import (
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestMipsRefusedFlowsReturnProtocolErrors(t *testing.T) {
	for _, family := range []struct {
		name, source, destination string
	}{
		{"ipv4", "198.18.0.1", "192.0.2.1"},
		{"ipv6", "fd00::1", "2001:db8::1"},
	} {
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(family.name+"/"+protocol, func(t *testing.T) {
				device := newMemoryTun()
				var asked atomic.Int32
				handler := &testHandler{prepare: func(DirectRouteContext) (DirectRouteDestination, error) {
					asked.Add(1)
					return nil, ErrReset
				}}
				testStack(t, device, handler, nil)
				source := netip.MustParseAddr(family.source)
				destination := netip.MustParseAddr(family.destination)
				if protocol == "tcp" {
					device.in <- tcpPacket(source, destination, 1, 0, 2, nil)
				} else {
					device.in <- udpPacket(source, destination, 443, []byte("denied"))
				}
				response := readPacket(t, device)
				from, to, next, ok := mipsPacketAddresses(response)
				if !ok || from != destination || to != source {
					t.Fatalf("unexpected error packet addresses: %v -> %v, valid=%v", from, to, ok)
				}
				headerSize := 20
				if source.Is6() {
					headerSize = 40
				}
				if protocol == "tcp" {
					if next != 6 || len(response) < headerSize+20 || response[headerSize+13]&4 == 0 {
						t.Fatalf("refused TCP SYN must receive RST, got %x", response)
					}
				} else if source.Is4() {
					if next != 1 || response[headerSize] != 3 {
						t.Fatalf("refused UDP must receive ICMP unreachable, got %x", response)
					}
				} else if next != 58 || response[headerSize] != 1 {
					t.Fatalf("refused UDP must receive ICMPv6 unreachable, got %x", response)
				}
				if asked.Load() != 1 {
					t.Fatalf("admission calls = %d, want 1", asked.Load())
				}
			})
		}
	}
}
