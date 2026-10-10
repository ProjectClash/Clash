package tcp

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

func TestTCPOptionsFitSmallRouteMTU(t *testing.T) {
	for _, mtu := range []uint32{68, 72, 80, 1280, 1500, 9000} {
		for _, timestamps := range []bool{false, true} {
			t.Run(fmt.Sprintf("mtu-%d/timestamps-%t", mtu, timestamps), func(t *testing.T) {
				s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
				t.Cleanup(s.Destroy)
				link := channel.New(1, mtu, "")
				if err := s.CreateNIC(1, link); err != nil {
					t.Fatal(err)
				}
				local := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
				remote := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
				if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: local, PrefixLen: 24}}, stack.AddressProperties{}); err != nil {
					t.Fatal(err)
				}
				s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
				route, err := s.FindRoute(1, local, remote, ipv4.ProtocolNumber, false)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(route.Release)
				e := &Endpoint{stack: s, route: route}
				e.SendTSOk, e.SACKPermitted = timestamps, true
				blocks := []header.SACKBlock{{Start: 100, End: 200}, {Start: 300, End: 400}, {Start: 500, End: 600}, {Start: 700, End: 800}}
				options := e.makeOptions(blocks)
				defer putOptions(options)
				if got := header.TCPMinimumSize + len(options) + 1; got > int(route.MTU()) {
					t.Errorf("TCP header/options and one payload byte need %d bytes; route permits %d", got, route.MTU())
				}
				parsed := header.ParseTCPOptions(options)
				if parsed.TS != timestamps || len(parsed.SACKBlocks) == 0 {
					t.Fatalf("negotiated options lost: %+v", parsed)
				}
				if !reflect.DeepEqual(parsed.SACKBlocks, blocks[:len(parsed.SACKBlocks)]) {
					t.Errorf("SACK priority/order changed: %+v", parsed.SACKBlocks)
				}
				if max := e.maxOptionSize(); max != len(options) {
					t.Errorf("sender budget %d differs from encoded maximum %d", max, len(options))
				}
				if mtu >= 1280 {
					want := 36
					if timestamps {
						want = 40
					}
					if len(options) != want {
						t.Errorf("ordinary MTU options changed: got %d, want %d", len(options), want)
					}
				}
			})
		}
	}
}
