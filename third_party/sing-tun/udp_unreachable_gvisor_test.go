//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ UDPUnreachableReporter = (*UDPBackWriter)(nil)

func TestGVisorStackReportsADatagramUnreachable(t *testing.T) {
	for _, pair := range [][2]string{{"172.19.0.2", "8.8.8.8"}, {"fdfe:dcba:9876::1", "2001:db8::10"}} {
		t.Run(pair[0], func(t *testing.T) {
			handler := newUnreachableHandler()
			s, ep := gvisorDoorStack(t, handler)
			app := netip.AddrPortFrom(netip.MustParseAddr(pair[0]), 12345)
			remote := netip.AddrPortFrom(netip.MustParseAddr(pair[1]), 443)
			id := stack.TransportEndpointID{
				LocalAddress: AddressFromAddr(remote.Addr()), LocalPort: remote.Port(),
				RemoteAddress: AddressFromAddr(app.Addr()), RemotePort: app.Port(),
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("hello"))})
			defer pkt.DecRef()
			if !NewUDPForwarder(context.Background(), s, handler).HandlePacket(id, pkt) {
				t.Fatal("the datagram must be handled")
			}
			if err := handler.writer(t).ReportUnreachable(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out := ep.ReadContext(ctx)
			if out == nil {
				t.Fatal("nothing was written towards the app")
			}
			defer out.DecRef()
			view := stack.PayloadSince(out.NetworkHeader())
			defer view.Release()
			assertPortUnreachable(t, view.AsSlice(), app, remote)
		})
	}
}
