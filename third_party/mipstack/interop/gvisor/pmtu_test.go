package gvisorinterop_test

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mipstack"
)

func TestPathMTUDiscoveryInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, nextHopMTU := range interopPathMTUsForFamily(family) {
			nextHopMTU := nextHopMTU
			t.Run(family.name+"/"+interopMTUName(nextHopMTU), func(t *testing.T) {
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500, gvisorMTU: nextHopMTU, forwarding: true,
				})
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				target := netipAddrPort(family.forwardAddress, 46001)
				netConnection, err := network.mipstack.DialUDP(ctx, family.udpNetwork, netip.AddrPort{}, target)
				if err != nil {
					t.Fatalf("dial mipstack PMTU probe socket: %v", err)
				}
				connection := netConnection.(*mipstack.UDPConn)
				defer connection.Close()
				if err = connection.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
					t.Fatalf("set mipstack PMTU socket deadline: %v", err)
				}
				if err = connection.SetPathMTUDiscovery(mipstack.PathMTUDiscoveryDo); err != nil {
					t.Fatalf("enable mipstack PMTU discovery: %v", err)
				}

				headerSize := 28
				if family.mipstackAddress.Is6() {
					headerSize = 48
				}
				fittingSize := int(nextHopMTU) - headerSize
				oversized := patternedPayload(fittingSize+1, 241)
				written, err := connection.Write(oversized)
				if err != nil || written != len(oversized) {
					t.Fatalf("write initial oversized PMTU datagram: n=%d, error=%v", written, err)
				}
				if _, err = connection.Read(make([]byte, 1)); err == nil {
					t.Fatal("read after gVisor PMTU error succeeded")
				}
				var networkError mipstack.ICMPError
				if !errors.As(err, &networkError) {
					t.Fatalf("mipstack PMTU error = %T %v, want ICMPError", err, err)
				}
				wantType, wantCode := byte(3), byte(4)
				if family.mipstackAddress.Is6() {
					wantType, wantCode = 2, 0
				}
				if networkError.Reporter != family.gvisorAddress || networkError.Type != wantType || networkError.Code != wantCode ||
					networkError.QuotedSource != family.mipstackAddress || networkError.QuotedTarget != family.forwardAddress {
					t.Fatalf("mipstack PMTU ICMP error = reporter %v, type/code %d/%d, MTU %d, quote %v -> %v", networkError.Reporter,
						networkError.Type, networkError.Code, networkError.MTU, networkError.QuotedSource, networkError.QuotedTarget)
				}
				if family.mipstackAddress.Is6() && networkError.MTU == 0 {
					if pathMTU, pathErr := network.mipstack.PathMTU(family.forwardAddress); pathErr != nil || pathMTU != 1500 {
						t.Fatalf("mipstack accepted invalid zero IPv6 PMTU: MTU=%d, error=%v", pathMTU, pathErr)
					}
					t.Skip("pinned gVisor emits an RFC 4443 Packet Too Big message with MTU zero")
				}
				if networkError.MTU != nextHopMTU {
					t.Fatalf("mipstack PMTU error MTU = %d, want %d", networkError.MTU, nextHopMTU)
				}
				if pathMTU, pathErr := network.mipstack.PathMTU(family.forwardAddress); pathErr != nil || pathMTU != int(nextHopMTU) {
					t.Fatalf("mipstack learned PMTU = %d, error=%v; want %d", pathMTU, pathErr, nextHopMTU)
				}
				if _, err = connection.Write(oversized); !errors.Is(err, syscall.EMSGSIZE) {
					t.Fatalf("write above learned PMTU = %v, want EMSGSIZE", err)
				}
				fitting := patternedPayload(fittingSize, 251)
				if written, err = connection.Write(fitting); err != nil || written != len(fitting) {
					t.Fatalf("write below learned PMTU: n=%d, error=%v", written, err)
				}
				if info := connection.Info(); info.PathMTU != int(nextHopMTU) || info.ICMPErrors != 1 {
					t.Fatalf("mipstack UDP PMTU info = %+v", info)
				}
			})
		}
	}
}

func interopPathMTUsForFamily(family interopFamily) []uint32 {
	if family.mipstackAddress.Is4() {
		return []uint32{68, 576, 1280, 1420}
	}
	return []uint32{1280, 1420}
}
