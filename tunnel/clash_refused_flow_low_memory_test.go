//go:build with_low_memory

package tunnel

import (
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

type closingPacket struct {
	keyedPacket
	flowClosed chan struct{}
}

func (p closingPacket) CloseFlow() { close(p.flowClosed) }

func TestAFullUDPQuotaEndsTheRefusedFlow(t *testing.T) {
	fillUDPSlots(t)
	withSessionTable(t)
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		return nothingPacketConn{}, nil
	}}
	withVerdictTunnel(t, "out", proxy)
	packet := closingPacket{newKeyedPacket(40401), make(chan struct{})}
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	select {
	case <-packet.flowClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("a flow refused by the quota kept its stack session")
	}
	select {
	case <-packet.reported:
	default:
		t.Fatal("the refused flow was ended before the app was answered unreachable")
	}
}
