package tunnel

import (
	"sync/atomic"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)

func TestBlockQUICDecidesByTheOutboundTheFlowEndsAt(t *testing.T) {
	direct := doorProxy{name: "DIRECT", typ: C.Direct}
	node := doorProxy{name: "HK", typ: C.Shadowsocks}
	reject := doorProxy{name: "REJECT", typ: C.Reject}
	groupToDirect := chainProxy{doorProxy{name: "G", typ: C.Selector}, direct}
	groupToNode := chainProxy{doorProxy{name: "G", typ: C.Selector}, node}
	flow := &C.Metadata{NetWork: C.UDP, DstPort: 443}
	for name, tc := range map[string]struct {
		mode, protocol string
		proxy          C.Proxy
		blocked        bool
	}{
		"all-proxy, a node":            {C.BlockQUICAllProxy, RC.ProtocolQUIC, node, true},
		"all-proxy, a group on a node": {C.BlockQUICAllProxy, RC.ProtocolQUIC, groupToNode, true},
		"all-proxy, DIRECT":            {C.BlockQUICAllProxy, RC.ProtocolQUIC, direct, false},
		"all-proxy, a group on DIRECT": {C.BlockQUICAllProxy, RC.ProtocolQUIC, groupToDirect, false},
		"all, DIRECT":                  {C.BlockQUICAll, RC.ProtocolQUIC, direct, true},
		"all, a node":                  {C.BlockQUICAll, RC.ProtocolQUIC, node, true},
		"all, already rejected":        {C.BlockQUICAll, RC.ProtocolQUIC, reject, false},
		"all-proxy, not QUIC":          {C.BlockQUICAllProxy, RC.ProtocolSTUN, node, false},
		"off, a node":                  {"", RC.ProtocolQUIC, node, false},
	} {
		if got := quicBlocked(tc.protocol, tc.proxy, flow, tc.mode); got != tc.blocked {
			t.Errorf("%s: blocked %v, want %v", name, got, tc.blocked)
		}
	}
}

type quicPacket struct{ *reportingPacket }

func (quicPacket) Data() []byte { return quicInitial(quicVersion1, 0) }

func TestAQUICFlowToAProxyIsRefusedAndOneToDirectIsCarried(t *testing.T) {
	for _, tc := range []struct {
		typ     C.AdapterType
		refused bool
	}{{C.Shadowsocks, true}, {C.Direct, false}} {
		var listens atomic.Int32
		out := &dialProxy{doorProxy: doorProxy{name: "out", typ: tc.typ}, listen: func() (C.PacketConn, error) {
			listens.Add(1)
			return nothingPacketConn{}, nil
		}}
		withVerdictTunnel(t, "out", out)
		prevRouting := loadVersion().routing
		UpdateClashRouting(C.ClashRouting{BlockQUIC: C.BlockQUICAllProxy})
		packet := quicPacket{newReportingPacket()}
		metadata := tunFlowTo("192.0.2.1")
		metadata.NetWork, metadata.SrcPort = C.UDP, uint16(41000+int(tc.typ))
		handleUDPConn(C.NewPacketAdapter(packet, metadata))
		reported := false
		select {
		case <-packet.reported:
			reported = true
		case <-time.After(500 * time.Millisecond):
		}
		UpdateClashRouting(prevRouting)
		if reported != tc.refused || (listens.Load() == 0) != tc.refused {
			t.Errorf("%s: answered unreachable %v, outbound opened %d time(s); want refused %v", tc.typ, reported, listens.Load(), tc.refused)
		}
	}
}
