package tunnel

import (
	"sync/atomic"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

type flowPacket struct {
	keyedPacket
	flowClosed chan struct{}
	ended      bool
}

func newFlowPacket(port int) flowPacket {
	return flowPacket{keyedPacket: newKeyedPacket(port), flowClosed: make(chan struct{})}
}

func (p flowPacket) CloseFlow()      { close(p.flowClosed) }
func (p flowPacket) FlowEnded() bool { return p.ended }

func TestAFlowWhoseOutboundCannotOpenEndsItsStackSession(t *testing.T) {
	oldProxies, oldProviders, oldMode := loadProxies(), loadProviders(), Mode()
	oldRules, oldSubRules, oldRuleProviders := loadRules(), loadVersion().subRules, loadRuleProviders()
	oldStatus := status.Load()
	t.Cleanup(func() {
		UpdateProxies(oldProxies, oldProviders)
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		SetMode(oldMode)
		status.Store(oldStatus)
	})
	UpdateProxies(map[string]C.Proxy{}, nil)
	UpdateRules(nil, nil, nil)
	SetMode(Rule)
	OnRunning()

	packet := newFlowPacket(40501)
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	select {
	case <-packet.flowClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("a flow whose outbound could not open kept its stack session")
	}
	select {
	case <-packet.reported:
	default:
		t.Fatal("the flow was ended before the app was answered unreachable")
	}
}

func TestADatagramFromAnEndedFlowOpensNoSession(t *testing.T) {
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		listens.Add(1)
		return nothingPacketConn{}, nil
	}}
	withVerdictTunnel(t, "out", proxy)
	packet := newFlowPacket(40502)
	packet.ended = true
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	packet.settled(t)
	if n := listens.Load(); n != 0 {
		t.Fatalf("a datagram from an ended flow opened its outbound %d time(s)", n)
	}
	key := packet.LocalAddr().String()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, left := natTable.GetOrCreate(key, newPacketSender); !left {
			natTable.Delete(key)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a datagram from an ended flow left a session in the table")
		}
	}
}

func TestAFlowWithMetadataTheTunnelCannotCarryIsEnded(t *testing.T) {
	oldStatus := status.Load()
	t.Cleanup(func() { status.Store(oldStatus) })
	OnRunning()
	packet := newFlowPacket(40503)
	handleUDPConn(C.NewPacketAdapter(packet, &C.Metadata{NetWork: C.UDP, Type: C.TUN}))
	select {
	case <-packet.flowClosed:
	default:
		t.Fatal("a flow whose metadata cannot be carried kept its stack session")
	}
}
