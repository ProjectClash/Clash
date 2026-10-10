package tunnel

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

type reportingPacket struct {
	reported chan struct{}
	dropped  chan struct{}
	dropOnce sync.Once
}

func newReportingPacket() *reportingPacket {
	return &reportingPacket{reported: make(chan struct{}), dropped: make(chan struct{})}
}

func (p *reportingPacket) Data() []byte                            { return []byte("hello") }
func (p *reportingPacket) WriteBack([]byte, net.Addr) (int, error) { return 0, nil }
func (p *reportingPacket) Drop()                                   { p.dropOnce.Do(func() { close(p.dropped) }) }
func (p *reportingPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(172, 19, 0, 2), Port: 12345}
}
func (p *reportingPacket) ReportUnreachable() error { close(p.reported); return nil }

func (p *reportingPacket) settled(t *testing.T) {
	t.Helper()
	select {
	case <-p.dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("the tunnel never let go of the datagram")
	}
}

func TestAUDPFlowThatCannotBeOpenedIsReportedUnreachable(t *testing.T) {
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

	packet := newReportingPacket()
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		SrcIP:   netip.MustParseAddr("172.19.0.2"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("192.0.2.1"),
		DstPort: 443,
	}
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	select {
	case <-packet.reported:
	case <-time.After(3 * time.Second):
		t.Fatal("the app was never told its flow could not be carried")
	}
	packet.settled(t)
}

func TestReportingUnreachableOnAnInboundThatCannotIsANoOp(t *testing.T) {
	if err := C.ReportUDPUnreachable(C.NewPacketAdapter(plainPacket{}, &C.Metadata{})); err != nil {
		t.Fatal(err)
	}
}

type plainPacket struct{}

func (plainPacket) Data() []byte                            { return nil }
func (plainPacket) WriteBack([]byte, net.Addr) (int, error) { return 0, nil }
func (plainPacket) Drop()                                   {}
func (plainPacket) LocalAddr() net.Addr                     { return &net.UDPAddr{} }
