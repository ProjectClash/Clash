package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

var errDNSRecordingNode = errors.New("dialed through the node")

type dnsRecordingNode struct {
	doorProxy
	dials atomic.Int32
}

func (n *dnsRecordingNode) IsL3Protocol(*C.Metadata) bool { return false }
func (n *dnsRecordingNode) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	n.dials.Add(1)
	return nil, errDNSRecordingNode
}
func (n *dnsRecordingNode) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	n.dials.Add(1)
	return nil, errDNSRecordingNode
}

func TestADNSDialerReachesALibrarysNode(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	node := &dnsRecordingNode{doorProxy: doorProxy{name: "wg node", typ: C.WireGuard}}
	UpdateProxiesAndRules(waitTestProxies(), nil, nil, nil, nil, testLibrary{node})
	dialer := NewDNSDialer(nil, nil, "wg node")
	ctx := context.Background()
	for _, dial := range []struct {
		name string
		run  func() error
	}{
		{"DialContext tcp", func() error { _, err := dialer.DialContext(ctx, "tcp", "10.0.0.1:53"); return err }},
		{"DialContext udp", func() error { _, err := dialer.DialContext(ctx, "udp", "10.0.0.1:53"); return err }},
		{"ListenPacket", func() error { _, err := dialer.ListenPacket(ctx, "udp", "10.0.0.1:853"); return err }},
	} {
		before := node.dials.Load()
		if err := dial.run(); !errors.Is(err, errDNSRecordingNode) {
			t.Fatalf("%s: %v, want the dial to go through the library's node", dial.name, err)
		}
		if node.dials.Load() != before+1 {
			t.Fatalf("%s: the node saw %d dials, want 1", dial.name, node.dials.Load()-before)
		}
	}
}
