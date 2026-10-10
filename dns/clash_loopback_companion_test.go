package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	D "github.com/miekg/dns"
)

type companionListenConfig struct {
	companion *countingPacketConn
}

func (companionListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, network, address)
}

func (companionListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

func (c companionListenConfig) LoopbackPacketCompanions(_ context.Context, network, address string, primary net.PacketConn) ([]net.PacketConn, error) {
	return []net.PacketConn{c.companion}, nil
}

type countingPacketConn struct {
	net.PacketConn
	reads atomic.Int64
}

func (c *countingPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.reads.Add(1)
	}
	return n, addr, err
}

type answeringService struct{}

func (answeringService) ServeMsg(_ context.Context, r *D.Msg) (*D.Msg, error) {
	m := new(D.Msg)
	m.SetReply(r)
	return m, nil
}

var _ C.InboundListenConfig = companionListenConfig{}

func TestADNSListenersLoopbackCompanionIsServed(t *testing.T) {
	companionSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	companion := &countingPacketConn{PacketConn: companionSocket}
	free, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	primaryAddr := free.LocalAddr().String()
	_ = free.Close()
	ReCreateServer(primaryAddr, companionListenConfig{companion: companion}, answeringService{})
	t.Cleanup(func() { ReCreateServer("", nil, nil) })

	client := &D.Client{Net: "udp", Timeout: 2 * time.Second}
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	deadline := time.Now().Add(3 * time.Second)
	for {
		reply, _, err := client.Exchange(query, companion.LocalAddr().String())
		if err == nil && reply != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the loopback companion was never served: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if companion.reads.Load() == 0 {
		t.Fatal("the answer did not come through the companion")
	}
}
