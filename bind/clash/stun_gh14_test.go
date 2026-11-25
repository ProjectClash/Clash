package clash

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

func TestSTUNThroughACustomNamedDirectOutboundCountsAsDirect(t *testing.T) {
	cfg, err := config.Parse([]byte(`
proxies:
  - name: "🇨🇳 直连 | 双栈"
    type: direct
proxy-groups:
  - name: "直连"
    type: select
    proxies: ["🇨🇳 直连 | 双栈"]
rules:
  - MATCH,直连
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 2048)
		n, from, err := server.ReadFrom(buffer)
		if err != nil {
			return
		}
		_, _ = server.WriteTo(buffer[:n], from)
	}()
	destination := server.LocalAddr().(*net.UDPAddr).AddrPort()
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: destination.Addr(), DstPort: destination.Port()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := cfg.Proxies["直连"].ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tracker := statistic.NewUDPTracker(pc, statistic.DefaultManager, metadata, nil, 0, 0, false)
	counted := newCountedSTUNPacketConn(tracker, tracker.Info())
	defer counted.Close()
	if counted.bucket != statistic.BucketDirect {
		t.Errorf("bucket = %d, want direct (%d)", counted.bucket, statistic.BucketDirect)
	}

	payload := make([]byte, 1200)
	before := statistic.DefaultManager.OutboundTotals()
	if _, err := counted.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = counted.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := counted.ReadFrom(make([]byte, 2048)); err != nil {
		t.Fatalf("read: %v", err)
	}
	after := statistic.DefaultManager.OutboundTotals()
	if up, down := after.Direct.Up-before.Direct.Up, after.Direct.Down-before.Direct.Down; up < 1200 || down < 1200 {
		t.Errorf("direct bucket moved %d/%d, want at least 1200/1200", up, down)
	}
}
