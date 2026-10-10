package tuic

import (
	"testing"
	"time"
)

type resetProbeClient struct {
	Client
	closed *int
}

func (c resetProbeClient) Close()                 { *c.closed++ }
func (c resetProbeClient) OpenStreams() int64     { return 0 }
func (c resetProbeClient) LastVisited() time.Time { return time.Now() }

func TestAPoolResetClosesEveryPooledConnection(t *testing.T) {
	closed := 0
	p := &PoolClient{}
	p.tcpClients.PushBack(resetProbeClient{closed: &closed})
	p.tcpClients.PushBack(resetProbeClient{closed: &closed})
	p.udpClients.PushBack(resetProbeClient{closed: &closed})
	p.Reset()
	if closed != 3 || p.tcpClients.Len() != 0 || p.udpClients.Len() != 0 {
		t.Fatalf("closed=%d tcp=%d udp=%d, want every connection closed and the pool empty", closed, p.tcpClients.Len(), p.udpClients.Len())
	}
}
