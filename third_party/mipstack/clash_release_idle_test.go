package mipstack

import (
	"testing"
)

func TestQuietConnectionsGiveBackTheirReusableStorage(t *testing.T) {
	for _, profile := range memoryTestProfiles() {
		t.Run(profile.name, func(t *testing.T) {
			s := memoryTestStack(t, profile.tcp)
			const count = 100
			conns := make([]*TCPConn, count)
			for i := range conns {
				c := newTCPConn(s, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				warmMemoryTestConn(c)
				chunk := make([]byte, tcpSendChunkMinimum)
				for j := 0; j < 2; j++ {
					c.sendBuffer.append(chunk)
					c.sendBuffer.append(chunk)
					c.sendBuffer.acknowledge(2 * len(chunk))
				}
				conns[i] = c
			}
			before := 0
			for _, c := range conns {
				before += idleMemoryTestBacking(c)
			}
			if before == 0 {
				t.Fatal("the warmed connections keep nothing to give back")
			}
			busy := conns[0]
			busyKept := idleMemoryTestBacking(busy)
			busy.sendBuffer.append([]byte("unacknowledged"))
			busy.readBuffer.append([]byte("unread"))

			spares := 0
			for _, c := range conns {
				c.inbound.mu.Lock()
				spares += cap(c.inbound.spare)
				c.inbound.mu.Unlock()
			}
			released := 0
			for _, c := range conns {
				released += c.releaseIdleBacking()
			}
			after := 0
			for _, c := range conns[1:] {
				after += idleMemoryTestBacking(c)
			}
			if after != 0 {
				t.Fatalf("quiet connections still keep %d B after the release", after)
			}
			if released < before-busyKept-spares || released > before-spares {
				t.Fatalf("released %d B of %d kept", released, before)
			}
			if busy.sendBuffer.size != len("unacknowledged") || busy.readBuffer.size != len("unread") {
				t.Fatal("the release touched data a connection still holds")
			}
			c := conns[1]
			c.sendBuffer.append(make([]byte, 1200))
			c.sendBuffer.acknowledge(1200)
			c.readBuffer.append([]byte("after"))
			got := make([]byte, 8)
			if n := c.readBuffer.read(got, len(got), c.inbound.recyclePayload); string(got[:n]) != "after" {
				t.Fatalf("read %q after the release", got[:n])
			}
			c.inbound.enqueue(tcpSegment{})
			c.inbound.dequeue()
			t.Logf("%s: %d connections kept %d B (%d B each); released %d B", profile.name, count, before, before/count, released)
		})
	}
}
