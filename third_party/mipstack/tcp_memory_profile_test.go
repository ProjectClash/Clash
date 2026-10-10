package mipstack

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
	"time"
	"unsafe"
)

func memoryTestProfiles() []struct {
	name string
	tcp  TCPSocketDefaults
} {
	return []struct {
		name string
		tcp  TCPSocketDefaults
	}{
		{"default", TCPSocketDefaults{}},
		{"bounded", TCPSocketDefaults{ReceiveBuffer: 32 << 10, MaximumReceiveBuffer: 256 << 10, SendBuffer: 32 << 10, MaximumSendBuffer: 512 << 10}},
		{"clash-ios-envelope", TCPSocketDefaults{ReceiveBuffer: 32 << 10, MaximumReceiveBuffer: 128 << 10, SendBuffer: 32 << 10, MaximumSendBuffer: 128 << 10}},
	}
}

func BenchmarkTCPMemoryProfileStream(b *testing.B) {
	for _, profile := range memoryTestProfiles() {
		b.Run(profile.name, func(b *testing.B) { benchmarkTCPMemoryStream(b, profile.tcp) })
	}
}

func benchmarkTCPMemoryStream(b *testing.B, defaults TCPSocketDefaults) {
	conn, _, _ := benchmarkTCPProfileConnection(b, defaults, defaultMTU, false, RXChecksumOffload{})
	if err := conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x57}, 1<<20)
	response := make([]byte, len(payload))
	b.SetBytes(int64(2 * len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan error, 1)
		go func() { _, err := conn.Write(payload); done <- err }()
		if _, err := io.ReadFull(conn, response); err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(payload, response) {
			b.Fatal("payload mismatch")
		}
	}
}

func memoryTestStack(t testing.TB, defaults TCPSocketDefaults) *Stack {
	t.Helper()
	s, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, TCP: defaults})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func warmMemoryTestConn(c *TCPConn) {
	payload := make([]byte, 1200)
	for i := 0; i < 2; i++ {
		c.sendBuffer.append(payload)
		c.sendBuffer.acknowledge(len(payload))
		c.readBuffer.append(append([]byte(nil), payload...))
		c.readBuffer.read(payload, len(payload), c.inbound.recyclePayload)
		c.inbound.enqueue(tcpSegment{})
		c.inbound.dequeue()
	}
}

func idleMemoryTestBacking(c *TCPConn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inbound.mu.Lock()
	defer c.inbound.mu.Unlock()
	return cap(c.sendBuffer.spare) + cap(c.readBuffer.chunks)*int(unsafe.Sizeof([]byte{})) +
		cap(c.inbound.spare) + cap(c.inbound.segments)*int(unsafe.Sizeof(tcpSegment{}))
}

func TestTCPMemoryProfileBaseline(t *testing.T) {
	for _, profile := range memoryTestProfiles() {
		t.Run(profile.name, func(t *testing.T) {
			s := memoryTestStack(t, profile.tcp)
			const count = 1000
			total := 0
			for i := 0; i < count; i++ {
				c := newTCPConn(s, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				warmMemoryTestConn(c)
				total += idleMemoryTestBacking(c)
			}
			t.Logf("%d drained connections: retained backing=%d B (%d B/connection), excluding connection structs and runtime", count, total, total/count)
		})
	}
}

func BenchmarkTCPMemoryProfileChurn(b *testing.B) {
	for _, profile := range memoryTestProfiles() {
		b.Run(profile.name, func(b *testing.B) {
			s := memoryTestStack(b, profile.tcp)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c := newTCPConn(s, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
				warmMemoryTestConn(c)
			}
		})
	}
}
