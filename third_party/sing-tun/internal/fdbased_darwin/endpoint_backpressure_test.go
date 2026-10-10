package fdbased

import (
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing-tun/internal/rawfile_darwin"

	"golang.org/x/sys/unix"
)

func newBridgeLikeEndpoint(t *testing.T, peerReceiveBytes int) (ep *endpoint, peer int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	if err := unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_RCVBUF, peerReceiveBytes); err != nil {
		t.Fatalf("SO_RCVBUF: %v", err)
	}
	if err := unix.SetNonblock(fds[1], true); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}
	t.Cleanup(func() { unix.Close(fds[1]) })
	link, err := New(&Options{FDs: []int{fds[0]}, MTU: 1500})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ep = link.(*endpoint)
	t.Cleanup(func() { unix.Close(fds[0]) })
	return ep, fds[1]
}

func burstOfPackets(count, size int) stack.PacketBufferList {
	var list stack.PacketBufferList
	for i := 0; i < count; i++ {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, size))})
		pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
		list.PushBack(pkt)
	}
	return list
}

func drainSlowly(t *testing.T, peer int, pause time.Duration, done <-chan struct{}) <-chan int {
	t.Helper()
	counted := make(chan int, 1)
	go func() {
		buf := make([]byte, 65536)
		read := 0
		for {
			n, err := unix.Read(peer, buf)
			switch {
			case n > 0:
				read++
				time.Sleep(pause)
				continue
			case err == unix.EAGAIN || err == unix.EWOULDBLOCK:
				select {
				case <-done:
					for {
						n, err := unix.Read(peer, buf)
						if n <= 0 || err != nil {
							counted <- read
							return
						}
						read++
					}
				default:
					time.Sleep(pause)
				}
			default:
				counted <- read
				return
			}
		}
	}()
	return counted
}

func TestEgressWaitsForABusyDrainerInsteadOfDropping(t *testing.T) {
	ResetPacketIOStats()
	ep, peer := newBridgeLikeEndpoint(t, 8*1024)
	const packets = 200
	done := make(chan struct{})
	counted := drainSlowly(t, peer, 300*time.Microsecond, done)

	list := burstOfPackets(packets, 1000)
	started := time.Now()
	written, err := ep.WritePackets(list)
	close(done)
	list.Reset()
	if err != nil {
		t.Fatalf("WritePackets: %v after %d packets", err, written)
	}
	if written != packets {
		t.Fatalf("WritePackets wrote %d of %d", written, packets)
	}
	if got := <-counted; got != packets {
		t.Fatalf("the peer received %d of %d datagrams: the writer dropped the rest", got, packets)
	}
	stats := PacketIOStatsSnapshot()
	if stats.EgressWriteWaits == 0 {
		t.Fatalf("the peer's queue holds a handful of datagrams and the drainer paused between each; the writer must have had to wait: %+v", stats)
	}
	if stats.EgressWriteErrors != 0 || stats.EgressWriteWaitExhausted != 0 {
		t.Fatalf("a drainer that is merely busy must cost waits, not drops: %+v", stats)
	}
	if stats.EgressWritePackets != packets {
		t.Fatalf("EgressWritePackets = %d, want %d", stats.EgressWritePackets, packets)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the burst took %s", elapsed)
	}
}

func TestEgressGivesUpOnAStalledDrainerWithinItsBudget(t *testing.T) {
	ResetPacketIOStats()
	ep, _ := newBridgeLikeEndpoint(t, 8*1024)
	const packets = 64
	list := burstOfPackets(packets, 1000)
	started := time.Now()
	written, err := ep.WritePackets(list)
	elapsed := time.Since(started)
	list.Reset()
	if err == nil {
		t.Fatalf("a peer nobody drains cannot take %d datagrams of 1000 bytes into 8 KiB; the write must fail (wrote %d)", packets, written)
	}
	if written == 0 {
		t.Fatal("the first datagrams fit and must be reported as written")
	}
	stats := PacketIOStatsSnapshot()
	if stats.EgressWriteWaitExhausted != 1 || stats.EgressWriteErrors != 1 {
		t.Fatalf("one packet spends the schedule and ends the batch: %+v", stats)
	}
	if stats.EgressWriteWaits == 0 {
		t.Fatalf("the schedule was not walked before giving up: %+v", stats)
	}
	if elapsed < rawfile.BufferFullWaitBudget || elapsed > 40*rawfile.BufferFullWaitBudget {
		t.Fatalf("gave up after %s; the schedule is %s", elapsed, rawfile.BufferFullWaitBudget)
	}
}
