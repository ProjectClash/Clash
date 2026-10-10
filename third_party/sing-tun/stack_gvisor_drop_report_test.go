//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
)


func TestGVisorWindowSnapshotReportsSegmentQueueDrops(t *testing.T) {
	prior := GVisorTCPBufferBytes
	t.Cleanup(func() { GVisorTCPBufferBytes = prior })
	GVisorTCPBufferBytes = 0

	stack, err := NewGVisorStack(channel.New(8, 1500, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	report := newGVisorWindowSnapshot(stack)()
	if report.SegmentQueueDroppedTotal != 0 {
		t.Fatalf("an idle stack must report no segment-queue drops, got %d",
			report.SegmentQueueDroppedTotal)
	}
	if report.MaxBytes == 0 {
		t.Fatal("the snapshot lost the live range while gaining the drop counter")
	}
}

func TestSegmentQueueDropTotalSurvivesEndpointsWithoutTCPStats(t *testing.T) {
	prior := GVisorTCPBufferBytes
	t.Cleanup(func() { GVisorTCPBufferBytes = prior })
	GVisorTCPBufferBytes = 0

	stack, err := NewGVisorStack(channel.New(8, 1500, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	first := newGVisorWindowSnapshot(stack)()
	second := newGVisorWindowSnapshot(stack)()
	if first.SegmentQueueDroppedTotal != second.SegmentQueueDroppedTotal {
		t.Fatalf("drop totals disagree across snapshots of an idle stack: %d vs %d",
			first.SegmentQueueDroppedTotal, second.SegmentQueueDroppedTotal)
	}
	if first.TCPConnections != second.TCPConnections {
		t.Fatalf("connection counts disagree: %d vs %d", first.TCPConnections, second.TCPConnections)
	}
}
