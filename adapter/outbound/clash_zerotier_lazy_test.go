//go:build !no_zerotier

package outbound

import (
	"fmt"
	"io"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestParsedZeroTierNodesHoldNoFrameQueue(t *testing.T) {
	home := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(home) })
	clashRequireParsedNodesHoldNothing(t, "zerotier", func(i int) (io.Closer, error) {
		return NewZeroTier(ZeroTierOption{Name: fmt.Sprint("zerotier-", i), Network: "8056c2e21c000001"})
	})
}

func TestZeroTierFrameQueueIsMadeOnceAtStart(t *testing.T) {
	home := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(home) })
	node, err := NewZeroTier(ZeroTierOption{Name: "zerotier", Network: "8056c2e21c000001"})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if node.frameCh != nil {
		t.Fatal("parsing made the frame queue")
	}
	node.clashMakeFrameQueue()
	queue := node.frameCh
	if cap(queue) != zeroTierFrameQueueSize {
		t.Fatalf("the queue holds %d frames, upstream's %d", cap(queue), zeroTierFrameQueueSize)
	}
	node.clashMakeFrameQueue()
	if node.frameCh != queue {
		t.Fatal("a second start replaced the queue the drain goroutine reads")
	}
}
