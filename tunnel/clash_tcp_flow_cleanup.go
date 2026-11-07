package tunnel

import (
	"context"
	"net"
	"sync"

	C "github.com/ProjectClash/Clash/constant"
)

type tcpFlowCleanup struct {
	slot   bool
	conn   net.Conn
	cancel context.CancelFunc
	remote C.Conn
	peek   *sync.Mutex
}

func (c *tcpFlowCleanup) run() {
	if c.slot {
		defer releaseTCPConnectionSlot()
	}
	if c.conn != nil {
		defer func() { _ = c.conn.Close() }()
	}
	if c.cancel != nil {
		defer c.cancel()
	}
	if c.remote != nil {
		defer func() { _ = c.remote.Close() }()
	}
	if c.peek != nil {
		c.peek.Unlock()
	}
}
