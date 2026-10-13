//go:build with_gvisor

package tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/waiter"
)

func gvisorQueuedSendBytes(endpoint tcpip.Endpoint) (int, bool) {
	if endpoint == nil {
		return 0, false
	}
	if queued, err := endpoint.GetSockOptInt(tcpip.SendQueueSizeOption); err == nil {
		return queued, true
	}
	if endpoint.Readiness(waiter.WritableEvents)&waiter.WritableEvents != 0 {
		return 0, true
	}
	return int(endpoint.SocketOptions().GetSendBufferSize()), true
}

func (c *abortableGVisorConn) QueuedSendBytes() (int, bool) {
	return gvisorQueuedSendBytes(c.endpoint)
}

type gvisorTCPConn struct {
	*gonet.TCPConn
	endpoint tcpip.Endpoint
}

func (c *gvisorTCPConn) QueuedSendBytes() (int, bool) { return gvisorQueuedSendBytes(c.endpoint) }

func (c *gvisorTCPConn) SetLinger(sec int) error {
	if sec == 0 {
		c.endpoint.Abort()
	}
	return nil
}

func (c *gvisorTCPConn) Upstream() any { return c.TCPConn }
