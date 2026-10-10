//go:build with_gvisor

package tun

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type gvisorDeferredRequest struct {
	request *tcp.ForwarderRequest
	stackDone <-chan struct{}
}

func (r gvisorDeferredRequest) accept(ctx context.Context) (net.Conn, error) {
	var wq waiter.Queue
	finished := make(chan struct{})
	var handshakeOver atomic.Bool
	interrupt := func() {
		if handshakeOver.Load() {
			return
		}
		wq.Notify(wq.Events())
	}
	go func() {
		select {
		case <-r.stackDone:
		case <-ctx.Done():
		case <-finished:
			return
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			interrupt()
			select {
			case <-finished:
				return
			case <-ticker.C:
			}
		}
	}()
	acceptStarted := time.Now()
	endpoint, err := r.request.CreateEndpoint(&wq)
	handshakeOver.Store(true)
	close(finished)
	if err != nil {
		noteDeferredCompletion(fmt.Sprintf("handshake with the client not completed after %s: %s", time.Since(acceptStarted).Round(time.Millisecond), err))
		r.request.Complete(true)
		return nil, gonet.TranslateNetstackError(err)
	}
	r.request.Complete(false)
	if took := time.Since(acceptStarted); took > time.Second {
		deferredStats.completedLate.Add(1)
		noteDeferredCompletion(fmt.Sprintf("handshake with the client completed only after %s: a SYN-ACK retransmission was needed", took.Round(time.Millisecond)))
	}
	configureForwardedTCPEndpoint(endpoint)
	return &abortableGVisorConn{TCPConn: gonet.NewTCPConn(&wq, endpoint), endpoint: endpoint}, nil
}

type abortableGVisorConn struct {
	*gonet.TCPConn
	endpoint tcpip.Endpoint
}

func (c *abortableGVisorConn) SetLinger(sec int) error {
	if sec != 0 {
		return nil
	}
	c.endpoint.Abort()
	return nil
}

func (c *abortableGVisorConn) Upstream() any { return c.TCPConn }

func (r gvisorDeferredRequest) reject() error {
	r.request.Complete(true)
	return nil
}

func (r gvisorDeferredRequest) done() <-chan struct{} { return nil }

func newGVisorLazyConn(ctx context.Context, request *tcp.ForwarderRequest, stackDone <-chan struct{}, local, remote net.Addr) *deferredConn {
	return newDeferredConn(ctx, gvisorDeferredRequest{request: request, stackDone: stackDone}, stackDone, local, remote)
}
