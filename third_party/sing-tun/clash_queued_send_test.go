//go:build with_gvisor

package tun

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/link/loopback"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	M "github.com/metacubex/sing/common/metadata"
)

type queuedSendReporter interface {
	QueuedSendBytes() (int, bool)
}

func loopbackPair(t *testing.T) (tcpip.Endpoint, *waiter.Queue, net.Conn) {
	t.Helper()
	s, err := NewGVisorStackWithOptions(loopback.New(), stack.NICOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	address := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	if err := s.AddProtocolAddress(DefaultNIC, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: address.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	var listenQueue waiter.Queue
	listener, tcpErr := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenQueue)
	if tcpErr != nil {
		t.Fatal(tcpErr)
	}
	t.Cleanup(listener.Close)
	if tcpErr := listener.Bind(tcpip.FullAddress{NIC: DefaultNIC, Addr: address, Port: 8080}); tcpErr != nil {
		t.Fatal(tcpErr)
	}
	if tcpErr := listener.Listen(1); tcpErr != nil {
		t.Fatal(tcpErr)
	}
	client, err := gonet.DialContextTCP(context.Background(), s, tcpip.FullAddress{NIC: DefaultNIC, Addr: address, Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
	listenQueue.EventRegister(&entry)
	defer listenQueue.EventUnregister(&entry)
	deadline := time.After(3 * time.Second)
	for {
		accepted, queue, tcpErr := listener.Accept(nil)
		if tcpErr == nil {
			t.Cleanup(accepted.Close)
			return accepted, queue, client
		}
		if _, wouldBlock := tcpErr.(*tcpip.ErrWouldBlock); !wouldBlock {
			t.Fatal(tcpErr)
		}
		select {
		case <-notify:
		case <-deadline:
			t.Fatal("the loopback connection was never accepted")
		}
	}
}

func TestGVisorConnReportsTheBytesTheAppHasNotTaken(t *testing.T) {
	endpoint, queue, client := loopbackPair(t)
	conn := &abortableGVisorConn{TCPConn: gonet.NewTCPConn(queue, endpoint), endpoint: endpoint}
	var reporter queuedSendReporter = conn
	if queued, known := reporter.QueuedSendBytes(); !known || queued != 0 {
		t.Fatalf("a connection that has sent nothing reports %d queued (known %v)", queued, known)
	}

	stop := make(chan struct{})
	writerDone := make(chan int)
	go func() {
		chunk := make([]byte, 16*1024)
		written := 0
		for {
			select {
			case <-stop:
				writerDone <- written
				return
			default:
			}
			_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			n, _ := conn.Write(chunk)
			written += n
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		queued, known := reporter.QueuedSendBytes()
		if !known {
			t.Fatal("the reading is unknown on a gVisor endpoint")
		}
		limit := int(endpoint.SocketOptions().GetSendBufferSize())
		if queued >= limit {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the app read nothing for three seconds and the reading is %d of a %d B buffer", queued, limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	written := <-writerDone

	if _, err := io.ReadFull(client, make([]byte, written)); err != nil {
		t.Fatalf("draining the app side: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		queued, _ := reporter.QueuedSendBytes()
		if queued == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the app read everything and the reading stayed %d", queued)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGVisorUndeferredConnCarriesTheQueuedReading(t *testing.T) {
	h := &gvisorQueuedHandler{conns: make(chan net.Conn, 1)}
	_, ep := gvisorDoorStack(t, h)
	injectSYN(t, ep)
	injectACK(t, ep, readReply(t, ep))
	select {
	case conn := <-h.conns:
		defer conn.Close()
		reporter, ok := conn.(queuedSendReporter)
		if !ok {
			t.Fatalf("the undeferred flow is a %T with no queued-bytes reading", conn)
		}
		if _, known := reporter.QueuedSendBytes(); !known {
			t.Fatal("the undeferred flow's reading is unknown")
		}
		if _, ok := conn.(interface{ Upstream() any }); !ok {
			t.Fatal("the wrapper hides the gonet connection from casts")
		}
		linger, ok := conn.(interface{ SetLinger(int) error })
		if !ok {
			t.Fatalf("the undeferred flow %T cannot be reset", conn)
		}
		if err := linger.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		reply := readReply(t, ep)
		if reply.Flags()&header.TCPFlagRst == 0 {
			t.Fatalf("SetLinger(0) sent flags %v, want a reset", reply.Flags())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the handler was never given the flow")
	}
}

type gvisorQueuedHandler struct {
	doorHandler
	conns chan net.Conn
}

func (h *gvisorQueuedHandler) DeferHandshake(string, M.Socksaddr, M.Socksaddr) bool { return false }

func (h *gvisorQueuedHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	h.conns <- c
	return nil
}

func TestGVisorConnReportsAPartlyFilledBuffer(t *testing.T) {
	endpoint, queue, client := loopbackPair(t)
	conn := &abortableGVisorConn{TCPConn: gonet.NewTCPConn(queue, endpoint), endpoint: endpoint}
	chunk := make([]byte, 16*1024)
	for i := 0; i < 64; i++ {
		_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := conn.Write(chunk); err != nil {
			break
		}
	}
	full := int(endpoint.SocketOptions().GetSendBufferSize())
	if _, err := io.ReadFull(client, make([]byte, 8*1024)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		queued, known := conn.QueuedSendBytes()
		if known && queued > 0 && queued < full {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the app took 8 KiB of a full %d B buffer the reading is %d (known %v); want what is still queued", full, queued, known)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
