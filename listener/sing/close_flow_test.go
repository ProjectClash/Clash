package sing

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
)

type sessionConn struct {
	first  chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newSessionConn() *sessionConn {
	conn := &sessionConn{first: make(chan struct{}, 1), closed: make(chan struct{})}
	conn.first <- struct{}{}
	return conn
}

func (c *sessionConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case <-c.first:
		_, _ = buffer.Write([]byte("stun"))
		return M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.1:3478")), nil
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func (c *sessionConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *sessionConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *sessionConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *sessionConn) SetDeadline(time.Time) error      { return nil }
func (c *sessionConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sessionConn) SetWriteDeadline(time.Time) error { return nil }

type refusingTunnel struct {
	C.Tunnel
	refused chan C.UDPPacket
}

func (r refusingTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) {
	packet.Drop()
	C.CloseUDPFlow(packet)
	if r.refused != nil {
		r.refused <- packet
	}
}

func TestARefusedFlowEndsItsSessionsReader(t *testing.T) {
	tunnel := refusingTunnel{refused: make(chan C.UDPPacket, 1)}
	handler := &ListenerHandler{ListenerConfig: ListenerConfig{Tunnel: tunnel, Type: C.TUN}}
	conn := newSessionConn()
	returned := make(chan error, 1)
	go func() {
		returned <- handler.NewPacketConnection(context.Background(), conn, M.Metadata{
			Source:      M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.18.0.1:40000")),
			Destination: M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.1:3478")),
		})
	}()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("the reader of a refused flow ended with %v, want a quiet end", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the reader of a refused flow is still reading its session")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("the refused flow's session was left open")
	}
	if refused := <-tunnel.refused; !C.UDPFlowEnded(refused) {
		t.Fatal("a datagram of the ended flow says its flow is still there")
	}
}

func TestARefusedSessionLeavesAServerInboundsConnectionOpen(t *testing.T) {
	handler := &ListenerHandler{ListenerConfig: ListenerConfig{Tunnel: refusingTunnel{}, Type: C.SHADOWSOCKS}}
	conn := newSessionConn()
	returned := make(chan error, 1)
	go func() {
		returned <- handler.NewPacketConnection(context.Background(), conn, M.Metadata{
			Source:      M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.7:40000")),
			Destination: M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.1:3478")),
		})
	}()
	select {
	case <-returned:
		t.Fatal("a refused session ended a server inbound's connection")
	case <-time.After(300 * time.Millisecond):
	}
	_ = conn.Close()
	<-returned
}

func TestADatagramWithNoSessionHasNoFlowToClose(t *testing.T) {
	(&packet{buff: buf.New()}).CloseFlow()
}
