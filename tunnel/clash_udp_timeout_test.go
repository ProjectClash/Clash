package tunnel

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

func TestAUDPFlowsTimeoutIsSingBoxsForWhatItIs(t *testing.T) {
	for _, c := range []struct {
		name     string
		datagram []byte
		port     uint16
		want     time.Duration
	}{
		{"a STUN request to Google's STUN port", stunBindingRequest(8), 19302, 10 * time.Second},
		{"anything to the STUN port", []byte("hello"), 3478, 10 * time.Second},
		{"DNS", []byte("hello"), 53, 10 * time.Second},
		{"NTP", []byte("hello"), 123, 10 * time.Second},
		{"anything to 443, QUIC's port", []byte("hello"), 443, 30 * time.Second},
		{"a QUIC Initial on another port", quicInitial(quicVersion1, 0), 8443, 30 * time.Second},
		{"a DTLS ClientHello on a media port", dtlsClientHello(), 5004, 30 * time.Second},
		{"a game's datagram", []byte("hello"), 27015, 0},
	} {
		if got := UDPProtocolTimeout(c.datagram, c.port); got != c.want {
			t.Errorf("%s: timeout %v, want %v", c.name, got, c.want)
		}
		want := c.want
		if want == 0 {
			want = udpTimeout
		}
		if got := udpSessionTimeout(classifyDatagram(c.datagram), c.datagram, c.port); got != want {
			t.Errorf("%s: the tunnel's session waits %v, want %v", c.name, got, want)
		}
	}
	if got := classifyDatagram(dtlsClientHello()); got != "" {
		t.Errorf("a DTLS record is classified %q for PROTOCOL rules, want nothing", got)
	}
}

func dtlsClientHello() []byte {
	return []byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0}
}

type deadlineConn struct {
	nothingPacketConn
	deadlines chan time.Duration
	closed    chan struct{}
	once      sync.Once
}

func newDeadlineConn() *deadlineConn {
	return &deadlineConn{deadlines: make(chan time.Duration, 16), closed: make(chan struct{})}
}

func (c *deadlineConn) SetReadDeadline(deadline time.Time) error {
	select {
	case c.deadlines <- time.Until(deadline):
	default:
	}
	return nil
}

func (c *deadlineConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	<-c.closed
	return nil, nil, nil, io.EOF
}

func (c *deadlineConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type datagramPacket struct {
	keyedPacket
	data []byte
}

func (p datagramPacket) Data() []byte { return p.data }

func TestAUDPSessionWaitsAsLongAsItsProtocolSays(t *testing.T) {
	for _, c := range []struct {
		name     string
		datagram []byte
		port     uint16
		srcPort  int
		want     time.Duration
	}{
		{"a STUN request", stunBindingRequest(8), 19302, 40301, 10 * time.Second},
		{"a game's datagram", []byte("hello"), 27015, 40302, udpTimeout},
	} {
		conn := newDeadlineConn()
		proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
			return conn, nil
		}}
		withVerdictTunnel(t, "out", proxy)
		metadata := tunFlowTo("192.0.2.1")
		metadata.NetWork = C.UDP
		metadata.DstPort = c.port
		handleUDPConn(C.NewPacketAdapter(datagramPacket{newKeyedPacket(c.srcPort), c.datagram}, metadata))
		for seen := 0; seen < 2; seen++ {
			select {
			case got := <-conn.deadlines:
				if got > c.want || got < c.want-2*time.Second {
					t.Errorf("%s: the session waits %v for an answer, want %v", c.name, got, c.want)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s: the session set %d of its two waits", c.name, seen)
			}
		}
		_ = conn.Close()
	}
}
