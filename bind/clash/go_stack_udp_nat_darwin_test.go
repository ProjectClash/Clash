package clash

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/listener/sing_tun"
	"github.com/metacubex/sing/common/buf"
	D "github.com/miekg/dns"
	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	goM "github.com/sagernet/sing/common/metadata"
	goN "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

type udpSessionRecorder struct {
	mu           sync.Mutex
	destinations []string
}

func (r *udpSessionRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.destinations)
}
func (r *udpSessionRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.destinations...)
}

func (r *udpSessionRecorder) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) gotun.FlowVerdict {
	return gotun.FlowVerdict{Action: gotun.ActionAccept}
}
func (r *udpSessionRecorder) NewDNSPacket([]byte, goM.Socksaddr, goM.Socksaddr, goN.PacketWriter) {}
func (r *udpSessionRecorder) NewConnectionEx(_ context.Context, conn net.Conn, _, _ goM.Socksaddr, _ goN.CloseHandlerFunc) {
	_ = conn.Close()
}
func (r *udpSessionRecorder) NewPacketConnectionEx(_ context.Context, conn goN.PacketConn, _, destination goM.Socksaddr, _ goN.CloseHandlerFunc) {
	r.mu.Lock()
	r.destinations = append(r.destinations, destination.String())
	r.mu.Unlock()
	go func() {
		for {
			buffer := gobuf.NewPacket()
			_, err := conn.ReadPacket(buffer)
			buffer.Release()
			if err != nil {
				return
			}
		}
	}()
}

func ipv4UDP(from, to netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:16], from.Addr().AsSlice())
	copy(packet[16:20], to.Addr().AsSlice())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(packet[20:], from.Port())
	binary.BigEndian.PutUint16(packet[22:], to.Port())
	binary.BigEndian.PutUint16(packet[24:], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func TestTheGoStackTakesACongestionControllerWrittenInAnyCase(t *testing.T) {
	for _, written := range []string{"", "bbr", "BBR", " Cubic ", "reno", "RENO", "bbr3", "BBR3"} {
		t.Run(written, func(t *testing.T) {
			device := gotun.NewMemoryTun(gotun.MemoryTunOptions{MTU: 1500, Outbound: func([]*gobuf.Buffer) {}})
			stack, err := gotun.NewGo(gotun.StackOptions{
				Context:              context.Background(),
				Tun:                  device,
				TunOptions:           gotun.Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}},
				UDPTimeout:           time.Minute,
				Handler:              &udpSessionRecorder{},
				TCPCongestionControl: goStackCongestion(written),
			})
			if err != nil {
				t.Fatalf("%q builds no go stack: %v", written, err)
			}
			_ = stack.Close()
		})
	}
}

func TestADatagramTooLargeForTheReaderIsNotHandedOverCut(t *testing.T) {
	big := make([]byte, 3000)
	for i := range big {
		big[i] = 'x'
	}
	inner := &queuedPackets{packets: [][]byte{big, []byte("next")}}
	conn := &goPacketConn{PacketConn: inner}
	buffer := buf.NewSize(2048)
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if got := string(buffer.Bytes()); got != "next" {
		t.Fatalf("the reader got %d bytes (%q...), want the next datagram whole and the oversized one dropped",
			buffer.Len(), got[:min(len(got), 8)])
	}
}

type queuedPackets struct {
	goN.PacketConn
	packets [][]byte
}

func (q *queuedPackets) ReadPacket(buffer *gobuf.Buffer) (goM.Socksaddr, error) {
	if len(q.packets) == 0 {
		return goM.Socksaddr{}, io.EOF
	}
	packet := q.packets[0]
	q.packets = q.packets[1:]
	_, err := buffer.Write(packet)
	return goM.ParseSocksaddr("203.0.113.9:53"), err
}

func TestAHijackedDNSFlowIsTheGoStacksOwnHijack(t *testing.T) {
	door := &fakeDoor{}
	handler := goStackHandler{
		handler: &sing_tun.ListenerHandler{DnsAddrPorts: []netip.AddrPort{netip.MustParseAddrPort("198.18.0.2:53")}},
		door:    door,
	}
	app := netip.MustParseAddrPort("198.18.0.1:50000")
	if verdict := handler.JudgeFlow(unix.IPPROTO_UDP, app, netip.MustParseAddrPort("198.18.0.2:53"), nil); verdict.Action != gotun.ActionHijackDNS {
		t.Fatalf("a query to the hijacked address is judged %v, want the go stack's DNS hijack", verdict.Action)
	}
	if len(door.asked) != 0 {
		t.Fatalf("a hijacked query asked the door (%v); the listener answers DNS before it asks", door.asked)
	}
	if verdict := handler.JudgeFlow(unix.IPPROTO_UDP, app, netip.MustParseAddrPort("203.0.113.9:27015"), nil); verdict.Action == gotun.ActionHijackDNS {
		t.Fatal("game traffic was judged a DNS hijack")
	}
	if len(door.asked) != 1 {
		t.Fatalf("other UDP did not ask the door (%v)", door.asked)
	}
}

func TestAHijackedDNSQueryIsAnsweredThroughItsWriter(t *testing.T) {
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	writer := &dnsReplyRecorder{replies: make(chan dnsReply, 1)}
	dnsAddress := goM.ParseSocksaddr("198.18.0.2:53")
	goStackHandler{}.NewDNSPacket(payload, goM.ParseSocksaddr("198.18.0.1:50000"), dnsAddress, writer)
	for i := range payload {
		payload[i] = 0
	}
	select {
	case reply := <-writer.replies:
		answer := new(D.Msg)
		if err := answer.Unpack(reply.bytes); err != nil {
			t.Fatalf("the reply is not a DNS message: %v", err)
		}
		if answer.Id != query.Id {
			t.Fatalf("the reply answers ID %d, the query was %d", answer.Id, query.Id)
		}
		if reply.from != dnsAddress {
			t.Fatalf("the reply comes from %s, want the DNS address %s", reply.from, dnsAddress)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply was written")
	}
}

type dnsReply struct {
	bytes []byte
	from  goM.Socksaddr
}

type dnsReplyRecorder struct{ replies chan dnsReply }

func (r *dnsReplyRecorder) WritePacket(buffer *gobuf.Buffer, destination goM.Socksaddr) error {
	defer buffer.Release()
	r.replies <- dnsReply{bytes: append([]byte(nil), buffer.Bytes()...), from: destination}
	return nil
}

func TestTheGoStacksHijackedQueriesEndWithTheStack(t *testing.T) {
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	from, dnsAddress := goM.ParseSocksaddr("198.18.0.1:50000"), goM.ParseSocksaddr("198.18.0.2:53")
	answered := func(dns *goStackDNS) bool {
		writer := &dnsReplyRecorder{replies: make(chan dnsReply, 1)}
		goStackHandler{dns: dns}.NewDNSPacket(payload, from, dnsAddress, writer)
		select {
		case <-writer.replies:
			return true
		case <-time.After(500 * time.Millisecond):
			return false
		}
	}
	if !answered(&goStackDNS{ctx: context.Background()}) {
		t.Fatal("a query to an open stack was not answered")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if answered(&goStackDNS{ctx: ctx}) {
		t.Fatal("a query was answered after the stack closed")
	}
}
