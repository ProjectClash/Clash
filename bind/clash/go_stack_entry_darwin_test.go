package clash

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/sing"
	"github.com/ProjectClash/Clash/listener/sing_tun"
	tun "github.com/metacubex/sing-tun"
	D "github.com/miekg/dns"
	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	"golang.org/x/sys/unix"
)

type goStackThroughTheListener struct {
	options gotun.StackOptions
	device  *gotun.MemoryTun
	tunnel  *recordingTunnel
	toApp   chan []byte
}

func startGoStackThroughTheListener(t *testing.T, mtu int, dnsHijack ...netip.AddrPort) *goStackThroughTheListener {
	t.Helper()
	return startGoStackThroughTheListenerWith(t, mtu, nil, dnsHijack...)
}

func startGoStackThroughTheListenerWith(t *testing.T, mtu int, loopback []netip.Addr, dnsHijack ...netip.AddrPort) *goStackThroughTheListener {
	t.Helper()
	entry := &goStackThroughTheListener{tunnel: &recordingTunnel{}, toApp: make(chan []byte, 4096)}
	entry.device = gotun.NewMemoryTun(gotun.MemoryTunOptions{MTU: mtu, Outbound: func(packets []*gobuf.Buffer) {
		for _, packet := range packets {
			select {
			case entry.toApp <- append([]byte(nil), packet.Bytes()...):
			default:
			}
		}
	}})
	standInForAUtun(t)
	previous := goStackOpenTunOnce
	goStackOpenTunOnce = func(options gotun.Options) (gotun.Tun, error) {
		_ = unix.Close(options.FileDescriptor)
		return entry.device, nil
	}
	t.Cleanup(func() { goStackOpenTunOnce = previous })
	previousNewGo := goStackNewGo
	goStackNewGo = func(options gotun.StackOptions) (*gotun.Go, error) {
		entry.options = options
		return previousNewGo(options)
	}
	t.Cleanup(func() { goStackNewGo = previousNewGo })

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]); _ = unix.Close(pair[1]) })
	inner, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: entry.tunnel, Type: C.TUN, UDPTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	prefix, prefix6 := netip.MustParsePrefix("198.18.0.1/16"), netip.MustParsePrefix("fdfe:dcba:9876::1/64")
	stack, err := newGoStack(sing_tun.GoStackOptions{
		Context:    context.Background(),
		Device:     utunStandIn{fd: pair[0]},
		TunOptions: tun.Options{Name: "utun-test", Inet4Address: []netip.Prefix{prefix}, Inet6Address: []netip.Prefix{prefix6}, MTU: uint32(mtu), Inet4LoopbackAddress: loopback},
		Handler:    &sing_tun.ListenerHandler{ListenerHandler: inner, DnsAddrPorts: dnsHijack, Inet4Address: []netip.Prefix{prefix}, Inet6Address: []netip.Prefix{prefix6}},
		UDPTimeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("newGoStack: %v", err)
	}
	if err := stack.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return entry
}

func (e *goStackThroughTheListener) send(t *testing.T, from, to netip.AddrPort, payload []byte) {
	t.Helper()
	if _, err := e.device.Write(ipv4UDP(from, to, payload)); err != nil {
		t.Fatal(err)
	}
}

func (e *goStackThroughTheListener) receive(t *testing.T) (netip.AddrPort, []byte, bool) {
	t.Helper()
	for {
		select {
		case packet := <-e.toApp:
			if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != unix.IPPROTO_UDP {
				continue
			}
			from := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[12:16])), binary.BigEndian.Uint16(packet[20:22]))
			return from, packet[28:], true
		case <-time.After(2 * time.Second):
			return netip.AddrPort{}, nil, false
		}
	}
}

func standInForAUtun(t *testing.T) {
	t.Helper()
	previous := goStackDescriptorIsUtun
	goStackDescriptorIsUtun = func(int) bool { return true }
	t.Cleanup(func() { goStackDescriptorIsUtun = previous })
}

type utunStandIn struct {
	tun.Tun
	fd int
}

func (u utunStandIn) UtunFileDescriptor() int { return u.fd }

type recordingTunnel struct {
	mu      sync.Mutex
	packets []recordedDatagram
	count   int
	drop    bool
}

type recordedDatagram struct {
	session     string
	destination string
	size        int
	packet      C.UDPPacket
}

func (r *recordingTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) { _ = conn.Close() }
func (r *recordingTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	if r.drop {
		packet.Drop()
		return
	}
	r.packets = append(r.packets, recordedDatagram{
		session: packet.LocalAddr().String(), destination: metadata.RemoteAddress(), size: len(packet.Data()), packet: packet,
	})
}
func (r *recordingTunnel) NatTable() C.NatTable { return nil }

func (r *recordingTunnel) waitFor(t *testing.T, count int) []recordedDatagram {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		got := append([]recordedDatagram(nil), r.packets...)
		r.mu.Unlock()
		if len(got) >= count || time.Now().After(deadline) {
			time.Sleep(100 * time.Millisecond)
			r.mu.Lock()
			got = append([]recordedDatagram(nil), r.packets...)
			r.mu.Unlock()
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAGoStackUDPSocketIsOneSessionWhateverItSendsTo(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 1500)
	app := netip.MustParseAddrPort("198.18.0.3:50000")
	stun := netip.MustParseAddrPort("203.0.113.9:3478")
	peer := netip.MustParseAddrPort("198.51.100.7:27015")
	entry.send(t, app, stun, []byte("binding request"))
	entry.send(t, app, peer, []byte("hello peer"))
	got := entry.tunnel.waitFor(t, 2)
	if len(got) != 2 {
		t.Fatalf("the tunnel got %d datagrams, want 2: %+v", len(got), got)
	}
	if got[0].session != got[1].session {
		t.Fatalf("one socket became two sessions: %s for %s, %s for %s", got[0].session, got[0].destination, got[1].session, got[1].destination)
	}

	stranger := netip.MustParseAddrPort("192.0.2.44:40000")
	if _, err := got[0].packet.WriteBack([]byte("punch"), net.UDPAddrFromAddrPort(stranger)); err != nil {
		t.Fatalf("WriteBack: %v", err)
	}
	from, payload, ok := entry.receive(t)
	if !ok {
		t.Fatalf("the reply from %s never reached the app: the session takes only the peers it sent to", stranger)
	}
	if from != stranger || string(payload) != "punch" {
		t.Fatalf("the app got %q from %s, want %q from %s", payload, from, "punch", stranger)
	}
}

func TestAHijackedDNSQueryIsAnsweredWhateverTheSocketSentFirst(t *testing.T) {
	dns := netip.MustParseAddrPort("198.18.0.2:53")
	game := netip.MustParseAddrPort("203.0.113.9:27015")
	for _, order := range [][]netip.AddrPort{{dns, game}, {game, dns}} {
		t.Run(order[0].String()+" first", func(t *testing.T) {
			entry := startGoStackThroughTheListener(t, 1500, dns)
			app := netip.MustParseAddrPort("198.18.0.3:50001")
			for _, to := range order {
				payload := []byte("game")
				if to == dns {
					payload = dnsQuery(t, 0x5151)
				}
				entry.send(t, app, to, payload)
			}
			got := entry.tunnel.waitFor(t, 1)
			if len(got) != 1 || got[0].destination != game.String() {
				t.Fatalf("the tunnel got %+v, want the game packet alone", got)
			}
			for {
				from, payload, ok := entry.receive(t)
				if !ok {
					t.Fatal("the DNS query was not answered")
				}
				if from == dns && len(payload) >= 2 && binary.BigEndian.Uint16(payload) == 0x5151 {
					return
				}
			}
		})
	}
}

func TestAGoStackDatagramReachesTheTunnelWhole(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 65535)
	payload := make([]byte, 20000)
	for i := range payload {
		payload[i] = byte(i)
	}
	entry.send(t, netip.MustParseAddrPort("198.18.0.3:50002"), netip.MustParseAddrPort("203.0.113.9:4500"), payload)
	got := entry.tunnel.waitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("the tunnel got %d datagrams, want 1", len(got))
	}
	if got[0].size != len(payload) {
		t.Fatalf("a %d-byte datagram reached the tunnel as %d bytes", len(payload), got[0].size)
	}
}

func dnsQuery(t *testing.T, id uint16) []byte {
	t.Helper()
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	query.Id = id
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestAnIdleGoStackUDPSessionHoldsNoReadBuffer(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 1500)
	entry.tunnel.drop = true
	inUse := func() uint64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapInuse + stats.StackInuse
	}
	time.Sleep(200 * time.Millisecond)
	before := inUse()
	const sessions = 1000
	to := netip.MustParseAddrPort("203.0.113.9:27015")
	for i := 0; i < sessions; i++ {
		entry.send(t, netip.AddrPortFrom(netip.MustParseAddr("198.18.0.3"), uint16(20000+i)), to, []byte("hello"))
		if i%50 == 49 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entry.tunnel.mu.Lock()
		count := entry.tunnel.count
		entry.tunnel.mu.Unlock()
		if count >= sessions {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entry.tunnel.mu.Lock()
	count := entry.tunnel.count
	entry.tunnel.mu.Unlock()
	if count < sessions {
		t.Fatalf("only %d of %d sessions reached the tunnel", count, sessions)
	}
	time.Sleep(200 * time.Millisecond)
	perSession := float64(inUse()-before) / sessions / 1024
	t.Logf("%.1f KiB in use per idle session", perSession)
	if perSession > 16 {
		t.Fatalf("an idle go stack UDP session costs %.1f KiB, want at most %d: its reader holds a buffer", perSession, 16)
	}
}

func TestAFlowTheTunnelRefusesIsAnsweredWithICMP(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 1500)
	app := netip.MustParseAddrPort("198.18.0.3:50003")
	quic := netip.MustParseAddrPort("203.0.113.9:443")
	expectUnreachable := func(what string) {
		t.Helper()
		deadline := time.After(2 * time.Second)
		for {
			select {
			case packet := <-entry.toApp:
				if len(packet) < 20+8+28 || packet[0]>>4 != 4 || packet[9] != unix.IPPROTO_ICMP {
					continue
				}
				icmp := packet[20:]
				quoted := icmp[8:]
				quotedTo := netip.AddrPortFrom(netip.AddrFrom4([4]byte(quoted[16:20])), binary.BigEndian.Uint16(quoted[22:24]))
				quotedFrom := netip.AddrPortFrom(netip.AddrFrom4([4]byte(quoted[12:16])), binary.BigEndian.Uint16(quoted[20:22]))
				from := netip.AddrFrom4([4]byte(packet[12:16]))
				if icmp[0] != 3 || icmp[1] != 3 || quotedTo != quic || quotedFrom != app || from != quic.Addr() {
					t.Fatalf("%s: the app got ICMP type %d code %d from %s about %s -> %s, want port unreachable from %s about %s -> %s",
						what, icmp[0], icmp[1], from, quotedFrom, quotedTo, quic.Addr(), app, quic)
				}
				return
			case <-deadline:
				t.Fatalf("%s: the app was never told the flow cannot be carried", what)
			}
		}
	}
	entry.send(t, app, quic, []byte("quic initial"))
	got := entry.tunnel.waitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("the tunnel got %d datagrams, want 1", len(got))
	}
	if err := C.ReportUDPUnreachable(got[0].packet); err != nil {
		t.Fatalf("ReportUDPUnreachable: %v", err)
	}
	expectUnreachable("the first datagram")

	if _, err := got[0].packet.WriteBack([]byte("reply"), net.UDPAddrFromAddrPort(quic)); err != nil {
		t.Fatal(err)
	}
	if from, _, ok := entry.receive(t); !ok || from != quic {
		t.Fatalf("the reply did not reach the app (%s)", from)
	}
	entry.send(t, app, quic, []byte("after the reply"))
	later := entry.tunnel.waitFor(t, 2)
	if len(later) != 2 {
		t.Fatalf("the tunnel got %d datagrams, want 2", len(later))
	}
	if err := C.ReportUDPUnreachable(later[1].packet); err != nil {
		t.Fatalf("ReportUDPUnreachable: %v", err)
	}
	expectUnreachable("a datagram after a reply")
}

func TestAFlowTheTunnelRefusesOverIPv6IsAnsweredWithICMPv6(t *testing.T) {
	entry := startGoStackThroughTheListener(t, 1500)
	app := netip.MustParseAddrPort("[fdfe:dcba:9876::2]:50004")
	quic := netip.MustParseAddrPort("[2001:db8::9]:443")
	if _, err := entry.device.Write(ipv6UDP(app, quic, []byte("quic initial"))); err != nil {
		t.Fatal(err)
	}
	got := entry.tunnel.waitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("the tunnel got %d datagrams, want 1", len(got))
	}
	if err := C.ReportUDPUnreachable(got[0].packet); err != nil {
		t.Fatalf("ReportUDPUnreachable: %v", err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case packet := <-entry.toApp:
			if len(packet) < 40+8+48 || packet[0]>>4 != 6 || packet[6] != unix.IPPROTO_ICMPV6 {
				continue
			}
			icmp := packet[40:]
			quoted := icmp[8:]
			quotedFrom := netip.AddrPortFrom(netip.AddrFrom16([16]byte(quoted[8:24])), binary.BigEndian.Uint16(quoted[40:42]))
			quotedTo := netip.AddrPortFrom(netip.AddrFrom16([16]byte(quoted[24:40])), binary.BigEndian.Uint16(quoted[42:44]))
			from := netip.AddrFrom16([16]byte(packet[8:24]))
			if icmp[0] != 1 || icmp[1] != 4 || quotedFrom != app || quotedTo != quic || from != quic.Addr() {
				t.Fatalf("the app got ICMPv6 type %d code %d from %s about %s -> %s, want port unreachable from %s about %s -> %s",
					icmp[0], icmp[1], from, quotedFrom, quotedTo, quic.Addr(), app, quic)
			}
			return
		case <-deadline:
			t.Fatal("the app was never told the flow cannot be carried")
		}
	}
}

func ipv6UDP(from, to netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, 48+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], uint16(8+len(payload)))
	packet[6], packet[7] = unix.IPPROTO_UDP, 64
	source, destination := from.Addr().As16(), to.Addr().As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	binary.BigEndian.PutUint16(packet[40:], from.Port())
	binary.BigEndian.PutUint16(packet[42:], to.Port())
	binary.BigEndian.PutUint16(packet[44:], uint16(8+len(payload)))
	copy(packet[48:], payload)
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(packet[8:40])
	sum += uint32(8 + len(payload))
	sum += unix.IPPROTO_UDP
	add(packet[40:])
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[46:], checksum)
	return packet
}
