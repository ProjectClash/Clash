package clash

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	IN "github.com/ProjectClash/Clash/listener/inbound"
	mieru "github.com/enfein/mieru/v3/pkg/protocol"
)

const mieruRelayHang = 30 * time.Second

func mieruRelayBody() []byte {
	body := make([]byte, 200<<10)
	for i := range body {
		body[i] = byte(i * 31)
	}
	return body
}

func mieruRelayFlow(t *testing.T, handshake string, body []byte, target func(conn net.Conn)) C.Conn {
	t.Helper()
	const username, password = "relay-user", "relay-password"
	limit, releases := mieru.StreamReceiveByteLimit(), mieru.ReleaseOnApplicationClose()
	mieru.SetStreamReceiveByteLimit(tunnelMieruStreamReceiveLimit)
	mieru.SetReleaseOnApplicationClose(true)
	t.Cleanup(func() {
		mieru.SetStreamReceiveByteLimit(limit)
		mieru.SetReleaseOnApplicationClose(releases)
	})

	stream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := stream.Addr().(*net.TCPAddr).Port
	server, err := IN.NewMieru(&IN.MieruOption{
		BaseOption: IN.BaseOption{
			NameStr: "relay-mieru-inbound", Listen: "127.0.0.1", Port: strconv.Itoa(port),
			ListenConfigForAPI: controlledMieruListenConfig{
				listen: func(context.Context, string, string) (net.Listener, error) { return stream, nil },
				listenPacket: func(context.Context, string, string) (net.PacketConn, error) {
					panic("unexpected Mieru packet listener for TCP transport")
				},
			},
		},
		Transport: "TCP", Users: map[string]string{username: password}, UserHintIsMandatory: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "relay-mieru-outbound", "type": "mieru", "server": "127.0.0.1", "port": port,
		"transport": "TCP", "username": username, "password": password,
		"handshake-mode": handshake, "multiplexing": "MULTIPLEXING_OFF",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request [1]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return
		}
		_, _ = conn.Write(body)
		target(conn)
	}()
	address := listener.Addr().(*net.TCPAddr).AddrPort()

	ctx, cancel := context.WithTimeout(context.Background(), mieruRelayHang)
	defer cancel()
	remote, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: address.Addr(), DstPort: address.Port()})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = remote.Close() })
	if _, err := remote.Write([]byte{'g'}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(mieruRelayHang); ; time.Sleep(10 * time.Millisecond) {
		if queued, _ := mieru.StreamReceiveQueued(); queued >= int64(len(body)) {
			break
		}
		if time.Now().After(deadline) {
			queued, sessions := mieru.StreamReceiveQueued()
			t.Fatalf("the answer never reached the session: %d bytes queued in %d sessions", queued, sessions)
		}
	}
	time.Sleep(300 * time.Millisecond)
	return remote
}

type mieruRelayApp struct {
	sends    []byte
	sent     bool
	taking   chan struct{}
	received bytes.Buffer
}

func (a *mieruRelayApp) Read(b []byte) (int, error) {
	if a.sent || len(a.sends) == 0 {
		return 0, io.EOF
	}
	a.sent = true
	return copy(b, a.sends), nil
}

func (a *mieruRelayApp) Write(b []byte) (int, error) {
	<-a.taking
	return a.received.Write(b)
}

func (a *mieruRelayApp) Close() error                     { return nil }
func (a *mieruRelayApp) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (a *mieruRelayApp) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (a *mieruRelayApp) SetDeadline(time.Time) error      { return nil }
func (a *mieruRelayApp) SetReadDeadline(time.Time) error  { return nil }
func (a *mieruRelayApp) SetWriteDeadline(time.Time) error { return nil }

func (a *mieruRelayApp) relayed(t *testing.T, remote C.Conn) []byte {
	t.Helper()
	a.taking = make(chan struct{})
	done := make(chan struct{})
	go func() {
		N.Relay(a, remote)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	close(a.taking)
	select {
	case <-done:
	case <-time.After(mieruRelayHang):
		t.Fatal("the relay did not end")
	}
	return a.received.Bytes()
}

func TestAMieruFlowItsAppHalfClosedStillDeliversWhatHadArrived(t *testing.T) {
	body := mieruRelayBody()
	for _, handshake := range []string{"HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"} {
		t.Run(handshake, func(t *testing.T) {
			remote := mieruRelayFlow(t, handshake, body, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			if got := (&mieruRelayApp{}).relayed(t, remote); !bytes.Equal(got, body) {
				t.Fatalf("the app that half-closed got %d of the %d bytes the node had delivered", len(got), len(body))
			}
		})
	}
}

func TestAMieruFlowTheNodeClosedStillDeliversWhatHadArrivedWhenTheAppWrites(t *testing.T) {
	body := mieruRelayBody()
	for _, handshake := range []string{"HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"} {
		t.Run(handshake, func(t *testing.T) {
			remote := mieruRelayFlow(t, handshake, body, func(net.Conn) {})
			if got := (&mieruRelayApp{sends: []byte("more")}).relayed(t, remote); !bytes.Equal(got, body) {
				t.Fatalf("the app that wrote after the node closed got %d of the %d bytes the node had delivered", len(got), len(body))
			}
		})
	}
}

func TestAMieruDialThatFailsItsHandshakeLeavesNoSessionBehind(t *testing.T) {
	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "silent-mieru-outbound", "type": "mieru", "server": "127.0.0.1", "port": silent.Addr().(*net.TCPAddr).Port,
		"transport": "TCP", "username": "u", "password": "p",
		"handshake-mode": "HANDSHAKE_STANDARD", "multiplexing": "MULTIPLEXING_OFF",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	for deadline := time.Now().Add(mieruRelayHang); ; time.Sleep(10 * time.Millisecond) {
		if _, sessions := mieru.StreamReceiveQueued(); sessions == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sessions of earlier tests are still live")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), mieruRelayHang)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 9})
	if err == nil {
		_ = conn.Close()
		t.Fatal("the dial to a server that never answers succeeded")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, sessions := mieru.StreamReceiveQueued(); sessions == 0 {
			return
		}
		if time.Now().After(deadline) {
			_, sessions := mieru.StreamReceiveQueued()
			t.Fatalf("the failed dial left %d session(s) open", sessions)
		}
	}
}
