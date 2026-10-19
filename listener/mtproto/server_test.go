package mtproto

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
)

type dialTunnel struct {
	mu       sync.Mutex
	metadata []C.Metadata
}

func (t *dialTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	t.mu.Lock()
	t.metadata = append(t.metadata, *metadata)
	t.mu.Unlock()
	defer conn.Close()
	remote, err := net.DialTimeout("tcp", metadata.RemoteAddress(), time.Second)
	if err != nil {
		return
	}
	N.Relay(conn, remote)
}

func (t *dialTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}

func (t *dialTunnel) NatTable() C.NatTable { return nil }

func (t *dialTunnel) seen() []C.Metadata {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]C.Metadata(nil), t.metadata...)
}

type fakeDC struct {
	ln    net.Listener
	reads chan dcRead
}

type dcRead struct {
	tag     [4]byte
	dc      int16
	payload []byte
}

func newFakeDC(t *testing.T, payloadLen int, reply []byte) *fakeDC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDC{ln: ln, reads: make(chan dcRead, 8)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var wire [64]byte
				if _, err := io.ReadFull(conn, wire[:]); err != nil {
					return
				}
				tag, dc, decrypt, encrypt := testServerInit(t, wire)
				payload := make([]byte, payloadLen)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}
				decrypt.XORKeyStream(payload, payload)
				f.reads <- dcRead{tag: tag, dc: dc, payload: payload}
				sealed := make([]byte, len(reply))
				encrypt.XORKeyStream(sealed, reply)
				_, _ = conn.Write(sealed)
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
	return f
}

func (f *fakeDC) addr() netip.AddrPort {
	return f.ln.Addr().(*net.TCPAddr).AddrPort()
}

func (f *fakeDC) read(t *testing.T) dcRead {
	t.Helper()
	select {
	case r := <-f.reads:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the fake DC read nothing")
		return dcRead{}
	}
}

func startTestListener(t *testing.T, secret string, tunnel C.Tunnel) netip.AddrPort {
	t.Helper()
	l, err := New(LC.MTProtoServer{Listen: "127.0.0.1:0", Secret: secret}, inbound.NewListenConfig(), tunnel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.AddrList()[0].(*net.TCPAddr).AddrPort()
}

type testClient struct {
	conn             net.Conn
	encrypt, decrypt cipher.Stream
}

func dialTestClient(t *testing.T, proxy netip.AddrPort, secret []byte, tag [4]byte, dc int16) *testClient {
	t.Helper()
	conn, err := net.Dial("tcp", proxy.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	wire, encrypt, decrypt := testClientInit(t, secret, tag, dc)
	if _, err := conn.Write(wire[:]); err != nil {
		t.Fatal(err)
	}
	return &testClient{conn: conn, encrypt: encrypt, decrypt: decrypt}
}

func (c *testClient) send(t *testing.T, plain []byte) {
	t.Helper()
	sealed := make([]byte, len(plain))
	c.encrypt.XORKeyStream(sealed, plain)
	if _, err := c.conn.Write(sealed); err != nil {
		t.Fatal(err)
	}
}

func (c *testClient) receive(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		t.Fatalf("the client read: %v", err)
	}
	c.decrypt.XORKeyStream(buf, buf)
	return buf
}

func TestServerRelaysToTheDC(t *testing.T) {
	upload := bytes.Repeat([]byte("upload "), 4096)
	reply := bytes.Repeat([]byte("reply "), 4096)
	dc := newFakeDC(t, len(upload), reply)
	useDCTable(t, []dataCenter{
		{v4: dcFamily{general: []netip.AddrPort{ap("127.0.0.1:1")}}},
		{v4: dcFamily{general: []netip.AddrPort{dc.addr()}}},
	})
	tunnel := &dialTunnel{}
	proxy := startTestListener(t, "dd"+testSecretHex, tunnel)
	secret := mustSecret(t, testSecretHex)

	for _, id := range []int16{2, -2} {
		client := dialTestClient(t, proxy, secret.key[:], tagPaddedBytes, id)
		client.send(t, upload)
		got := dc.read(t)
		if got.tag != tagPaddedBytes || got.dc != id {
			t.Fatalf("the DC read tag %x dc %d, want %x %d", got.tag, got.dc, tagPaddedBytes, id)
		}
		if !bytes.Equal(got.payload, upload) {
			t.Fatal("the DC read another payload")
		}
		if back := client.receive(t, len(reply)); !bytes.Equal(back, reply) {
			t.Fatal("the client read another reply")
		}

		seen := tunnel.seen()
		m := seen[len(seen)-1]
		if m.Type != C.MTPROTO || m.NetWork != C.TCP {
			t.Fatalf("metadata type %s network %s", m.Type, m.NetWork)
		}
		if m.DstIP != dc.addr().Addr() || m.DstPort != dc.addr().Port() || m.Host != "" {
			t.Fatalf("metadata destination %s, want %s", m.RemoteAddress(), dc.addr())
		}
		local := client.conn.LocalAddr().(*net.TCPAddr).AddrPort()
		if m.SrcIP != local.Addr() || m.SrcPort != local.Port() {
			t.Fatalf("metadata source %s, want %s", m.SourceAddress(), local)
		}
		if m.InPort != proxy.Port() {
			t.Fatalf("metadata in-port %d, want %d", m.InPort, proxy.Port())
		}
	}
}

func expectClosedWithoutReply(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.Copy(io.Discard, conn)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("the proxy kept the connection open")
	}
	if n != 0 {
		t.Fatalf("the proxy answered %d bytes", n)
	}
}

func TestServerClosesAnInvalidHandshakeWithoutReply(t *testing.T) {
	dc := newFakeDC(t, 1, []byte{1})
	useDCTable(t, []dataCenter{{v4: dcFamily{general: []netip.AddrPort{dc.addr()}}}})
	tunnel := &dialTunnel{}
	proxy := startTestListener(t, "dd"+testSecretHex, tunnel)
	secret := mustSecret(t, testSecretHex)
	other := mustSecret(t, "ffeeddccbbaa99887766554433221100")

	for _, c := range []struct {
		name   string
		secret []byte
		tag    [4]byte
		dc     int16
	}{
		{"wrong secret", other.key[:], tagPaddedBytes, 1},
		{"no secret", nil, tagPaddedBytes, 1},
		{"intermediate under a dd secret", secret.key[:], tagIntermediateBytes, 1},
		{"unknown DC", secret.key[:], tagPaddedBytes, 9},
	} {
		t.Run(c.name, func(t *testing.T) {
			client := dialTestClient(t, proxy, c.secret, c.tag, c.dc)
			client.send(t, []byte("hello"))
			expectClosedWithoutReply(t, client.conn)
		})
	}
	t.Run("short init", func(t *testing.T) {
		conn, err := net.Dial("tcp", proxy.String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write(bytes.Repeat([]byte{0x42}, 63))
		_ = conn.(*net.TCPConn).CloseWrite()
		expectClosedWithoutReply(t, conn)
	})
	if seen := tunnel.seen(); len(seen) != 0 {
		t.Fatalf("the tunnel was handed %d invalid connections", len(seen))
	}
}

func TestServerSkipsAnEndpointThatFailed(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().(*net.TCPAddr).AddrPort()
	_ = dead.Close()

	upload := []byte("ping")
	reply := []byte("pong")
	dc := newFakeDC(t, len(upload), reply)
	useDCTable(t, []dataCenter{
		{v4: dcFamily{general: []netip.AddrPort{deadAddr, dc.addr()}}},
	})
	tunnel := &dialTunnel{}
	proxy := startTestListener(t, testSecretHex, tunnel)
	secret := mustSecret(t, testSecretHex)

	first := dialTestClient(t, proxy, secret.key[:], tagIntermediateBytes, 1)
	first.send(t, upload)
	expectClosedWithoutReply(t, first.conn)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, _ := pickEndpoint(1, false); p.addr == dc.addr() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the endpoint that refused the connection was not marked")
		}
		time.Sleep(10 * time.Millisecond)
	}

	second := dialTestClient(t, proxy, secret.key[:], tagIntermediateBytes, 1)
	second.send(t, upload)
	if got := dc.read(t); !bytes.Equal(got.payload, upload) {
		t.Fatal("the DC read another payload")
	}
	if back := second.receive(t, len(reply)); !bytes.Equal(back, reply) {
		t.Fatal("the client read another reply")
	}
	seen := tunnel.seen()
	if len(seen) != 2 || seen[0].DstPort != deadAddr.Port() || seen[1].DstPort != dc.addr().Port() {
		t.Fatalf("the tunnel was handed %v", seen)
	}

	leaving := dialTestClient(t, proxy, secret.key[:], tagIntermediateBytes, 1)
	_ = leaving.conn.Close()
	time.Sleep(100 * time.Millisecond)
	if p, _ := pickEndpoint(1, false); p.addr != dc.addr() {
		t.Fatalf("a client leaving marked the endpoint: next pick %s", p.addr)
	}
}
