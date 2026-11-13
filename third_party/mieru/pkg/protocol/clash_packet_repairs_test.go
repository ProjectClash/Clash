package protocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
)

func clashTestOpeningPacketSession(t *testing.T) *Session {
	t.Helper()
	block, err := cipher.BlockCipherFromPassword([]byte(t.Name()), true)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	s := NewSession(1, true, 1400, nil, nil)
	s.conn = &PacketUnderlay{baseUnderlay: *newBaseUnderlay(true, 1400, nil), conn: conn, serverAddr: peer.LocalAddr(), block: block}
	s.transportProtocol = common.PacketTransport
	s.remoteAddr = peer.LocalAddr()
	s.forwardStateTo(sessionAttached)
	return s
}

func clashTestServerData(seq uint32, payload []byte) *segment {
	seg := testDataSegment(1, seq, payload, common.PacketTransport)
	seg.metadata.(*dataAckStruct).protocol = uint8(dataServerToClient)
	return seg
}

func TestAClientPacketSessionTheServerSendsDataToIsOpen(t *testing.T) {
	for _, c := range []struct {
		name string
		on   bool
		open bool
	}{
		{"repaired", true, true},
		{"as shipped", false, false},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetPacketRepairs, c.on)
			session := clashTestOpeningPacketSession(t)
			if err := session.input(clashTestServerData(0, []byte("payload"))); err != nil {
				t.Fatal(err)
			}
			if open := session.isState(sessionEstablished); open != c.open {
				t.Fatalf("a session opening that received the server's data is open: %v, want %v", open, c.open)
			}
		})
	}
	clashTestSet(t, SetPacketRepairs, true)
	session := clashTestOpeningPacketSession(t)
	ack := clashTestServerData(0, nil)
	ack.metadata.(*dataAckStruct).protocol = uint8(ackServerToClient)
	if err := session.input(ack); err != nil {
		t.Fatal(err)
	}
	if session.isState(sessionEstablished) {
		t.Fatal("a session opening that received the server's acknowledgement is open; only data opens it")
	}
}

func TestAPeersCloseThatLeavesDataBehindEndsTheReadAsBroken(t *testing.T) {
	for _, c := range []struct {
		name     string
		on       bool
		closeSeq uint32
		want     error
	}{
		{"a gap, repaired", true, 5, io.ErrUnexpectedEOF},
		{"no gap, repaired", true, 3, io.EOF},
		{"a gap, as shipped", false, 5, io.EOF},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetPacketRepairs, c.on)
			session, _, _ := newTestPacketSession(t)
			for seq := uint32(0); seq < 3; seq++ {
				if err := session.input(clashTestServerData(seq, []byte("abc"))); err != nil {
					t.Fatal(err)
				}
			}
			closing := &segment{
				metadata: &sessionStruct{
					baseStruct: baseStruct{protocol: uint8(closeSessionRequest)},
					sessionID:  1,
					seq:        c.closeSeq,
					statusCode: uint8(statusOK),
				},
				transport: common.PacketTransport,
			}
			if err := session.input(closing); err != nil {
				t.Fatal(err)
			}
			_ = session.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := io.ReadAll(readerWithEOF{session})
			if !bytes.Equal(got, []byte("abcabcabc")) || !errors.Is(err, c.want) {
				t.Fatalf("read %q, %v; want the nine bytes that arrived, then %v", got, err, c.want)
			}
		})
	}
}

type readerWithEOF struct{ s *Session }

func (r readerWithEOF) Read(b []byte) (int, error) {
	n, err := r.s.Read(b)
	if err == io.EOF {
		return n, errEOFSeen
	}
	return n, err
}

var errEOFSeen = &eofSeen{}

type eofSeen struct{}

func (*eofSeen) Error() string { return "EOF" }

func (*eofSeen) Is(target error) bool { return target == io.EOF }

func clashTestLossyRelay(t *testing.T, target *net.UDPAddr, drop func(n, size int) bool, back *atomic.Bool, listen ...net.IP) *net.UDPAddr {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if len(listen) > 0 {
		ip = listen[0]
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	var upstreams sync.Map
	t.Cleanup(func() {
		relay.Close()
		upstreams.Range(func(_, v any) bool { v.(*net.UDPConn).Close(); return true })
	})
	go func() {
		buf := make([]byte, 65536)
		counts := map[string]int{}
		for {
			k, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			key := from.String()
			counts[key]++
			n := counts[key]
			upstream, ok := upstreams.Load(key)
			if !ok {
				conn, err := net.DialUDP("udp", nil, target)
				if err != nil {
					t.Errorf("the relay could not reach %v for a new client: %v", target, err)
					continue
				}
				upstream = conn
				upstreams.Store(key, conn)
				go func(conn *net.UDPConn, to *net.UDPAddr) {
					reply := make([]byte, 65536)
					for {
						k, err := conn.Read(reply)
						if err != nil {
							return
						}
						if back != nil && back.Load() {
							continue
						}
						_, _ = relay.WriteToUDP(reply[:k], to)
					}
				}(conn, from)
			}
			if !drop(n, k) {
				_, _ = upstream.(*net.UDPConn).Write(buf[:k])
			}
		}
	}()
	return relay.LocalAddr().(*net.UDPAddr)
}

func clashTestPacketPair(t *testing.T, cut *atomic.Bool) (client *Mux, accepted chan net.Conn) {
	t.Helper()
	port, err := common.UnusedUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	address := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	server := NewMux(false).SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, common.PacketTransport, address, nil)})
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	accepted = make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	target := address
	if cut != nil {
		target = clashTestLossyRelay(t, address, func(int, int) bool { return cut.Load() }, cut)
	}
	client = NewMux(true).
		SetClientUserNamePassword("xiaochitang", cipher.HashPassword([]byte("kuiranbudong"), []byte("xiaochitang"))).
		SetClientMultiplexFactor(0).
		SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, common.PacketTransport, nil, target)})
	t.Cleanup(func() { client.Close() })
	return client, accepted
}

func clashTestPacketDial(t *testing.T, client *Mux) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clashTestHang)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestOurOwnCloseDoesNotEndTheReadAsBroken(t *testing.T) {
	clashTestSet(t, SetPacketRepairs, true)
	client, accepted := clashTestPacketPair(t, nil)
	four := make([]byte, 4)
	for i := 0; i < 20; i++ {
		conn := clashTestPacketDial(t, client)
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		server := <-accepted
		if _, err := io.ReadFull(server, four); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Write([]byte("pong")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(clashTestHang))
		if _, err := io.ReadFull(conn, four); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
		_ = conn.SetReadDeadline(time.Now().Add(clashTestHang))
		if _, err := conn.Read(four); err != io.EOF {
			t.Fatalf("round %d: a read after our own close, everything read, ended with %v", i, err)
		}
		_ = server.Close()
	}
}

func TestAfterOurCloseNoGapIsJudged(t *testing.T) {
	clashTestSet(t, SetPacketRepairs, true)
	for _, past := range []uint32{1, 5} {
		session, _, _ := newTestPacketSession(t)
		session.closeRequested.Store(true)
		closing := &segment{
			metadata: &sessionStruct{
				baseStruct: baseStruct{protocol: uint8(closeSessionRequest)},
				sessionID:  session.id,
				seq:        session.nextRecv.Load() + past,
				statusCode: uint8(statusOK),
			},
			transport: common.PacketTransport,
		}
		session.notePeerClose(closing)
		if session.bounds.peerLeftData.Load() {
			t.Fatalf("after our close a close request %d past what arrived was taken for a gap", past)
		}
	}
}
