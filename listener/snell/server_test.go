package snell

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/transport/snell"
)

func TestServerAnswersV1Ping(t *testing.T) {
	const psk = "snell-ping-psk"
	l, err := New(LC.SnellServer{Listen: "127.0.0.1:0", Psk: psk, Version: snell.Version1}, inbound.NewListenConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.AddrList()[0].String()

	ping := func(psk string) (byte, error) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		stream := snell.StreamConn(conn, []byte(psk), snell.Version1)
		if _, err := stream.Conn.Write([]byte{snell.Version, snell.CommandPing}); err != nil {
			t.Fatal(err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(stream.Conn, reply[:]); err != nil {
			return 0, err
		}
		return reply[0], nil
	}

	reply, err := ping(psk)
	if err != nil {
		t.Fatalf("no pong: %v", err)
	}
	if reply != snell.CommandPong {
		t.Fatalf("reply %d, want pong %d", reply, snell.CommandPong)
	}
	if _, err := ping("another-psk"); err == nil {
		t.Fatal("a ping under another PSK was answered")
	}
}
