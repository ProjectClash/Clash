package smux

import (
	"io"
	"testing"
	"time"
)

func TestASessionsUnreadBytesAreWhatItsStreamsHaveNotRead(t *testing.T) {
	baseBytes, baseSessions := UnreadBytes()
	client, server, err := getSmuxStreamPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, sessions := UnreadBytes(); sessions != baseSessions+2 {
		t.Fatalf("%d sessions listed, want the pair's 2 more than %d", sessions, baseSessions)
	}
	const sent = 100_000
	go func() { _, _ = server.Write(make([]byte, sent)) }()
	unread := func() int64 { bytes, _ := UnreadBytes(); return bytes - baseBytes }
	deadline := time.Now().Add(5 * time.Second)
	for unread() < sent && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := unread(); got != sent {
		t.Fatalf("%d bytes unread, want the %d the stream was sent", got, sent)
	}
	if _, err := io.ReadFull(client, make([]byte, sent)); err != nil {
		t.Fatal(err)
	}
	if got := unread(); got != 0 {
		t.Fatalf("%d bytes still unread after the stream read them all", got)
	}
	_ = client.sess.Close()
	_ = server.sess.Close()
	deadline = time.Now().Add(5 * time.Second)
	for _, sessions := UnreadBytes(); sessions != baseSessions && time.Now().Before(deadline); _, sessions = UnreadBytes() {
		time.Sleep(10 * time.Millisecond)
	}
	if _, sessions := UnreadBytes(); sessions != baseSessions {
		t.Fatalf("%d sessions listed after both closed, want %d", sessions, baseSessions)
	}
}
