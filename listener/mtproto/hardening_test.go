package mtproto

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	LC "github.com/ProjectClash/Clash/listener/config"
)

func TestAnInitSentAgainIsRefused(t *testing.T) {
	secret := mustSecret(t, testSecretHex)
	raw, _ := hex.DecodeString(testSecretHex)
	wire, _, _ := testClientInit(t, raw, tagIntermediate, 2)
	var cache initReplayCache
	for i, want := range []bool{true, false} {
		frame := wire
		if _, err := acceptInit(&frame, secret); err != nil {
			t.Fatal(err)
		}
		if got := cache.firstTime(&frame); got != want {
			t.Fatalf("time %d: first time %v, want %v", i+1, got, want)
		}
	}
	other, _, _ := testClientInit(t, raw, tagIntermediate, 2)
	if !cache.firstTime(&other) {
		t.Fatal("a fresh init was taken for a replay")
	}
}

func TestTheReplayCacheIsBounded(t *testing.T) {
	var cache initReplayCache
	var first [initLen]byte
	first[8] = 1
	cache.firstTime(&first)
	for i := 0; i < replayCacheSize; i++ {
		var frame [initLen]byte
		frame[9], frame[10], frame[11] = byte(i), byte(i>>8), 0xaa
		cache.firstTime(&frame)
	}
	if len(cache.keys) != replayCacheSize || !cache.firstTime(&first) {
		t.Fatalf("%d keys kept, and the oldest is still remembered", len(cache.keys))
	}
}

func TestConnectionsStillToSendTheirInitAreBounded(t *testing.T) {
	started, err := New(LC.MTProtoServer{Listen: "127.0.0.1:0", Secret: testSecretHex}, inbound.NewListenConfig(), &dialTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = started.Close() })
	listener := started.(*Listener)
	proxy := listener.AddrList()[0].(*net.TCPAddr).AddrPort()
	var silent []net.Conn
	defer func() {
		for _, c := range silent {
			_ = c.Close()
		}
	}()
	for i := 0; i < maxHandshaking; i++ {
		c, err := net.Dial("tcp", proxy.String())
		if err != nil {
			t.Fatal(err)
		}
		silent = append(silent, c)
	}
	for deadline := time.Now().Add(5 * time.Second); len(listener.handshaking) < maxHandshaking; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the listener took %d of %d silent connections", len(listener.handshaking), maxHandshaking)
		}
	}
	extra, err := net.Dial("tcp", proxy.String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection past the bound was kept")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("a connection past the bound was kept waiting, not closed")
	}
}
