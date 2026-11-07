package tun

import "testing"

func TestQueuedSendBytesIsWhatTheTransmitStoreHolds(t *testing.T) {
	conn := &GoConn{}
	conn.bufferedTail.Store(10_000)
	conn.sendReleased.Store(3_000)
	if queued, known := conn.QueuedSendBytes(); !known || queued != 7_000 {
		t.Fatalf("queued=%d known=%v, want 7000 and true", queued, known)
	}
	conn.sendReleased.Store(10_000)
	if queued, _ := conn.QueuedSendBytes(); queued != 0 {
		t.Fatalf("an empty store reports %d", queued)
	}
}
