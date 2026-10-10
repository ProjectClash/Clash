package mipstack

import "testing"

func TestTCPReceiveAfterCloseRequestsReset(t *testing.T) {
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("late")
	c.appendReadBuffer(payload, payload, 0)
	if !c.takeAbortReset() {
		t.Fatal("new data received after Close must request a reset")
	}
}

func TestTCPPromotedReadAccountingBeforeClose(t *testing.T) {
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("ready")
	c.outOfOrderUnread.Store(int64(len(payload)))
	c.appendTCPReadBuffer(payload, payload, 0, true)
	buffer := make([]byte, len(payload))
	if n, err := c.Read(buffer); n != len(payload) || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.takeAbortReset() {
		t.Fatal("fully consumed promoted data was misclassified as unread")
	}
}

func TestTCPOutOfOrderAfterCloseRequestsReset(t *testing.T) {
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("late")
	var pieces []tcpReceivedPiece
	var count int
	c.storeTCPOutOfOrder(100, 32, 101, payload, payload, false, &pieces, &count)
	if !c.takeAbortReset() {
		t.Fatal("new out-of-order data received after Close must request a reset")
	}
}

func TestTCPPartialPromotionKeepsUndeliveredBytesAccounted(t *testing.T) {
	c := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	c.receiveCapacity = 5
	c.readBuffer.append([]byte("ready"))
	payload := []byte("late")
	c.outOfOrderUnread.Store(int64(len(payload)))
	if n := c.appendTCPReadBuffer(payload, payload, 0, true); n != 0 {
		t.Fatalf("full buffer accepted %d bytes", n)
	}
	buffer := make([]byte, 5)
	if n, err := c.Read(buffer); n != 5 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !c.takeAbortReset() {
		t.Fatal("unpromoted bytes were omitted from Close's unread accounting")
	}
}
