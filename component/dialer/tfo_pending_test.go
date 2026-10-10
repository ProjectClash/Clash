package dialer

import (
	"net"
	"testing"
)

func TestAFastOpenConnIsPendingUntilItHasDialled(t *testing.T) {
	conn := &tfoConn{}
	if !conn.TransportPending() {
		t.Fatal("nothing has been dialled yet")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn.Conn = client
	if conn.TransportPending() {
		t.Fatal("once the transport is there nothing is pending")
	}
}
