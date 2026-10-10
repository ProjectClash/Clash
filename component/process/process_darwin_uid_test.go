//go:build darwin

package process

import (
	"net"
	"net/netip"
	"os"
	"testing"
)


func TestDarwinLookupReturnsTheSocketOwnerUid(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if server := <-accepted; server != nil {
		defer server.Close()
	}

	local := client.LocalAddr().(*net.TCPAddr)
	address, ok := netip.AddrFromSlice(local.IP.To4())
	if !ok {
		t.Fatalf("could not read the local address back as an address: %v", local.IP)
	}

	uid, path, err := findProcessName("tcp", address, local.Port)
	if err != nil {
		t.Fatalf("findProcessName for this process's own socket: %v", err)
	}

	if want := uint32(os.Getuid()); uid != want {
		t.Fatalf("uid = %d, want %d. A hardcoded 0 here makes a UID rule for uid 0 match every "+
			"connection and a rule for any real uid match none, and nothing reports the mismatch",
			uid, want)
	}
	if path == "" {
		t.Fatal("no executable path returned; the pid read at the adjacent offset is what " +
			"cross-checks the uid offset, so an empty path means the struct layout assumption is wrong")
	}
}
