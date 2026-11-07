package clash

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/callback"
	clashnet "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

func TestASplicedConnectionLetsGoOfItsReadAheadBuffer(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() { _, _ = server.Write([]byte("GET / HTTP/1.1\r\n")) }()
	buffered := clashnet.NewBufferedConn(client)
	if _, err := buffered.Peek(4); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if !drainSpliceCaches([]clashnet.SpliceCache{{Reader: buffered}}, &out) {
		t.Fatal("the drain failed")
	}
	if out.Len() == 0 {
		t.Fatal("what the sniffer read ahead did not go out first")
	}
	if buffered.Reader() != nil {
		t.Fatal("the read-ahead buffer is still held after the splice drained it")
	}
}

func TestAGroupsMemberIsSplicedOnceItsFirstWriteIsMade(t *testing.T) {
	client, peer := tcpPairForSplice(t)
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	fired := false
	member := callback.NewFirstWriteCallBackConn(outbound.NewConn(client, outbound.NewDirect()), func(error) { fired = true })
	tracker := statistic.NewTCPTracker(member, statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	t.Cleanup(func() { _ = tracker.Close() })
	if _, ok := spliceRemote(tracker); ok {
		t.Fatal("a member not yet written to was spliceable; the test proves nothing")
	}

	app, appPeer := net.Pipe()
	t.Cleanup(func() { _ = app.Close(); _ = appPeer.Close() })
	go func() { _, _ = appPeer.Write([]byte("\\x16\\x03\\x01 client hello")) }()
	sniffed := clashnet.NewBufferedConn(app)
	if _, err := sniffed.Peek(4); err != nil {
		t.Fatal(err)
	}
	right, ok, drained := spliceRemoteWithReadAhead([]clashnet.SpliceCache{{Reader: sniffed}}, tracker)
	if !ok {
		t.Fatalf("the member is still not spliceable after the read-ahead (drained %v, callback fired %v)", drained, fired)
	}
	if !drained || !fired {
		t.Fatalf("drained %v, callback fired %v; the read-ahead should be the member's first write", drained, fired)
	}
	if right.Layer != any(client) {
		t.Fatal("the splice did not reach the member's socket")
	}
}
