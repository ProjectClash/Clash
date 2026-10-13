package outbound

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)


type pipeOutbound struct {
	*Base
	mu      sync.Mutex
	open    []net.Conn
	entered chan struct{}
	gate    chan struct{}
}

func newPipeOutbound(name string) *pipeOutbound {
	return &pipeOutbound{Base: NewBase(BaseOption{Name: name, Addr: "127.0.0.1:9", Type: C.Shadowsocks, UDP: true})}
}

func (o *pipeOutbound) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	client, server := net.Pipe()
	go func() { _, _ = io.Copy(server, server) }()
	o.mu.Lock()
	o.open = append(o.open, client, server)
	o.mu.Unlock()
	return NewConn(client, o), nil
}

func (o *pipeOutbound) ReleaseSessions() bool {
	if o.entered != nil {
		close(o.entered)
		<-o.gate
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, c := range o.open {
		_ = c.Close()
	}
	o.open = nil
	return true
}

type resettingOutbound struct {
	*Base
	pipes *pipeOutbound
}

func newResettingOutbound(name string) *resettingOutbound {
	return &resettingOutbound{
		Base:  NewBase(BaseOption{Name: name, Addr: "127.0.0.1:9", Type: C.Hysteria2, UDP: true}),
		pipes: newPipeOutbound(name),
	}
}

func (o *resettingOutbound) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return o.pipes.DialContext(ctx, metadata)
}

func (o *resettingOutbound) ResetNetwork() { o.pipes.ReleaseSessions() }

func echoes(t *testing.T, c net.Conn) error {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	reply := make([]byte, 4)
	_, err := io.ReadFull(c, reply)
	return err
}

func TestASharedOutboundIsNotReleasedUnderANewHolder(t *testing.T) {
	first := newPipeOutbound("shared")
	var builds []*pipeOutbound
	build := func(string, C.Dialer, C.Tunnel, string) (ProxyAdapter, error) {
		o := newPipeOutbound("shared")
		if len(builds) == 0 {
			o = first
		}
		builds = append(builds, o)
		return o, nil
	}
	parsed := func() ProxyAdapter {
		node, ok := NewSingleCatalogNode(newPipeOutbound("shared"), "config", "airport", nil, nil, build)
		if !ok {
			t.Fatal("no catalog node")
		}
		return NewAutoCloseProxyAdapter(node)
	}
	old, refreshed := parsed(), parsed()
	t.Cleanup(func() { _ = old.Close(); _ = refreshed.Close() })
	metadata := &C.Metadata{Host: "example.net", DstPort: 443}
	conn, err := old.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	first.entered, first.gate = make(chan struct{}), make(chan struct{})
	released := make(chan bool)
	go func() { released <- ReleaseUserSessionIfIdle(old, time.Now().Add(time.Hour), 0) }()
	<-first.entered
	newConn, err := refreshed.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer newConn.Close()
	close(first.gate)
	<-released
	if err := echoes(t, newConn); err != nil {
		t.Fatalf("the refreshed node's connection: %v", err)
	}
}

func TestAReadKeepsTheMappedStoreUntilItCopied(t *testing.T) {
	if os.Getenv("CLASH_MAPPED_READ_CHILD") == "1" {
		mappedReadChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAReadKeepsTheMappedStoreUntilItCopied$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CLASH_MAPPED_READ_CHILD=1", "CLASH_MAPPED_READ_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "read after collection: ok") {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func mappedReadChild(t *testing.T) {
	defer func() { catalogRecordRead = nil }()
	for i := 0; i < 3; i++ {
		read, collected := mappedNodeRead(t)
		if read != "127.0.0.1:9" {
			t.Fatalf("read %q", read)
		}
		if !collected {
			t.Log("the store was not collected during the read")
		}
	}
	os.Stdout.WriteString("read after collection: ok\n")
}

// mappedNodeRead parses one node into a mapped store and reads it as the node's last use, the
// collector running between taking the record and copying from it. It reports whether the
// store's cleanup ran during the read (it may not, once reads keep the store alive).
//
//go:noinline
func mappedNodeRead(t *testing.T) (string, bool) {
	cleaned := make(chan struct{}, 1)
	collected := false
	catalogRecordRead = func() {
		for i := 0; i < 10 && !collected; i++ {
			runtime.GC()
			select {
			case <-cleaned:
				collected = true
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	store := NewNodeStore("airport", nil, nil, nil)
	node, ok := NewCatalogNode(newPipeOutbound("mapped"), strings.Repeat("c", 64<<10), store)
	if !ok {
		t.Fatal("no catalog node")
	}
	if err := store.Seal(os.Getenv("CLASH_MAPPED_READ_DIR")); err != nil {
		t.Fatal(err)
	}
	runtime.AddCleanup(store, func(c chan struct{}) { c <- struct{}{} }, cleaned)
	store = nil
	read := lastRead(node)
	return read, collected
}

//go:noinline
func lastRead(node ProxyAdapter) string { return node.Addr() }

func TestAProbeOutboundGoesAfterAReleaseThatHeldTheNode(t *testing.T) {
	var built []*resettingOutbound
	build := func(string, C.Dialer, C.Tunnel, string) (ProxyAdapter, error) {
		o := newResettingOutbound("probed")
		built = append(built, o)
		return o, nil
	}
	node, _ := NewSingleCatalogNode(newResettingOutbound("probed"), "probe config", "airport", nil, nil, build)
	wrapped := NewAutoCloseProxyAdapter(node)
	t.Cleanup(func() { _ = wrapped.Close() })
	before := NodeCatalogOutbounds()
	conn, err := wrapped.DialContext(dialer.WithDialKind(context.Background(), dialer.DialKindProbe), &C.Metadata{Host: "example.net", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	use := wrapped.(*autoCloseProxyAdapter).use
	use.mu.Lock()
	use.conns--
	node.(*catalogNode).afterUse()
	use.mu.Unlock()
	t.Cleanup(func() { _ = conn; built[0].ResetNetwork() })
	if NodeCatalogOutbounds() != before+1 {
		t.Fatal("the probe's outbound went while the record was held; the race this tests did not happen")
	}
	ReleaseProbedSession(wrapped)
	deadline := time.Now().Add(time.Second)
	for NodeCatalogOutbounds() != before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if NodeCatalogOutbounds() != before {
		t.Fatal("the probe's outbound stayed after the release ended")
	}
}

func TestProbesOfAReleasingOutboundShareOneOutbound(t *testing.T) {
	builds := 0
	build := func(string, C.Dialer, C.Tunnel, string) (ProxyAdapter, error) {
		builds++
		return newPipeOutbound("device"), nil
	}
	node, _ := NewSingleCatalogNode(newPipeOutbound("device"), "device config", "airport", nil, nil, build)
	wrapped := NewAutoCloseProxyAdapter(node)
	t.Cleanup(func() { _ = wrapped.Close() })
	probe := dialer.WithDialKind(context.Background(), dialer.DialKindProbe)
	metadata := &C.Metadata{Host: "example.net", DstPort: 443}
	for i := 0; i < 2; i++ {
		conn, err := wrapped.DialContext(probe, metadata)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		ReleaseProbedSession(wrapped)
	}
	conn, err := wrapped.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if builds != 1 {
		t.Fatalf("two probes and a dial built %d outbounds; want one", builds)
	}
}
