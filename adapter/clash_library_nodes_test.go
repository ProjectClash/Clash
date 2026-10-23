package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

func connectProxy(t *testing.T) (host string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				request, err := http.ReadRequest(bufio.NewReader(client))
				if err != nil || request.Method != http.MethodConnect {
					return
				}
				target, err := net.Dial("tcp", request.Host)
				if err != nil {
					return
				}
				defer target.Close()
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(target, client) }()
				_, _ = io.Copy(client, target)
			}()
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	return address.IP.String(), address.Port
}

func libraryNodesForTest(t *testing.T, n int) *LibraryNodes {
	t.Helper()
	host, port := connectProxy(t)
	writer := outbound.NewNodeLibraryWriter("")
	for i := 0; i < n; i++ {
		built, config, err := BuildLibraryNode(map[string]any{"name": fmt.Sprintf("node %d", i), "type": "http", "server": host, "port": port})
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Add(built, config); err != nil {
			t.Fatal(err)
		}
		_ = built.Close()
	}
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	words := make([]uint64, (buffer.Len()+7)/8)
	data := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), buffer.Len())
	copy(data, buffer.Bytes())
	library, err := outbound.OpenNodeLibrary(data)
	if err != nil {
		t.Fatal(err)
	}
	return NewLibraryNodes(library)
}

func TestALibraryNodeKeepsItsRecordsAndNotItsObjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	url := server.URL + "/generate_204"
	nodes := libraryNodesForTest(t, 400)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < nodes.Len(); i++ {
		if _, err := nodes.At(i).URLTest(ctx, url, nil); err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for nodes.Sweep(); nodes.LiveCount() != 0 && time.Now().Before(deadline); nodes.Sweep() {
		time.Sleep(10 * time.Millisecond)
	}
	if live := nodes.LiveCount(); live != 0 {
		t.Fatalf("%d nodes still hold objects after their tests", live)
	}
	for i := 0; i < nodes.Len(); i++ {
		node := nodes.At(i)
		if node.LastDelayForTestUrl(url) == 0xffff || !node.AliveForTestUrl(url) || len(node.DelayHistory()) != 1 {
			t.Fatalf("node %d: delay %d alive %v history %v", i, node.LastDelayForTestUrl(url), node.AliveForTestUrl(url), node.DelayHistory())
		}
		if state, ok := node.ExtraDelayHistories()[url]; !ok || !state.Alive || len(state.History) != 1 {
			t.Fatalf("node %d: extra %+v", i, node.ExtraDelayHistories())
		}
	}
	encoded, err := nodes.At(3).MarshalJSON()
	if err != nil || !strings.Contains(string(encoded), `"history":[{"time":`) || !strings.Contains(string(encoded), `"name":"node 3"`) {
		t.Fatalf("%s %v", encoded, err)
	}
	if nodes.At(5) != nodes.At(5) || nodes.At(5) == nodes.At(6) {
		t.Fatal("a node is not itself")
	}
	if proxy, ok := nodes.Lookup("node 7"); !ok || proxy != nodes.At(7) {
		t.Fatal("lookup by name")
	}
}

func TestALibraryNodeRecordsAFailedTestAsUpstream(t *testing.T) {
	nodes := libraryNodesForTest(t, 2)
	node := nodes.At(0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "http://127.0.0.1:1/unreachable"
	if _, err := node.URLTest(ctx, url, nil); err == nil {
		t.Fatal("a test of a closed port passed")
	}
	if node.AliveForTestUrl(url) || node.LastDelayForTestUrl(url) != 0xffff {
		t.Fatal("a failed URL is alive")
	}
	if history := node.DelayHistory(); len(history) != 1 || history[0].Delay != 0 {
		t.Fatalf("history %v", history)
	}
	if !nodes.At(1).AliveForTestUrl(url) || len(nodes.At(1).DelayHistory()) != 0 {
		t.Fatal("an untested node is alive with no history, as upstream's")
	}
	var _ C.Proxy = node
}

func TestAURLsRecordsAreMadeForTheNodesTestedWithIt(t *testing.T) {
	nodes := libraryNodesForTest(t, 3)
	set := newURLRecordSet(100000)
	if len(set.chunks) != 98 || set.madeChunks() != 0 {
		t.Fatalf("%d chunks, %d made", len(set.chunks), set.madeChunks())
	}
	set.store(99999, 7)
	set.store(5, 9)
	if set.load(99999) != 7 || set.load(5) != 9 || set.load(6) != 0 || set.madeChunks() != 2 {
		t.Fatalf("records %d %d %d, %d chunks made", set.load(99999), set.load(5), set.load(6), set.madeChunks())
	}
	slot := nodes.At(1).(*libraryNode)
	for u := 0; u < libraryURLLimit; u++ {
		slot.recorded(fmt.Sprintf("http://u%d.example/", u), C.DelayHistory{Delay: 10}, true, nil, C.DelayHistory{Delay: 10}, true, nil, "")
	}
	made := 0
	nodes.rangeURLRecords(func(url string, records *urlRecordSet) { made += records.madeChunks() })
	if made != libraryURLLimit {
		t.Fatalf("%d chunks made for %d URLs of one node", made, libraryURLLimit)
	}
	if histories := slot.ExtraDelayHistories(); len(histories) != libraryURLLimit {
		t.Fatalf("%d URLs in the node's histories", len(histories))
	}
}

func TestALibraryKeepsTheRecordsOfALimitedNumberOfURLs(t *testing.T) {
	nodes := libraryNodesForTest(t, 2)
	slot := nodes.At(0).(*libraryNode)
	slot.recorded("http://kept.example/", C.DelayHistory{Delay: 5}, true, nil, C.DelayHistory{Delay: 5}, true, nil, "")
	for u := 0; u < 100; u++ {
		slot.recorded(fmt.Sprintf("http://u%d.example/", u), C.DelayHistory{Delay: 10}, true, nil, C.DelayHistory{Delay: 10}, true, nil, "")
		if u%10 == 0 {
			slot.recorded("http://kept.example/", C.DelayHistory{Delay: 5}, true, nil, C.DelayHistory{Delay: 5}, true, nil, "")
		}
	}
	urls := 0
	nodes.rangeURLRecords(func(string, *urlRecordSet) { urls++ })
	if urls > libraryURLLimit {
		t.Fatalf("%d URLs kept", urls)
	}
	if _, ok := slot.ExtraDelayHistories()["http://kept.example/"]; !ok {
		t.Fatal("the URL stored lately was dropped")
	}
}

func TestHealthCountsAreWhatTheNodeListSays(t *testing.T) {
	nodes := libraryNodesForTest(t, 4)
	nodes.At(0).(*libraryNode).recorded("http://a.example/", C.DelayHistory{Time: time.Now(), Delay: 10}, true, nil, C.DelayHistory{Time: time.Now(), Delay: 10}, true, nil, "")
	nodes.At(1).(*libraryNode).recorded("http://a.example/", C.DelayHistory{Time: time.Now()}, false, nil, C.DelayHistory{Time: time.Now()}, false, nil, "")
	plain := make(C.ProxySlice, 3)
	for i := range plain {
		built, _, err := BuildLibraryNode(map[string]any{"name": fmt.Sprintf("plain %d", i), "type": "http", "server": "127.0.0.1", "port": 1})
		if err != nil {
			t.Fatal(err)
		}
		plain[i] = NewProxy(built)
	}
	plain[0].(*Proxy).history.Put(C.DelayHistory{Time: time.Now(), Delay: 5})
	plain[1].(*Proxy).history.Put(C.DelayHistory{Time: time.Now()})
	plain[1].(*Proxy).alive.Store(false)
	for name, list := range map[string]C.ProxyList{"library": nodes, "slice": plain} {
		var wantAlive, wantDead int
		for i := 0; i < list.Len(); i++ {
			encoded, err := list.At(i).MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var node struct {
				Alive   bool
				History []any
			}
			_ = json.Unmarshal(encoded, &node)
			if len(node.History) > 0 && node.Alive {
				wantAlive++
			} else if len(node.History) > 0 {
				wantDead++
			}
		}
		if alive, dead := ClashHealthCounts(list); alive != wantAlive || dead != wantDead || alive != 1 || dead != 1 {
			t.Fatalf("%s: alive %d dead %d, the list says %d and %d", name, alive, dead, wantAlive, wantDead)
		}
	}
}

func TestALibraryNodesInfoIsReadInPlace(t *testing.T) {
	nodes := libraryNodesForTest(t, 100)
	allocs := testing.AllocsPerRun(10, func() {
		for i := 0; i < nodes.Len(); i++ {
			node := nodes.At(i)
			_ = node.ProxyInfo().DialerProxy
			_ = node.Addr()
		}
	})
	if allocs > float64(nodes.Len()) {
		t.Fatalf("%.0f allocations reading %d nodes", allocs, nodes.Len())
	}
	info := testing.AllocsPerRun(10, func() {
		for i := 0; i < nodes.Len(); i++ {
			_ = nodes.At(i).ProxyInfo().DialerProxy
		}
	})
	if info != 0 {
		t.Fatalf("ProxyInfo made %.0f allocations over %d nodes", info, nodes.Len())
	}
}
