package adapter

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)


func closedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func TestAParsedNodeKeepsWhyItsNewestRecordFailed(t *testing.T) {
	answer := http.StatusServiceUnavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(answer) }))
	defer server.Close()
	proxy := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	refused := fmt.Sprintf("http://127.0.0.1:%d/generate_204", closedPort(t))
	if _, err := proxy.URLTest(ctx, refused, nil); err == nil {
		t.Fatal("a test of a closed port passed")
	}
	_, failure, _ := proxy.LastRecord()
	if failure == nil || failure.Kind != "dial" || failure.Message == "" {
		t.Fatalf("the history's failure: %+v", failure)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if failure.Errno != "ECONNREFUSED" {
			t.Fatalf("the history's failure: %+v, want ECONNREFUSED", failure)
		}
	}
	delays := proxy.AppendURLDelays(nil)
	if len(delays) != 1 || delays[0].Failure == nil || delays[0].Failure.Errno != failure.Errno {
		t.Fatalf("the URL's records: %+v", delays)
	}

	if _, err := proxy.URLTest(ctx, server.URL, statusRanges(t, "200-299")); err != nil {
		t.Fatal(err)
	}
	if _, failure, _ := proxy.LastRecord(); failure != nil {
		t.Fatalf("an answer failed the history's record: %+v", failure)
	}
	var status *URLTestFailure
	for _, d := range proxy.AppendURLDelays(nil) {
		if d.URL == server.URL {
			status = d.Failure
		}
	}
	if status == nil || status.Kind != URLTestFailureStatus || status.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("the status failure: %+v", status)
	}

	answer = http.StatusNoContent
	if _, err := proxy.URLTest(ctx, server.URL, statusRanges(t, "200-299")); err != nil {
		t.Fatal(err)
	}
	for _, d := range proxy.AppendURLDelays(nil) {
		if d.URL == server.URL && d.Failure != nil {
			t.Fatalf("a passed record kept a failure: %+v", d.Failure)
		}
	}
}

func libraryOf(t *testing.T, n int, host string, port int) *LibraryNodes {
	t.Helper()
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

func TestALibraryNodeKeepsWhyItsNewestRecordFailed(t *testing.T) {
	nodes := libraryOf(t, 2, "127.0.0.1", closedPort(t))
	node := nodes.At(0).(*libraryNode)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "http://example.invalid/generate_204"
	if _, err := node.URLTest(ctx, url, nil); err == nil {
		t.Fatal("a test through a closed port passed")
	}
	_, failure, _ := node.LastRecord()
	if failure == nil || failure.Kind != "dial" || failure.Message == "" {
		t.Fatalf("the history's failure: %+v", failure)
	}
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && failure.Errno != "ECONNREFUSED" {
		t.Fatalf("the history's failure: %+v, want ECONNREFUSED", failure)
	}
	if history := node.DelayHistory(); len(history) != 1 || history[0].Delay != 0 {
		t.Fatalf("a failed record's delay: %v", history)
	}
	if node.LastDelayForTestUrl(url) != 0xffff || node.AliveForTestUrl(url) {
		t.Fatal("a failed URL reads alive")
	}
	delays := node.AppendURLDelays(nil)
	if len(delays) != 1 || delays[0].Failure == nil || delays[0].Failure.Errno != failure.Errno || delays[0].Failure.Message == "" {
		t.Fatalf("the URL's records: %+v", delays)
	}
	if _, failure, _ := nodes.At(1).(*libraryNode).LastRecord(); failure != nil {
		t.Fatal("an untested node has a failure")
	}
	if unsafe.Sizeof(libraryNode{}) != 16 {
		t.Fatalf("a slot is %d bytes", unsafe.Sizeof(libraryNode{}))
	}
}

func TestOnlyTheNewestFailureSentencesAreKept(t *testing.T) {
	nodes := libraryOf(t, maxFailureNotes+8, "127.0.0.1", closedPort(t))
	refused := &URLTestFailure{Kind: "dial", Errno: "ECONNREFUSED", Message: "connection refused", errno: syscall.ECONNREFUSED}
	at := time.Now()
	for i := 0; i < nodes.Len(); i++ {
		record := C.DelayHistory{Time: at.Add(time.Duration(i) * time.Millisecond)}
		nodes.At(i).(*libraryNode).recorded("http://a.example/", record, false, refused, record, false, refused, "")
	}
	if n := len(nodes.notes.notes); n != maxFailureNotes || nodes.notes.order.Len() != maxFailureNotes {
		t.Fatalf("%d sentences kept", n)
	}
	_, first, _ := nodes.At(0).(*libraryNode).LastRecord()
	_, last, _ := nodes.At(nodes.Len() - 1).(*libraryNode).LastRecord()
	if first == nil || first.Kind != "dial" || first.Message != "" {
		t.Fatalf("the oldest failure: %+v, want its kind without its sentence", first)
	}
	if last == nil || last.Message != "connection refused" {
		t.Fatalf("the newest failure: %+v", last)
	}
	again := nodes.At(1).(*libraryNode)
	for i := 0; i < 2*maxFailureNotes; i++ {
		record := C.DelayHistory{Time: at.Add(time.Hour + time.Duration(i)*time.Millisecond)}
		again.recorded("http://a.example/", record, false, refused, record, false, refused, "")
		other := nodes.At(2 + i%(nodes.Len()-2)).(*libraryNode)
		other.recorded("http://b.example/", record, false, refused, record, false, refused, "")
	}
	if _, failure, _ := again.LastRecord(); failure == nil || failure.Message != "connection refused" {
		t.Fatalf("a node failing every round lost its sentence: %+v", failure)
	}
}

func TestAFailurePacksIntoSixteenBits(t *testing.T) {
	for _, failure := range []*URLTestFailure{
		{Kind: URLTestFailureTimeout},
		{Kind: URLTestFailureCanceled},
		{Kind: URLTestFailureStatus, HTTPStatus: 403},
		{Kind: "dial", errno: syscall.ECONNREFUSED, Errno: errnoName(syscall.ECONNREFUSED)},
		{Kind: "read", errno: syscall.ECONNRESET, Errno: errnoName(syscall.ECONNRESET)},
		{Kind: "write", errno: syscall.EPIPE, Errno: errnoName(syscall.EPIPE)},
		{Kind: URLTestFailureUnknown},
	} {
		back := failureOfCode(failure.code())
		if back == nil || back.Kind != failure.Kind || back.HTTPStatus != failure.HTTPStatus || back.Errno != failure.Errno {
			t.Errorf("%+v came back %+v", failure, back)
		}
	}
	if failureOfCode((&URLTestFailure{Kind: "close"}).code()).Kind != URLTestFailureUnknown {
		t.Error("a kind not in the table does not pack as unknown")
	}
	if (*URLTestFailure)(nil).code() != 0 || failureOfCode(0) != nil {
		t.Error("no failure is not 0")
	}
}

func TestARecordAndItsFailureAreReadTogether(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	refused := fmt.Sprintf("http://127.0.0.1:%d/generate_204", closedPort(t))
	proxy := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if record, failure, ok := proxy.LastRecord(); ok && (failure != nil) != (record.Delay == 0) {
				t.Errorf("a record of delay %d beside failure %+v", record.Delay, failure)
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		var wg sync.WaitGroup
		for _, url := range []string{server.URL, refused} {
			wg.Add(1)
			go func(url string) { defer wg.Done(); _, _ = proxy.URLTest(ctx, url, nil) }(url)
		}
		wg.Wait()
	}
	close(stop)
	<-done
}
