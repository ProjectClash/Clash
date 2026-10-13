package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/queue"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
)

func bytesPerProxy(n int, touch func(p *Proxy)) float64 {
	keep := make([]*Proxy, n)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range keep {
		p := NewProxy(outbound.NewDirect())
		touch(p)
		keep[i] = p
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(keep)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(n)
}

func TestReadingAnUnmeasuredNodeBuildsNothing(t *testing.T) {
	const n = 2000
	const url = "https://www.gstatic.com/generate_204"
	bare := bytesPerProxy(n, func(*Proxy) {})
	read := bytesPerProxy(n, func(p *Proxy) {
		_, _, _, _ = p.LastURLTestRecord(url)
		_ = p.AliveForTestUrl(url)
		_ = p.LastDelayForTestUrl(url)
	})
	if extra := read - bare; extra > 64 {
		t.Fatalf("reading an unmeasured node allocated %.0f B per node", extra)
	}
}

func TestAMeasuredURLCostsOneSmallRecord(t *testing.T) {
	const n = 2000
	const url = "https://www.gstatic.com/generate_204"
	bare := bytesPerProxy(n, func(*Proxy) {})
	measured := bytesPerProxy(n, func(p *Proxy) {
		state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState {
			return &internalProxyState{history: queue.New[C.DelayHistory](defaultHistoriesNum), alive: atomic.NewBool(true)}
		})
		state.history.Put(C.DelayHistory{Time: time.Now(), Delay: 42})
	})
	if extra := measured - bare; extra > 1024 {
		t.Fatalf("one measured URL costs %.0f B per node", extra)
	}
	if testing.Verbose() {
		t.Logf("one measured URL: %.0f B per node", measured-bare)
	}
}

func TestANodeBetweenProbesHoldsNoProbeTables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	p := NewProxy(outbound.NewDirect())
	expected, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.URLTest(ctx, server.URL, expected); err != nil {
		t.Fatal(err)
	}
	p.urlTests.mu.Lock()
	flights := p.urlTests.flights
	p.urlTests.mu.Unlock()
	if flights != nil {
		t.Fatalf("a node between probes holds a flight table of %d", len(flights))
	}
	if _, _, asked, ok := p.LastURLTestRecord(server.URL); !ok || asked != expected.String() {
		t.Fatalf("the record answers %q, want %q", asked, expected.String())
	}
}
