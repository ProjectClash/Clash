package dns

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

type countingAdapter struct {
	C.ProxyAdapter
	dials    atomic.Int32
	inFlight atomic.Int32
	peak     atomic.Int32
	delay    atomic.Int64
	stall func(n int32) bool
}

func (a *countingAdapter) Name() string                     { return "counting" }
func (a *countingAdapter) Type() C.AdapterType              { return C.Direct }
func (a *countingAdapter) Addr() string                     { return "" }
func (a *countingAdapter) IsL3Protocol(*C.Metadata) bool    { return false }
func (a *countingAdapter) SupportUDP() bool                 { return false }
func (a *countingAdapter) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func (a *countingAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	n := a.dials.Add(1)
	now := a.inFlight.Add(1)
	defer a.inFlight.Add(-1)
	for peak := a.peak.Load(); now > peak && !a.peak.CompareAndSwap(peak, now); peak = a.peak.Load() {
	}
	if a.stall != nil && a.stall(n) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-time.After(time.Duration(a.delay.Load())):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return &countedConn{ExtendedConn: N.NewExtendedConn(conn)}, nil
}

type countedConn struct{ N.ExtendedConn }

func (*countedConn) Chains() C.Chain               { return nil }
func (*countedConn) ProviderChains() C.Chain       { return nil }
func (*countedConn) AppendToChains(C.ProxyAdapter) {}
func (*countedConn) RemoteDestination() string     { return "" }

func dohServer(t *testing.T, http2 bool) *httptest.Server {
	return slowDoHServer(t, http2, 0)
}

func slowDoHServer(t *testing.T, http2 bool, answerAfter time.Duration) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(answerAfter)
		body, _ := io.ReadAll(r.Body)
		if encoded := r.URL.Query().Get("dns"); encoded != "" {
			body, _ = base64.RawURLEncoding.DecodeString(encoded)
		}
		var query D.Msg
		if err := query.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		answer := new(D.Msg)
		answer.SetReply(&query)
		answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
		packed, _ := answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	server.EnableHTTP2 = http2
	server.TLS = &tls.Config{}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func dohTestClient(server *httptest.Server, adapter *countingAdapter) dnsClient {
	return newDoHClient(server.URL+"/dns-query", nil, false, map[string]string{"skip-cert-verify": "true"}, adapter, "")
}

func queryAll(t *testing.T, client dnsClient, starts []time.Duration, timeout time.Duration) int32 {
	t.Helper()
	var wg sync.WaitGroup
	var failed atomic.Int32
	began := time.Now()
	for _, start := range starts {
		start := start
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Until(began.Add(start)))
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			m := new(D.Msg)
			m.SetQuestion("example.com.", D.TypeA)
			if _, err := client.ExchangeContext(ctx, m); err != nil {
				if failed.Add(1) == 1 {
					t.Logf("first failure: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	return failed.Load()
}

func atOnce(n int) []time.Duration { return make([]time.Duration, n) }

func TestConcurrentQueriesOfAColdDoHResolverShareItsDials(t *testing.T) {
	for _, http2 := range []bool{true, false} {
		adapter := &countingAdapter{}
		adapter.delay.Store(int64(100 * time.Millisecond))
		client := dohTestClient(dohServer(t, http2), adapter)
		const queries = 32
		if failed := queryAll(t, client, atOnce(queries), 10*time.Second); failed != 0 {
			t.Errorf("http2 %v: %d of %d queries failed", http2, failed, queries)
		}
		if dials := adapter.dials.Load(); dials > 2 {
			t.Errorf("http2 %v: %d queries at once dialed %d times, want at most 2", http2, queries, dials)
		}
	}
}

func TestOneStalledDialDoesNotHoldEveryQuery(t *testing.T) {
	adapter := &countingAdapter{stall: func(n int32) bool { return n == 1 }}
	client := dohTestClient(dohServer(t, true), adapter)
	starts := []time.Duration{0}
	for i := 0; i < 8; i++ {
		starts = append(starts, 100*time.Millisecond)
	}
	if failed := queryAll(t, client, starts, 2*time.Second); failed > 1 {
		t.Fatalf("%d of %d queries failed behind one stalled dial", failed, len(starts))
	}
}

func TestAnHTTP11ServerAnswersTwoQueriesAtATime(t *testing.T) {
	adapter := &countingAdapter{}
	client := dohTestClient(slowDoHServer(t, false, 100*time.Millisecond), adapter)
	if failed := queryAll(t, client, atOnce(24), 2*time.Second); failed != 0 {
		t.Fatalf("%d of 24 queries failed on an HTTP/1.1 server", failed)
	}
}

func TestTimeoutsOnOneStalledClientReplaceItOnce(t *testing.T) {
	server := dohServer(t, true)
	adapter := &countingAdapter{}
	client := dohTestClient(server, adapter)
	if failed := queryAll(t, client, atOnce(1), 5*time.Second); failed != 0 {
		t.Fatal("warm-up query failed")
	}
	server.CloseClientConnections()
	adapter.delay.Store(int64(600 * time.Millisecond))
	adapter.peak.Store(0)
	var starts []time.Duration
	for at := time.Duration(0); at < 900*time.Millisecond; at += 10 * time.Millisecond {
		starts = append(starts, at)
	}
	queryAll(t, client, starts, 500*time.Millisecond)
	peak := adapter.peak.Load()
	t.Logf("peak dials in flight: %d", peak)
	if peak > 4 {
		t.Fatalf("%d dials to one server were in flight at once, want at most 4", peak)
	}
}

type cancellingTimeout struct{ cancel func() }

func (c cancellingTimeout) RoundTrip(*http.Request) (*http.Response, error) {
	c.cancel()
	return nil, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
}

func TestAQueryWhoseTimeEndsReplacesOnlyTheClientItUsed(t *testing.T) {
	client := dohTestClient(dohServer(t, true), &countingAdapter{}).(*dnsOverHTTPS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.client = &http.Client{Transport: cancellingTimeout{cancel}}
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	m := new(D.Msg)
	m.SetQuestion("example.com.", D.TypeA)
	_, _ = client.ExchangeContext(ctx, m)
	recreated := 0
	for draining := true; draining; {
		select {
		case event := <-sub:
			if strings.Contains(event.Payload, "re-creating the http client") {
				recreated++
			}
		case <-time.After(200 * time.Millisecond):
			draining = false
		}
	}
	if recreated != 1 {
		t.Fatalf("the client was re-created %d times, want once", recreated)
	}
}

func warmThenDrop(t *testing.T, server *httptest.Server, client dnsClient, adapter *countingAdapter, dial time.Duration) {
	t.Helper()
	if failed := queryAll(t, client, atOnce(1), 5*time.Second); failed != 0 {
		t.Fatal("warm-up query failed")
	}
	server.CloseClientConnections()
	time.Sleep(100 * time.Millisecond)
	adapter.delay.Store(int64(dial))
	adapter.peak.Store(0)
}

func TestATimeoutDoesNotFailTheQueriesWaitingOnTheSameDial(t *testing.T) {
	server := dohServer(t, true)
	adapter := &countingAdapter{}
	client := dohTestClient(server, adapter)
	warmThenDrop(t, server, client, adapter, time.Second)
	done := make(chan int32)
	go func() { done <- queryAll(t, client, atOnce(4), 5*time.Second) }()
	time.Sleep(50 * time.Millisecond)
	queryAll(t, client, atOnce(1), 200*time.Millisecond)
	if failed := <-done; failed != 0 {
		t.Fatalf("%d of 4 queries waiting on the dial failed when another timed out", failed)
	}
}

func TestDialsSlowerThanTheQueryBudgetStillAnswer(t *testing.T) {
	server := dohServer(t, true)
	adapter := &countingAdapter{}
	client := dohTestClient(server, adapter)
	warmThenDrop(t, server, client, adapter, 1500*time.Millisecond)
	var starts []time.Duration
	for at := time.Duration(0); at < 4*time.Second; at += 100 * time.Millisecond {
		starts = append(starts, at)
	}
	if failed := queryAll(t, client, starts, time.Second); failed == int32(len(starts)) {
		t.Fatalf("none of %d queries was answered", len(starts))
	}
}

func TestQueriesWaitingOnADialAreAnsweredAfterANetworkChange(t *testing.T) {
	server := dohServer(t, true)
	adapter := &countingAdapter{}
	client := dohTestClient(server, adapter)
	warmThenDrop(t, server, client, adapter, time.Second)
	done := make(chan int32)
	go func() { done <- queryAll(t, client, atOnce(4), 5*time.Second) }()
	time.Sleep(200 * time.Millisecond)
	client.ResetConnection()
	if failed := <-done; failed != 0 {
		t.Fatalf("%d of 4 queries failed after the network changed, with time left", failed)
	}
}

func TestTheResolverAnswersAsSoonAsAStalledNodeRecovers(t *testing.T) {
	server := dohServer(t, true)
	recovered := time.Now().Add(time.Second)
	adapter := &countingAdapter{stall: func(int32) bool { return time.Now().Before(recovered) }}
	client := dohTestClient(server, adapter)
	var starts []time.Duration
	for at := time.Duration(0); at < 4*time.Second; at += 50 * time.Millisecond {
		starts = append(starts, at)
	}
	began := time.Now()
	var answeredAfter, after atomic.Int32
	var wg sync.WaitGroup
	for _, start := range starts {
		start := start
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Until(began.Add(start)))
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			m := new(D.Msg)
			m.SetQuestion("example.com.", D.TypeA)
			_, err := client.ExchangeContext(ctx, m)
			if began.Add(start).After(recovered.Add(200 * time.Millisecond)) {
				after.Add(1)
				if err == nil {
					answeredAfter.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n, ok := after.Load(), answeredAfter.Load(); ok*10 < n*9 {
		t.Fatalf("after the node recovered, %d of %d queries were answered", ok, n)
	}
}
