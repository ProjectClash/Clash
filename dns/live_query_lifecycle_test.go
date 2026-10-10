package dns

import (
	"context"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestResetConnectionDoesNotCancelALiveQuery(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}

	question := new(D.Msg)
	question.SetQuestion("live.example.com.", D.TypeA)

	done := make(chan error, 1)
	go func() {
		_, err := resolver.ExchangeContext(context.Background(), question)
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("the live query never reached the client; this test would prove nothing")
	}

	resolver.ResetConnection()

	time.Sleep(300 * time.Millisecond)
	if got := client.cancels.Load(); got != 0 {
		t.Fatalf("ResetConnection cancelled %d live query/queries; the caller gets SERVFAIL for "+
			"a lookup whose upstream was fine, and on Apple this fires on every "+
			"default-interface change", got)
	}

	close(client.block)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the live query never returned after the client was unblocked")
	}
}

func TestShutdownStillCancelsRefetches(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}

	question := new(D.Msg)
	question.SetQuestion("stale-after-split.example.com.", D.TypeA)
	answer := new(D.Msg)
	answer.SetReply(question)
	answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{
		Name: "stale-after-split.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1,
	}}}
	resolver.cache.SetWithExpire(question.Question[0].String(), answer, time.Now().Add(-time.Minute))

	if _, err := resolver.ExchangeContext(context.Background(), question); err != nil {
		t.Fatalf("a stale hit expired and served stale (mihomo has no window) must still be served: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("a stale hit must fire a refresh")
	}

	resolver.CloseQueries()

	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("shutdown stopped cancelling detached refreshes; those must not outlive the " +
			"core they belong to")
	}
}

func TestShutdownDoesNotResurrectTheQueryItCancelled(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{main: []dnsClient{client}, cache: Config{}.newCache()}

	question := new(D.Msg)
	question.SetQuestion("resurrect.example.com.", D.TypeA)
	go func() { _, _ = resolver.ExchangeContext(context.Background(), question) }()

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	started := client.started.Load()
	if started == 0 {
		t.Fatal("the live query never reached the client")
	}

	resolver.CloseQueries()

	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("shutdown did not cancel the in-flight query")
	}

	time.Sleep(400 * time.Millisecond)
	entered, done := client.started.Load(), client.finished.Load()
	if entered != done {
		t.Fatalf("%d of %d queries are still running after shutdown; a cancelled query was "+
			"retried under a freshly built live context and outlives the core that owned it",
			entered-done, entered)
	}
	if entered > started+3 {
		t.Fatalf("client entered %d times after shutdown (was %d); even instant returns should "+
			"be bounded by the retry limit, so this is a loop", entered-started, started)
	}

	if err := resolver.queryContext().Err(); err == nil {
		t.Fatal("queryContext returned a live context after CloseQueries; the next query would " +
			"run under a core that has been shut down")
	}
}
