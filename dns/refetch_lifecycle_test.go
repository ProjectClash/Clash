package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)


type refetchCountingClient struct {
	started  atomic.Int64
	finished atomic.Int64
	cancels  atomic.Int64
	block    chan struct{}
}

func (c *refetchCountingClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.started.Add(1)
	defer c.finished.Add(1)
	select {
	case <-c.block:
		return nil, context.Canceled
	case <-ctx.Done():
		c.cancels.Add(1)
		return nil, ctx.Err()
	}
}

func (c *refetchCountingClient) Address() string { return "refetch-counting" }

func (c *refetchCountingClient) ResetConnection() {}

func TestShutdownCancelsInFlightRefetches(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}

	question := new(D.Msg)
	question.SetQuestion("stale.example.com.", D.TypeA)

	answer := new(D.Msg)
	answer.SetReply(question)
	answer.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: "stale.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1},
	}}
	resolver.cache.SetWithExpire(question.Question[0].String(), answer, time.Now().Add(-time.Minute))

	if _, err := resolver.ExchangeContext(context.Background(), question); err != nil {
		t.Fatalf("a stale hit must still be served: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("a stale hit must fire a refresh; without one this test proves nothing")
	}

	resolver.CloseQueries()

	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("shutdown did not cancel the in-flight refresh; it would outlive the core it " +
			"belongs to, and this process can host the next one")
	}
}

func TestRefetchesWorkAgainAfterAReset(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	close(client.block)
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}
	resolver.ResetConnection()

	question := new(D.Msg)
	question.SetQuestion("after-reset.example.com.", D.TypeA)
	answer := new(D.Msg)
	answer.SetReply(question)
	answer.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: "after-reset.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1},
	}}
	resolver.cache.SetWithExpire(question.Question[0].String(), answer, time.Now().Add(-time.Minute))

	if _, err := resolver.ExchangeContext(context.Background(), question); err != nil {
		t.Fatalf("serving a stale hit after a reset: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("no refresh fired after a reset; the refetch context must be renewed, not " +
			"left cancelled forever")
	}
}

func TestOneCallerCancellingDoesNotKillSharedQuery(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{main: []dnsClient{client}, cache: Config{}.newCache()}

	question := new(D.Msg)
	question.SetQuestion("shared.example.com.", D.TypeA)

	impatient, cancelImpatient := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = resolver.ExchangeContext(impatient, question)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("the upstream query never started")
	}

	cancelImpatient()
	<-done

	time.Sleep(100 * time.Millisecond)
	if client.cancels.Load() != 0 {
		t.Fatal("one caller cancelling aborted the shared upstream query; every other caller " +
			"waiting on the same question would have failed with it")
	}

	resolver.ResetConnection()
	time.Sleep(100 * time.Millisecond)
	if client.cancels.Load() != 0 {
		t.Fatal("ResetConnection aborted the shared upstream query; on Apple that fires on " +
			"every default-interface change")
	}

	resolver.CloseQueries()
	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("the core could not stop its own query at shutdown")
	}
}
