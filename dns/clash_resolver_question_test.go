package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	D "github.com/miekg/dns"
)

type countingResolver struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	received []uint16
	answerOn int
	rcode    int
	truncate bool
}

func (r *countingResolver) set(rcode int, truncate bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rcode, r.truncate = rcode, truncate
}

func startCountingResolver(t *testing.T, answerOn int) *countingResolver {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &countingResolver{conn: conn, answerOn: answerOn}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var q D.Msg
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			r.mu.Lock()
			r.received = append(r.received, q.Id)
			count := len(r.received)
			r.mu.Unlock()
			if count == answerOn {
				reply := new(D.Msg)
				reply.SetReply(&q)
				r.mu.Lock()
				reply.Rcode, reply.Truncated = r.rcode, r.truncate
				r.mu.Unlock()
				packed, _ := reply.Pack()
				_, _ = conn.WriteToUDP(packed, from)
			}
		}
	}()
	return r
}

func (r *countingResolver) seen() []uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint16(nil), r.received...)
}

type questionEvent struct {
	kind, network, address string
	event                  dialer.PhysicalDialEvent
	err                    error
}

func observeQuestions(t *testing.T) *[]questionEvent {
	t.Helper()
	beyond := resolverBeyondThisLink
	resolverBeyondThisLink = func(netip.Addr) bool { return true }
	t.Cleanup(func() { resolverBeyondThisLink = beyond })
	var mu sync.Mutex
	events := &[]questionEvent{}
	dialer.SetPhysicalDialObserver(func(kind, network, address string, _ uint64, event dialer.PhysicalDialEvent, err error) {
		mu.Lock()
		defer mu.Unlock()
		*events = append(*events, questionEvent{kind, network, address, event, err})
	})
	t.Cleanup(func() { dialer.SetPhysicalDialObserver(nil) })
	return events
}

func aQuestionFor(name string) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion(D.Fqdn(name), D.TypeA)
	return m
}

func TestAQuestionNobodyAnswersIsReportedAsSilence(t *testing.T) {
	r := startCountingResolver(t, 0)
	events := observeQuestions(t)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := c.ExchangeContext(ctx, aQuestionFor("example.test"))
	if err == nil {
		t.Fatal("a resolver that never answers must fail the question")
	}
	if len(*events) != 2 || (*events)[0].event != dialer.PhysicalDialStarted || (*events)[1].event != dialer.PhysicalDialFailed {
		t.Fatalf("events %+v, want sent then failed", *events)
	}
	last := (*events)[1]
	if last.kind != dialer.DialKindResolver || last.network != "udp" || last.address != r.conn.LocalAddr().String() {
		t.Fatalf("event %+v", last)
	}
	var netErr net.Error
	if !(errors.Is(last.err, context.DeadlineExceeded) || errors.Is(last.err, os.ErrDeadlineExceeded) || (errors.As(last.err, &netErr) && netErr.Timeout())) {
		t.Fatalf("the failure must read as a timeout, got %v", last.err)
	}
}

func TestAnAnsweredQuestionIsReportedAsTheNetworkDelivering(t *testing.T) {
	r := startCountingResolver(t, 1)
	events := observeQuestions(t)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.ExchangeContext(ctx, aQuestionFor("example.test")); err != nil {
		t.Fatal(err)
	}
	if len(*events) != 2 || (*events)[1].event != dialer.PhysicalDialSucceeded {
		t.Fatalf("events %+v, want sent then answered", *events)
	}
}

func TestAQuestionIsResentWhenTheFirstCopyIsLost(t *testing.T) {
	r := startCountingResolver(t, 2)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	started := time.Now()
	reply, err := c.ExchangeContext(ctx, aQuestionFor("example.test"))
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(started)
	if took < 900*time.Millisecond || took > 2500*time.Millisecond {
		t.Fatalf("the second copy goes out at one second; the answer took %s", took)
	}
	seen := r.seen()
	if len(seen) != 2 || seen[0] != seen[1] || reply.Id != seen[0] {
		t.Fatalf("the resolver must see the same question twice, saw %v, reply id %d", seen, reply.Id)
	}
}

func TestTheThirdCopyGoesOutAtThreeSeconds(t *testing.T) {
	r := startCountingResolver(t, 3)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := c.ExchangeContext(ctx, aQuestionFor("example.test")); err != nil {
		t.Fatal(err)
	}
	took := time.Since(started)
	if took < 2900*time.Millisecond || took > 4500*time.Millisecond {
		t.Fatalf("the third copy goes out at three seconds; the answer took %s", took)
	}
	if seen := r.seen(); len(seen) != 3 {
		t.Fatalf("three copies expected, resolver saw %d", len(seen))
	}
}

func TestAServerFailureIsNeitherAnswerNorSilence(t *testing.T) {
	r := startCountingResolver(t, 1)
	r.set(D.RcodeServerFailure, false)
	events := observeQuestions(t)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = c.ExchangeContext(ctx, aQuestionFor("example.test"))
	assertNeutral(t, *events)
}

func TestAnAnswerFromAResolverOnThisLinkSaysNothing(t *testing.T) {
	r := startCountingResolver(t, 1)
	events := observeQuestions(t)
	resolverBeyondThisLink = func(addr netip.Addr) bool { return !addr.IsLoopback() }
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.ExchangeContext(ctx, aQuestionFor("example.test")); err != nil {
		t.Fatal(err)
	}
	assertNeutral(t, *events)
}

func TestACallersShortDeadlineIsNotTheResolversSilence(t *testing.T) {
	r := startCountingResolver(t, 0)
	events := observeQuestions(t)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = c.ExchangeContext(ctx, aQuestionFor("example.test"))
	assertNeutral(t, *events)
}

func TestATruncatedAnswerCountsBeforeTheTCPLeg(t *testing.T) {
	r := startCountingResolver(t, 1)
	r.set(D.RcodeSuccess, true)
	events := observeQuestions(t)
	c := newClient(r.conn.LocalAddr().String(), nil, "udp", nil, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = c.ExchangeContext(ctx, aQuestionFor("example.test"))
	var questions []questionEvent
	for _, e := range *events {
		if e.kind == dialer.DialKindResolver {
			questions = append(questions, e)
		}
	}
	if len(questions) != 2 || questions[1].event != dialer.PhysicalDialSucceeded {
		t.Fatalf("question events %+v, want sent then answered", questions)
	}
}

func TestOnlyThisDevicesOwnSocketIsReported(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if isPhysicalUDP(a) {
		t.Fatal("a conn that is not this device's UDP socket must not be reported")
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !isPhysicalUDP(conn) {
		t.Fatal("this device's UDP socket must be reported")
	}
}

func assertNeutral(t *testing.T, events []questionEvent) {
	t.Helper()
	if len(events) != 2 || events[1].event != dialer.PhysicalDialFailed {
		t.Fatalf("events %+v, want sent then ended", events)
	}
	var netErr net.Error
	if err := events[1].err; errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("a reply that says nothing must not read as a timeout, got %v", err)
	}
}
