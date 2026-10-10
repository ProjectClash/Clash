package adapter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
)


const sharedPatienceSlack = 100 * time.Millisecond

var errURLTestLeaderGone = errors.New("url test: the probe this one was waiting on did not finish")

type urlTestResult struct {
	delay     uint16
	satisfied bool
	status    int
}

type urlTestFlight struct {
	done chan struct{}
	patience time.Duration

	result urlTestResult
	err    error
	abandoned bool
	timedOut bool
}

type urlTestFlights struct {
	mu      sync.Mutex
	flights map[string]*urlTestFlight
	asked map[string]string
}

func urlTestFlightKey(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) string {
	class := "fg"
	if IsBackgroundProbe(ctx) {
		class = "bg"
	}
	return class + "\x00" + url + "\x00" + expectedStatus.String()
}

func patienceOf(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}

func isGroupType(kind C.AdapterType) bool {
	switch kind {
	case C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return true
	}
	return false
}

func (p *Proxy) urlTestShared(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	if isGroupType(p.Type()) {
		return p.urlTestNotingTheQuestion(ctx, url, expectedStatus)
	}
	key := urlTestFlightKey(ctx, url, expectedStatus)
	patience := patienceOf(ctx)
	for {
		p.urlTests.mu.Lock()
		flight := p.urlTests.flights[key]
		if flight == nil {
			flight = &urlTestFlight{done: make(chan struct{}), patience: patience, err: errURLTestLeaderGone, abandoned: true}
			if p.urlTests.flights == nil {
				p.urlTests.flights = make(map[string]*urlTestFlight)
			}
			p.urlTests.flights[key] = flight
			p.urlTests.mu.Unlock()
			return p.leadURLTest(ctx, key, flight, url, expectedStatus)
		}
		p.urlTests.mu.Unlock()

		select {
		case <-flight.done:
			if ctx.Err() == nil {
				if flight.abandoned {
					continue
				}
				morePatient := patience == 0 || (flight.patience != 0 && patience > flight.patience+sharedPatienceSlack)
				if flight.timedOut && morePatient {
					continue
				}
			}
			return flight.result.delay, flight.result.satisfied, flight.result.status, flight.err
		case <-ctx.Done():
			return 0, false, 0, ctx.Err()
		}
	}
}

func (p *Proxy) leadURLTest(ctx context.Context, key string, flight *urlTestFlight, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	defer func() {
		p.urlTests.mu.Lock()
		delete(p.urlTests.flights, key)
		p.urlTests.mu.Unlock()
		close(flight.done)
	}()

	t, satisfied, status, err = p.urlTestNotingTheQuestion(ctx, url, expectedStatus)

	flight.result = urlTestResult{delay: t, satisfied: satisfied, status: status}
	flight.err = err
	flight.abandoned = err != nil && errors.Is(ctx.Err(), context.Canceled)
	flight.timedOut = err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)
	return
}

func (p *Proxy) urlTestNotingTheQuestion(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	before, _, _, _ := p.LastURLTestRecord(url)
	t, satisfied, status, err = p.urlTestOnce(ctx, url, expectedStatus)
	if after, _, _, ok := p.LastURLTestRecord(url); ok && !after.Time.Equal(before.Time) {
		p.urlTests.mu.Lock()
		if p.urlTests.asked == nil {
			p.urlTests.asked = make(map[string]string)
		}
		p.urlTests.asked[url] = expectedStatus.String()
		p.urlTests.mu.Unlock()
	}
	return
}

func (p *Proxy) LastURLTestRecord(url string) (record C.DelayHistory, alive bool, expected string, ok bool) {
	state, found := p.extra.Load(url)
	if !found {
		return C.DelayHistory{}, false, "", false
	}
	history := state.history.Copy()
	if len(history) == 0 {
		return C.DelayHistory{}, false, "", false
	}
	p.urlTests.mu.Lock()
	expected = p.urlTests.asked[url]
	p.urlTests.mu.Unlock()
	return history[len(history)-1], state.alive.Load(), expected, true
}
