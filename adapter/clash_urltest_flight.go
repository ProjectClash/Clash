package adapter

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/adapter/outbound"
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
	running chan struct{}
	patience time.Duration

	result urlTestResult
	err    error
	abandoned bool
	timedOut bool
}

type urlTestFlights struct {
	mu sync.Mutex
	flights map[string]*urlTestFlight
}

func urlTestFlightKey(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) string {
	class := "fg"
	if IsBackgroundProbe(ctx) {
		class = "bg"
	}
	return class + "\x00" + url + "\x00" + expectedStatus.String()
}

func patienceOf(ctx context.Context) time.Duration {
	timeout, carried := urlTestTimeoutOf(ctx)
	deadline, ok := ctx.Deadline()
	switch {
	case !ok && !carried:
		return 0
	case !ok:
		return timeout
	}
	if untilDeadline := time.Until(deadline); !carried || untilDeadline < timeout {
		return untilDeadline
	}
	return timeout
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
		t, satisfied, status, err, _ = p.urlTestAdmitted(ctx, url, expectedStatus, nil)
		return
	}
	key := urlTestFlightKey(ctx, url, expectedStatus)
	for {
		patience := patienceOf(ctx)
		p.urlTests.mu.Lock()
		flight := p.urlTests.flights[key]
		if flight == nil {
			flight = &urlTestFlight{done: make(chan struct{}), running: make(chan struct{}), patience: patience, err: errURLTestLeaderGone, abandoned: true}
			if p.urlTests.flights == nil {
				p.urlTests.flights = make(map[string]*urlTestFlight)
			}
			p.urlTests.flights[key] = flight
			p.urlTests.mu.Unlock()
			return p.leadURLTest(ctx, key, flight, url, expectedStatus)
		}
		p.urlTests.mu.Unlock()

		spent, err := awaitFlight(ctx, flight)
		if err != nil {
			return 0, false, 0, err
		}
		if ctx.Err() == nil {
			morePatient := patience == 0 || (flight.patience != 0 && patience > flight.patience+sharedPatienceSlack)
			if flight.abandoned || (flight.timedOut && morePatient) {
				if timeout, carried := urlTestTimeoutOf(ctx); carried && spent > 0 {
					if spent >= timeout {
						return 0, false, 0, context.DeadlineExceeded
					}
					ctx = WithURLTestTimeout(ctx, timeout-spent)
				}
				continue
			}
		}
		return flight.result.delay, flight.result.satisfied, flight.result.status, flight.err
	}
}

func awaitFlight(ctx context.Context, flight *urlTestFlight) (spent time.Duration, err error) {
	var running <-chan struct{}
	timeout, carried := urlTestTimeoutOf(ctx)
	if carried {
		running = flight.running
	}
	var started time.Time
	var expired <-chan time.Time
	for {
		select {
		case <-flight.done:
			if !started.IsZero() {
				spent = time.Since(started)
			}
			return spent, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-running:
			running = nil
			started = time.Now()
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			expired = timer.C
		case <-expired:
			return timeout, context.DeadlineExceeded
		}
	}
}

func (p *Proxy) leadURLTest(ctx context.Context, key string, flight *urlTestFlight, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	defer func() {
		p.urlTests.mu.Lock()
		delete(p.urlTests.flights, key)
		if len(p.urlTests.flights) == 0 {
			p.urlTests.flights = nil
		}
		p.urlTests.mu.Unlock()
		close(flight.done)
	}()

	var timedOut bool
	t, satisfied, status, err, timedOut = p.urlTestAdmitted(ctx, url, expectedStatus, func() { close(flight.running) })

	flight.result = urlTestResult{delay: t, satisfied: satisfied, status: status}
	flight.err = err
	flight.abandoned = err != nil && errors.Is(ctx.Err(), context.Canceled)
	flight.timedOut = timedOut
	return
}

func (p *Proxy) urlTestAdmitted(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16], admitted func()) (t uint16, satisfied bool, status int, err error, timedOut bool) {
	if admit := urlTestAdmission.Load(); admit != nil {
		var end func()
		if end, err = admit(ctx); err != nil {
			return 0, false, 0, err, errors.Is(ctx.Err(), context.DeadlineExceeded)
		}
		if end != nil {
			defer end()
		}
	}
	if finished := urlTestFinished.Load(); finished != nil {
		ctx = outbound.WithProbeDials(ctx)
		defer finished(ctx, p)
	}
	if admitted != nil {
		admitted()
	}
	probeCtx := ctx
	if timeout, ok := urlTestTimeoutOf(ctx); ok {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	t, satisfied, status, err = p.urlTestNotingTheQuestion(probeCtx, url, expectedStatus)
	return t, satisfied, status, err, err != nil && errors.Is(probeCtx.Err(), context.DeadlineExceeded)
}

func (p *Proxy) urlTestNotingTheQuestion(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	before, _, _, _ := p.LastURLTestRecord(url)
	t, satisfied, status, err = p.urlTestOnce(ctx, url, expectedStatus)
	if after, _, _, ok := p.LastURLTestRecord(url); ok && !after.Time.Equal(before.Time) {
		if state, found := p.extra.Load(url); found {
			p.urlTests.mu.Lock()
			state.asked = expectedStatus.String()
			p.urlTests.mu.Unlock()
		}
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
	expected = state.asked
	p.urlTests.mu.Unlock()
	return history[len(history)-1], state.alive.Load(), expected, true
}
