package provider

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/adapter"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/singledo"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/pause"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/sync/errgroup"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type extraOption struct {
	expectedStatus utils.IntRanges[uint16]
	filters        map[string]struct{}
}

type HealthCheck struct {
	ctx            context.Context
	ctxCancel      context.CancelFunc
	url            string
	extra          map[string]*extraOption
	mu             sync.Mutex
	proxies        C.ProxyList
	interval       time.Duration
	lazy           bool
	expectedStatus utils.IntRanges[uint16]
	lastTouch      atomic.TypedValue[time.Time]
	singleDo       *singledo.Single[struct{}]
	scheduledDo    *singledo.Single[struct{}]
	timeout        time.Duration
	networkRounds  networkChangeRounds
	windowMu       sync.Mutex
	windowNext     map[string]int
	failedFirst    failedNames
	forcedDo       *singledo.Single[struct{}]
	scheduledHeld  atomic.Bool
	lastScheduled  atomic.Int64
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(hc.interval)

	stopPauseTracking, tick := pause.RegisterTickerResumingOnDeviceWake(ticker, hc.untilScheduled, func() {
		if pause.IsDevicePaused() || pause.IsNetworkPaused() {
			return
		}
		if hc.lazy && time.Since(hc.lastTouch.Load()) >= hc.interval {
			log.Debugln("Skip the resume health check because we are lazy")
			return
		}
		if !hc.scheduledOverdue() {
			return
		}
		go hc.checkScheduled()
	})
	defer stopPauseTracking()

	go hc.checkScheduled()
	for {
		select {
		case <-ticker.C:
			if !tick(hc.interval) {
				continue
			}
			lastTouch := hc.lastTouch.Load()
			since := time.Since(lastTouch)
			if !hc.lazy || since < hc.interval {
				hc.checkScheduled()
			} else {
				log.Debugln("Skip once health check because we are lazy")
			}
		case <-hc.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func (hc *HealthCheck) setProxies(proxies []C.Proxy) {
	hc.setProxyList(C.ProxySlice(proxies))
}

func (hc *HealthCheck) setProxyList(proxies C.ProxyList) {
	hc.mu.Lock()
	hc.proxies = proxies
	hc.mu.Unlock()
}

func (hc *HealthCheck) snapshotProxies() C.ProxyList {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.proxies == nil {
		return C.ProxySlice(nil)
	}
	return hc.proxies
}

func (hc *HealthCheck) registerHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = time.Duration(interval) * time.Second
	}

	if hc.extra == nil {
		hc.extra = make(map[string]*extraOption)
	}

	// prioritize the use of previously registered configurations, especially those from provider
	if _, ok := hc.extra[url]; ok {
		// provider default health check does not set filter
		if url != hc.url && len(filter) != 0 {
			splitAndAddFiltersToExtra(filter, hc.extra[url])
		}

		log.Debugln("health check url: %s exists", url)
		return
	}

	option := &extraOption{filters: map[string]struct{}{}, expectedStatus: expectedStatus}
	splitAndAddFiltersToExtra(filter, option)
	hc.extra[url] = option
}

func splitAndAddFiltersToExtra(filter string, option *extraOption) {
	filter = strings.TrimSpace(filter)
	if len(filter) != 0 {
		for _, regex := range strings.Split(filter, "`") {
			regex = strings.TrimSpace(regex)
			if len(regex) != 0 {
				option.filters[regex] = struct{}{}
			}
		}
	}
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now())
}

func (hc *HealthCheck) check() {
	hc.round(hc.singleDo, time.Time{}, false)
}

func (hc *HealthCheck) round(single *singledo.Single[struct{}], scheduledSince time.Time, background bool) {
	if hc.snapshotProxies().Len() == 0 {
		return
	}

	_, _, _ = single.Do(func() (struct{}, error) {
		proxies := chosenFirst(hc.snapshotProxies(), hc.failedFirst.take()...)
		listFor := func(string) C.ProxyList { return proxies }
		if background {
			listFor = hc.windows(proxies)
		}
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b := new(errgroup.Group)
		b.SetLimit(roundConcurrency())

		// execute default health check
		option := &extraOption{filters: nil, expectedStatus: hc.expectedStatus}
		hc.execute(b, listFor(hc.url), hc.url, id, option, scheduledSince)

		// execute extra health check
		if len(hc.extra) != 0 {
			for url, option := range hc.extra {
				hc.execute(b, listFor(url), url, id, option, scheduledSince)
			}
		}
		_ = b.Wait()
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

func (hc *HealthCheck) execute(b *errgroup.Group, proxies C.ProxyList, url, uid string, option *extraOption, scheduledSince time.Time) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return
	}

	var filterReg *regexp2.Regexp
	var expectedStatus utils.IntRanges[uint16]
	if option != nil {
		expectedStatus = option.expectedStatus
		if len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for filter := range option.filters {
				filters = append(filters, filter)
			}

			filterReg = regexp2.MustCompile(strings.Join(filters, "|"), regexp2.None)
		}
	}

	for i := 0; i < proxies.Len(); i++ {
		proxy := proxies.At(i)
		// skip proxies that do not require health check
		if filterReg != nil {
			if match, _ := filterReg.MatchString(proxy.Name()); !match {
				continue
			}
		}

		p := proxy
		b.Go(func() error {
			if !scheduledSince.IsZero() && measuredAliveSince(p, url, expectedStatus.String(), hc.timeout, scheduledSince) {
				return nil
			}
			ctx := adapter.WithURLTestTimeout(adapter.WithBackgroundProbe(hc.ctx), hc.timeout)
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			if _, err := p.URLTest(ctx, url, expectedStatus); errors.Is(err, adapter.ErrURLTestDeferred) {
				log.Debugln("Health Check deferred, proxy: %s, url: %s, not measured uid: {%s}", p.Name(), url, uid)
				return nil
			}
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return nil
		})
	}
}

func (hc *HealthCheck) close() {
	hc.ctxCancel()
}

func NewHealthCheck(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	return NewHealthCheckList(C.ProxySlice(proxies), url, timeout, interval, lazy, expectedStatus)
}

func NewHealthCheckList(proxies C.ProxyList, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	if url == "" {
		expectedStatus = nil
		interval = 0
	}
	if timeout == 0 {
		timeout = 5000
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:            ctx,
		ctxCancel:      cancel,
		proxies:        proxies,
		url:            url,
		timeout:        time.Duration(timeout) * time.Millisecond,
		extra:          map[string]*extraOption{},
		interval:       time.Duration(interval) * time.Second,
		lazy:           lazy,
		expectedStatus: expectedStatus,
		singleDo:       singledo.NewSingle[struct{}](time.Second),
		scheduledDo:    singledo.NewSingle[struct{}](time.Second),
		forcedDo:       singledo.NewSingle[struct{}](time.Second),
	}
}
