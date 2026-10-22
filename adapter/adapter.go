package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProjectClash/Clash/component/dialer"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/queue"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/ca"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	"github.com/metacubex/http"
)

var UnifiedDelay = atomic.NewBool(false)

const (
	defaultHistoriesNum = 10
)

type internalProxyState struct {
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
	asked   string
}

type Proxy struct {
	C.ProxyAdapter
	alive   atomic.Bool
	history nodeHistory
	extra   proxyStates
	now func() time.Time
	urlTests urlTestFlights
	clashRecorded func(url string, record C.DelayHistory, alive bool, urlRecord C.DelayHistory, urlAlive bool, asked string)
}

type URLTestOutcome struct {
	Delay      uint16
	Satisfied  bool
	HTTPStatus int
}

type URLTestOutcomeProvider interface {
	URLTestOutcome(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (URLTestOutcome, error)
}

// Adapter implements C.Proxy
func (p *Proxy) Adapter() C.ProxyAdapter {
	return p.ProxyAdapter
}

// AliveForTestUrl implements C.Proxy
func (p *Proxy) AliveForTestUrl(url string) bool {
	if state, ok := p.extra.Load(url); ok {
		return state.alive.Load()
	}

	return p.alive.Load()
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata)
	return conn, err
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata)
	return pc, err
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queueM := p.history.Copy()
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// DelayHistoryForTestUrl implements C.Proxy
func (p *Proxy) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	var queueM []C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		queueM = state.history.Copy()
	}
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// ExtraDelayHistories return all delay histories for each test URL
// implements C.Proxy
func (p *Proxy) ExtraDelayHistories() map[string]C.ProxyState {
	histories := map[string]C.ProxyState{}

	p.extra.Range(func(k string, v *internalProxyState) bool {
		testUrl := k
		state := v

		queueM := state.history.Copy()
		var history []C.DelayHistory

		for _, item := range queueM {
			history = append(history, item)
		}

		histories[testUrl] = C.ProxyState{
			Alive:   state.alive.Load(),
			History: history,
		}
		return true
	})
	return histories
}

// LastDelayForTestUrl return last history record of the specified URL. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelayForTestUrl(url string) (delay uint16) {
	var maxDelay uint16 = 0xffff

	alive := false
	var history C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		alive = state.alive.Load()
		history = state.history.Last()
	}

	if !alive || history.Delay == 0 {
		return maxDelay
	}
	return history.Delay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	if b, ok, err := p.clashAppendJSON(nil); ok {
		return b, err
	}
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistories()
	mapping["alive"] = p.alive.Load()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["uot"] = p.SupportUOT()

	proxyInfo := p.ProxyInfo()
	mapping["xudp"] = proxyInfo.XUDP
	mapping["tfo"] = proxyInfo.TFO
	mapping["mptcp"] = proxyInfo.MPTCP
	mapping["smux"] = proxyInfo.SMUX
	mapping["interface"] = proxyInfo.Interface
	mapping["routing-mark"] = proxyInfo.RoutingMark
	mapping["provider-name"] = proxyInfo.ProviderName
	mapping["dialer-proxy"] = proxyInfo.DialerProxy

	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
func (p *Proxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, err error) {
	t, _, _, err = p.urlTest(ctx, url, expectedStatus)
	return t, err
}

func (p *Proxy) URLTestOutcome(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (URLTestOutcome, error) {
	t, satisfied, status, err := p.urlTest(ctx, url, expectedStatus)
	return URLTestOutcome{Delay: t, Satisfied: satisfied, HTTPStatus: status}, err
}

func (p *Proxy) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

var urlTestAdmission = atomic.NewTypedValue[func(ctx context.Context) (func(), error)](nil)

var ErrURLTestDeferred = errors.New("url test deferred: memory admission")

func SetURLTestAdmission(f func(ctx context.Context) error) {
	if f == nil {
		urlTestAdmission.Store(nil)
		return
	}
	urlTestAdmission.Store(func(ctx context.Context) (func(), error) { return nil, f(ctx) })
}

func SetURLTestGate(f func(ctx context.Context) (func(), error)) {
	urlTestAdmission.Store(f)
}

var urlTestFinished = atomic.NewTypedValue[func(ctx context.Context, proxy *Proxy)](nil)

func SetURLTestFinished(f func(ctx context.Context, proxy *Proxy)) {
	urlTestFinished.Store(f)
}

type backgroundProbeKey struct{}

func WithBackgroundProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundProbeKey{}, true)
}

func IsBackgroundProbe(ctx context.Context) bool {
	v, _ := ctx.Value(backgroundProbeKey{}).(bool)
	return v
}

type urlTestTimeoutKey struct{}

func WithURLTestTimeout(ctx context.Context, timeout time.Duration) context.Context {
	return context.WithValue(ctx, urlTestTimeoutKey{}, timeout)
}

func urlTestTimeoutOf(ctx context.Context) (time.Duration, bool) {
	timeout, ok := ctx.Value(urlTestTimeoutKey{}).(time.Duration)
	return timeout, ok
}

func (p *Proxy) urlTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	return p.urlTestShared(ctx, url, expectedStatus)
}

func (p *Proxy) urlTestOnce(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	defer func() {
		alive := err == nil
		record := C.DelayHistory{Time: time.Now()}
		if alive {
			record.Delay = t
		}

		p.alive.Store(alive)
		historyRecord, historyAlive := record, alive
		p.history.Put(record)
		if p.history.Len() > defaultHistoriesNum {
			p.history.Pop()
		}

		state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState {
			return &internalProxyState{
				history: queue.New[C.DelayHistory](defaultHistoriesNum),
				alive:   atomic.NewBool(true),
			}
		})

		if !satisfied {
			record.Delay = 0
			alive = false
		}

		state.alive.Store(alive)
		state.history.Put(record)
		if state.history.Len() > defaultHistoriesNum {
			state.history.Pop()
		}

		if p.clashRecorded != nil {
			p.clashRecorded(url, historyRecord, historyAlive, record, alive, expectedStatus.String())
		}
	}()

	unifiedDelay := UnifiedDelay.Load()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := p.clock()
	instance, err := p.DialContext(dialer.WithDialKind(ctx, dialer.DialKindProbe), &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return
	}

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	defer client.CloseIdleConnections()

	resp, err := client.Do(req)

	if err != nil {
		err = fmt.Errorf("%s: %w", url, err)
		return
	}

	_ = resp.Body.Close()

	if unifiedDelay {
		second := p.clock()
		var ignoredErr error
		var secondResp *http.Response
		secondResp, ignoredErr = client.Do(req)
		if ignoredErr == nil {
			resp = secondResp
			_ = resp.Body.Close()
			start = second
		} else {
			if strings.HasPrefix(url, "http://") {
				log.Errorln("%s failed to get the second response from %s: %v", p.Name(), url, ignoredErr)
				log.Warnln("It is recommended to use HTTPS for provider.health-check.url and group.url to ensure better reliability. Due to some proxy providers hijacking test addresses and not being compatible with repeated HEAD requests, using HTTP may result in failed tests.")
			}
		}
	}

	satisfied = resp != nil && (expectedStatus == nil || expectedStatus.Check(uint16(resp.StatusCode)))
	if resp != nil {
		status = resp.StatusCode
	}
	t = uint16(p.clock().Sub(start) / time.Millisecond)
	if t == 0 {
		// a zero delay means a failed test to callers, so report a test
		// that completed in under a millisecond as 1 ms
		t = 1
	}
	return
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{
		ProxyAdapter: adapter,
		alive:        atomic.NewBool(true),
	}
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	err = addr.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port))
	return
}
