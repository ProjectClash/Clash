package clash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/component/ca"
	mihomoHttp "github.com/ProjectClash/Clash/component/http"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
)

const FetchThroughUnavailablePrefix = "clash: fetch through unavailable: "

const (
	fetchThroughRoute = "/fetch-through"

	fetchThroughMinimumTimeout = time.Second
	fetchThroughMaximumTimeout = 10 * time.Second
	fetchThroughMaximumBytes   = 8 << 10
	fetchThroughAnswerGrace    = 5 * time.Second
	fetchThroughRequestBytes   = 16 << 10
	fetchThroughAnswerBytes    = 256 << 10
	fetchThroughUserAgentMax   = 512
	fetchThroughURLMax         = 4 << 10
	fetchThroughProxyMax       = 1 << 10
	fetchThroughHeaderBytes    = 16 << 10
	fetchThroughGroupDepth     = 32
)

const (
	fetchThroughNotFound       = "notFound"
	fetchThroughRefused        = "refused"
	fetchThroughTimeout        = "timeout"
	fetchThroughDialFailed     = "dialFailed"
	fetchThroughRequestFailed  = "requestFailed"
	fetchThroughTooLarge       = "tooLarge"
	fetchThroughInvalidRequest = "invalidRequest"
)

type fetchThroughRequest struct {
	Proxy               string `json:"proxy"`
	URL                 string `json:"url"`
	TimeoutMilliseconds int64  `json:"timeoutMilliseconds"`
	UserAgent           string `json:"userAgent,omitempty"`
}

type fetchThroughAnswer struct {
	Status  *int     `json:"status,omitempty"`
	Body    *string  `json:"body,omitempty"`
	Chain   []string `json:"chain"`
	Failure string   `json:"failure,omitempty"`
	Message string   `json:"message,omitempty"`
}

func (r fetchThroughRequest) timeout() time.Duration {
	return time.Duration(r.TimeoutMilliseconds) * time.Millisecond
}

func (r fetchThroughRequest) validate() error {
	if r.Proxy == "" {
		return fmt.Errorf("clash: fetch through %s: no outbound named", r.URL)
	}
	if len(r.Proxy) > fetchThroughProxyMax {
		return fmt.Errorf("clash: fetch through %s: the outbound's name is %d bytes, over %d", r.URL, len(r.Proxy), fetchThroughProxyMax)
	}
	if len(r.URL) > fetchThroughURLMax {
		return fmt.Errorf("clash: fetch through: the URL is %d bytes, over %d", len(r.URL), fetchThroughURLMax)
	}
	parsed, err := url.Parse(r.URL)
	if err != nil {
		return fmt.Errorf("clash: fetch through %s: %w", r.URL, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return fmt.Errorf("clash: fetch through %s: only https URLs with a host are looked up", r.URL)
	}
	if port := parsed.Port(); port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("clash: fetch through %s: port %s is not 1-65535", r.URL, port)
		}
	}
	if parsed.User != nil {
		return fmt.Errorf("clash: fetch through %s: a URL with credentials is not looked up", r.URL)
	}
	if r.TimeoutMilliseconds < fetchThroughMinimumTimeout.Milliseconds() || r.TimeoutMilliseconds > fetchThroughMaximumTimeout.Milliseconds() {
		return fmt.Errorf("clash: fetch through %s: timeoutMilliseconds %d is outside %d-%d", r.URL, r.TimeoutMilliseconds,
			fetchThroughMinimumTimeout.Milliseconds(), fetchThroughMaximumTimeout.Milliseconds())
	}
	if len(r.UserAgent) > fetchThroughUserAgentMax || strings.ContainsFunc(r.UserAgent, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return fmt.Errorf("clash: fetch through %s: userAgent %q is not a header value", r.URL, r.UserAgent)
	}
	return nil
}

func fetchThroughFailure(failure string, chain []string, err error) fetchThroughAnswer {
	if chain == nil {
		chain = []string{}
	}
	return fetchThroughAnswer{Chain: chain, Failure: failure, Message: err.Error()}
}

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Post(prefix+fetchThroughRoute, serveFetchThrough)
		}
	})
}

func serveFetchThrough(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if local, ok := request.Context().Value(mhttp.LocalAddrContextKey).(net.Addr); !ok || local.Network() != "unix" {
		mhttp.NotFound(writer, request)
		return
	}
	var fetch fetchThroughRequest
	received, err := io.ReadAll(io.LimitReader(request.Body, fetchThroughRequestBytes))
	if err == nil {
		err = json.Unmarshal(received, &fetch)
	}
	if err != nil {
		err = fmt.Errorf("clash: fetch through: invalid request: %w", err)
	} else {
		err = fetch.validate()
	}
	if err != nil {
		writeFetchThroughAnswer(writer, fetchThroughFailure(fetchThroughInvalidRequest, nil, err))
		return
	}
	if currentCoreService() == nil {
		mhttp.Error(writer, "Clash service is not running", mhttp.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), fetch.timeout())
	defer cancel()
	writeFetchThroughAnswer(writer, runFetchThrough(ctx, fetch))
}

func writeFetchThroughAnswer(writer mhttp.ResponseWriter, answer fetchThroughAnswer) {
	encoded, err := json.Marshal(answer)
	if err != nil {
		mhttp.Error(writer, "clash: fetch through: "+err.Error(), mhttp.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = writer.Write(encoded)
}

func runFetchThrough(ctx context.Context, fetch fetchThroughRequest) fetchThroughAnswer {
	answer := fetchThroughLookup(ctx, fetch)
	via := C.Chain(answer.Chain).String()
	if via == "" {
		via = fetch.Proxy
	}
	if answer.Failure != "" {
		log.Warnln("[FetchThrough] %s via %s: %s: %s", fetch.URL, via, answer.Failure, answer.Message)
	} else {
		log.Infoln("[FetchThrough] %s via %s: HTTP %d, %d bytes", fetch.URL, via, *answer.Status, len(*answer.Body))
	}
	return answer
}

func fetchThroughLookup(ctx context.Context, fetch fetchThroughRequest) fetchThroughAnswer {
	proxy, ok := tunnel.LookupProxy(fetch.Proxy)
	if !ok {
		return fetchThroughFailure(fetchThroughNotFound, nil, fmt.Errorf("clash: fetch through %s: proxy %s not found", fetch.URL, fetch.Proxy))
	}
	target, err := url.Parse(fetch.URL)
	if err != nil {
		return fetchThroughFailure(fetchThroughInvalidRequest, nil, fmt.Errorf("clash: fetch through %s: %w", fetch.URL, err))
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	var metadata C.Metadata
	if err := metadata.SetRemoteAddress(net.JoinHostPort(target.Hostname(), port)); err != nil {
		return fetchThroughFailure(fetchThroughInvalidRequest, nil, fmt.Errorf("clash: fetch through %s: %w", fetch.URL, err))
	}
	if exit := fetchThroughExit(proxy, &metadata); fetchThroughGoesNowhere(exit.Type()) {
		return fetchThroughFailure(fetchThroughRefused, nil, fmt.Errorf("clash: fetch through %s: %s goes to %s, which does not go out", fetch.URL, fetch.Proxy, exit.Name()))
	}
	type probed struct {
		answer fetchThroughAnswer
		err    error
	}
	done := make(chan probed, 1)
	go func() {
		var result probed
		defer func() {
			if recovered := recover(); recovered != nil {
				result = probed{answer: fetchThroughFailure(fetchThroughRequestFailed, nil,
					fmt.Errorf("clash: fetch through %s via %s: panic: %v\n%s", fetch.URL, fetch.Proxy, recovered, debug.Stack()))}
			}
			done <- result
		}()
		result.err = adapter.RunAsProbe(ctx, proxy, func(ctx context.Context) error {
			result.answer = fetchThroughGet(ctx, proxy, &metadata, fetch)
			return nil
		})
	}()
	var result probed
	select {
	case result = <-done:
	case <-ctx.Done():
		select {
		case result = <-done:
		default:
			failure := fetchThroughRequestFailed
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				failure = fetchThroughTimeout
			}
			return fetchThroughFailure(failure, nil, fmt.Errorf("clash: fetch through %s via %s: %w (the probe had not finished)", fetch.URL, fetch.Proxy, ctx.Err()))
		}
	}
	answer, err := result.answer, result.err
	if err != nil {
		failure := fetchThroughRequestFailed
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			failure = fetchThroughTimeout
		}
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (waiting for a probe slot): %w", ctx.Err(), err)
		}
		return fetchThroughFailure(failure, nil, fmt.Errorf("clash: fetch through %s via %s: %w", fetch.URL, fetch.Proxy, err))
	}
	return answer
}

func fetchThroughExit(proxy C.Proxy, metadata *C.Metadata) C.Proxy {
	for range fetchThroughGroupDepth {
		next := proxy.Unwrap(metadata, false)
		if next == nil {
			break
		}
		proxy = next
	}
	return proxy
}

func fetchThroughGoesNowhere(kind C.AdapterType) bool {
	switch kind {
	case C.Reject, C.RejectDrop, C.Pass, C.PassRule, C.Rematch, C.Dns:
		return true
	}
	return false
}

func fetchThroughGet(ctx context.Context, proxy C.Proxy, metadata *C.Metadata, fetch fetchThroughRequest) fetchThroughAnswer {
	failed := func(failure string, chain []string, err error) fetchThroughAnswer {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && failure != fetchThroughTooLarge {
			failure = fetchThroughTimeout
			if !errors.Is(err, ctx.Err()) {
				err = fmt.Errorf("%w: %w", ctx.Err(), err)
			}
		}
		return fetchThroughFailure(failure, chain, fmt.Errorf("clash: fetch through %s via %s: %w", fetch.URL, fetch.Proxy, err))
	}
	connection, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		return failed(fetchThroughDialFailed, nil, err)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	chain := append([]string{}, connection.Chains()...)
	if providers := connection.ProviderChains(); len(providers) > 0 && providers[0] == "" {
		if exit, ok := tunnel.LookupProxy(C.Chain(chain).Last()); ok && fetchThroughGoesNowhere(exit.Type()) {
			return failed(fetchThroughRefused, chain, fmt.Errorf("the dial went to %s, which does not go out", exit.Name()))
		}
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return failed(fetchThroughRequestFailed, chain, err)
	}
	var dialed atomic.Bool
	transport := &mhttp.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("the lookup's one connection is used")
			}
			return connection, nil
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: fetchThroughHeaderBytes,
		TLSHandshakeTimeout:    fetchThroughMaximumTimeout,
		TLSClientConfig:        tlsConfig,
	}
	defer transport.CloseIdleConnections()
	client := &mhttp.Client{
		Transport: transport,
		CheckRedirect: func(*mhttp.Request, []*mhttp.Request) error {
			return mhttp.ErrUseLastResponse
		},
	}
	request, err := mhttp.NewRequestWithContext(ctx, mhttp.MethodGet, fetch.URL, nil)
	if err != nil {
		return failed(fetchThroughRequestFailed, chain, err)
	}
	userAgent := fetch.UserAgent
	if userAgent == "" {
		userAgent = mihomoHttp.UA()
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return failed(fetchThroughRequestFailed, chain, err)
	}
	defer response.Body.Close()
	tooLarge := fmt.Errorf("the body is larger than %d bytes", fetchThroughMaximumBytes)
	if response.ContentLength > fetchThroughMaximumBytes {
		return failed(fetchThroughTooLarge, chain, fmt.Errorf("%w (Content-Length %d)", tooLarge, response.ContentLength))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, fetchThroughMaximumBytes+1))
	if err != nil {
		return failed(fetchThroughRequestFailed, chain, err)
	}
	if len(body) > fetchThroughMaximumBytes {
		return failed(fetchThroughTooLarge, chain, tooLarge)
	}
	status, text := response.StatusCode, strings.ToValidUTF8(string(body), "�")
	return fetchThroughAnswer{Status: &status, Body: &text, Chain: chain}
}

func (c *APIClient) FetchThrough(requestJSON string) (string, error) {
	answer, err := recoverAppCall("FetchThrough", func() (string, error) {
		return c.fetchThrough(requestJSON)
	})
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) fetchThrough(requestJSON string) (string, error) {
	var fetch fetchThroughRequest
	err := json.Unmarshal([]byte(requestJSON), &fetch)
	if err != nil {
		err = fmt.Errorf("clash: fetch through: invalid request: %w", err)
	} else {
		err = fetch.validate()
	}
	if err != nil {
		return encodeFetchThroughAnswer(fetchThroughFailure(fetchThroughInvalidRequest, nil, err))
	}
	payload, err := json.Marshal(fetch)
	if err != nil {
		return "", fmt.Errorf("%s%s: %w", FetchThroughUnavailablePrefix, fetch.URL, err)
	}
	if len(payload) > fetchThroughRequestBytes {
		return encodeFetchThroughAnswer(fetchThroughFailure(fetchThroughInvalidRequest, nil,
			fmt.Errorf("clash: fetch through: the request is %d bytes written, over %d", len(payload), fetchThroughRequestBytes)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetch.timeout()+fetchThroughAnswerGrace)
	defer cancel()
	path := c.privatePath(fetchThroughRoute)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("%s%s: %w", FetchThroughUnavailablePrefix, fetch.URL, err)
	}
	request.Host = "localhost"
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s%s: the Extension did not answer on %s: %w", FetchThroughUnavailablePrefix, fetch.URL, c.socketPath, err)
	}
	defer response.Body.Close()
	received, err := io.ReadAll(io.LimitReader(response.Body, fetchThroughAnswerBytes))
	if err != nil {
		return "", fmt.Errorf("%s%s: the Extension's answer was cut off: %w", FetchThroughUnavailablePrefix, fetch.URL, err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s%s: HTTP %d from %s: %s", FetchThroughUnavailablePrefix, fetch.URL, response.StatusCode, path, strings.TrimSpace(string(received)))
	}
	var answer fetchThroughAnswer
	if err := json.Unmarshal(received, &answer); err != nil || answer.Chain == nil {
		return "", fmt.Errorf("%s%s: the Extension's answer is not a lookup's: %q", FetchThroughUnavailablePrefix, fetch.URL, received)
	}
	return string(received), nil
}

func encodeFetchThroughAnswer(answer fetchThroughAnswer) (string, error) {
	encoded, err := json.Marshal(answer)
	if err != nil {
		return "", fmt.Errorf("clash: fetch through: %w", err)
	}
	return string(encoded), nil
}
