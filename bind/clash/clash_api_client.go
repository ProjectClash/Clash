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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
)

const (
	clashAPIRequestTimeout   = 15 * time.Second
	clashAPIDialAttempts     = 10
	clashAPIMaxMessageSize   = 16 << 20
	clashAPIProviderIndexTTL = time.Minute
)

const (
	CommandLog int32 = iota
	CommandStatus
	CommandConnections
	CommandMode
	CommandConnectionEvents
)

type ConnectionEventsWriter interface {
	WriteConnectionEvents(message string)
}

type APIClientOptions struct {
	LogLevel            string
	StatusInterval      int64
	OnlyStatisticsProxy bool
	commands            []int32
}

func (o *APIClientOptions) AddCommand(command int32) {
	if o == nil {
		return
	}
	o.commands = append(o.commands, command)
}

type APIClientHandler interface {
	Connected()
	Disconnected(message string)
	WriteTraffic(message string)
	WriteMemory(message string)
	WriteLogs(message string)
	WriteConnections(message string)
	WriteMode(message string)
}

type clashAPIStream struct {
	path    string
	write   func(string)
	conn    *websocket.Conn
	client  *APIClient
	retired atomic.Bool
}

type clashAPISession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	streams   []*clashAPIStream
	wg        sync.WaitGroup
	done      chan struct{}
	closing   bool
	connected bool
	ready     bool
	cause     error
}

type APIClient struct {
	mu         sync.Mutex
	socketPath string
	handler    APIClientHandler
	httpClient *http.Client
	session    *clashAPISession
	options    APIClientOptions

	scopeMu             sync.Mutex
	onlyStatisticsProxy atomic.Bool

	connectionEvents atomic.Pointer[ConnectionEventsWriter]

	providerIndexMu sync.Mutex
	providerIndex   map[string]string
	providerIndexAt time.Time
}

func NewAPIClient(socketPath string, handler APIClientHandler) (*APIClient, error) {
	options := &APIClientOptions{}
	options.AddCommand(CommandStatus)
	options.AddCommand(CommandLog)
	bridgedValue0, bridgedErr := NewAPIClientWithOptions(socketPath, handler, options)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func NewAPIClientWithOptions(socketPath string, handler APIClientHandler, options *APIClientOptions) (*APIClient, error) {
	out, err := recoverAppCall("NewAPIClientWithOptions", func() (*APIClient, error) {
		return newAPIClientWithOptionsUnguarded(socketPath, handler, options)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func newAPIClientWithOptionsUnguarded(socketPath string, handler APIClientHandler, options *APIClientOptions) (*APIClient, error) {
	if socketPath == "" {
		return nil, bridgeSafeError(errors.New("clash: Clash API client requires a Unix socket path"))
	}
	if len([]byte(socketPath)) > clashAPIMaxUnixPathBytes {
		return nil, bridgeSafeError(fmt.Errorf("clash: Clash API Unix path is %d bytes; Darwin limit is %d", len([]byte(socketPath)), clashAPIMaxUnixPathBytes))
	}
	if handler == nil {
		return nil, bridgeSafeError(errors.New("clash: Clash API client requires a handler"))
	}
	handler = bridgeSafeClashHandler(handler)
	if options == nil {
		options = &APIClientOptions{}
		options.AddCommand(CommandStatus)
		options.AddCommand(CommandLog)
	}
	clientOptions := APIClientOptions{
		LogLevel:            options.LogLevel,
		StatusInterval:      options.StatusInterval,
		OnlyStatisticsProxy: options.OnlyStatisticsProxy,
		commands:            append([]int32(nil), options.commands...),
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	client := &APIClient{
		socketPath: socketPath,
		handler:    handler,
		httpClient: &http.Client{Transport: transport},
		options:    clientOptions,
	}
	client.onlyStatisticsProxy.Store(clientOptions.OnlyStatisticsProxy)
	return client, nil
}

func (c *APIClient) Connect() error {
	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		return bridgeSafeError(errors.New("clash: Clash API client already connecting, connected, or closing"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &clashAPISession{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	session.wg.Add(1)
	c.session = session
	c.mu.Unlock()

	go c.completeSession(session)
	err := c.connectSession(session)
	if err != nil {
		c.finish(session, err)
	}
	session.wg.Done()
	if err != nil {
		<-session.done
	}
	return bridgeSafeError(err)
}

func (c *APIClient) connectSession(session *clashAPISession) error {
	streamSpecs, err := c.streamSpecs(session.ctx)
	if err != nil {
		return err
	}
	if len(streamSpecs) == 0 {
		if err := c.probeWithRetry(session.ctx); err != nil {
			return err
		}
	}
	for _, spec := range streamSpecs {
		path := spec.path
		conn, err := c.dialWebSocketWithRetry(session.ctx, path)
		if err != nil {
			return err
		}
		conn.SetReadLimit(clashAPIMaxMessageSize)
		c.mu.Lock()
		if session.closing {
			c.mu.Unlock()
			conn.CloseNow()
			return session.ctx.Err()
		}
		session.streams = append(session.streams, &clashAPIStream{
			path: path, write: spec.write, conn: conn, client: c,
		})
		c.mu.Unlock()
	}

	c.mu.Lock()
	if session.closing {
		c.mu.Unlock()
		return session.ctx.Err()
	}
	session.connected = true
	c.mu.Unlock()
	c.handler.Connected()

	c.mu.Lock()
	if session.closing {
		c.mu.Unlock()
		return session.ctx.Err()
	}
	session.ready = true
	streams := append([]*clashAPIStream(nil), session.streams...)
	session.wg.Add(len(streams))
	c.mu.Unlock()
	for _, stream := range streams {
		go stream.read(session)
	}
	return nil
}

func (c *APIClient) completeSession(session *clashAPISession) {
	<-session.ctx.Done()
	session.wg.Wait()
	c.mu.Lock()
	connected, cause := session.connected, session.cause
	c.mu.Unlock()
	if connected {
		message := ""
		if cause != nil {
			message = cause.Error()
		}
		c.handler.Disconnected(message)
	}
	c.mu.Lock()
	if c.session == session {
		c.session = nil
	}
	close(session.done)
	c.mu.Unlock()
}

type clashAPIStreamSpec struct {
	path          string
	write         func(string)
	privateSuffix string
}

func (c *APIClient) streamSpecs(ctx context.Context) ([]clashAPIStreamSpec, error) {
	var specs []clashAPIStreamSpec
	seen := make(map[int32]bool)
	for _, command := range c.options.commands {
		if seen[command] {
			continue
		}
		seen[command] = true
		switch command {
		case CommandLog:
			level := strings.ToLower(strings.TrimSpace(c.options.LogLevel))
			if level == "" {
				level = "info"
			}
			switch level {
			case "debug", "info", "warning", "error", "silent":
			default:
				return nil, fmt.Errorf("clash: invalid Clash API log level %q", c.options.LogLevel)
			}
			specs = append(specs, clashAPIStreamSpec{
				path:  "/logs?" + url.Values{"level": []string{level}}.Encode(),
				write: c.handler.WriteLogs,
			})
		case CommandStatus:
			specs = append(specs,
				clashAPIStreamSpec{
					path:  trafficStreamPath(c.onlyStatisticsProxy.Load()),
					write: c.handler.WriteTraffic,
				},
				clashAPIStreamSpec{path: "/memory", write: c.enrichMemoryFrames(ctx, c.handler.WriteMemory)},
			)
		case CommandMode:
			specs = append(specs, clashAPIStreamSpec{
				path:          c.privatePath("/mode"),
				privateSuffix: "/mode",
				write:         c.handler.WriteMode,
			})
		case CommandConnections:
			interval, err := c.connectionsInterval()
			if err != nil {
				return nil, err
			}
			specs = append(specs, clashAPIStreamSpec{
				path:  "/connections?" + url.Values{"interval": []string{fmt.Sprint(interval)}}.Encode(),
				write: c.handler.WriteConnections,
			})
		case CommandConnectionEvents:
			writer := c.connectionEvents.Load()
			if writer == nil {
				return nil, errors.New("clash: CommandConnectionEvents needs SetConnectionEventsWriter before Connect")
			}
			interval, err := c.connectionsInterval()
			if err != nil {
				return nil, err
			}
			suffix := "/connections/events?" + url.Values{"interval": []string{fmt.Sprint(interval)}}.Encode()
			specs = append(specs, clashAPIStreamSpec{
				path:          c.privatePath(suffix),
				privateSuffix: suffix,
				write:         (*writer).WriteConnectionEvents,
			})
		default:
			return nil, fmt.Errorf("clash: unknown Clash API command %d", command)
		}
	}
	return specs, nil
}

func (c *APIClient) connectionsInterval() (int64, error) {
	interval := c.options.StatusInterval
	if interval == 0 {
		interval = 1000
	}
	if interval < 100 || interval > 60_000 {
		return 0, fmt.Errorf("clash: connections interval %dms is outside 100...60000", interval)
	}
	return interval, nil
}

func (c *APIClient) SetConnectionEventsWriter(writer ConnectionEventsWriter) {
	if writer == nil {
		c.connectionEvents.Store(nil)
		return
	}
	writer = bridgeSafeConnectionEvents(writer)
	c.connectionEvents.Store(&writer)
}

func trafficStreamPath(onlyProxy bool) string {
	if onlyProxy {
		return "/traffic?" + url.Values{"only-proxy": []string{"true"}}.Encode()
	}
	return "/traffic"
}

func (c *APIClient) SetOnlyStatisticsProxy(enabled bool) error {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.onlyStatisticsProxy.Load() == enabled {
		return nil
	}

	c.mu.Lock()
	session := c.session
	if session != nil && (!session.ready || session.closing) {
		c.mu.Unlock()
		return bridgeSafeError(errors.New("clash: control session is connecting or closing"))
	}
	var current *clashAPIStream
	if session != nil {
		for _, stream := range session.streams {
			if strings.HasPrefix(stream.path, "/traffic") {
				current = stream
				break
			}
		}
	}
	if current == nil {
		c.onlyStatisticsProxy.Store(enabled)
		c.mu.Unlock()
		return nil
	}
	session.wg.Add(1)
	c.mu.Unlock()
	defer session.wg.Done()

	path := trafficStreamPath(enabled)
	conn, err := c.dialWebSocketWithRetry(session.ctx, path)
	if err != nil {
		return bridgeSafeError(fmt.Errorf("clash: re-subscribe %s: %w", path, err))
	}
	conn.SetReadLimit(clashAPIMaxMessageSize)
	c.mu.Lock()
	if c.session != session || session.closing {
		c.mu.Unlock()
		conn.CloseNow()
		return bridgeSafeError(errors.New("clash: control session changed while re-subscribing traffic"))
	}
	index := -1
	for position, stream := range session.streams {
		if stream == current {
			index = position
			break
		}
	}
	if index < 0 {
		c.mu.Unlock()
		conn.CloseNow()
		return bridgeSafeError(errors.New("clash: traffic stream disappeared while re-subscribing"))
	}
	replacement := &clashAPIStream{path: path, write: current.write, conn: conn, client: c}
	session.streams[index] = replacement
	current.retired.Store(true)
	c.onlyStatisticsProxy.Store(enabled)
	session.wg.Add(1)
	c.mu.Unlock()
	current.conn.CloseNow()
	go replacement.read(session)
	return nil
}

func (c *APIClient) probeWithRetry(ctx context.Context) error {
	var lastErr error
	for attempt := 0; attempt < clashAPIDialAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, clashAPIClientDialDelay(attempt))
		_, lastErr = c.requestWithContext(attemptCtx, http.MethodGet, "/", nil)
		cancel()
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(clashAPIClientDialDelay(attempt)):
		}
	}
	return fmt.Errorf("clash: probe Clash API: %w", lastErr)
}

func (c *APIClient) dialWebSocketWithRetry(ctx context.Context, path string) (*websocket.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < clashAPIDialAttempts; attempt++ {
		dialCtx, cancel := context.WithTimeout(ctx, clashAPIClientDialDelay(attempt))
		conn, response, err := websocket.Dial(dialCtx, "ws://localhost"+path, &websocket.DialOptions{
			HTTPClient: c.httpClient,
			Host:       "localhost",
		})
		cancel()
		if err == nil {
			return conn, nil
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if response != nil && response.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("clash: connect Clash API stream %s: HTTP %d: %w", path, response.StatusCode, err)
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(clashAPIClientDialDelay(attempt)):
		}
	}
	return nil, fmt.Errorf("clash: connect Clash API stream %s: %w", path, lastErr)
}

func clashAPIClientDialDelay(attempt int) time.Duration {
	return 100*time.Millisecond + time.Duration(attempt)*50*time.Millisecond
}

func (s *clashAPIStream) read(session *clashAPISession) {
	defer session.wg.Done()
	defer s.conn.CloseNow()
	for {
		messageType, payload, err := s.conn.Read(session.ctx)
		if err != nil {
			if s.retired.Load() {
				return
			}
			if session.ctx.Err() == nil {
				s.client.finish(session, fmt.Errorf("%s stream: %w", s.path, err))
			}
			return
		}
		if messageType != websocket.MessageText || !json.Valid(payload) {
			s.client.finish(session, fmt.Errorf("%s stream returned invalid JSON text", s.path))
			return
		}
		if session.ctx.Err() != nil {
			return
		}
		s.write(string(payload))
	}
}

func (c *APIClient) finish(session *clashAPISession, cause error) {
	c.mu.Lock()
	if session.closing {
		c.mu.Unlock()
		return
	}
	session.wg.Add(1)
	defer session.wg.Done()
	session.closing = true
	session.cause = cause
	streams := append([]*clashAPIStream(nil), session.streams...)
	session.cancel()
	c.mu.Unlock()
	for _, stream := range streams {
		stream.conn.CloseNow()
	}
}

func (c *APIClient) Close() {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return
	}
	c.finish(session, nil)
	<-session.done
}

func (c *APIClient) request(method, path string, body any) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clashAPIRequestTimeout)
	defer cancel()
	return c.requestWithContext(ctx, method, path, body)
}

func (c *APIClient) requestAllowingStatus(method, path string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clashAPIRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, nil)
	if err != nil {
		return 0, "", fmt.Errorf("clash: build Clash API request %s: %w", path, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return 0, "", fmt.Errorf("clash: Clash API %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return response.StatusCode, "", fmt.Errorf("clash: read Clash API %s: %w", path, err)
	}
	if len(payload) > clashAPIMaxMessageSize {
		return response.StatusCode, "", fmt.Errorf("clash: Clash API %s response exceeds %d bytes", path, clashAPIMaxMessageSize)
	}
	return response.StatusCode, string(payload), nil
}

func (c *APIClient) requestWithContext(ctx context.Context, method, path string, body any) (string, error) {
	errorEndpoint := path
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("clash: encode Clash API request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reader)
	if err != nil {
		return "", fmt.Errorf("clash: build Clash API request %s: %w", errorEndpoint, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("clash: Clash API %s %s: %w", method, errorEndpoint, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return "", fmt.Errorf("clash: read Clash API %s: %w", errorEndpoint, err)
	}
	if len(payload) > clashAPIMaxMessageSize {
		return "", fmt.Errorf("clash: Clash API %s response exceeds %d bytes", errorEndpoint, clashAPIMaxMessageSize)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("clash: Clash API %s %s: HTTP %d: %s", method, errorEndpoint, response.StatusCode, strings.TrimSpace(string(payload)))
	}
	if len(payload) > 0 && !json.Valid(payload) {
		return "", fmt.Errorf("clash: Clash API %s returned invalid JSON", errorEndpoint)
	}
	return string(payload), nil
}

func (c *APIClient) GetConfigs() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/configs", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetTraffic() (string, error) {
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, "/traffic", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetMemory() (string, error) {
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, "/memory", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) ExplainDNS(domain string, qType string, probe bool) (string, error) {
	if strings.TrimSpace(domain) == "" {
		return "", bridgeSafeError(errors.New("clash: explain DNS requires a domain"))
	}
	query := url.Values{"domain": []string{domain}}
	if trimmed := strings.TrimSpace(qType); trimmed != "" {
		query.Set("type", trimmed)
	}
	if probe {
		query.Set("probe", "1")
	}
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, "/dns/explain?"+query.Encode(), nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetRules() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/rules", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) QueryDNS(name, qType string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "\t\r\n /?#") {
		return "", bridgeSafeError(errors.New("clash: DNS query requires a valid name"))
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return "", bridgeSafeError(errors.New("clash: DNS query requires a valid name"))
	}
	qType = strings.ToUpper(strings.TrimSpace(qType))
	if qType == "" {
		qType = "A"
	}
	if _, ok := dns.StringToType[qType]; !ok {
		return "", bridgeSafeError(errors.New("clash: DNS query requires a valid type"))
	}
	query := url.Values{"name": []string{name}, "type": []string{qType}}
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/dns/query?"+query.Encode(), nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) ScriptDNSQuery(requestJSON string) (string, error) {
	if len(requestJSON) > scriptDNSRequestLimit {
		return "", bridgeSafeError(fmt.Errorf("clash: script DNS query request exceeds %d bytes", scriptDNSRequestLimit))
	}
	ctx, cancel := context.WithTimeout(context.Background(), scriptDNSLongestCall+5*time.Second)
	defer cancel()
	path := c.privatePath("/dns/script-query")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+path, strings.NewReader(requestJSON))
	if err != nil {
		return "", bridgeSafeError(fmt.Errorf("clash: build Clash API request %s: %w", path, err))
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", bridgeSafeError(fmt.Errorf("clash: Clash API %s %s: %w", http.MethodPost, path, err))
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return "", bridgeSafeError(fmt.Errorf("clash: read Clash API %s: %w", path, err))
	}
	if len(payload) > clashAPIMaxMessageSize {
		return "", bridgeSafeError(fmt.Errorf("clash: Clash API %s response exceeds %d bytes", path, clashAPIMaxMessageSize))
	}
	if response.StatusCode != http.StatusOK {
		return "", bridgeSafeError(fmt.Errorf("clash: Clash API %s %s: HTTP %d: %s", http.MethodPost, path, response.StatusCode, strings.TrimSpace(string(payload))))
	}
	return bridgeSafeString(string(payload)), nil
}

func (c *APIClient) FlushDNSCache() error {
	_, err := c.request(http.MethodPost, "/cache/dns/flush", nil)
	return bridgeSafeError(err)
}

func (c *APIClient) FlushFakeIPCache() error {
	_, err := c.request(http.MethodPost, "/cache/fakeip/flush", nil)
	return bridgeSafeError(err)
}

func (c *APIClient) GetProxies() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/proxies", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetGroups() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/group", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetVersion() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/version", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetConnections() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/connections", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) CloseConnection(id string) error {
	if id == "" {
		return bridgeSafeError(errors.New("clash: close connection requires an id"))
	}
	_, err := c.request(http.MethodDelete, "/connections/"+url.PathEscape(id), nil)
	return bridgeSafeError(err)
}

func (c *APIClient) CloseConnections() error {
	_, err := c.request(http.MethodDelete, "/connections", nil)
	return bridgeSafeError(err)
}

func (c *APIClient) GetConfigDeviations() (string, error) {
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, "/deviations", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetProxyShareStatus() (string, error) {
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, "/proxy-share", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) StartProxyShare(port int32, username, password string) error {
	if _, err := newProxyShareConfiguration(port, username, password); err != nil {
		return bridgeSafeError(err)
	}
	_, err := c.privateRequest(http.MethodPut, "/proxy-share", proxyShareRequest{
		Port:     port,
		Username: username,
		Password: password,
	})
	return bridgeSafeError(err)
}

func (c *APIClient) StopProxyShare() error {
	_, err := c.privateRequest(http.MethodDelete, "/proxy-share", nil)
	return bridgeSafeError(err)
}

func (c *APIClient) SetMode(mode string) error {
	normalized := strings.ToLower(mode)
	switch normalized {
	case "rule", "global", "direct":
	default:
		return bridgeSafeError(fmt.Errorf("clash: unknown mode %q", mode))
	}
	_, err := c.privateRequest(http.MethodPatch, "/configs/mode", map[string]string{"mode": normalized})
	return bridgeSafeError(err)
}

func (c *APIClient) SelectProxy(group, name string) error {
	if group == "" || name == "" {
		return bridgeSafeError(errors.New("clash: select proxy requires group and name"))
	}
	_, err := c.request(
		http.MethodPut,
		"/proxies/"+url.PathEscape(group),
		map[string]string{"name": name},
	)
	return bridgeSafeError(err)
}

func (c *APIClient) UnfixProxy(group string) error {
	if group == "" {
		return bridgeSafeError(errors.New("clash: unfix proxy requires a group"))
	}
	_, err := c.request(
		http.MethodDelete,
		"/proxies/"+url.PathEscape(group),
		nil,
	)
	return bridgeSafeError(err)
}

func (c *APIClient) GetProxyProviders() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/providers/proxies", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetProxyProvider(name string) (string, error) {
	if !validProviderSideUpdateName(name) {
		return "", bridgeSafeError(errors.New("clash: proxy provider detail requires a valid name"))
	}
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/providers/proxies/"+url.PathEscape(name), nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) HealthCheckProxyProvider(name string) error {
	if !validProviderSideUpdateName(name) {
		return bridgeSafeError(errors.New("clash: proxy provider health check requires a valid name"))
	}
	_, err := c.request(http.MethodPost, privateAPIPrefix+"/providers/health-check?name="+url.QueryEscape(name), nil)
	return bridgeSafeError(err)
}

func (c *APIClient) GetRuleProviders() (string, error) {
	bridgedValue0, bridgedErr := c.request(http.MethodGet, "/providers/rules", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) UpdateProxyProvider(name string) error {
	return bridgeSafeError(c.updateProvider("proxies", name))
}

func (c *APIClient) UpdateRuleProvider(name string) error {
	return bridgeSafeError(c.updateProvider("rules", name))
}

func (c *APIClient) updateProvider(kind, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("clash: update provider requires a name")
	}
	_, err := c.request(
		http.MethodPut,
		"/providers/"+kind+"/"+url.PathEscape(name),
		nil,
	)
	if err == nil {
		c.invalidateProviderIndex()
	}
	return err
}

func (c *APIClient) invalidateProviderIndex() {
	c.providerIndexMu.Lock()
	c.providerIndex = nil
	c.providerIndexAt = time.Time{}
	c.providerIndexMu.Unlock()
}

func (c *APIClient) SideUpdateProxyProvider(name string, payload []byte) error {
	return bridgeSafeError(c.sideUpdateProvider("proxy", name, payload, ""))
}

func (c *APIClient) SideUpdateRuleProvider(name string, payload []byte) error {
	return bridgeSafeError(c.sideUpdateProvider("rule", name, payload, ""))
}

func (c *APIClient) SideUpdateProxyProviderExpecting(name string, payload []byte, expectedConfigSHA256 string) error {
	if !validConfigurationSHA256(expectedConfigSHA256, false) {
		return bridgeSafeError(errors.New("clash: side update requires the expected configuration's SHA-256"))
	}
	return bridgeSafeError(c.sideUpdateProvider("proxy", name, payload, expectedConfigSHA256))
}

func (c *APIClient) SideUpdateRuleProviderExpecting(name string, payload []byte, expectedConfigSHA256 string) error {
	if !validConfigurationSHA256(expectedConfigSHA256, false) {
		return bridgeSafeError(errors.New("clash: side update requires the expected configuration's SHA-256"))
	}
	return bridgeSafeError(c.sideUpdateProvider("rule", name, payload, expectedConfigSHA256))
}

func (c *APIClient) sideUpdateProvider(kind, name string, payload []byte, expectedConfigSHA256 string) error {
	if !validProviderSideUpdateName(name) {
		return errors.New("clash: side update requires a valid provider name")
	}
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return fmt.Errorf("clash: provider side-update payload size is invalid")
	}
	query := url.Values{"kind": []string{kind}, "name": []string{name}}
	if expectedConfigSHA256 != "" {
		query.Set("expect", expectedConfigSHA256)
	}
	ctx, cancel := context.WithTimeout(context.Background(), clashAPIRequestTimeout)
	defer cancel()
	endpoint, status, body, err := c.privateBinaryStatus(ctx, http.MethodPut, "/providers/side-update?"+query.Encode(), payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return clientSideUpdateError(endpoint, status, body)
	}
	c.invalidateProviderIndex()
	return nil
}

func clientSideUpdateError(endpoint string, status int, body string) error {
	if status == http.StatusConflict {
		for _, prefix := range []string{SideUpdateDeferredPrefix, SideUpdateStalePrefix} {
			if strings.HasPrefix(body, prefix) {
				return errors.New(body)
			}
		}
	}
	return fmt.Errorf("clash: Clash API %s %s: HTTP %d: %s", http.MethodPut, endpoint, status, body)
}

func (c *APIClient) requestBinaryStatus(ctx context.Context, method, path string, payload []byte) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return 0, "", fmt.Errorf("clash: build Clash API request %s: %w", path, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return 0, "", fmt.Errorf("clash: Clash API %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	responsePayload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return 0, "", fmt.Errorf("clash: read Clash API %s: %w", path, err)
	}
	if len(responsePayload) > clashAPIMaxMessageSize {
		return 0, "", fmt.Errorf("clash: Clash API %s response exceeds %d bytes", path, clashAPIMaxMessageSize)
	}
	return response.StatusCode, strings.TrimSpace(string(responsePayload)), nil
}

func (c *APIClient) requestBinary(ctx context.Context, method, path string, payload []byte) error {
	errorEndpoint := path
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("clash: build Clash API request %s: %w", errorEndpoint, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("clash: Clash API %s %s: %w", method, errorEndpoint, err)
	}
	defer response.Body.Close()
	responsePayload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return fmt.Errorf("clash: read Clash API %s: %w", errorEndpoint, err)
	}
	if len(responsePayload) > clashAPIMaxMessageSize {
		return fmt.Errorf("clash: Clash API %s response exceeds %d bytes", errorEndpoint, clashAPIMaxMessageSize)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("clash: Clash API %s %s: HTTP %d: %s", method, errorEndpoint, response.StatusCode, strings.TrimSpace(string(responsePayload)))
	}
	return nil
}

func (c *APIClient) URLTest(name, testURL string) (int, error) {
	if name == "" {
		return -1, bridgeSafeError(errors.New("clash: URL test requires a proxy name"))
	}
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	query := url.Values{
		"url":      []string{testURL},
		"timeout":  []string{"5000"},
		"expected": []string{"200-299"},
	}
	payload, err := c.request(http.MethodGet, "/proxies/"+url.PathEscape(name)+"/delay?"+query.Encode(), nil)
	if err != nil && isClashAPINotFound(err) {
		if providerName, ok := c.providerOf(name); ok {
			payload, err = c.request(http.MethodGet,
				"/providers/proxies/"+url.PathEscape(providerName)+
					"/"+url.PathEscape(name)+"/healthcheck?"+query.Encode(), nil)
		}
	}
	if err != nil {
		return -1, bridgeSafeError(err)
	}
	var response struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal([]byte(payload), &response); err != nil || response.Delay <= 0 {
		return -1, bridgeSafeError(fmt.Errorf("clash: invalid URL test response %q", payload))
	}
	return response.Delay, nil
}

func isClashAPINotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), ": HTTP 404:")
}

func (c *APIClient) privatePath(suffix string) string {
	return privateAPIPrefix + suffix
}

func (c *APIClient) privateRequestWithContext(ctx context.Context, method, suffix string, body any) (string, error) {
	return c.requestWithContext(ctx, method, c.privatePath(suffix), body)
}

func (c *APIClient) privateRequest(method, suffix string, body any) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clashAPIRequestTimeout)
	defer cancel()
	return c.privateRequestWithContext(ctx, method, suffix, body)
}

func (c *APIClient) privateBinaryStatus(ctx context.Context, method, suffix string, payload []byte) (string, int, string, error) {
	endpoint := c.privatePath(suffix)
	status, body, err := c.requestBinaryStatus(ctx, method, endpoint, payload)
	return endpoint, status, body, err
}

func (c *APIClient) providerOf(name string) (string, bool) {
	c.providerIndexMu.Lock()
	defer c.providerIndexMu.Unlock()
	if c.providerIndex == nil || time.Since(c.providerIndexAt) > clashAPIProviderIndexTTL {
		payload, err := c.request(http.MethodGet, "/providers/proxies", nil)
		if err != nil {
			return "", false
		}
		var listing struct {
			Providers map[string]struct {
				VehicleType string `json:"vehicleType"`
				Proxies     []struct {
					Name string `json:"name"`
				} `json:"proxies"`
			} `json:"providers"`
		}
		if err := json.Unmarshal([]byte(payload), &listing); err != nil {
			return "", false
		}
		const ambiguous = "\x00ambiguous"
		index := make(map[string]string)
		for providerName, provider := range listing.Providers {
			if strings.EqualFold(provider.VehicleType, "Compatible") ||
				providerName == "default" {
				continue
			}
			for _, proxy := range provider.Proxies {
				if existing, seen := index[proxy.Name]; seen && existing != providerName {
					index[proxy.Name] = ambiguous
					continue
				}
				index[proxy.Name] = providerName
			}
		}
		for name, providerName := range index {
			if providerName == ambiguous {
				delete(index, name)
			}
		}
		c.providerIndex = index
		c.providerIndexAt = time.Now()
	}
	providerName, ok := c.providerIndex[name]
	return providerName, ok
}

func (c *APIClient) URLTestOutcome(name, testURL string) (string, error) {
	if name == "" {
		return "", bridgeSafeError(errors.New("clash: URL test requires a proxy name"))
	}
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	query := url.Values{
		"url":      []string{testURL},
		"timeout":  []string{"5000"},
		"expected": []string{"200-299"},
	}
	suffix := "/delay?" + query.Encode()
	status, payload, err := c.requestAllowingStatus(http.MethodGet, "/proxies/"+url.PathEscape(name)+suffix)
	if err == nil && status == http.StatusNotFound {
		if providerName, ok := c.providerOf(name); ok {
			status, payload, err = c.requestAllowingStatus(http.MethodGet,
				"/providers/proxies/"+url.PathEscape(providerName)+"/"+url.PathEscape(name)+"/healthcheck?"+query.Encode())
		}
	}
	if err != nil {
		return "", bridgeSafeError(err)
	}
	if !json.Valid([]byte(payload)) {
		return "", bridgeSafeError(fmt.Errorf("clash: Clash API delay for %q returned invalid JSON", name))
	}
	if status < 200 || status >= 300 {
		if status != http.StatusServiceUnavailable && status != http.StatusGatewayTimeout {
			return "", bridgeSafeError(fmt.Errorf("clash: Clash API delay for %q: HTTP %d: %s", name, status, strings.TrimSpace(payload)))
		}
	}
	return bridgeSafeString(payload), nil
}
