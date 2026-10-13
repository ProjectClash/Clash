package clash

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	internalSTUN "github.com/ProjectClash/Clash/bind/clash/internal/stun"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const STUNDefaultServer = internalSTUN.DefaultServer

const (
	STUNPhaseBinding      = int32(internalSTUN.PhaseBinding)
	STUNPhaseNATMapping   = int32(internalSTUN.PhaseNATMapping)
	STUNPhaseNATFiltering = int32(internalSTUN.PhaseNATFiltering)
	STUNPhaseDone         = int32(internalSTUN.PhaseDone)
)

const (
	STUNAddressFamilyUnknown = int32(internalSTUN.AddressFamilyUnknown)
	STUNAddressFamilyIPv4    = int32(internalSTUN.AddressFamilyIPv4)
	STUNAddressFamilyIPv6    = int32(internalSTUN.AddressFamilyIPv6)
)

const (
	NATMappingUnknown                 = int32(internalSTUN.NATMappingUnknown)
	NATMappingEndpointIndependent     = int32(internalSTUN.NATMappingEndpointIndependent)
	NATMappingAddressDependent        = int32(internalSTUN.NATMappingAddressDependent)
	NATMappingAddressAndPortDependent = int32(internalSTUN.NATMappingAddressAndPortDependent)
)

const (
	NATFilteringUnknown                 = int32(internalSTUN.NATFilteringUnknown)
	NATFilteringEndpointIndependent     = int32(internalSTUN.NATFilteringEndpointIndependent)
	NATFilteringAddressDependent        = int32(internalSTUN.NATFilteringAddressDependent)
	NATFilteringAddressAndPortDependent = int32(internalSTUN.NATFilteringAddressAndPortDependent)
)

type STUNTestProgress struct {
	Phase                 int32
	ExternalAddr          string
	ExternalAddressFamily int32
	LatencyMs             int32
	NATMapping            int32
	NATFiltering          int32
}

type STUNTestResult struct {
	ExternalAddr          string
	ExternalAddressFamily int32
	LatencyMs             int32
	NATMapping            int32
	NATFiltering          int32
	NATTypeSupported      bool
}

type STUNTestHandler interface {
	OnProgress(progress *STUNTestProgress)
	OnResult(result *STUNTestResult)
	OnError(message string)
}

type STUNTest struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	used   bool
}

func NewSTUNTest() *STUNTest {
	ctx, cancel := context.WithCancel(context.Background())
	return &STUNTest{ctx: ctx, cancel: cancel}
}

func (t *STUNTest) Start(server string, handler STUNTestHandler) {
	if t == nil || handler == nil {
		return
	}
	handler = bridgeSafeSTUNHandler(handler)
	t.mu.Lock()
	if t.used {
		t.mu.Unlock()
		handler.OnError("clash: STUN test instances are single-use")
		return
	}
	t.used = true
	ctx := t.ctx
	t.mu.Unlock()
	go func() {
		result, err := internalSTUN.Run(internalSTUN.Options{
			Server:  server,
			Context: ctx,
			OnProgress: func(progress internalSTUN.Progress) {
				handler.OnProgress(stunProgress(progress))
			},
		})
		if err != nil {
			handler.OnError(stunPublicError(err))
			return
		}
		handler.OnResult(stunResult(result))
	}()
}

func (t *STUNTest) Cancel() {
	if t == nil {
		return
	}
	t.mu.Lock()
	cancel := t.cancel
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func FormatNATMapping(value int32) string {
	return bridgeSafeString(internalSTUN.NATMapping(value).String())
}

func FormatNATFiltering(value int32) string {
	return bridgeSafeString(internalSTUN.NATFiltering(value).String())
}

func FormatSTUNAddressFamily(value int32) string {
	switch internalSTUN.AddressFamily(value) {
	case internalSTUN.AddressFamilyIPv4:
		return "IPv4"
	case internalSTUN.AddressFamilyIPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

func stunProgress(progress internalSTUN.Progress) *STUNTestProgress {
	return &STUNTestProgress{
		Phase:                 int32(progress.Phase),
		ExternalAddr:          progress.ExternalAddr,
		ExternalAddressFamily: int32(progress.ExternalAddressFamily),
		LatencyMs:             progress.LatencyMs,
		NATMapping:            int32(progress.NATMapping),
		NATFiltering:          int32(progress.NATFiltering),
	}
}

func stunResult(result *internalSTUN.Result) *STUNTestResult {
	return &STUNTestResult{
		ExternalAddr:          result.ExternalAddr,
		ExternalAddressFamily: int32(result.ExternalAddressFamily),
		LatencyMs:             result.LatencyMs,
		NATMapping:            int32(result.NATMapping),
		NATFiltering:          int32(result.NATFiltering),
		NATTypeSupported:      result.NATTypeSupported,
	}
}

type stunWireRequest struct {
	Server   string `json:"server"`
	Outbound string `json:"outbound,omitempty"`
}

type stunWireEvent struct {
	Phase                 int32  `json:"phase"`
	ExternalAddr          string `json:"externalAddr,omitempty"`
	ExternalAddressFamily int32  `json:"externalAddressFamily,omitempty"`
	LatencyMs             int32  `json:"latencyMs,omitempty"`
	NATMapping            int32  `json:"natMapping,omitempty"`
	NATFiltering          int32  `json:"natFiltering,omitempty"`
	NATTypeSupported      bool   `json:"natTypeSupported,omitempty"`
	Final                 bool   `json:"final,omitempty"`
	Error                 string `json:"error,omitempty"`
}

func stunWireProgress(progress internalSTUN.Progress) stunWireEvent {
	return stunWireEvent{
		Phase:                 int32(progress.Phase),
		ExternalAddr:          progress.ExternalAddr,
		ExternalAddressFamily: int32(progress.ExternalAddressFamily),
		LatencyMs:             progress.LatencyMs,
		NATMapping:            int32(progress.NATMapping),
		NATFiltering:          int32(progress.NATFiltering),
	}
}

func stunWireResult(result *internalSTUN.Result) stunWireEvent {
	return stunWireEvent{
		Phase:                 STUNPhaseDone,
		ExternalAddr:          result.ExternalAddr,
		ExternalAddressFamily: int32(result.ExternalAddressFamily),
		LatencyMs:             result.LatencyMs,
		NATMapping:            int32(result.NATMapping),
		NATFiltering:          int32(result.NATFiltering),
		NATTypeSupported:      result.NATTypeSupported,
		Final:                 true,
	}
}

type STUNTestSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	body      io.ReadCloser
	closeOnce sync.Once
}

func (s *STUNTestSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.body.Close()
	})
	return nil
}

func (c *APIClient) postSTUNSession(ctx context.Context, path string, payload []byte) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("clash: build STUN request: %w", err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/x-ndjson")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("clash: start STUN test: %w", err)
	}
	return response, nil
}

func (c *APIClient) StartSTUNTest(server, outbound string, handler STUNTestHandler) (*STUNTestSession, error) {
	if c == nil || c.httpClient == nil {
		return nil, bridgeSafeError(errors.New("clash: Clash API client is unavailable"))
	}
	if handler == nil {
		return nil, bridgeSafeError(errors.New("clash: STUN test requires a handler"))
	}
	handler = bridgeSafeSTUNHandler(handler)
	payload, err := json.Marshal(stunWireRequest{Server: server, Outbound: outbound})
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: encode STUN request: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	stunPath := c.privatePath("/stun")
	response, err := c.postSTUNSession(ctx, stunPath, payload)
	if err != nil {
		cancel()
		return nil, bridgeSafeError(err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4097))
		cancel()
		return nil, bridgeSafeError(fmt.Errorf("clash: start STUN test: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message))))
	}
	mediaType, _, mediaTypeError := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaTypeError != nil || mediaType != "application/x-ndjson" {
		_ = response.Body.Close()
		cancel()
		return nil, bridgeSafeError(errors.New("clash: STUN stream returned an unexpected content type"))
	}
	session := &STUNTestSession{ctx: ctx, cancel: cancel, body: response.Body}
	go session.read(handler)
	return session, nil
}

func (s *STUNTestSession) read(handler STUNTestHandler) {
	defer s.closeOnce.Do(func() {
		s.cancel()
		_ = s.body.Close()
	})
	reader := bufio.NewReaderSize(s.body, 4096)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > 4096 {
			handler.OnError("clash: STUN event exceeds 4096 bytes")
			return
		}
		if len(bytes.TrimSpace(line)) > 0 {
			var event stunWireEvent
			if decodeError := json.Unmarshal(line, &event); decodeError != nil {
				handler.OnError("clash: STUN stream returned invalid JSON")
				return
			}
			if event.Final {
				if event.Error != "" {
					handler.OnError(event.Error)
				} else {
					handler.OnResult(&STUNTestResult{
						ExternalAddr:          event.ExternalAddr,
						ExternalAddressFamily: event.ExternalAddressFamily,
						LatencyMs:             event.LatencyMs,
						NATMapping:            event.NATMapping,
						NATFiltering:          event.NATFiltering,
						NATTypeSupported:      event.NATTypeSupported,
					})
				}
				return
			}
			handler.OnProgress(&STUNTestProgress{
				Phase:                 event.Phase,
				ExternalAddr:          event.ExternalAddr,
				ExternalAddressFamily: event.ExternalAddressFamily,
				LatencyMs:             event.LatencyMs,
				NATMapping:            event.NATMapping,
				NATFiltering:          event.NATFiltering,
			})
		}
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				handler.OnError("clash: STUN stream ended before a final result")
			}
			return
		}
	}
}

func (s *BoxService) beginSTUNSession(parent context.Context) (context.Context, func(), error) {
	s.stunMu.Lock()
	defer s.stunMu.Unlock()
	if s.stunClosing {
		return nil, nil, errors.New("clash: STUN diagnostics are stopping")
	}
	if len(s.stunSessions) != 0 {
		return nil, nil, errors.New("clash: another STUN test is already running")
	}
	if s.stunSessions == nil {
		s.stunSessions = make(map[uint64]context.CancelFunc)
	}
	s.stunNextID++
	id := s.stunNextID
	ctx, cancel := context.WithCancel(parent)
	s.stunSessions[id] = cancel
	s.stunWG.Add(1)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel()
			s.stunMu.Lock()
			delete(s.stunSessions, id)
			s.stunMu.Unlock()
			s.stunWG.Done()
		})
	}
	return ctx, finish, nil
}

func (s *BoxService) stopSTUNSessions() {
	s.stunMu.Lock()
	s.stunClosing = true
	cancellations := make([]context.CancelFunc, 0, len(s.stunSessions))
	for _, cancel := range s.stunSessions {
		cancellations = append(cancellations, cancel)
	}
	s.stunMu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
	s.stunWG.Wait()
}

func (s *BoxService) resumeSTUNSessions() {
	s.stunMu.Lock()
	s.stunClosing = false
	s.stunMu.Unlock()
}

func (s *BoxService) runSTUN(
	parent context.Context,
	server string,
	outbound string,
	onProgress func(internalSTUN.Progress),
) (*internalSTUN.Result, error) {
	if err := validateSTUNOutbound(outbound); err != nil {
		return nil, err
	}
	ctx, finish, err := s.beginSTUNSession(parent)
	if err != nil {
		return nil, err
	}
	defer finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil, errors.New("clash: service not running")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return internalSTUN.Run(internalSTUN.Options{
		Server:     server,
		Context:    ctx,
		OnProgress: onProgress,
		Dial: func(ctx context.Context, endpoint string) (net.PacketConn, netip.AddrPort, error) {
			return dialSTUNThroughCore(ctx, endpoint, outbound)
		},
	})
}

func validateSTUNOutbound(outbound string) error {
	if len(outbound) > 256 {
		return errors.New("clash: STUN outbound name exceeds 256 bytes")
	}
	for _, character := range outbound {
		if unicode.IsControl(character) {
			return errors.New("clash: STUN outbound name contains control characters")
		}
	}
	if outbound == "" {
		return nil
	}
	proxy, exists := lookupRunningProxy(outbound)
	if !exists {
		return errors.New("clash: selected STUN outbound was not found")
	}
	if !proxy.SupportUDP() {
		return errors.New("clash: selected STUN outbound does not support UDP")
	}
	return nil
}

func dialSTUNThroughCore(ctx context.Context, endpoint, outbound string) (net.PacketConn, netip.AddrPort, error) {
	var dialer *tunnel.DNSDialer
	if outbound == "" {
		dialer = tunnel.NewDNSDialer(resolver.DefaultResolver, nil, tunnel.DnsRespectRules)
	} else {
		proxy, _ := lookupRunningProxy(outbound)
		dialer = tunnel.NewDNSDialer(resolver.DefaultResolver, proxy, "")
	}
	connection, err := dialer.ListenPacket(ctx, "udp", endpoint)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	tracker, ok := connection.(interface{ Info() *statistic.TrackerInfo })
	if !ok || tracker.Info() == nil || tracker.Info().Metadata == nil {
		_ = connection.Close()
		return nil, netip.AddrPort{}, errors.New("clash: STUN Core dialer returned no resolved metadata")
	}
	logicalAddress := tracker.Info().Metadata.AddrPort()
	if !logicalAddress.IsValid() || logicalAddress.Port() == 0 {
		_ = connection.Close()
		return nil, netip.AddrPort{}, errors.New("clash: STUN Core dialer returned an invalid address")
	}
	return &countedSTUNPacketConn{
		PacketConn:    connection,
		finalOutbound: tracker.Info().Chain.Last(),
	}, logicalAddress, nil
}

type countedSTUNPacketConn struct {
	net.PacketConn
	finalOutbound string
}

func (c *countedSTUNPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	count, address, err := c.PacketConn.ReadFrom(payload)
	if count > 0 {
		statistic.DefaultManager.PushDownloaded(c.finalOutbound, int64(count))
	}
	return count, address, err
}

func (c *countedSTUNPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	count, err := c.PacketConn.WriteTo(payload, address)
	if count > 0 {
		statistic.DefaultManager.PushUploaded(c.finalOutbound, int64(count))
	}
	return count, err
}

func stunPublicError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "clash: STUN test cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "clash: STUN test timed out"
	}
	return "clash: STUN test failed: " + err.Error()
}
