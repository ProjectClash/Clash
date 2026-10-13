package realm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/sing/common"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"

	"golang.org/x/exp/slices"
	"golang.org/x/sync/singleflight"
)

const (
	connectSTUNCacheTTL = 10 * time.Second
	eventBufferSize     = 16
	sseBackoffMin       = 1 * time.Second
	sseBackoffMax       = 30 * time.Second
)

type Resolver func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error)

type Options struct {
	ServerURL   string
	Token       string
	HTTPClient  *http.Client
	RealmID     string
	STUNServers []string
	Resolver    Resolver
	Logger      logger.Logger
	IPVersion   int
}

type Server struct {
	options       Options
	controlClient *ControlClient
	punchConn     *PunchPacketConn
	puncher       *ServerPuncher
	cancel        context.CancelFunc
	done          chan struct{}
	resetSignal   chan struct{}

	addressAccess          sync.RWMutex
	addresses              []netip.AddrPort
	addressesAt            time.Time
	lastPublishedAddresses []netip.AddrPort
	connectFlight          singleflight.Group

	stunServerAccess sync.Mutex
	stunServers      []netip.AddrPort

	sessionAccess sync.Mutex
	sessionID     string
	ttl           int
}

func NewServer(options Options) (*Server, error) {
	controlClient, err := NewControlClient(options.ServerURL, options.Token, options.HTTPClient)
	if err != nil {
		return nil, err
	}
	if options.RealmID == "" {
		return nil, E.New("realm ID is required")
	}
	if len(options.STUNServers) == 0 {
		return nil, E.New("at least one STUN server is required")
	}
	if options.Resolver == nil {
		return nil, E.New("resolver is required")
	}
	if options.IPVersion != 0 && options.IPVersion != 4 && options.IPVersion != 6 {
		return nil, E.New("invalid IP version: ", options.IPVersion)
	}
	return &Server{
		options:       options,
		controlClient: controlClient,
		done:          make(chan struct{}),
		resetSignal:   make(chan struct{}, 1),
	}, nil
}

func (s *Server) Start(ctx context.Context, conn net.PacketConn) (*PunchPacketConn, error) {
	punchConn := NewPunchPacketConn(conn, eventBufferSize)
	s.punchConn = punchConn
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.puncher = NewServerPuncher(runCtx, punchConn)
	go s.run(runCtx)
	s.Reset()
	return punchConn, nil
}

func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.puncher != nil {
		s.puncher.Close()
	}
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.controlClient.Deregister(ctx, s.options.RealmID, sessionID)
		cancel()
		return err
	}
	return nil
}

func (s *Server) run(ctx context.Context) {
	eventStreamDone := make(chan struct{})
	go func() {
		defer close(eventStreamDone)
		s.runEventStream(ctx)
	}()
	defer func() {
		<-eventStreamDone
		close(s.done)
	}()
	heartbeatInterval := time.Duration(s.ttl/2) * time.Second
	if heartbeatInterval < time.Second {
		heartbeatInterval = time.Second
	}
	heartbeatTimer := time.NewTimer(heartbeatInterval)
	defer heartbeatTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTimer.C:
			s.handleHeartbeat(ctx)
			s.sessionAccess.Lock()
			heartbeatInterval = time.Duration(s.ttl/2) * time.Second
			s.sessionAccess.Unlock()
			if heartbeatInterval < time.Second {
				heartbeatInterval = time.Second
			}
			heartbeatTimer.Reset(heartbeatInterval)
		case <-s.resetSignal:
			s.handleReset(ctx)
			if !heartbeatTimer.Stop() {
				select {
				case <-heartbeatTimer.C:
				default:
				}
			}
			heartbeatTimer.Reset(heartbeatInterval)
		}
	}
}

func (s *Server) runEventStream(ctx context.Context) {
	sseBackoff := sseBackoffMin
	for {
		streamDone := make(chan struct{})
		if s.openEventStream(ctx, streamDone) {
			sseBackoff = sseBackoffMin
			select {
			case <-streamDone:
			case <-ctx.Done():
				return
			}
		} else if ctx.Err() != nil {
			return
		}
		s.options.Logger.Info("event stream disconnected, reconnecting in ", sseBackoff)
		select {
		case <-time.After(sseBackoff):
			sseBackoff = sseBackoff * 2
			if sseBackoff > sseBackoffMax {
				sseBackoff = sseBackoffMax
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) openEventStream(ctx context.Context, streamDone chan struct{}) bool {
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID == "" {
		s.options.Logger.Debug("no session ID, deferring event stream")
		close(streamDone)
		return false
	}
	stream, err := s.controlClient.Events(ctx, s.options.RealmID, sessionID)
	if err != nil {
		if ctx.Err() == nil {
			s.options.Logger.Error(E.Cause(err, "open event stream"))
		}
		close(streamDone)
		return false
	}
	go s.readEvents(ctx, stream, streamDone)
	return true
}

func (s *Server) readEvents(ctx context.Context, stream *EventStream, streamDone chan struct{}) {
	defer func() {
		stream.Close()
		close(streamDone)
	}()
	for {
		event, err := stream.Next()
		if err != nil {
			if ctx.Err() == nil {
				s.options.Logger.Error(E.Cause(err, "read event stream"))
			}
			return
		}
		peerAddresses := event.Addresses
		if s.options.IPVersion != 0 {
			peerAddresses = common.Filter(peerAddresses, func(address netip.AddrPort) bool {
				return address.Addr().Is4() == (s.options.IPVersion == 4)
			})
		}
		metadata := event.PunchMetadata
		go func() {
			freshAddresses, stunErr := s.connectAddresses(ctx)
			if stunErr != nil {
				s.options.Logger.Warn(E.Cause(stunErr, "connect STUN failed; using last-known addresses"))
			}
			s.sessionAccess.Lock()
			sessionID := s.sessionID
			s.sessionAccess.Unlock()
			if sessionID != "" && len(freshAddresses) > 0 {
				postCtx, postCancel := context.WithTimeout(ctx, 4*time.Second)
				nonceHex := hex.EncodeToString(metadata.Nonce[:])
				postErr := s.controlClient.ConnectResponse(postCtx, s.options.RealmID, sessionID, nonceHex, freshAddresses)
				postCancel()
				if postErr != nil {
					s.options.Logger.Warn(E.Cause(postErr, "connect response post"))
				}
			}
			result, punchErr := s.puncher.Respond(ctx, generateAttemptID(), peerAddresses, metadata)
			if punchErr != nil {
				if !E.IsClosedOrCanceled(punchErr) {
					s.options.Logger.Error(E.Cause(punchErr, "punch respond"))
				}
				return
			}
			s.options.Logger.Info("punch successful, peer: ", result.PeerAddr)
		}()
	}
}

func (s *Server) cachedAddresses() []netip.AddrPort {
	s.addressAccess.RLock()
	defer s.addressAccess.RUnlock()
	if s.addresses == nil || time.Since(s.addressesAt) >= connectSTUNCacheTTL {
		return nil
	}
	return slices.Clone(s.addresses)
}

func (s *Server) resolvedSTUNServers(ctx context.Context) ([]netip.AddrPort, error) {
	s.stunServerAccess.Lock()
	defer s.stunServerAccess.Unlock()
	if s.stunServers != nil {
		return s.stunServers, nil
	}
	resolved, err := ResolveSTUNServers(ctx, s.options.STUNServers, s.options.Resolver, s.options.IPVersion != 6, s.options.IPVersion != 4)
	if err != nil {
		return nil, err
	}
	s.stunServers = resolved
	return resolved, nil
}

func (s *Server) connectAddresses(ctx context.Context) ([]netip.AddrPort, error) {
	cached := s.cachedAddresses()
	if cached != nil {
		return cached, nil
	}
	value, err, _ := s.connectFlight.Do("stun", func() (any, error) {
		recheck := s.cachedAddresses()
		if recheck != nil {
			return recheck, nil
		}
		servers, resolveErr := s.resolvedSTUNServers(ctx)
		if resolveErr != nil {
			return nil, resolveErr
		}
		fresh, discoverErr := DiscoverDemuxed(ctx, s.punchConn, servers)
		if discoverErr != nil {
			return nil, discoverErr
		}
		s.addressAccess.Lock()
		s.addresses = slices.Clone(fresh)
		s.addressesAt = time.Now()
		s.addressAccess.Unlock()
		return fresh, nil
	})
	if err != nil {
		s.addressAccess.RLock()
		fallback := slices.Clone(s.addresses)
		s.addressAccess.RUnlock()
		if len(fallback) > 0 {
			return fallback, err
		}
		return nil, err
	}
	return value.([]netip.AddrPort), nil
}

func (s *Server) handleHeartbeat(ctx context.Context) {
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID == "" {
		s.addressAccess.RLock()
		haveAddresses := len(s.addresses) > 0
		s.addressAccess.RUnlock()
		if haveAddresses {
			s.reRegister(ctx)
		}
		return
	}
	s.addressAccess.RLock()
	var publish []netip.AddrPort
	if !slices.Equal(s.addresses, s.lastPublishedAddresses) {
		publish = slices.Clone(s.addresses)
	}
	s.addressAccess.RUnlock()
	ttl, err := s.controlClient.Heartbeat(ctx, s.options.RealmID, sessionID, publish)
	if err != nil {
		statusErr, isStatus := E.Cast[*StatusError](err)
		switch {
		case isStatus && (statusErr.StatusCode == 401 || statusErr.StatusCode == 404):
			s.options.Logger.Warn("session invalid, re-registering")
			s.reRegister(ctx)
		case isStatus && statusErr.StatusCode == 400:
			s.options.Logger.Error(E.Cause(err, "heartbeat fatal error"))
		default:
			s.options.Logger.Error(E.Cause(err, "heartbeat"))
		}
		return
	}
	s.sessionAccess.Lock()
	s.ttl = ttl
	s.sessionAccess.Unlock()
	if publish != nil {
		s.addressAccess.Lock()
		s.lastPublishedAddresses = publish
		s.addressAccess.Unlock()
	}
}

func (s *Server) Reset() {
	select {
	case s.resetSignal <- struct{}{}:
	default:
	}
}

func (s *Server) handleReset(ctx context.Context) {
	s.options.Logger.Info("network reset, re-discovering")
	s.addressAccess.Lock()
	s.addressesAt = time.Time{}
	s.addressAccess.Unlock()
	_, err := s.connectAddresses(ctx)
	if err != nil {
		s.options.Logger.Warn(E.Cause(err, "STUN re-discovery on reset"))
		return
	}
	s.sessionAccess.Lock()
	haveSession := s.sessionID != ""
	s.sessionAccess.Unlock()
	if !haveSession {
		s.reRegister(ctx)
		return
	}
	s.handleHeartbeat(ctx)
}

func (s *Server) reRegister(ctx context.Context) {
	s.addressAccess.RLock()
	addresses := slices.Clone(s.addresses)
	s.addressAccess.RUnlock()
	registration, err := s.controlClient.Register(ctx, s.options.RealmID, addresses)
	if err != nil {
		s.options.Logger.Warn(E.Cause(err, "re-register"))
		return
	}
	s.sessionAccess.Lock()
	s.sessionID = registration.SessionID
	s.ttl = registration.TTL
	s.sessionAccess.Unlock()
	s.addressAccess.Lock()
	s.lastPublishedAddresses = addresses
	s.addressAccess.Unlock()
	s.options.Logger.Info("re-registered with control, session: ", registration.SessionID)
}

func generateAttemptID() string {
	var buffer [8]byte
	_, _ = rand.Read(buffer[:])
	return hex.EncodeToString(buffer[:])
}
