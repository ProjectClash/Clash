// Copyright (C) 2023  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"reflect"
	"sync"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/mathext"
	"github.com/enfein/mieru/v3/pkg/protocol/serveruser"
	"github.com/enfein/mieru/v3/pkg/sockopts"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

const (
	underlayCleanInterval      = 5 * time.Second
	minUnderlayCapacityReclaim = 16
)

type Mux struct {
	isClient              bool
	endpoints             []UnderlayProperties
	underlays             []Underlay
	dialer                apicommon.Dialer
	packetDialer          apicommon.PacketDialer
	resolver              apicommon.DNSResolver
	clientDNSConfig       *apicommon.ClientDNSConfig
	streamListenerFactory apicommon.StreamListenerFactory
	packetListenerFactory apicommon.PacketListenerFactory
	trafficPattern        *trafficpattern.Config
	chAccept              chan net.Conn
	acceptErr             *muxAcceptErr
	used                  bool
	done                  chan struct{}
	closeDone             chan struct{}
	maintenanceDone       chan struct{}
	ctx                   context.Context
	ctxCancelFunc         context.CancelFunc
	mu                    sync.Mutex
	serverUnderlayLoopWG  sync.WaitGroup
	cleaner               *time.Ticker

	username        string
	password        []byte
	multiplexFactor int

	serverUsers          serveruser.Registry
	serverTCPIdleTimeout time.Duration
}

var _ net.Listener = &Mux{}

func NewMux(isClinet bool) *Mux {
	if isClinet {
		log.Infof("Initializing client multiplexer")
	} else {
		log.Infof("Initializing server multiplexer")
	}
	mux := &Mux{
		isClient:              isClinet,
		underlays:             make([]Underlay, 0),
		dialer:                &net.Dialer{Timeout: 10 * time.Second, Control: sockopts.DefaultDialerControl()},
		packetDialer:          common.UDPDialer{Control: sockopts.DefaultDialerControl()},
		resolver:              &net.Resolver{},
		clientDNSConfig:       &apicommon.ClientDNSConfig{},
		streamListenerFactory: &net.ListenConfig{Control: sockopts.DefaultListenerControl()},
		packetListenerFactory: &net.ListenConfig{Control: sockopts.DefaultListenerControl()},
		chAccept:              make(chan net.Conn, sessionChanCapacity),
		acceptErr:             newMuxAcceptErr(),
		done:                  make(chan struct{}),
		closeDone:             make(chan struct{}),
		maintenanceDone:       make(chan struct{}),
		cleaner:               time.NewTicker(underlayCleanInterval),
	}
	mux.ctx, mux.ctxCancelFunc = context.WithCancel(context.Background())

	go func() {
		defer close(mux.maintenanceDone)
		for {
			select {
			case <-mux.cleaner.C:
				mux.mu.Lock()
				if isClinet {
					mux.cleanUnderlay(true)
				} else {
					mux.cleanUnderlay(false)
				}
				mux.mu.Unlock()
				if !isClinet {
					mux.flushServerUserCacheMetrics()
				}
			case <-mux.done:
				mux.cleaner.Stop()
				return
			}
		}
	}()
	return mux
}

func (m *Mux) flushServerUserCacheMetrics() {
	m.serverUsers.FlushMetrics()
}

func (m *Mux) SetEndpoints(endpoints []UnderlayProperties) *Mux {
	if err := m.UpdateEndpoints(endpoints); err != nil {
		log.Errorf("Update mux endpoints failed: %v", err)
	}
	return m
}

func (m *Mux) UpdateEndpoints(endpoints []UnderlayProperties) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return io.ErrClosedPipe
	default:
	}
	if m.isClient || !m.used {
		m.endpoints = endpoints
		return nil
	}
	new := m.newEndpoints(m.endpoints, endpoints)
	var wg sync.WaitGroup
	results := make([]*muxAcceptErr, len(new))
	for i, p := range new {
		results[i] = newMuxAcceptErr()
		wg.Add(1)
		go m.acceptUnderlayLoop(m.ctx, p, &wg, results[i])
	}
	wg.Wait()
	var errs []error
	for i, result := range results {
		if err := result.get(); err != nil {
			errs = append(errs, err)
		} else {
			m.endpoints = append(m.endpoints, new[i])
		}
	}
	log.Infof("Mux now has %d endpoints", len(m.endpoints))
	return errors.Join(errs...)
}

func (m *Mux) SetDialer(dialer apicommon.Dialer) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialer = dialer
	log.Infof("Mux dialer has been updated")
	return m
}

func (m *Mux) SetPacketDialer(packetDialer apicommon.PacketDialer) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packetDialer = packetDialer
	log.Infof("Mux packet dialer has been updated")
	return m
}

func (m *Mux) SetResolver(resolver apicommon.DNSResolver) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolver = resolver
	log.Infof("Mux DNS resolver has been updated")
	return m
}

func (m *Mux) SetClientDNSConfig(clientDNSConfig *apicommon.ClientDNSConfig) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientDNSConfig = clientDNSConfig
	log.Infof("Mux client DNS configuration has been updated")
	return m
}

func (m *Mux) SetStreamListenerFactory(listenerFactory apicommon.StreamListenerFactory) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamListenerFactory = listenerFactory
	log.Infof("Mux stream listener factory has been updated")
	return m
}

func (m *Mux) SetPacketListenerFactory(listenerFactory apicommon.PacketListenerFactory) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packetListenerFactory = listenerFactory
	log.Infof("Mux packet listener factory has been updated")
	return m
}

func (m *Mux) SetTrafficPattern(trafficPattern *trafficpattern.Config) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trafficPattern = trafficPattern
	log.Infof("Mux traffic pattern has been updated")
	return m
}

func (m *Mux) SetClientUserNamePassword(username string, password []byte) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isClient {
		panic("Can't set client password in server mux")
	}
	if m.used {
		panic("Can't set client password after mux is used")
	}
	m.username = username
	m.password = password
	return m
}

func (m *Mux) SetClientMultiplexFactor(n int) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isClient {
		panic("Can't set multiplex factor in server mux")
	}
	if m.used {
		panic("Can't set multiplex factor after mux is used")
	}
	m.multiplexFactor = mathext.Max(n, 0)
	log.Infof("Mux multiplexing factor is set to %d", m.multiplexFactor)
	return m
}

func (m *Mux) SetServerUsers(users map[string]*appctlpb.User) *Mux {
	if m.isClient {
		panic("Can't set server users in client mux")
	}
	m.serverUsers.SetUsers(users)
	return m
}

func (m *Mux) SetServerUserHintIsMandatory(userHintIsMandatory bool) *Mux {
	if m.isClient {
		panic("Can't set server user hint is mandatory in client mux")
	}
	m.serverUsers.SetHintMandatory(userHintIsMandatory)
	log.Infof("Mux user hint is mandatory is set to %v", userHintIsMandatory)
	return m
}

func (m *Mux) SetServerTCPIdleTimeout(timeout time.Duration) *Mux {
	if m.isClient {
		panic("Can't set server TCP idle timeout in client mux")
	}
	if timeout < 0 {
		panic("Server TCP idle timeout can't be negative")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serverTCPIdleTimeout = timeout
	log.Infof("Mux server TCP idle timeout is set to %v", timeout)
	return m
}

func (m *Mux) Accept() (net.Conn, error) {
	select {
	case <-m.acceptErr.done:
		return nil, io.ErrClosedPipe
	case conn := <-m.chAccept:
		return conn, nil
	case <-m.done:
		return nil, io.EOF
	}
}

func (m *Mux) Close() error {
	m.mu.Lock()
	select {
	case <-m.done:
		closeDone := m.closeDone
		m.mu.Unlock()
		<-closeDone
		return nil
	default:
	}

	if m.isClient {
		log.Infof("Closing client multiplexer")
	} else {
		log.Infof("Closing server multiplexer")
	}
	close(m.done)
	m.ctxCancelFunc()
	for _, underlay := range m.underlays {
		underlay.Close()
	}
	m.underlays = make([]Underlay, 0)
	m.mu.Unlock()

	<-m.maintenanceDone
	m.serverUnderlayLoopWG.Wait()
	if !m.isClient {
		m.flushServerUserCacheMetrics()
	}
	close(m.closeDone)
	return nil
}

func (m *Mux) Addr() net.Addr {
	return common.NilNetAddr()
}

func (m *Mux) Start() error {
	if m.isClient {
		return stderror.ErrInvalidOperation
	}
	if !m.serverUsers.HasUsers() {
		return fmt.Errorf("no user found")
	}
	if len(m.endpoints) == 0 {
		return fmt.Errorf("no server listening endpoint found")
	}
	for _, p := range m.endpoints {
		if common.IsNilNetAddr(p.LocalAddr()) {
			return fmt.Errorf("endpoint local address is not set")
		}
	}

	m.mu.Lock()
	m.used = true
	var wg sync.WaitGroup
	for _, p := range m.endpoints {
		wg.Add(1)
		go m.acceptUnderlayLoop(m.ctx, p, &wg, m.acceptErr)
	}
	wg.Wait()
	acceptErr := m.acceptErr.get()
	m.mu.Unlock()
	if acceptErr != nil {
		if err := m.Close(); err != nil {
			log.Warnf("mux Close() failed: %v", err)
		}
		return fmt.Errorf("mux server listener failed: %w", acceptErr)
	}
	return nil
}

func (m *Mux) DialContext(ctx context.Context) (net.Conn, error) {
	if !m.isClient {
		return nil, stderror.ErrInvalidOperation
	}
	if len(m.password) == 0 {
		return nil, fmt.Errorf("client password is not set")
	}
	if len(m.endpoints) == 0 {
		return nil, fmt.Errorf("no server listening endpoint found")
	}
	for _, p := range m.endpoints {
		if common.IsNilNetAddr(p.RemoteAddr()) {
			return nil, fmt.Errorf("endpoint remote address is not set")
		}
	}

	var err error
	m.mu.Lock()
	m.used = true
	m.cleanUnderlay(true)
	underlay := m.maybePickExistingUnderlay()
	m.mu.Unlock()
	if underlay == nil {
		underlay, err = m.newUnderlay(ctx)
		if err != nil {
			return nil, err
		}
		log.Debugf("Created new underlay %v", underlay)
	} else {
		log.Debugf("Reusing existing underlay %v", underlay)
	}

	if ok := underlay.Scheduler().IncPending(); !ok {
		underlay, err = m.newUnderlay(ctx)
		if err != nil {
			return nil, err
		}
		log.Debugf("Created yet another new underlay %v", underlay)
		underlay.Scheduler().IncPending()
	}
	defer func() {
		underlay.Scheduler().DecPending()
	}()
	var trafficPattern *appctlpb.TrafficPattern
	if m.trafficPattern != nil {
		trafficPattern = m.trafficPattern.Effective()
	}
	session := NewSession(mrand.Uint32(), true, underlay.MTU(), nil, trafficPattern)
	session.bounds.alone = m.multiplexFactor == 0
	if err := underlay.AddSession(session, nil); err != nil {
		return nil, fmt.Errorf("AddSession() failed: %v", err)
	}
	return session, nil
}

func (m *Mux) ExportSessionInfoList() *appctlpb.SessionInfoList {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]*appctlpb.SessionInfo, 0)
	for _, underlay := range m.underlays {
		items = append(items, underlay.SessionInfos()...)
	}
	return &appctlpb.SessionInfoList{Items: items}
}

func (m *Mux) newEndpoints(old, new []UnderlayProperties) []UnderlayProperties {
	newEndpoints := []UnderlayProperties{}

	for _, n := range new {
		found := false
		for _, o := range old {
			if reflect.DeepEqual(n, o) {
				found = true
				break
			}
		}
		if !found {
			newEndpoints = append(newEndpoints, n)
		}
	}

	return newEndpoints
}

func (m *Mux) acceptUnderlayLoop(ctx context.Context, properties UnderlayProperties, wg *sync.WaitGroup, acceptErr *muxAcceptErr) {
	laddr := properties.LocalAddr().String()
	if laddr == "" {
		err := fmt.Errorf("underlay local address is empty")
		log.Errorf("%v", err)
		acceptErr.set(err)
		wg.Done()
		return
	}

	network := properties.LocalAddr().Network()
	switch network {
	case "tcp", "tcp4", "tcp6":
		tcpAddr, err := apicommon.ResolveTCPAddr(ctx, m.resolver, "tcp", laddr)
		if err != nil {
			err = fmt.Errorf("resolve TCP address %q failed: %w", laddr, err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		rawListener, err := m.streamListenerFactory.Listen(ctx, tcpAddr.Network(), tcpAddr.String())
		if err != nil {
			err = fmt.Errorf("listen %s %s failed: %w", tcpAddr.Network(), tcpAddr.String(), err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		wg.Done()
		log.Infof("Mux is listening to endpoint %s %s", network, laddr)

		go func(ctx context.Context, l net.Listener) {
			<-ctx.Done()
			log.Infof("Closing TCPListener %v", rawListener.Addr())
			rawListener.Close()
		}(ctx, rawListener)

		for {
			underlay, err := m.acceptTCPUnderlay(rawListener, properties)
			if err != nil {
				log.Debugf("%v", err)
				break
			}
			log.Debugf("Created new server underlay %v", underlay)
			UnderlayPassiveOpens.Add(1)
			currEst := UnderlayCurrEstablished.Add(1)
			maxConn := UnderlayMaxConn.Load()
			if currEst > maxConn {
				UnderlayMaxConn.Store(currEst)
			}
			m.mu.Lock()
			select {
			case <-m.done:
				m.mu.Unlock()
				underlay.Close()
				return
			default:
			}
			m.underlays = append(m.underlays, underlay)
			m.cleanUnderlay(false)
			m.startServerUnderlayEventLoop(ctx, underlay)
			m.mu.Unlock()

			go func(ctx context.Context, underlay Underlay) {
				for {
					conn, err := underlay.Accept()
					if err != nil {
						if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
							log.Debugf("%v Accept(): %v", underlay, err)
						}
						break
					}
					select {
					case m.chAccept <- conn:
					case <-ctx.Done():
						return
					}
				}
			}(ctx, underlay)
		}
	case "udp", "udp4", "udp6":
		udpAddr, err := apicommon.ResolveUDPAddr(ctx, m.resolver, "udp", laddr)
		if err != nil {
			err = fmt.Errorf("resolve UDP address %q failed: %w", laddr, err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		conn, err := m.packetListenerFactory.ListenPacket(ctx, udpAddr.Network(), udpAddr.String())
		if err != nil {
			err = fmt.Errorf("listen %s %s failed: %w", udpAddr.Network(), udpAddr.String(), err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		wg.Done()
		log.Infof("Mux is listening to endpoint %s %s", network, laddr)

		var trafficPattern *appctlpb.TrafficPattern
		if m.trafficPattern != nil {
			trafficPattern = m.trafficPattern.Effective()
		}
		underlay := &PacketUnderlay{
			baseUnderlay:       *newBaseUnderlay(false, properties.MTU(), trafficPattern),
			conn:               conn,
			sessionCleanTicker: time.NewTicker(sessionCleanInterval),
			serverUsers:        &m.serverUsers,
		}
		log.Infof("Created new server underlay %v", underlay)
		UnderlayPassiveOpens.Add(1)
		currEst := UnderlayCurrEstablished.Add(1)
		maxConn := UnderlayMaxConn.Load()
		if currEst > maxConn {
			UnderlayMaxConn.Store(currEst)
		}
		m.mu.Lock()
		select {
		case <-m.done:
			m.mu.Unlock()
			underlay.Close()
			return
		default:
		}
		m.underlays = append(m.underlays, underlay)
		m.cleanUnderlay(false)
		m.startServerUnderlayEventLoop(ctx, underlay)
		m.mu.Unlock()

		go func(ctx context.Context, underlay Underlay) {
			for {
				conn, err := underlay.Accept()
				if err != nil {
					if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
						log.Debugf("%v Accept(): %v", underlay, err)
					}
					break
				}
				select {
				case m.chAccept <- conn:
				case <-ctx.Done():
					return
				}
			}
		}(ctx, underlay)
	default:
		err := fmt.Errorf("unsupported underlay network type %q", network)
		log.Errorf("%v", err)
		acceptErr.set(err)
		wg.Done()
	}
}

func (m *Mux) acceptTCPUnderlay(rawListener net.Listener, properties UnderlayProperties) (Underlay, error) {
	rawConn, err := rawListener.Accept()
	if err != nil {
		return nil, fmt.Errorf("Accept() underlay failed: %w", err)
	}
	var trafficPattern *appctlpb.TrafficPattern
	if m.trafficPattern != nil {
		trafficPattern = m.trafficPattern.Effective()
	}
	return m.serverWrapTCPConn(rawConn, properties.MTU(), trafficPattern), nil
}

func (m *Mux) serverWrapTCPConn(rawConn net.Conn, mtu int, trafficPattern *appctlpb.TrafficPattern) Underlay {
	var source serveruser.Source
	if rawConn != nil {
		source = serveruser.SourceFromAddr(rawConn.RemoteAddr())
		rawConn = common.NewIdleTrackingConn(rawConn)
	}
	return &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, mtu, trafficPattern),
		conn:               rawConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        &m.serverUsers,
		serverUserSource:   source,
	}
}

func (m *Mux) newUnderlay(ctx context.Context) (Underlay, error) {
	var underlay Underlay
	var trafficPattern *appctlpb.TrafficPattern

	m.mu.Lock()
	i := mrand.Intn(len(m.endpoints))
	p := m.endpoints[i]
	if m.trafficPattern != nil {
		trafficPattern = m.trafficPattern.Effective()
	}
	m.mu.Unlock()

	switch p.TransportProtocol() {
	case common.StreamTransport:
		block, err := cipher.BlockCipherFromPassword(m.password, false)
		if err != nil {
			return nil, fmt.Errorf("cipher.BlockCipherFromPassword() failed: %v", err)
		}
		block.SetBlockContext(cipher.BlockContext{
			UserName: m.username,
		})
		if trafficPattern != nil {
			block.SetNoncePattern(trafficPattern.GetNonce())
		}
		underlay, err = NewStreamUnderlay(ctx, m.dialer, m.resolver, m.clientDNSConfig, p.RemoteAddr().Network(), p.RemoteAddr().String(), p.MTU(), block, trafficPattern)
		if err != nil {
			return nil, fmt.Errorf("NewTCPUnderlay() failed: %v", err)
		}
	case common.PacketTransport:
		block, err := cipher.BlockCipherFromPassword(m.password, true)
		if err != nil {
			return nil, fmt.Errorf("cipher.BlockCipherFromPassword() failed: %v", err)
		}
		block.SetBlockContext(cipher.BlockContext{
			UserName: m.username,
		})
		if trafficPattern != nil {
			block.SetNoncePattern(trafficPattern.GetNonce())
		}
		underlay, err = NewPacketUnderlay(ctx, m.packetDialer, m.resolver, p.RemoteAddr().Network(), p.RemoteAddr().String(), p.MTU(), block, trafficPattern)
		if err != nil {
			return nil, fmt.Errorf("NewUDPUnderlay() failed: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupport transport protocol %v", p.TransportProtocol())
	}

	m.mu.Lock()
	m.underlays = append(m.underlays, underlay)
	m.mu.Unlock()
	UnderlayActiveOpens.Add(1)
	currEst := UnderlayCurrEstablished.Add(1)
	maxConn := UnderlayMaxConn.Load()
	if currEst > maxConn {
		UnderlayMaxConn.Store(currEst)
	}
	go func() {
		err := underlay.RunEventLoop(context.Background())
		if err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			log.Debugf("%v RunEventLoop(): %v", underlay, err)
		}
		underlay.Close()
	}()
	return underlay, nil
}

func (m *Mux) startServerUnderlayEventLoop(ctx context.Context, underlay Underlay) {
	m.serverUnderlayLoopWG.Add(1)
	go func() {
		defer m.serverUnderlayLoopWG.Done()
		err := underlay.RunEventLoop(ctx)
		if err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			log.Debugf("%v RunEventLoop(): %v", underlay, err)
		}
		underlay.Close()
	}()
}

func (m *Mux) maybePickExistingUnderlay() Underlay {
	active := make([]Underlay, 0)
	for _, underlay := range m.underlays {
		select {
		case <-underlay.Done():
		default:
			if !underlay.Scheduler().IsDisabled() {
				active = append(active, underlay)
			}
		}
	}

	if m.multiplexFactor > 0 {
		reuseUnderlayFactor := len(active) * m.multiplexFactor
		n := mrand.Intn(reuseUnderlayFactor + 1)
		if n < reuseUnderlayFactor {
			return active[n/m.multiplexFactor]
		}
	}
	return nil
}

func (m *Mux) cleanUnderlay(alsoDisableIdleOrOverloadUnderlay bool) {
	disable := 0
	close := 0
	n := 0
	for _, underlay := range m.underlays {
		select {
		case <-underlay.Done():
		default:
			if !m.isClient && m.serverTCPIdleTimeout > 0 {
				if stream, ok := underlay.(*StreamUnderlay); ok && stream.closeIfIdle(m.serverTCPIdleTimeout) {
					close++
					continue
				}
			}
			if underlay.SessionCount() == 0 && underlay.Scheduler().Idle() {
				underlay.Close()
				close++
			} else {
				m.underlays[n] = underlay
				n++
			}

			if alsoDisableIdleOrOverloadUnderlay {
				if underlay.SessionCount() == 0 {
					if underlay.Scheduler().TryDisableIdle() {
						disable++
					}
				}

				var trafficVolumeLimit int64 = 512 * 1024 * 1024 << m.multiplexFactor
				if underlay.Scheduler().DisableTime().IsZero() && (underlay.InBytes() > trafficVolumeLimit || underlay.OutBytes() > trafficVolumeLimit) {
					underlay.Scheduler().SetRemainingTime(0)
					disable++
				}
			}
		}
	}

	for i := n; i < len(m.underlays); i++ {
		m.underlays[i] = nil
	}
	m.underlays = m.underlays[:n]

	if cap(m.underlays) > minUnderlayCapacityReclaim && len(m.underlays)*4 <= cap(m.underlays) {
		reclaimed := make([]Underlay, len(m.underlays))
		copy(reclaimed, m.underlays)
		m.underlays = reclaimed
	}

	if close > 0 {
		log.Debugf("Mux cleaned %d underlays", close)
	}
	if disable > 0 {
		log.Debugf("Mux disabled scheduling from %d underlays", disable)
	}
}

type muxAcceptErr struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newMuxAcceptErr() *muxAcceptErr {
	return &muxAcceptErr{
		done: make(chan struct{}),
	}
}

func (e *muxAcceptErr) set(err error) {
	e.once.Do(func() {
		e.mu.Lock()
		e.err = err
		e.mu.Unlock()
		close(e.done)
	})
}

func (e *muxAcceptErr) get() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}
