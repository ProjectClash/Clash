package clash

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	coreInbound "github.com/ProjectClash/Clash/adapter/inbound"
	coreAuth "github.com/ProjectClash/Clash/component/auth"
	C "github.com/ProjectClash/Clash/constant"
	authStore "github.com/ProjectClash/Clash/listener/auth"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/listener/mixed"
	"github.com/ProjectClash/Clash/tunnel"
)

const (
	ProxyShareMinimumPort            int32 = 1024
	ProxyShareMaximumPort            int32 = 65535
	ProxyShareMaximumCredentialBytes int32 = 255
	ProxyShareMinimumPasswordBytes   int32 = 1
)

var proxyShareAllowedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

type proxyShareConfiguration struct {
	port     int32
	username string
	password string
}

type proxySharePortUnavailableError struct {
	port  int32
	cause error
}

func (e proxySharePortUnavailableError) Error() string {
	return fmt.Sprintf("clash: proxy-share port %d is unavailable", e.port)
}

func (e proxySharePortUnavailableError) Unwrap() error { return e.cause }

type proxyShareRuntime struct {
	configuration  *proxyShareConfiguration
	authentication coreAuth.AuthStore
	listeners      []*mixed.Listener
}

type proxyShareListenConfig struct {
	base    C.InboundListenConfig
	network string
}

func (configuration proxyShareListenConfig) Listen(
	ctx context.Context,
	_ string,
	address string,
) (net.Listener, error) {
	listener, err := configuration.base.Listen(ctx, configuration.network, address)
	if err != nil {
		return nil, err
	}
	return &proxyShareFilteredListener{Listener: listener}, nil
}

func (configuration proxyShareListenConfig) ListenPacket(
	ctx context.Context,
	_ string,
	address string,
) (net.PacketConn, error) {
	network := "udp4"
	if configuration.network == "tcp6" {
		network = "udp6"
	}
	packetConnection, err := configuration.base.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &proxyShareFilteredPacketConnection{PacketConn: packetConnection}, nil
}

type proxyShareFilteredListener struct {
	net.Listener
}

func (listener *proxyShareFilteredListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if proxyShareRemoteAllowed(connection.RemoteAddr()) {
			return connection, nil
		}
		_ = connection.Close()
	}
}

type proxyShareFilteredPacketConnection struct {
	net.PacketConn
}

func (connection *proxyShareFilteredPacketConnection) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		count, remote, err := connection.PacketConn.ReadFrom(payload)
		if err != nil {
			return count, remote, err
		}
		if proxyShareRemoteAllowed(remote) {
			return count, remote, nil
		}
	}
}

func proxyShareRemoteAllowed(remote net.Addr) bool {
	var ip net.IP
	switch address := remote.(type) {
	case *net.TCPAddr:
		ip = address.IP
	case *net.UDPAddr:
		ip = address.IP
	default:
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range proxyShareAllowedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

type proxyShareStatus struct {
	Enabled                bool     `json:"enabled"`
	Port                   int32    `json:"port"`
	Protocols              []string `json:"protocols"`
	AuthenticationRequired bool     `json:"authenticationRequired"`
}

func (s *BoxService) StartProxyShare(port int32, username, password string) error {
	configuration, err := newProxyShareConfiguration(port, username, password)
	if err != nil {
		return bridgeSafeError(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return bridgeSafeError(errors.New("clash: proxy share requires a running service"))
	}
	previous := s.proxyShare
	if previous != nil {
		_ = previous.close()
		s.proxyShare = nil
	}
	runtime, err := newProxyShareRuntime(configuration)
	if err != nil {
		if previous != nil {
			restored, restoreError := newProxyShareRuntime(previous.configuration)
			if restoreError != nil {
				s.updateRuntimeInboundCountLocked()
				return bridgeSafeError(errors.New("clash: proxy share update and rollback failed"))
			}
			s.proxyShare = restored
		}
		return bridgeSafeError(err)
	}
	s.proxyShare = runtime
	s.updateRuntimeInboundCountLocked()
	return nil
}

func (s *BoxService) StopProxyShare() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.stopProxyShareLocked()
	if s.running {
		s.updateRuntimeInboundCountLocked()
	}
	return bridgeSafeError(err)
}

func (s *BoxService) ProxyShareStatusJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bridgeSafeString(mustJSON(s.proxyShareStatusLocked()))
}

func (s *BoxService) proxyShareStatusLocked() proxyShareStatus {
	if !s.running || s.proxyShare == nil || len(s.proxyShare.listeners) != 2 {
		return proxyShareStatus{}
	}
	authenticator := s.proxyShare.authentication.Authenticator()
	configuration := s.proxyShare.configuration
	if authenticator == nil || !authenticator.Verify(configuration.username, configuration.password) {
		return proxyShareStatus{}
	}
	return proxyShareStatus{
		Enabled:                true,
		Port:                   configuration.port,
		Protocols:              []string{"http", "socks5"},
		AuthenticationRequired: true,
	}
}

func (s *BoxService) reapplyProxyShareLocked() error {
	if s.proxyShare == nil {
		return nil
	}
	if len(s.proxyShare.listeners) != 2 {
		return errors.New("clash: proxy-share listener is unavailable")
	}
	return nil
}

func (s *BoxService) stopProxyShareLocked() error {
	if s.proxyShare == nil {
		return nil
	}
	err := s.proxyShare.close()
	s.proxyShare = nil
	return err
}

func (s *BoxService) updateRuntimeInboundCountLocked() {
	s.inboundCount = s.runtimeInboundCountLocked()
	setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
}

func (s *BoxService) runtimeInboundCountLocked() int32 {
	count := runtimeInboundCount()
	if s.proxyShare != nil {
		count++
	}
	return count
}

func newProxyShareConfiguration(port int32, username, password string) (*proxyShareConfiguration, error) {
	if port < ProxyShareMinimumPort || port > ProxyShareMaximumPort {
		return nil, fmt.Errorf("clash: proxy-share port must be within %d...%d", ProxyShareMinimumPort, ProxyShareMaximumPort)
	}
	if !validProxyShareUsername(username) {
		return nil, errors.New("clash: proxy-share username is invalid")
	}
	if !validProxySharePassword(password) {
		return nil, fmt.Errorf("clash: proxy-share password must be %d...%d bytes without control characters", ProxyShareMinimumPasswordBytes, ProxyShareMaximumCredentialBytes)
	}
	return &proxyShareConfiguration{port: port, username: username, password: password}, nil
}

func validProxyShareUsername(value string) bool {
	return value != "" &&
		len(value) <= int(ProxyShareMaximumCredentialBytes) &&
		utf8.ValidString(value) &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsRune(value, ':') &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validProxySharePassword(value string) bool {
	return len(value) >= int(ProxyShareMinimumPasswordBytes) &&
		len(value) <= int(ProxyShareMaximumCredentialBytes) &&
		utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func newProxyShareRuntime(configuration *proxyShareConfiguration) (*proxyShareRuntime, error) {
	authentication := authStore.NewAuthStore(coreAuth.NewAuthenticator([]coreAuth.AuthUser{{
		User: configuration.username,
		Pass: configuration.password,
	}}))
	runtime := &proxyShareRuntime{
		configuration:  configuration,
		authentication: authentication,
	}
	port := strconv.Itoa(int(configuration.port))
	for _, endpoint := range []struct {
		host    string
		network string
	}{{"0.0.0.0", "tcp4"}, {"::", "tcp6"}} {
		listener, err := mixed.NewWithConfig(
			LC.AuthServer{
				Enable:    true,
				Listen:    net.JoinHostPort(endpoint.host, port),
				AuthStore: authentication,
			},
			proxyShareListenConfig{
				base:    coreInbound.NewListenConfig(),
				network: endpoint.network,
			},
			tunnel.Tunnel,
			coreInbound.WithInName("CLASH-PROXY-SHARE"),
			coreInbound.WithSpecialRules(""),
		)
		if err != nil {
			_ = runtime.close()
			return nil, proxySharePortUnavailableError{
				port:  configuration.port,
				cause: fmt.Errorf("clash: proxy-share listener failed to start on %s: %w", endpoint.host, err),
			}
		}
		runtime.listeners = append(runtime.listeners, listener)
	}
	return runtime, nil
}

func (runtime *proxyShareRuntime) close() error {
	if runtime == nil {
		return nil
	}
	var closeErrors []error
	for _, listener := range runtime.listeners {
		if err := listener.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	runtime.listeners = nil
	return errors.Join(closeErrors...)
}
