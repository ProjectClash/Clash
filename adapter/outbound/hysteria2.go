package outbound

import (
	"context"
	"errors"
	"fmt"
	"github.com/ProjectClash/Clash/component/dialer"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/ca"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/transport/tuic/common"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/sing-quic/hysteria2/realm"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

const minHopInterval = 5
const defaultHopInterval = 30

type Hysteria2 struct {
	*Base

	option *Hysteria2Option
	clientMu    sync.Mutex
	client      *hysteria2.Client
	clientErr   error
	clientTried bool
	closed      bool
	buildClient func() (*hysteria2.Client, error)
}

func (h *Hysteria2) lazyClient() (*hysteria2.Client, error) {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	if h.closed {
		return nil, errOutboundClosed
	}
	if !h.clientTried {
		h.clientTried = true
		h.client, h.clientErr = h.buildClient()
	}
	return h.client, h.clientErr
}

func (h *Hysteria2) clientBuilt() bool {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	return h.client != nil
}

type Hysteria2Option struct {
	BasicOption
	Name              string     `proxy:"name"`
	Server            string     `proxy:"server"`
	Port              int        `proxy:"port,omitempty"`
	Ports             string     `proxy:"ports,omitempty"`
	HopInterval       string     `proxy:"hop-interval,omitempty"`
	Up                string     `proxy:"up,omitempty"`
	Down              string     `proxy:"down,omitempty"`
	Password          string     `proxy:"password,omitempty"`
	Obfs              string     `proxy:"obfs,omitempty"`
	ObfsPassword      string     `proxy:"obfs-password,omitempty"`
	ObfsMinPacketSize int        `proxy:"obfs-min-packet-size,omitempty"`
	ObfsMaxPacketSize int        `proxy:"obfs-max-packet-size,omitempty"`
	SNI               string     `proxy:"sni,omitempty"`
	ECHOpts           ECHOptions `proxy:"ech-opts,omitempty"`
	SkipCertVerify    bool       `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify    string     `proxy:"name-cert-verify,omitempty"`
	Fingerprint       string     `proxy:"fingerprint,omitempty"`
	Certificate       string     `proxy:"certificate,omitempty"`
	PrivateKey        string     `proxy:"private-key,omitempty"`
	ALPN              []string   `proxy:"alpn,omitempty"`
	CWND              int        `proxy:"cwnd,omitempty"`
	BBRProfile        string     `proxy:"bbr-profile,omitempty"`
	UdpMTU            int        `proxy:"udp-mtu,omitempty"`
	HandshakeTimeout  int        `proxy:"handshake-timeout,omitempty"`

	RealmOpts Hysteria2RealmOption `proxy:"realm-opts,omitempty"`

	// quic-go special config
	InitialStreamReceiveWindow     uint64 `proxy:"initial-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow         uint64 `proxy:"max-stream-receive-window,omitempty"`
	InitialConnectionReceiveWindow uint64 `proxy:"initial-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow     uint64 `proxy:"max-connection-receive-window,omitempty"`
}

type Hysteria2RealmOption struct {
	Enable      bool     `proxy:"enable,omitempty"`
	ServerURL   string   `proxy:"server-url,omitempty"`
	Token       string   `proxy:"token,omitempty"`
	RealmID     string   `proxy:"realm-id,omitempty"`
	STUNServers []string `proxy:"stun-servers,omitempty"`

	// for ServerURL
	SNI            string   `proxy:"sni,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify string   `proxy:"name-cert-verify,omitempty"`
	Fingerprint    string   `proxy:"fingerprint,omitempty"`
	Certificate    string   `proxy:"certificate,omitempty"`
	PrivateKey     string   `proxy:"private-key,omitempty"`
	ALPN           []string `proxy:"alpn,omitempty"`
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	client, err := h.lazyClient()
	if err != nil {
		return nil, err
	}
	c, err := client.DialConn(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, h), nil
}

func (h *Hysteria2) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = h.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	client, err := h.lazyClient()
	if err != nil {
		return nil, err
	}
	pc, err := client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(N.NewThreadSafePacketConn(pc), h), nil
}

// Close implements C.ProxyAdapter
func (h *Hysteria2) Close() error {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	h.closed = true
	if h.client == nil {
		return nil
	}
	client := h.client
	h.client = nil
	return client.CloseWithError(errors.New("proxy removed"))
}

// ProxyInfo implements C.ProxyAdapter
func (h *Hysteria2) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Hysteria2{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Hysteria2,
			ProviderName: option.ProviderName,
			UDP:          true,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	build := func() (*hysteria2.Client, error) {

		var salamanderPassword string
		var geckoPassword string
		var geckoMinPacketSize, geckoMaxPacketSize int
		if len(option.Obfs) > 0 {
			if option.ObfsPassword == "" {
				return nil, errors.New("missing obfs password")
			}
			switch option.Obfs {
			case hysteria2.ObfsTypeSalamander:
				salamanderPassword = option.ObfsPassword
			case hysteria2.ObfsTypeGecko:
				geckoPassword = option.ObfsPassword
				geckoMinPacketSize = option.ObfsMinPacketSize
				geckoMaxPacketSize = option.ObfsMaxPacketSize
			default:
				return nil, fmt.Errorf("unknown obfs type: %s", option.Obfs)
			}
		}

		serverName := option.Server
		if option.SNI != "" {
			serverName = option.SNI
		}

		tlsConfig, err := ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: option.SkipCertVerify,
				MinVersion:         tls.VersionTLS13,
			},
			Fingerprint:    option.Fingerprint,
			NameCertVerify: option.NameCertVerify,
			Certificate:    option.Certificate,
			PrivateKey:     option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}

		if option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			tlsConfig.NextProtos = option.ALPN
		}

		tlsClientConfig := tlsConfig
		echConfig, err := option.ECHOpts.Parse()
		if err != nil {
			return nil, err
		}

		if option.UdpMTU == 0 {
			// "1200" from quic-go's MaxDatagramSize
			// "-3" from quic-go's DatagramFrame.MaxDataLen
			option.UdpMTU = 1200 - 3
		}

		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     option.InitialStreamReceiveWindow,
			MaxStreamReceiveWindow:         option.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: option.InitialConnectionReceiveWindow,
			MaxConnectionReceiveWindow:     option.MaxConnectionReceiveWindow,
		}

		clientOptions := hysteria2.ClientOptions{
			Context:            context.TODO(),
			Logger:             log.SingLogger,
			SendBPS:            utils.StringToBps(option.Up),
			ReceiveBPS:         utils.StringToBps(option.Down),
			SalamanderPassword: salamanderPassword,
			GeckoPassword:      geckoPassword,
			GeckoMinPacketSize: geckoMinPacketSize,
			GeckoMaxPacketSize: geckoMaxPacketSize,
			Password:           option.Password,
			TLSConfig:          tlsClientConfig,
			QUICConfig:         quicConfig,
			UDPDisabled:        false,
			UdpMTU:             option.UdpMTU,
			ServerAddress:      M.ParseSocksaddr(addr),
			PacketListener:     outbound.dialer,
			QuicDialer: qtls.QuicDialerFunc(func(ctx context.Context, addr string, packetDialer qtls.PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
				err := echConfig.ClientHandle(ctx, tlsCfg)
				if err != nil {
					return nil, nil, err
				}
				return common.DialQuic(ctx, addr, outbound.DialOptions(), packetDialer, tlsCfg, cfg, common.DialQuicOption{Early: early, PhysicalPeer: dialer.IsPhysicalDialer(outbound.dialer)})
			}),
			SetBBRCongestion: func(quicConn *quic.Conn) {
				common.SetCongestionController(quicConn, "bbr", option.CWND, option.BBRProfile)
			},
			HandshakeTimeout: time.Duration(option.HandshakeTimeout) * time.Second,
		}

		var serverPorts []uint16
		if option.Ports != "" {
			ranges, err := utils.NewUnsignedRanges[uint16](option.Ports)
			if err != nil {
				return nil, err
			}
			ranges.Range(func(port uint16) bool {
				serverPorts = append(serverPorts, port)
				return true
			})
			if len(serverPorts) > 0 {
				hopRange, err := utils.NewUnsignedRange[uint64](option.HopInterval)
				if err != nil {
					return nil, err
				}
				start, end := hopRange.Start(), hopRange.End()
				if start == 0 {
					start = defaultHopInterval
				} else if start < minHopInterval {
					start = minHopInterval
				}
				if end < start {
					end = start
				}
				clientOptions.HopInterval = time.Duration(start) * time.Second
				clientOptions.HopIntervalMax = time.Duration(end) * time.Second
				clientOptions.ServerPorts = serverPorts
			}
		}
		if option.Port == 0 && len(serverPorts) == 0 {
			return nil, errors.New("invalid port")
		}

		if option.RealmOpts.Enable {
			httpTLSClientConfig, err := ca.GetTLSConfig(ca.Option{
				TLSConfig: &tls.Config{
					ServerName:         option.RealmOpts.SNI,
					InsecureSkipVerify: option.RealmOpts.SkipCertVerify,
					NextProtos:         option.RealmOpts.ALPN,
				},
				Fingerprint:    option.RealmOpts.Fingerprint,
				NameCertVerify: option.RealmOpts.NameCertVerify,
				Certificate:    option.RealmOpts.Certificate,
				PrivateKey:     option.RealmOpts.PrivateKey,
			})
			if err != nil {
				return nil, err
			}
			clientOptions.RealmOptions = &realm.Options{
				ServerURL:   option.RealmOpts.ServerURL,
				Token:       option.RealmOpts.Token,
				RealmID:     option.RealmOpts.RealmID,
				STUNServers: option.RealmOpts.STUNServers,
				HTTPClient: &http.Client{
					Transport: &http.Transport{
						DialContext:     outbound.dialer.DialContext,
						TLSClientConfig: httpTLSClientConfig,
						// from http.DefaultTransport
						ForceAttemptHTTP2:     true,
						MaxIdleConns:          100,
						IdleConnTimeout:       90 * time.Second,
						TLSHandshakeTimeout:   10 * time.Second,
						ExpectContinueTimeout: 1 * time.Second,
					},
				},
				Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
					if ipv4 && !ipv6 {
						return resolver.LookupIPv4WithResolver(ctx, host, resolver.ProxyServerHostResolver)
					} else if ipv6 && !ipv4 {
						return resolver.LookupIPv6WithResolver(ctx, host, resolver.ProxyServerHostResolver)
					}
					return resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
				},
				Logger: log.SingLogger,
			}
		}

		return hysteria2.NewClient(clientOptions)
	}

	probe, err := build()
	if err != nil {
		return nil, err
	}
	_ = probe.CloseWithError(nil)
	outbound.buildClient = build

	return outbound, nil
}
