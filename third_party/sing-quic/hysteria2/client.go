package hysteria2

import (
	"context"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/randv2"
	qtls "github.com/metacubex/sing-quic"
	hyCC "github.com/metacubex/sing-quic/hysteria2/congestion"
	"github.com/metacubex/sing-quic/hysteria2/internal/protocol"
	"github.com/metacubex/sing-quic/hysteria2/realm"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/baderror"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type ClientOptions struct {
	Context            context.Context
	QuicDialer         qtls.QuicDialer
	PacketListener     qtls.PacketDialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	ServerPorts        []uint16
	HopInterval        time.Duration
	HopIntervalMax     time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	GeckoPassword      string
	GeckoMinPacketSize int
	GeckoMaxPacketSize int
	Password           string
	TLSConfig          *tls.Config
	QUICConfig         *quic.Config
	UDPDisabled        bool
	RealmOptions       *realm.Options
	SetBBRCongestion   SetCongestionControllerFunc
	UdpMTU             int
	HandshakeTimeout   time.Duration
}

type Client struct {
	ctx                context.Context
	quicDialer         qtls.QuicDialer
	packetDialer       qtls.PacketDialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddress      M.Socksaddr
	serverPorts        []uint16
	hopInterval        time.Duration
	hopIntervalMax     time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	geckoPassword      string
	geckoMinPacketSize int
	geckoMaxPacketSize int
	password           string
	tlsConfig          *tls.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	realmOptions       *realm.Options
	controlClient      *realm.ControlClient
	setBBRCongestion   SetCongestionControllerFunc
	udpMTU             int
	handshakeTimeout   time.Duration

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{}
	if options.QUICConfig != nil {
		quicConfig = options.QUICConfig
	}
	quicConfig.DisablePathMTUDiscovery = !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin")
	quicConfig.EnableDatagrams = !options.UDPDisabled
	if quicConfig.InitialStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if quicConfig.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if quicConfig.InitialConnectionReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnReceiveWindow
	}
	if quicConfig.MaxConnectionReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = DefaultConnReceiveWindow
	}
	if quicConfig.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = DefaultMaxIdleTimeout
	}
	if quicConfig.KeepAlivePeriod == 0 {
		quicConfig.KeepAlivePeriod = DefaultKeepAlivePeriod
	}
	if len(options.TLSConfig.NextProtos) == 0 {
		options.TLSConfig.NextProtos = []string{http3.NextProtoH3}
	}
	if options.RealmOptions != nil {
		if len(options.ServerPorts) > 0 {
			return nil, E.New("realm and port hopping are mutually exclusive")
		}
		if options.RealmOptions.IPVersion != 0 && options.RealmOptions.IPVersion != 4 && options.RealmOptions.IPVersion != 6 {
			return nil, E.New("invalid IP version: ", options.RealmOptions.IPVersion)
		}
	}
	if options.GeckoPassword != "" {
		if options.GeckoMinPacketSize == 0 {
			options.GeckoMinPacketSize = geckoDefaultMinPacketSize
		}
		if options.GeckoMaxPacketSize == 0 {
			options.GeckoMaxPacketSize = geckoDefaultMaxPacketSize
		}
		if options.GeckoMinPacketSize <= 0 || options.GeckoMinPacketSize > options.GeckoMaxPacketSize || options.GeckoMaxPacketSize > geckoMaxOnWireSize {
			return nil, E.New("gecko: invalid packet size range")
		}
	}
	var controlClient *realm.ControlClient
	if options.RealmOptions != nil {
		var err error
		controlClient, err = realm.NewControlClient(options.RealmOptions.ServerURL, options.RealmOptions.Token, options.RealmOptions.HTTPClient)
		if err != nil {
			return nil, E.Cause(err, "create control client")
		}
	}
	client := &Client{
		ctx:                options.Context,
		quicDialer:         options.QuicDialer,
		packetDialer:       options.PacketListener,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddress:      options.ServerAddress,
		serverPorts:        options.ServerPorts,
		hopInterval:        options.HopInterval,
		hopIntervalMax:     options.HopIntervalMax,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		geckoPassword:      options.GeckoPassword,
		geckoMinPacketSize: options.GeckoMinPacketSize,
		geckoMaxPacketSize: options.GeckoMaxPacketSize,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		realmOptions:       options.RealmOptions,
		controlClient:      controlClient,
		setBBRCongestion:   options.SetBBRCongestion,
		udpMTU:             options.UdpMTU,
		handshakeTimeout:   options.HandshakeTimeout,
	}
	return client, nil
}

func (c *Client) nextHopInterval() time.Duration {
	if c.hopInterval >= c.hopIntervalMax {
		return c.hopInterval
	}
	return c.hopInterval + time.Duration(randv2.Int64N(int64(c.hopIntervalMax-c.hopInterval)+1))
}

func (c *Client) hopLoop(conn *clientQUICConnection) {
	timer := time.NewTimer(c.nextHopInterval())
	defer timer.Stop()
	c.logger.Debug("Entering hop loop ...")
	remoteAddr, ok := conn.quicConn.RemoteAddr().(*net.UDPAddr)
	if !ok || remoteAddr == nil {
		c.logger.Error("Failed to get remote address for hop", remoteAddr)
		return
	}
	for {
		select {
		case <-timer.C:
			targetAddr := *remoteAddr
			targetAddr.Port = int(c.serverPorts[randv2.IntN(len(c.serverPorts))])
			conn.quicConn.SetRemoteAddr(&targetAddr)
			c.logger.Debug("Hopped to ", &targetAddr)
			timer.Reset(c.nextHopInterval())
			continue
		case <-c.ctx.Done():
		case <-conn.quicConn.Context().Done():
		case <-conn.connDone:
		}
		c.logger.Debug("Exiting hop loop ...")
		return
	}
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}

	if c.handshakeTimeout <= 0 {
		defer c.connAccess.Unlock()
		conn, err := c.offerNew(ctx)
		if err != nil {
			return nil, err
		}
		c.conn = conn
		return conn, nil
	}

	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := common.ContextWithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	offerCtx, cancel := context.WithTimeout(offerCtx, c.handshakeTimeout)
	defer cancel()
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	if c.realmOptions != nil {
		return c.offerNewRealm(ctx)
	}
	serverAddr := c.serverAddress
	if len(c.serverPorts) > 0 {
		serverAddr.Port = c.serverPorts[randv2.IntN(len(c.serverPorts))]
	}
	return c.authenticateAndWrap(ctx, c.packetDialer, serverAddr)
}

type realmFamilyConn struct {
	family         string
	ipv4           bool
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

func (c *Client) offerNewRealm(ctx context.Context) (*clientQUICConnection, error) {
	families, err := c.realmOpenFamilies(ctx)
	if err != nil {
		return nil, err
	}
	surviving, localAddresses, err := c.realmDiscoverFamilies(ctx, families)
	if err != nil {
		return nil, err
	}
	closeSurviving := func() {
		for _, family := range surviving {
			_ = family.conn.Close()
		}
	}
	localMetadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		closeSurviving()
		return nil, E.Cause(err, "generate punch metadata")
	}
	response, err := c.controlClient.Connect(ctx, c.realmOptions.RealmID, localAddresses, localMetadata)
	if err != nil {
		closeSurviving()
		return nil, E.Cause(err, "realm connect")
	}
	winner, result, err := c.realmRacePunch(ctx, surviving, response.Addresses, response.PunchMetadata)
	if err != nil {
		return nil, err
	}
	packetConn := winner.conn
	peerAddr := M.SocksaddrFromNetIP(result.PeerAddr)
	packetDialer := qtls.PacketDialerFunc(func(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
		return packetConn, nil
	})
	return c.authenticateAndWrap(ctx, packetDialer, peerAddr)
}

func (c *Client) realmOpenFamilies(ctx context.Context) ([]*realmFamilyConn, error) {
	specs := []struct {
		family string
		ipv4   bool
		addr   M.Socksaddr
	}{
		{"v4", true, M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{"v6", false, M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	switch c.realmOptions.IPVersion {
	case 4:
		specs = specs[:1]
	case 6:
		specs = specs[1:]
	}
	conns := make([]*realmFamilyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		i, spec := i, spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := c.packetDialer.ListenPacket(ctx, "udp", "", spec.addr.AddrPort())
			if listenErr != nil {
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &realmFamilyConn{family: spec.family, ipv4: spec.ipv4, conn: conn}
		}()
	}
	wg.Wait()
	var families []*realmFamilyConn
	var errs []error
	for i, family := range conns {
		if family != nil {
			families = append(families, family)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 {
		return nil, E.Cause(E.Errors(errs...), "listen UDP for realm")
	}
	return families, nil
}

func (c *Client) realmDiscoverFamilies(ctx context.Context, families []*realmFamilyConn) ([]*realmFamilyConn, []netip.AddrPort, error) {
	var needIPv4, needIPv6 bool
	for _, family := range families {
		if family.ipv4 {
			needIPv4 = true
		} else {
			needIPv6 = true
		}
	}
	stunServers, err := realm.ResolveSTUNServers(ctx, c.realmOptions.STUNServers, c.realmOptions.Resolver, needIPv4, needIPv6)
	if err != nil {
		for _, family := range families {
			_ = family.conn.Close()
		}
		return nil, nil, E.Cause(err, "resolve STUN servers")
	}
	type discoverResult struct {
		addrs []netip.AddrPort
		err   error
	}
	results := make([]discoverResult, len(families))
	var wg sync.WaitGroup
	for i, family := range families {
		i, family := i, family
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers := make([]netip.AddrPort, 0, len(stunServers))
			for _, server := range stunServers {
				if server.Addr().Is4() == family.ipv4 {
					servers = append(servers, server)
				}
			}
			addrs, discoverErr := realm.Discover(ctx, family.conn, servers)
			results[i] = discoverResult{addrs: addrs, err: discoverErr}
		}()
	}
	wg.Wait()
	var surviving []*realmFamilyConn
	var union []netip.AddrPort
	var errs []error
	for i, family := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, family.family))
			_ = family.conn.Close()
			continue
		}
		family.localAddresses = result.addrs
		surviving = append(surviving, family)
		union = append(union, result.addrs...)
	}
	if len(surviving) == 0 {
		return nil, nil, E.Cause(E.Errors(errs...), "realm STUN discovery")
	}
	return surviving, union, nil
}

func (c *Client) realmRacePunch(
	ctx context.Context,
	families []*realmFamilyConn,
	peerAddresses []netip.AddrPort,
	metadata realm.PunchMetadata,
) (*realmFamilyConn, realm.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	type outcome struct {
		family *realmFamilyConn
		result realm.PunchResult
		err    error
	}
	out := make(chan outcome, len(families))
	for _, family := range families {
		family := family
		go func() {
			peers := make([]netip.AddrPort, 0, len(peerAddresses))
			for _, peer := range peerAddresses {
				if peer.Addr().Is4() == family.ipv4 {
					peers = append(peers, peer)
				}
			}
			punchResult, punchErr := realm.Punch(raceCtx, family.conn, peers, metadata)
			out <- outcome{family: family, result: punchResult, err: punchErr}
		}()
	}
	var errs []error
	for pending := len(families); pending > 0; pending-- {
		result := <-out
		if result.err == nil {
			for _, family := range families {
				if family != result.family {
					_ = family.conn.Close()
				}
			}
			return result.family, result.result, nil
		}
		errs = append(errs, E.Cause(result.err, result.family.family))
	}
	for _, family := range families {
		_ = family.conn.Close()
	}
	return nil, realm.PunchResult{}, E.Cause(E.Errors(errs...), "realm punch")
}

func (c *Client) authenticateAndWrap(ctx context.Context, packetDialer qtls.PacketDialer, serverAddr M.Socksaddr) (*clientQUICConnection, error) {
	_packetDialer := packetDialer
	packetDialer = qtls.PacketDialerFunc(func(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
		pc, err := _packetDialer.ListenPacket(ctx, network, address, rAddrPort)
		if err != nil {
			return nil, err
		}
		if c.geckoPassword != "" {
			pc = NewGeckoConn(pc, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize)
		} else if c.salamanderPassword != "" {
			pc = NewSalamanderConn(pc, []byte(c.salamanderPassword))
		}
		return pc, nil
	})

	packetConn, quicConn, err := c.quicDialer.DialContext(ctx, serverAddr.String(), packetDialer, c.tlsConfig, c.quicConfig, true)
	if err != nil {
		return nil, err
	}

	http3Transport := &http3.Transport{
		TLSClientConfig: c.tlsConfig,
		QUICConfig:      c.quicConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quicConn, nil
		},
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	response, err := http3Transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		_ = packetConn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		_ = quicConn.CloseWithError(0, "")
		_ = packetConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, c.brutalDebug, c.logger))
	} else {
		if c.setBBRCongestion != nil {
			c.setBBRCongestion(quicConn)
		}
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     packetConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	go func() {
		<-quicConn.Context().Done()
		conn.closeWithError(context.Cause(quicConn.Context()))
	}()
	if c.hopInterval > 0 {
		go c.hopLoop(conn)
	}
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	}, c.udpMTU)
	conn.udpAccess.Lock()
	select {
	case <-conn.connDone:
		conn.udpAccess.Unlock()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		c.udpAccess.Lock()
		close(c.connDone)
		udpConnMap := c.udpConnMap
		c.udpConnMap = make(map[uint32]*udpPacketConn)
		c.udpAccess.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(err)
		}
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, baderror.WrapQUIC(err)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, baderror.WrapQUIC(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
