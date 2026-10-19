package clash

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	"github.com/ProjectClash/Clash/adapter/outbound"
	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
	snelllistener "github.com/ProjectClash/Clash/listener/snell"
	"github.com/ProjectClash/Clash/log"
	"github.com/sagernet/sing-snell/snellv6"
	sbuf "github.com/sagernet/sing/common/buf"
	sbufio "github.com/sagernet/sing/common/bufio"
	sM "github.com/sagernet/sing/common/metadata"
	sN "github.com/sagernet/sing/common/network"
)

func init() {
	outbound.NewSnellV6Client = newSnellV6Client
	snelllistener.NewV6ConnHandler = newSnellV6ConnHandler
}

const snellV6MinPSK, snellV6MaxPSK = 12, 255

var errSnellV6PSKLength = errors.New("version 6 needs a psk of 12 to 255 bytes")

type snellV6Client struct {
	client     *snellv6.Client
	reuse      bool
	generation atomic.Uint64
}

func newSnellV6Client(options outbound.SnellV6ClientOptions) (outbound.SnellV6Client, error) {
	if len(options.PSK) < snellV6MinPSK || len(options.PSK) > snellV6MaxPSK {
		return nil, errSnellV6PSKLength
	}
	mode, err := snellv6.ParseMode(options.Mode)
	if err != nil {
		return nil, err
	}
	client, err := snellv6.NewClient(snellv6.ClientOptions{
		PSK:     options.PSK,
		UserKey: options.UserKey,
		Mode:    mode,
		Reuse:   options.Reuse,
		Dialer:  snellV6Dialer(options.Dial),
	})
	if err != nil {
		return nil, err
	}
	return &snellV6Client{client: client, reuse: options.Reuse}, nil
}

func (c *snellV6Client) DialContext(ctx context.Context, host string, port uint16) (net.Conn, error) {
	generation := c.generation.Load()
	conn, err := c.client.DialContext(ctx, sM.ParseSocksaddrHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return &snellV6Conn{guardedConn: guardedConn{Conn: conn}, client: c, generation: generation}, nil
}

func (c *snellV6Client) StreamConn(conn net.Conn, host string, port uint16) net.Conn {
	return &snellV6Conn{guardedConn: guardedConn{Conn: c.client.DialEarlyConn(conn, sM.ParseSocksaddrHostPort(host, port))}}
}

func (c *snellV6Client) PacketConn(conn net.Conn) (net.PacketConn, error) {
	return c.client.DialPacketConn(conn)
}

func (c *snellV6Client) Reset() {
	c.generation.Add(1)
	c.client.Reset()
}
func (c *snellV6Client) Close() error { return c.client.Close() }

type snellV6Dialer func(ctx context.Context) (net.Conn, error)

func (d snellV6Dialer) DialContext(ctx context.Context, network string, _ sM.Socksaddr) (net.Conn, error) {
	if network != sN.NetworkTCP {
		return nil, errors.New("snell v6 dials its server over TCP only")
	}
	return d(ctx)
}

func (d snellV6Dialer) ListenPacket(context.Context, sM.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("snell v6 dials its server over TCP only")
}

type guardedConn struct {
	net.Conn
	closing atomic.Bool
	writing atomic.Int32
}

func (c *guardedConn) Write(p []byte) (int, error) {
	c.writing.Add(1)
	defer c.writing.Add(-1)
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *guardedConn) close() (first bool, err error) {
	if c.closing.Swap(true) {
		return false, c.Conn.Close()
	}
	if c.writing.Load() > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now())
	}
	return true, c.Conn.Close()
}

func (c *guardedConn) CloseWrite() error {
	c.writing.Add(1)
	defer c.writing.Add(-1)
	if c.closing.Load() {
		return net.ErrClosed
	}
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

type snellV6Conn struct {
	guardedConn
	client     *snellV6Client
	generation uint64
}

func (c *snellV6Conn) NeedHandshake() bool {
	if early, ok := c.Conn.(interface{ NeedHandshakeForWrite() bool }); ok {
		return early.NeedHandshakeForWrite()
	}
	return false
}

func (c *snellV6Conn) Close() error {
	first, err := c.close()
	if first && c.client != nil && c.client.reuse && c.generation != c.client.generation.Load() {
		c.client.client.Reset()
	}
	return err
}

func (c *snellV6Conn) Upstream() any { return c.Conn }

type snellV6ServerConn struct {
	guardedConn
}

func (c *snellV6ServerConn) Close() error {
	_, err := c.close()
	return err
}

type snellV6Accepted struct {
	conn      net.Conn
	additions []inbound.Addition
}

type snellV6AcceptedKey struct{}

type snellV6Handler struct {
	tunnel C.Tunnel
	udp    bool
}

func newSnellV6ConnHandler(config LC.SnellServer, tunnel C.Tunnel) (snelllistener.V6ConnHandler, error) {
	if len(config.Psk) < snellV6MinPSK || len(config.Psk) > snellV6MaxPSK {
		return nil, errSnellV6PSKLength
	}
	mode, err := snellv6.ParseMode(config.Mode)
	if err != nil {
		return nil, err
	}
	handler := &snellV6Handler{tunnel: tunnel, udp: config.UDP}
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(config.Psk), Mode: mode, Handler: handler})
	if err != nil {
		return nil, err
	}
	return func(conn net.Conn, additions ...inbound.Addition) {
		ctx := context.WithValue(context.Background(), snellV6AcceptedKey{}, &snellV6Accepted{conn: conn, additions: additions})
		if err := service.NewConnection(ctx, conn, sM.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
			log.Debugln("[Snell] v6 %s: %v", conn.RemoteAddr(), err)
		}
	}, nil
}

func (h *snellV6Handler) NewConnectionEx(ctx context.Context, conn net.Conn, _, destination sM.Socksaddr, onClose sN.CloseHandlerFunc) {
	h.tunnel.HandleTCPConn(&snellV6ServerConn{guardedConn{Conn: conn}}, snellV6Metadata(ctx, C.TCP, destination))
	if onClose != nil {
		onClose(nil)
	}
}

func (h *snellV6Handler) NewPacketConnectionEx(ctx context.Context, conn sN.PacketConn, _, _ sM.Socksaddr, onClose sN.CloseHandlerFunc) {
	err := h.servePackets(ctx, conn)
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (h *snellV6Handler) servePackets(ctx context.Context, conn sN.PacketConn) error {
	if !h.udp {
		return errors.New("snell v6: udp is off on this listener")
	}
	var remote net.Addr
	if accepted, ok := ctx.Value(snellV6AcceptedKey{}).(*snellV6Accepted); ok {
		remote = accepted.conn.RemoteAddr()
	}
	localAddr := N.NewCustomAddr(C.SNELL.String(), utils.NewUUIDV4().String(), remote)
	writer := &snellV6PacketWriter{conn: conn}
	handle := func(buffer *sbuf.Buffer, destination sM.Socksaddr) {
		payload := append([]byte(nil), buffer.Bytes()...)
		buffer.Release()
		metadata := snellV6Metadata(ctx, C.UDP, destination)
		h.tunnel.HandleUDPPacket(&snellV6Packet{data: payload, writer: writer, localAddr: localAddr, destination: metadata.UDPAddr()}, metadata)
	}
	if cached, ok := conn.(interface{ ReadCachedPacket() *sN.PacketBuffer }); ok {
		if first := cached.ReadCachedPacket(); first != nil {
			handle(first.Buffer, first.Destination)
			sN.PutPacketBuffer(first)
		}
	}
	if waiter, ok := sbufio.CreatePacketReadWaiter(conn); ok {
		waiter.InitializeReadWaiter(sN.ReadWaitOptions{})
		for {
			buffer, destination, err := waiter.WaitReadPacket()
			if err != nil {
				return err
			}
			handle(buffer, destination)
		}
	}
	for {
		buffer := sbuf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		handle(buffer, destination)
	}
}

type snellV6PacketWriter struct {
	mu   sync.Mutex
	conn sN.PacketConn
}

type snellV6Packet struct {
	data        []byte
	writer      *snellV6PacketWriter
	localAddr   net.Addr
	destination net.Addr
}

func (p *snellV6Packet) Data() []byte { return p.data }

func (p *snellV6Packet) WriteBack(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		addr = p.destination
	}
	p.writer.mu.Lock()
	defer p.writer.mu.Unlock()
	return sbufio.WritePacketBuffer(p.writer.conn, sbuf.As(b), sM.SocksaddrFromNet(addr))
}

func (p *snellV6Packet) Drop()               { p.data = nil }
func (p *snellV6Packet) LocalAddr() net.Addr { return p.localAddr }

func snellV6Metadata(ctx context.Context, network C.NetWork, destination sM.Socksaddr) *C.Metadata {
	metadata := &C.Metadata{NetWork: network, Type: C.SNELL, DstPort: destination.Port}
	if destination.IsFqdn() {
		metadata.Host = destination.Fqdn
	} else if destination.Addr.IsValid() {
		metadata.DstIP = destination.Addr.Unmap()
	}
	if accepted, ok := ctx.Value(snellV6AcceptedKey{}).(*snellV6Accepted); ok {
		inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(accepted.conn.RemoteAddr()), inbound.WithInAddr(accepted.conn.LocalAddr()))
		inbound.ApplyAdditions(metadata, accepted.additions...)
	}
	return metadata
}

var (
	_ outbound.SnellV6Client = (*snellV6Client)(nil)
	_ C.UDPPacket            = (*snellV6Packet)(nil)
	_ sN.Dialer              = snellV6Dialer(nil)
)
