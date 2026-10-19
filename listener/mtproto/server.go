package mtproto

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	"github.com/ProjectClash/Clash/common/pool"
	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/log"
)

var listenOnLoopbackOnly = runtime.GOOS == "ios"

type Listener struct {
	closed    atomic.Bool
	config    LC.MTProtoServer
	secret    Secret
	listeners []net.Listener
	handshaking chan struct{}
	seen initReplayCache
}

const maxHandshaking = 64

func New(config LC.MTProtoServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (C.MultiAddrListener, error) {
	secret, err := ParseSecret(config.Secret)
	if err != nil {
		return nil, err
	}
	l := &Listener{config: config, secret: secret, handshaking: make(chan struct{}, maxHandshaking)}
	for _, addr := range strings.Split(config.Listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		ln, err := lc.Listen(context.Background(), "tcp", listenAddress(addr, listenOnLoopbackOnly))
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		l.listeners = append(l.listeners, ln)
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					if l.closed.Load() {
						return
					}
					continue
				}
				select {
				case l.handshaking <- struct{}{}:
				default:
					_ = conn.Close()
					continue
				}
				go l.handleConn(conn, tunnel, func() { <-l.handshaking }, additions...)
			}
		}(ln)
	}
	return l, nil
}

func listenAddress(addr string, loopbackOnly bool) string {
	host, port, err := net.SplitHostPort(addr)
	if !loopbackOnly || err != nil {
		return addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsUnspecified() {
		return addr
	}
	if ip.Is4() || ip.Is4In6() {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return net.JoinHostPort("::1", port)
}

func (l *Listener) Close() error {
	l.closed.Store(true)
	var retErr error
	for _, ln := range l.listeners {
		if err := ln.Close(); err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, ln := range l.listeners {
		addrList = append(addrList, ln.Addr())
	}
	return
}

const handshakeTimeout = C.DefaultTCPTimeout

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	l.handleConn(conn, tunnel, func() {}, additions...)
}

func (l *Listener) handleConn(conn net.Conn, tunnel C.Tunnel, handshaken func(), additions ...inbound.Addition) {
	defer conn.Close()
	var frame [initLen]byte
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	_, err := io.ReadFull(conn, frame[:])
	handshaken()
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	client, err := acceptInit(&frame, l.secret)
	if err != nil {
		log.Debugln("[MTProto] %s refused: %s", conn.RemoteAddr(), err)
		return
	}
	if !l.seen.firstTime(&frame) {
		log.Debugln("[MTProto] %s refused: an init seen before (a replay)", conn.RemoteAddr())
		return
	}
	endpoint, ok := pickEndpoint(client.dc, l.config.IPv6)
	if !ok {
		log.Debugln("[MTProto] %s asked for DC %d, which has no endpoint", conn.RemoteAddr(), client.dc)
		return
	}
	relay, err := newRelayConn(conn, client, endpoint)
	if err != nil {
		log.Warnln("[MTProto] %s: %s", conn.RemoteAddr(), err)
		return
	}
	defer relay.Close()

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.MTPROTO,
		DstIP:   endpoint.addr.Addr(),
		DstPort: endpoint.addr.Port(),
	}
	inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(conn.RemoteAddr()), inbound.WithInAddr(conn.LocalAddr()))
	inbound.ApplyAdditions(metadata, additions...)
	tunnel.HandleTCPConn(relay, metadata)
}

type relayConn struct {
	net.Conn
	fromClient, toClient cipher.Stream
	toDC, fromDC         cipher.Stream
	endpoint             dcPick
	dc                   int16

	init     [initLen]byte
	initRead int

	dcAnswered atomic.Bool
	clientLeft atomic.Bool
	closed     atomic.Bool
}

func newRelayConn(conn net.Conn, client clientInit, endpoint dcPick) (*relayConn, error) {
	init, toDC, fromDC, err := newDCInit(rand.Reader, client.tag, client.dc)
	if err != nil {
		return nil, err
	}
	return &relayConn{
		Conn:       conn,
		fromClient: client.decrypt,
		toClient:   client.encrypt,
		toDC:       toDC,
		fromDC:     fromDC,
		endpoint:   endpoint,
		dc:         client.dc,
		init:       init,
	}, nil
}

func (c *relayConn) Read(b []byte) (int, error) {
	if c.initRead < initLen {
		n := copy(b, c.init[c.initRead:])
		c.initRead += n
		return n, nil
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.fromClient.XORKeyStream(b[:n], b[:n])
		c.toDC.XORKeyStream(b[:n], b[:n])
	}
	if err != nil {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			c.clientLeft.Store(true)
		}
	}
	return n, err
}

func (c *relayConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !c.dcAnswered.Load() {
		c.dcAnswered.Store(true)
	}
	size := len(b)
	if size > pool.RelayBufferSize {
		size = pool.RelayBufferSize
	}
	buf := pool.Get(size)
	defer pool.Put(buf)
	written := 0
	for written < len(b) {
		chunk := buf
		if rest := len(b) - written; rest < len(chunk) {
			chunk = chunk[:rest]
		}
		c.fromDC.XORKeyStream(chunk, b[written:written+len(chunk)])
		c.toClient.XORKeyStream(chunk, chunk)
		n, err := c.Conn.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *relayConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && !c.dcAnswered.Load() && !c.clientLeft.Load() {
		c.endpoint.markFailed()
		log.Debugln("[MTProto] DC %d endpoint %s gave no answer, the next connection to it skips it", c.dc, c.endpoint.addr)
	}
	return c.Conn.Close()
}

type initReplayCache struct {
	mu   sync.Mutex
	keys map[[16]byte]struct{}
	ring [][16]byte
	next int
}

const replayCacheSize = 1024

func (c *initReplayCache) firstTime(frame *[initLen]byte) bool {
	key := [16]byte(frame[8:24])
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = make(map[[16]byte]struct{}, replayCacheSize)
		c.ring = make([][16]byte, replayCacheSize)
	}
	if _, seen := c.keys[key]; seen {
		return false
	}
	if len(c.keys) == replayCacheSize {
		delete(c.keys, c.ring[c.next])
	}
	c.keys[key] = struct{}{}
	c.ring[c.next] = key
	c.next = (c.next + 1) % replayCacheSize
	return true
}
