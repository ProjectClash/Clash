package qtls

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type PacketDialer interface {
	ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)
}

type PacketDialerFunc func(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)

func (f PacketDialerFunc) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return f(ctx, network, address, rAddrPort)
}

type QuicDialer interface {
	DialContext(ctx context.Context, addr string, listener PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error)
}

type QuicDialerFunc func(ctx context.Context, addr string, listener PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error)

func (f QuicDialerFunc) DialContext(ctx context.Context, addr string, listener PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
	return f(ctx, addr, listener, tlsCfg, cfg, early)
}
