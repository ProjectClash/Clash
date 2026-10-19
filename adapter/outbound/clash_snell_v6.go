package outbound

import (
	"context"
	"fmt"
	"net"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/transport/jls"
	"github.com/ProjectClash/Clash/transport/restls"
	"github.com/ProjectClash/Clash/transport/shadowtls"
)


const snellVersionV6 = 6

type SnellV6ClientOptions struct {
	PSK, UserKey []byte
	Mode         string
	Reuse        bool
	Dial         func(ctx context.Context) (net.Conn, error)
}

type SnellV6Client interface {
	DialContext(ctx context.Context, host string, port uint16) (net.Conn, error)
	StreamConn(conn net.Conn, host string, port uint16) net.Conn
	PacketConn(conn net.Conn) (net.PacketConn, error)
	Reset()
	Close() error
}

var NewSnellV6Client func(SnellV6ClientOptions) (SnellV6Client, error)

func warnSnellV6OnlyFields(addr string, option SnellOption) {
	if option.Version != snellVersionV6 && (option.Mode != "" || option.UserKey != "") {
		log.Warnln("[Snell] %s: mode and user-key are version 6's; version %d ignores them", addr, option.Version)
	}
}

func (s *Snell) initV6() error {
	if NewSnellV6Client == nil {
		return fmt.Errorf("snell %s: version 6 is not in this build", s.addr)
	}
	switch s.obfsOption.Mode {
	case "", shadowtls.Mode, restls.Mode, jls.Mode:
	default:
		return fmt.Errorf("snell %s: version 6 has no obfs (mode replaces it): %s", s.addr, s.obfsOption.Mode)
	}
	client, err := NewSnellV6Client(SnellV6ClientOptions{
		PSK:     s.psk,
		UserKey: []byte(s.option.UserKey),
		Mode:    s.option.Mode,
		Reuse:   s.option.Reuse,
		Dial:    s.dialServerV6,
	})
	if err != nil {
		return fmt.Errorf("snell %s: %w", s.addr, err)
	}
	s.v6 = client
	return nil
}

func (s *Snell) dialServerV6(ctx context.Context) (net.Conn, error) {
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	wrapped, err := s.transportV6(ctx, c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return wrapped, nil
}

func (s *Snell) transportV6(ctx context.Context, c net.Conn) (net.Conn, error) {
	switch s.obfsOption.Mode {
	case shadowtls.Mode:
		return shadowtls.NewShadowTLS(ctx, c, s.shadowTLSOption)
	case restls.Mode:
		return restls.NewRestls(ctx, c, s.restlsConfig)
	case jls.Mode:
		return jls.NewClient(ctx, c, s.jlsConfig)
	}
	return c, nil
}

func (s *Snell) dialV6(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := s.v6.DialContext(ctx, metadata.String(), metadata.DstPort)
	if err != nil {
		return nil, err
	}
	return NewConn(c, s), nil
}

func (s *Snell) streamConnV6(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c, err := s.transportV6(ctx, c)
	if err != nil {
		return nil, err
	}
	return s.v6.StreamConn(c, metadata.String(), metadata.DstPort), nil
}

func (s *Snell) listenPacketV6(ctx context.Context) (_ C.PacketConn, err error) {
	c, err := s.dialServerV6(ctx)
	if err != nil {
		return nil, err
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)
	pc, err := s.v6.PacketConn(c)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, s), nil
}

func (s *Snell) ResetNetwork() {
	if s.v6 != nil {
		s.v6.Reset()
	}
}

func (s *Snell) keepsOwnSessions() bool { return s.v6 != nil && s.option.Reuse }

func (s *Snell) Close() error {
	if s.v6 != nil {
		return s.v6.Close()
	}
	return s.Base.Close()
}
