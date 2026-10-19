package http

import (
	"context"
	"github.com/metacubex/tls"
	"net"
)

type TLSConn interface {
	net.Conn
	NetConn() net.Conn
	HandshakeContext(ctx context.Context) error
	ConnectionState() tls.ConnectionState
}

var _ TLSConn = (*tls.Conn)(nil)
