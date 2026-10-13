package hysteria2

import "github.com/metacubex/quic-go"

type SetCongestionControllerFunc func(quicConn *quic.Conn)
