package outbound

import (
	"net"
	"sync/atomic"
)

var mieruTunnelMultiplexingOff atomic.Bool

const MieruTunnelMultiplexing = "MULTIPLEXING_OFF"

const MieruTunnelMultiplexingTransport = "TCP"

func SetMieruTunnelMultiplexingOff(on bool) (previous bool) {
	return mieruTunnelMultiplexingOff.Swap(on)
}

func MieruTunnelMultiplexingOff() bool { return mieruTunnelMultiplexingOff.Load() }

func mieruMultiplexing(written, transport string) string {
	if transport == MieruTunnelMultiplexingTransport && mieruTunnelMultiplexingOff.Load() {
		return MieruTunnelMultiplexing
	}
	return written
}

func closeMieruDial(conn net.Conn) {
	if conn != nil {
		_ = conn.Close()
	}
}
