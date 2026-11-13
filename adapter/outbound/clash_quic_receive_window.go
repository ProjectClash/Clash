package outbound

import (
	"sync/atomic"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/sing-quic/hysteria2"
)

var quicDefaultReceiveWindows atomic.Pointer[QUICReceiveWindows]

type QUICReceiveWindows struct {
	InitialStream     uint64
	InitialConnection uint64
	MaxConnection     uint64
	GrowingMaxConnection uint64
}

const (
	quicTunnelInitialStream     = 1 << 20
	quicTunnelInitialConnection = 12 << 20
	QUICTunnelMaxConnection = 20 << 20
	QUICTunnelGrowingMaxConnection = 0
)

func QUICTunnelReceiveWindows() *QUICReceiveWindows {
	return &QUICReceiveWindows{InitialStream: quicTunnelInitialStream, InitialConnection: quicTunnelInitialConnection,
		MaxConnection: QUICTunnelMaxConnection, GrowingMaxConnection: QUICTunnelGrowingMaxConnection}
}

func SetQUICDefaultReceiveWindows(windows *QUICReceiveWindows) {
	quicDefaultReceiveWindows.Store(windows)
}

func QUICDefaultReceiveWindows() *QUICReceiveWindows {
	return quicDefaultReceiveWindows.Load()
}

func applyQUICDefaultReceiveWindows(config *quic.Config, connectionWritten bool) {
	applyQUICDefaultReceiveWindowFields(&config.InitialConnectionReceiveWindow, &config.MaxConnectionReceiveWindow, connectionWritten)
}

func applyQUICDefaultReceiveWindowFields(initialConnection, maxConnection *uint64, connectionWritten bool) {
	windows := quicDefaultReceiveWindows.Load()
	if windows == nil || connectionWritten || windows.GrowingMaxConnection == 0 {
		return
	}
	if *maxConnection > windows.GrowingMaxConnection {
		*maxConnection = windows.GrowingMaxConnection
	}
	if *initialConnection > *maxConnection {
		*initialConnection = *maxConnection
	}
}

func fillQUICDefaultReceiveWindows(config *quic.Config) {
	windows := quicDefaultReceiveWindows.Load()
	if windows == nil {
		return
	}
	if config.InitialStreamReceiveWindow == 0 && config.MaxStreamReceiveWindow == 0 {
		config.InitialStreamReceiveWindow = windows.InitialStream
		config.MaxStreamReceiveWindow = hysteria2.DefaultStreamReceiveWindow
	}
	if config.InitialConnectionReceiveWindow == 0 && config.MaxConnectionReceiveWindow == 0 {
		config.InitialConnectionReceiveWindow = windows.InitialConnection
		config.MaxConnectionReceiveWindow = windows.MaxConnection
	}
}
