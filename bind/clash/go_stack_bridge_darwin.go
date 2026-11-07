package clash

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"

	tun "github.com/metacubex/sing-tun"

	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	"golang.org/x/sys/unix"
)

type goStackBridge struct {
	memory *gotun.MemoryTun
	device tun.Tun
	mtu    int
	closed atomic.Bool
}

const goStackBridgeHeader = 4

func newGoStackBridge(device tun.Tun, mtu int) *goStackBridge {
	bridge := &goStackBridge{device: device, mtu: mtu}
	bridge.memory = gotun.NewMemoryTun(gotun.MemoryTunOptions{
		MTU:      mtu,
		Headroom: goStackBridgeHeader,
		Outbound: bridge.toApp,
	})
	return bridge
}

func (b *goStackBridge) start() {
	go b.fromApp()
}

func (b *goStackBridge) fromApp() {
	frame := make([]byte, goStackBridgeHeader+b.mtu)
	packets := make([][]byte, 1)
	for {
		n, err := b.device.Read(frame)
		if err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			if b.closed.Load() || goStackBridgeClosedError(err) || tun.FailDevice(b.device, err) {
				return
			}
			continue
		}
		if n <= goStackBridgeHeader {
			continue
		}
		packets[0] = frame[goStackBridgeHeader:n]
		if err := b.memory.WaitWritePackets(packets); err != nil {
			return
		}
	}
}

func (b *goStackBridge) toApp(packets []*gobuf.Buffer) {
	for _, packet := range packets {
		if !b.closed.Load() && packet.Len() > 0 {
			family := byte(unix.AF_INET)
			if packet.Byte(0)>>4 == 6 {
				family = unix.AF_INET6
			}
			header := packet.ExtendHeader(goStackBridgeHeader)
			header[0], header[1], header[2], header[3] = 0, 0, 0, family
			if _, err := b.device.Write(packet.Bytes()); err != nil && errors.Is(err, syscall.ECONNRESET) {
				tun.FailDevice(b.device, err)
			}
		}
		packet.Release()
	}
}

func (b *goStackBridge) Close() error {
	b.closed.Store(true)
	return b.memory.Close()
}

func goStackBridgeClosedError(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed)
}
