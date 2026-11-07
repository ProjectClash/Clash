package clash

import (
	"errors"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/log"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

func tunDescriptorUtun(fd int) (string, error) {
	if name, ok := tun.UtunControlName(fd); ok {
		return name, nil
	}
	if address, err := unix.Getsockname(fd); err == nil {
		if _, unixSocket := address.(*unix.SockaddrUnix); unixSocket {
			return "", errors.New("a unix socket, not a utun's control socket")
		}
	}
	return "", errors.New("not a utun's control socket")
}

func handOverTunDescriptor(tun *LC.Tun, fd int) {
	tun.FileDescriptor = fd
	_, err := tunDescriptorUtun(fd)
	tun.RecvMsgX = err == nil
	tun.Stack = C.TunGo
}

func tunDescriptorKind(fd int) string {
	name, err := tunDescriptorUtun(fd)
	if err != nil {
		return "a PacketFlow bridge (no utun name: " + err.Error() + ")"
	}
	return "the utun " + name
}

var (
	tunDescriptor     atomic.Pointer[string]
	tunFailure        atomic.Pointer[string]
	tunHookGeneration atomic.Uint64
)

func recordTunDescriptor(fd int) {
	kind := tunDescriptorKind(fd)
	tunDescriptor.Store(&kind)
	tunFailure.Store(nil)
}

func reportTunFailure(platform PlatformInterface, err error) {
	reason := err.Error()
	words := time.Now().UTC().Format(time.RFC3339) + " " + reason
	tunFailure.Store(&words)
	log.Errorln("[Apple] the tunnel stopped: reading its descriptor failed (%s), so the core stopped reading it and asks the extension to end the tunnel", reason)
	platform.TunFailed(reason)
}

func lastTunFailure() string {
	if words := tunFailure.Load(); words != nil {
		return *words
	}
	return ""
}

func lastTunDescriptor() string {
	if kind := tunDescriptor.Load(); kind != nil {
		return *kind
	}
	return ""
}
