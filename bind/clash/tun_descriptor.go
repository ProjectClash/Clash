package clash

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/log"
	"golang.org/x/sys/unix"
)

func tunDescriptorUtun(fd int) (string, error) {
	name, err := unix.GetsockoptString(fd, 2, 2)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(name, "utun") {
		return "", fmt.Errorf("interface %q is not a utun", name)
	}
	return name, nil
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
