package clash

import (
	"net"
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
)

func loopbackUDPHost(t testing.TB) string {
	t.Helper()
	loopbackUDPHostOnce.Do(func() {
		probe, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			loopbackUDPHostValue = "127.0.0.1"
			return
		}
		_ = probe.Close()
		loopbackUDPHostValue = "::1"
	})
	if loopbackUDPHostValue == "::1" {
		previous := resolver.DisableIPv6
		resolver.DisableIPv6 = false
		t.Cleanup(func() { resolver.DisableIPv6 = previous })
	}
	return loopbackUDPHostValue
}

var (
	loopbackUDPHostOnce  sync.Once
	loopbackUDPHostValue string
)
