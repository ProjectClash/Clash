package outbound

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/dns"
)

func TestWireGuardRefusedForItsDNSClosesItsDevice(t *testing.T) {
	previous := dns.ParseNameServer
	dns.ParseNameServer = func([]string) ([]dns.NameServer, error) { return nil, errors.New("bad nameserver") }
	t.Cleanup(func() { dns.ParseNameServer = previous })
	option := WireGuardOption{
		Name: "wg", Ip: "10.0.0.2/32",
		WireGuardPeerOption: WireGuardPeerOption{
			Server: "192.0.2.1", Port: 51820, PublicKey: "aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		PrivateKey:       "aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		RemoteDnsResolve: true,
		Dns:              []string{"https://["},
		Workers:          4,
	}
	settle := func() int {
		for i := 0; i < 20; i++ {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	before := settle()
	for i := 0; i < 10; i++ {
		if _, err := NewWireGuard(option); err == nil {
			t.Fatal("a dns list that does not parse must be refused")
		}
	}
	if after := settle(); after > before+2 {
		t.Fatalf("goroutines %d before, %d after ten refused nodes", before, after)
	}
}
