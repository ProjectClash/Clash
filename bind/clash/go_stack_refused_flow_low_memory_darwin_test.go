//go:build darwin && with_low_memory

package clash

import (
	"bytes"
	"net/netip"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
	"golang.org/x/sys/unix"
)

func TestARefusedUDPFlowHoldsNoGoroutine(t *testing.T) {
	_, app, source, _ := startServiceOverTheBridge(t, "tun:\n  enable: true\nproxies: []\nrules: ['MATCH,DIRECT']\n")
	t.Cleanup(func() {
		statistic.DefaultManager.Range(func(c statistic.Tracker) bool { _ = c.Close(); return true })
	})
	destination := netip.MustParseAddrPort("192.0.2.1:27015")
	port := uint16(41000)
	send := func(n int) {
		for i := 0; i < n; i++ {
			datagram := ipv4UDP(netip.AddrPortFrom(source, port), destination, []byte("hello"))
			port++
			for {
				_, err := unix.Write(app, append([]byte{0, 0, 0, unix.AF_INET}, datagram...))
				if err == nil {
					break
				}
				if err != unix.ENOBUFS {
					t.Fatalf("write to the bridge: %v", err)
				}
				time.Sleep(5 * time.Millisecond)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitFor := func(what string, done func(tunnel.UDPSessionAdmission) bool) {
		deadline := time.Now().Add(10 * time.Second)
		for !done(tunnel.UDPSessionAdmissionSnapshot()) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %+v", what, tunnel.UDPSessionAdmissionSnapshot())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	before := tunnel.UDPSessionAdmissionSnapshot()
	send(int(before.Limit - before.Active))
	waitFor("the quota never filled", func(s tunnel.UDPSessionAdmission) bool { return s.Active == s.Limit })
	time.Sleep(500 * time.Millisecond)
	full := flowReaders(t)
	if full < int(before.Limit-before.Active) {
		t.Fatalf("%d flows were admitted and %d readers counted: the count does not see the readers it is about", before.Limit-before.Active, full)
	}

	const refused = 40
	rejectedBefore := tunnel.UDPSessionAdmissionSnapshot().Rejected
	send(refused)
	waitFor("the flows past the quota were not refused", func(s tunnel.UDPSessionAdmission) bool {
		return s.Rejected >= rejectedBefore+refused
	})
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		held := flowReaders(t) - full
		if held <= 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d flows refused at a full UDP quota left %d more readers behind; a refused flow must hold none", refused, held)
		}
	}
}

func flowReaders(t *testing.T) int {
	t.Helper()
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		t.Fatal(err)
	}
	readers := 0
	for _, entry := range strings.Split(profile.String(), "\n\n") {
		if !strings.Contains(entry, "listener/sing.(*ListenerHandler).NewPacketConnection") {
			continue
		}
		count, _, _ := strings.Cut(entry, " @ ")
		count = strings.TrimSpace(count[strings.LastIndex(count, "\n")+1:])
		n, err := strconv.Atoi(count)
		if err != nil {
			t.Fatalf("goroutine profile entry %q: %v", count, err)
		}
		readers += n
	}
	return readers
}
