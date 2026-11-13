package clash

import (
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	mieru "github.com/enfein/mieru/v3/pkg/protocol"
)

func TestSetupBoundsAMieruNodeByProfile(t *testing.T) {
	limit := mieru.StreamReceiveByteLimit()
	skips, releases := mieru.ClientSkipsReplayCache(), mieru.ReleaseOnApplicationClose()
	off, repairs := outbound.MieruTunnelMultiplexingOff(), mieru.PacketRepairs()
	t.Cleanup(func() {
		mieru.SetStreamReceiveByteLimit(limit)
		mieru.SetClientSkipsReplayCache(skips)
		mieru.SetReleaseOnApplicationClose(releases)
		outbound.SetMieruTunnelMultiplexingOff(off)
		mieru.SetPacketRepairs(repairs)
	})
	for _, c := range []struct {
		profile string
		tunnel  bool
	}{{RuntimeProfileMacOSPacketTunnel, false}, {RuntimeProfileTVOSPacketTunnel, true}, {RuntimeProfileIOSPacketTunnel, true}} {
		mieru.SetPacketRepairs(false)
		base := t.TempDir()
		if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t"), RuntimeProfile: c.profile}); err != nil {
			t.Fatal(err)
		}
		wantLimit := int64(0)
		if c.tunnel {
			wantLimit = 256 << 10
		}
		if got := mieru.StreamReceiveByteLimit(); got != wantLimit {
			t.Fatalf("%s: a stream session queues %d bytes at most, want %d", c.profile, got, wantLimit)
		}
		if got := mieru.ClientSkipsReplayCache(); got != c.tunnel {
			t.Fatalf("%s: a client skips the replay cache %v, want %v", c.profile, got, c.tunnel)
		}
		if got := mieru.ReleaseOnApplicationClose(); got != c.tunnel {
			t.Fatalf("%s: an application's close drops the queue %v, want %v", c.profile, got, c.tunnel)
		}
		if got := outbound.MieruTunnelMultiplexingOff(); got != c.tunnel {
			t.Fatalf("%s: a node on the TCP transport runs with multiplexing off %v, want %v", c.profile, got, c.tunnel)
		}
		if !mieru.PacketRepairs() {
			t.Fatalf("%s: the UDP transport's open and end are as shipped, want them repaired", c.profile)
		}
	}
}
