package outbound

import (
	"testing"

	"github.com/ProjectClash/Clash/transport/tuic"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/sing-quic/hysteria2"
)

const mib = 1 << 20

func withTunnelWindows(t *testing.T) {
	t.Helper()
	before := QUICDefaultReceiveWindows()
	SetQUICDefaultReceiveWindows(QUICTunnelReceiveWindows())
	t.Cleanup(func() { SetQUICDefaultReceiveWindows(before) })
}

func withGrowingCeiling(t *testing.T, ceiling uint64) {
	t.Helper()
	before := QUICDefaultReceiveWindows()
	windows := QUICTunnelReceiveWindows()
	windows.GrowingMaxConnection = ceiling
	SetQUICDefaultReceiveWindows(windows)
	t.Cleanup(func() { SetQUICDefaultReceiveWindows(before) })
}

func windows(config *quic.Config) [4]uint64 {
	return [4]uint64{config.InitialStreamReceiveWindow, config.MaxStreamReceiveWindow,
		config.InitialConnectionReceiveWindow, config.MaxConnectionReceiveWindow}
}

func TestTheTunnelsWindowsAreTheMeasuredOnes(t *testing.T) {
	if got, want := *QUICTunnelReceiveWindows(), (QUICReceiveWindows{InitialStream: 1 * mib, InitialConnection: 12 * mib, MaxConnection: 20 * mib}); got != want {
		t.Fatalf("the tunnels' windows %+v, want %+v", got, want)
	}
	if QUICTunnelMaxConnection > hysteria2.DefaultConnReceiveWindow {
		t.Fatalf("the tunnels' connection window grows to %d, past the protocol's own %d", QUICTunnelMaxConnection, hysteria2.DefaultConnReceiveWindow)
	}
}

func TestTheTunnelsLeaveAGrowingProtocolsWindowsAsUpstreamHasThem(t *testing.T) {
	withTunnelWindows(t)
	stream, connection := uint64(tuic.DefaultStreamReceiveWindow), uint64(tuic.DefaultConnectionReceiveWindow)
	want := [4]uint64{stream / 10, stream, connection / 10, connection}
	if ceiling := uint64(QUICTunnelGrowingMaxConnection); ceiling != 0 {
		want[3] = ceiling
	}
	if got := windows(newTuicQUICConfig(&TuicOption{})); got != want {
		t.Errorf("TUIC %v, want %v", got, want)
	}
	node, err := NewShadowQuic(ShadowQuicOption{Name: "sq", Server: "127.0.0.1", Port: 1, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if got := [4]uint64{node.quicConfig.InitialStreamReceiveWindow, node.quicConfig.MaxStreamReceiveWindow,
		node.quicConfig.InitialConnectionReceiveWindow, node.quicConfig.MaxConnectionReceiveWindow}; got != want {
		t.Errorf("ShadowQUIC %v, want %v", got, want)
	}
}

func TestAHysteria2NodesUnwrittenWindowsStartSmallAndGrow(t *testing.T) {
	withTunnelWindows(t)
	stream, connection := uint64(hysteria2.DefaultStreamReceiveWindow), uint64(hysteria2.DefaultConnReceiveWindow)
	if stream != 8*mib || connection != 20*mib {
		t.Fatalf("Hysteria2's own windows are %d / %d, no longer 8 MiB / 20 MiB: the tunnels' figures were measured against those", stream, connection)
	}
	for _, c := range []struct {
		name    string
		written [4]uint64
		want    [4]uint64
	}{
		{"none written", [4]uint64{}, [4]uint64{1 * mib, 8 * mib, 12 * mib, 20 * mib}},
		{"an initial stream window", [4]uint64{2 * mib, 0, 0, 0}, [4]uint64{2 * mib, 0, 12 * mib, 20 * mib}},
		{"a max stream window", [4]uint64{0, 4 * mib, 0, 0}, [4]uint64{0, 4 * mib, 12 * mib, 20 * mib}},
		{"an initial connection window", [4]uint64{0, 0, 30 * mib, 0}, [4]uint64{1 * mib, 8 * mib, 30 * mib, 0}},
		{"a max connection window", [4]uint64{0, 0, 0, 4 * mib}, [4]uint64{1 * mib, 8 * mib, 0, 4 * mib}},
		{"all written", [4]uint64{3, 5, 7, 9}, [4]uint64{3, 5, 7, 9}},
	} {
		config := &quic.Config{InitialStreamReceiveWindow: c.written[0], MaxStreamReceiveWindow: c.written[1],
			InitialConnectionReceiveWindow: c.written[2], MaxConnectionReceiveWindow: c.written[3]}
		fillQUICDefaultReceiveWindows(config)
		if got := windows(config); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWithoutTheTunnelsWindowsAHysteria2NodeIsLeftToUpstream(t *testing.T) {
	before := QUICDefaultReceiveWindows()
	SetQUICDefaultReceiveWindows(nil)
	t.Cleanup(func() { SetQUICDefaultReceiveWindows(before) })
	config := &quic.Config{}
	fillQUICDefaultReceiveWindows(config)
	if got := windows(config); got != [4]uint64{} {
		t.Fatalf("filled %v with no tunnel windows set", got)
	}
}

func TestAGrowingProtocolsConnectionWindowStopsAtACeiling(t *testing.T) {
	withGrowingCeiling(t, 16*mib)
	upstream := func() *quic.Config {
		return &quic.Config{
			InitialStreamReceiveWindow: tuic.DefaultStreamReceiveWindow / 10, MaxStreamReceiveWindow: tuic.DefaultStreamReceiveWindow,
			InitialConnectionReceiveWindow: tuic.DefaultConnectionReceiveWindow / 10, MaxConnectionReceiveWindow: tuic.DefaultConnectionReceiveWindow,
		}
	}
	config := upstream()
	applyQUICDefaultReceiveWindows(config, false)
	if got, want := windows(config), [4]uint64{tuic.DefaultStreamReceiveWindow / 10, tuic.DefaultStreamReceiveWindow, tuic.DefaultConnectionReceiveWindow / 10, 16 * mib}; got != want {
		t.Errorf("an unwritten connection window: %v, want %v", got, want)
	}
	config = upstream()
	config.InitialConnectionReceiveWindow, config.MaxConnectionReceiveWindow = 40*mib, 40*mib
	applyQUICDefaultReceiveWindows(config, true)
	if got := windows(config); got[2] != 40*mib || got[3] != 40*mib {
		t.Errorf("a written connection window: %v, want the node's 40 MiB", got)
	}
	config = &quic.Config{InitialConnectionReceiveWindow: 24 * mib, MaxConnectionReceiveWindow: 64 * mib}
	applyQUICDefaultReceiveWindows(config, false)
	if got := windows(config); got[2] != 16*mib || got[3] != 16*mib {
		t.Errorf("a start above the ceiling: %v, want both 16 MiB", got)
	}
}

func TestHysteriaTuicAndShadowQUICNodesAreBuiltWithTheCeiling(t *testing.T) {
	withGrowingCeiling(t, 16*mib)
	stream, connection := uint64(tuic.DefaultStreamReceiveWindow), uint64(tuic.DefaultConnectionReceiveWindow)
	want := [4]uint64{stream / 10, stream, connection / 10, 16 * mib}

	tuicConfig := newTuicQUICConfig(&TuicOption{})
	if got := windows(tuicConfig); got != want {
		t.Errorf("TUIC %v, want %v", got, want)
	}
	if got := windows(newTuicQUICConfig(&TuicOption{ReceiveWindow: 4 * mib})); got[2] != 4*mib || got[3] != 4*mib {
		t.Errorf("TUIC writing recv-window 4 MiB: %v", got)
	}

	node, err := NewShadowQuic(ShadowQuicOption{Name: "sq", Server: "127.0.0.1", Port: 1, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if got := [4]uint64{node.quicConfig.InitialStreamReceiveWindow, node.quicConfig.MaxStreamReceiveWindow,
		node.quicConfig.InitialConnectionReceiveWindow, node.quicConfig.MaxConnectionReceiveWindow}; got != want {
		t.Errorf("ShadowQUIC %v, want %v", got, want)
	}
	own, err := NewShadowQuic(ShadowQuicOption{Name: "sq", Server: "127.0.0.1", Port: 1, Username: "u", Password: "p", ReceiveWindow: 4 * mib})
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if own.quicConfig.InitialConnectionReceiveWindow != 4*mib || own.quicConfig.MaxConnectionReceiveWindow != 4*mib {
		t.Errorf("ShadowQUIC writing recv-window 4 MiB: %d / %d", own.quicConfig.InitialConnectionReceiveWindow, own.quicConfig.MaxConnectionReceiveWindow)
	}
}
