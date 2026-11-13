package outbound

import (
	"testing"

	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

func TestAMieruNodeOnTheTCPTransportRunsWithMultiplexingOffOnTheTunnels(t *testing.T) {
	previous := MieruTunnelMultiplexingOff()
	t.Cleanup(func() { SetMieruTunnelMultiplexingOff(previous) })

	for _, c := range []struct {
		tunnel    bool
		transport string
		written   string
		want  mierupb.MultiplexingLevel
		unset bool
	}{
		{tunnel: true, transport: "TCP", written: "", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: true, transport: "TCP", written: "MULTIPLEXING_DEFAULT", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: true, transport: "TCP", written: "MULTIPLEXING_LOW", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: true, transport: "TCP", written: "MULTIPLEXING_MIDDLE", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: true, transport: "TCP", written: "MULTIPLEXING_HIGH", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: true, transport: "TCP", written: "MULTIPLEXING_OFF", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: true, transport: "UDP", written: "", unset: true},
		{tunnel: true, transport: "UDP", written: "MULTIPLEXING_HIGH", want: mierupb.MultiplexingLevel_MULTIPLEXING_HIGH},
		{tunnel: true, transport: "UDP", written: "MULTIPLEXING_OFF", want: mierupb.MultiplexingLevel_MULTIPLEXING_OFF},
		{tunnel: false, transport: "TCP", written: "", unset: true},
		{tunnel: false, transport: "UDP", written: "", unset: true},
		{tunnel: false, transport: "TCP", written: "MULTIPLEXING_HIGH", want: mierupb.MultiplexingLevel_MULTIPLEXING_HIGH},
	} {
		SetMieruTunnelMultiplexingOff(c.tunnel)
		config, err := buildMieruClientConfig(MieruOption{
			Name: "n", Server: "192.0.2.1", Port: 10000, Transport: c.transport, UserName: "u", Password: "p",
			Multiplexing: c.written,
		})
		if err != nil {
			t.Fatalf("tunnel %v, %s, multiplexing %q: %v", c.tunnel, c.transport, c.written, err)
		}
		multiplexing := config.Profile.Multiplexing
		switch {
		case c.unset && multiplexing != nil:
			t.Fatalf("tunnel %v, %s, multiplexing %q: the client is given %v, upstream gives none", c.tunnel, c.transport, c.written, multiplexing.GetLevel())
		case !c.unset && (multiplexing == nil || multiplexing.GetLevel() != c.want):
			t.Fatalf("tunnel %v, %s, multiplexing %q: the client is given %v, want %v", c.tunnel, c.transport, c.written, multiplexing.GetLevel(), c.want)
		}
	}
}

func TestAMieruNodeWithAnUnknownLevelStillFailsToLoadOnTheTunnels(t *testing.T) {
	previous := MieruTunnelMultiplexingOff()
	t.Cleanup(func() { SetMieruTunnelMultiplexingOff(previous) })
	SetMieruTunnelMultiplexingOff(true)
	if _, err := NewMieru(MieruOption{Name: "n", Server: "192.0.2.1", Port: 10000, Transport: "TCP", UserName: "u", Password: "p",
		Multiplexing: "MULTIPLEXING_SOMETIMES"}); err == nil {
		t.Fatal("a node writing an unknown multiplexing level loaded")
	}
}
