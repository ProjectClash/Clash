package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestLocalProxyInboundSurfaceMatchesUpstream(t *testing.T) {
	const document = `
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: true
bind-address: "*"
authentication:
  - "alice:correct-horse"
skip-auth-prefixes:
  - 127.0.0.1/32
lan-allowed-ips:
  - 192.168.0.0/16
lan-disallowed-ips:
  - 192.168.9.0/24
inbound-tfo: true
inbound-mptcp: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(true) })

	mihomo, ours := parseBoth(t, document)

	for name, pair := range map[string][2]int{
		"port":       {mihomo.General.Port, ours.General.Port},
		"socks-port": {mihomo.General.SocksPort, ours.General.SocksPort},
		"mixed-port": {mihomo.General.MixedPort, ours.General.MixedPort},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: mihomo %d, ours %d -- the listener the user asked for is not opened",
				name, pair[0], pair[1])
		}
	}
	if mihomo.General.AllowLan != ours.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- with the permission granted this is upstream's "+
			"field again", mihomo.General.AllowLan, ours.General.AllowLan)
	}
	if mihomo.General.BindAddress != ours.General.BindAddress {
		t.Errorf("bind-address: mihomo %q, ours %q", mihomo.General.BindAddress, ours.General.BindAddress)
	}
	if len(mihomo.General.Authentication) != len(ours.General.Authentication) {
		t.Errorf("authentication: mihomo %d entries, ours %d -- a LAN listener without the "+
			"credentials the user set is worse than no listener",
			len(mihomo.General.Authentication), len(ours.General.Authentication))
	}
	if len(mihomo.General.SkipAuthPrefixes) != len(ours.General.SkipAuthPrefixes) {
		t.Errorf("skip-auth-prefixes: mihomo %d, ours %d",
			len(mihomo.General.SkipAuthPrefixes), len(ours.General.SkipAuthPrefixes))
	}
	if len(mihomo.General.LanAllowedIPs) != len(ours.General.LanAllowedIPs) {
		t.Errorf("lan-allowed-ips: mihomo %d, ours %d", len(mihomo.General.LanAllowedIPs), len(ours.General.LanAllowedIPs))
	}
	if len(mihomo.General.LanDisAllowedIPs) != len(ours.General.LanDisAllowedIPs) {
		t.Errorf("lan-disallowed-ips: mihomo %d, ours %d", len(mihomo.General.LanDisAllowedIPs), len(ours.General.LanDisAllowedIPs))
	}
	if mihomo.General.InboundTfo != ours.General.InboundTfo {
		t.Errorf("inbound-tfo: mihomo %v, ours %v", mihomo.General.InboundTfo, ours.General.InboundTfo)
	}
	if mihomo.General.InboundMPTCP != ours.General.InboundMPTCP {
		t.Errorf("inbound-mptcp: mihomo %v, ours %v", mihomo.General.InboundMPTCP, ours.General.InboundMPTCP)
	}
}

func TestAnUnauthenticatedLANListenerIsAnnounced(t *testing.T) {
	const exposed = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	notices := unauthenticatedLANListenerNotices(mustUnmarshalRaw(t, exposed))
	if len(notices) == 0 {
		t.Error("a LAN-exposed listener with no authentication says nothing; the reader gets an " +
			"open proxy on every network their device joins and no line anywhere about it")
	}

	const guarded = `
mixed-port: 7890
allow-lan: true
authentication:
  - "alice:correct-horse"
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if notices := unauthenticatedLANListenerNotices(mustUnmarshalRaw(t, guarded)); len(notices) != 0 {
		t.Errorf("a listener with credentials was still flagged: %v", notices)
	}

	const localOnly = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if notices := unauthenticatedLANListenerNotices(mustUnmarshalRaw(t, localOnly)); len(notices) != 0 {
		t.Errorf("a loopback-only listener was flagged as LAN-exposed: %v", notices)
	}
}

func mustUnmarshalRaw(t *testing.T, document string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}
