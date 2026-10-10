package clash

import "testing"

func TestInboundServerSurfaceIsHonouredAsWritten(t *testing.T) {
	const document = `
ss-config: "ss://chacha20-ietf-poly1305:test@:8388"
vmess-config: "vmess://11111111-2222-3333-4444-555555555555@:8080"
tuic-server:
  enable: true
  listen: 0.0.0.0:8443
  token: ["deadbeef"]
listeners:
  - name: extra-mixed
    type: mixed
    port: 7899
tunnels:
  - tcp/udp,127.0.0.1:7777,target.example:80,DIRECT
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	if ours.General.ShadowSocksConfig != mihomo.General.ShadowSocksConfig {
		t.Errorf("ss-config: mihomo %q, ours %q", mihomo.General.ShadowSocksConfig, ours.General.ShadowSocksConfig)
	}
	if ours.General.VmessConfig != mihomo.General.VmessConfig {
		t.Errorf("vmess-config: mihomo %q, ours %q", mihomo.General.VmessConfig, ours.General.VmessConfig)
	}
	if !ours.General.TuicServer.Enable {
		t.Error("tuic-server was disabled after finalize; hub/executor ReCreateTuic reads this")
	}
	if len(ours.Listeners) != len(mihomo.Listeners) {
		t.Errorf("listeners: mihomo %d, ours %d -- PatchInboundListeners reads this",
			len(mihomo.Listeners), len(ours.Listeners))
	}
	if len(ours.Tunnels) != len(mihomo.Tunnels) {
		t.Errorf("tunnels: mihomo %d, ours %d -- updateTunnels reads this",
			len(mihomo.Tunnels), len(ours.Tunnels))
	}
}

func TestOnlyThePlatformImpossiblePortsAreStillCleared(t *testing.T) {
	const document = `
redir-port: 7892
tproxy-port: 7893
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	if ours.General.RedirPort != 0 {
		t.Error("redir-port survived: upstream's darwin implementation reads /dev/pf, which an " +
			"App Sandbox cannot open, and installing the pf rule needs root")
	}
	if ours.General.TProxyPort != 0 {
		t.Error("tproxy-port survived: upstream's own non-Linux build answers " +
			"\"not supported on current platform\"")
	}
	if ours.General.MixedPort != 7890 {
		t.Error("mixed-port was cleared; it is neither of the two")
	}
}
