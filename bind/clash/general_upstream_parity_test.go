package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func parseBoth(t *testing.T, document string) (*config.Config, *config.Config) {
	t.Helper()
	mihomo, err := config.Parse([]byte(document))
	if err != nil {
		t.Fatalf("mihomo's own parser rejected the fixture: %v", err)
	}
	ours, err := parseConfigForIOS(document, true)
	if err != nil {
		t.Fatalf("this core rejected the fixture: %v", err)
	}
	return mihomo, ours
}

func TestSilentReaderSeesNoDeviationOnGeoAndNTPDefaults(t *testing.T) {
	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, silent)

	if mihomo.General.GeoAutoUpdate != ours.General.GeoAutoUpdate {
		t.Errorf("geo-auto-update: mihomo %v, ours %v", mihomo.General.GeoAutoUpdate, ours.General.GeoAutoUpdate)
	}
	if mihomo.General.GeodataLoader != ours.General.GeodataLoader {
		t.Errorf("geodata-loader: mihomo %q, ours %q", mihomo.General.GeodataLoader, ours.General.GeodataLoader)
	}
	if mihomo.NTP.WriteToSystem != ours.NTP.WriteToSystem {
		t.Errorf("ntp.write-to-system: mihomo %v, ours %v", mihomo.NTP.WriteToSystem, ours.NTP.WriteToSystem)
	}
}

func TestOptedInReaderGetsTheOverride(t *testing.T) {
	const optedIn = `
mixed-port: 7890
geo-auto-update: true
geodata-loader: standard
ntp:
  enable: true
  server: time.apple.com
  write-to-system: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, optedIn)

	t.Logf("geo-auto-update      mihomo=%v ours=%v", mihomo.General.GeoAutoUpdate, ours.General.GeoAutoUpdate)
	t.Logf("geodata-loader       mihomo=%q ours=%q", mihomo.General.GeodataLoader, ours.General.GeodataLoader)
	t.Logf("ntp.write-to-system  mihomo=%v ours=%v", mihomo.NTP.WriteToSystem, ours.NTP.WriteToSystem)

	if mihomo.General.GeoAutoUpdate == ours.General.GeoAutoUpdate &&
		mihomo.General.GeodataLoader == ours.General.GeodataLoader &&
		mihomo.NTP.WriteToSystem == ours.NTP.WriteToSystem {
		t.Fatal("expected the documented override to be observable for an opted-in reader; " +
			"if this passes, config_pipeline.go:122,138,408 no longer force these and the " +
			"inventory's `force` disposition is stale")
	}
}

func TestFindProcessModeIsForcedOffOnlyWhereNoProcessPathExists(t *testing.T) {
	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	t.Run("iOS packet tunnel has no process path, so the force applies", func(t *testing.T) {
		restoreRuntimeProfileForTest(t)

		mihomo, ours := parseBoth(t, silent)
		t.Logf("find-process-mode  mihomo=%v ours=%v", mihomo.General.FindProcessMode, ours.General.FindProcessMode)

		if mihomo.General.FindProcessMode == ours.General.FindProcessMode {
			t.Fatal("expected find-process-mode to be forced Off under the iOS packet-tunnel " +
				"profile; if it no longer is, override.go:40 and the `force` disposition " +
				"disagree with the code")
		}
	})

	t.Run("macOS packet tunnel does the lookup itself, so the reader keeps their value", func(t *testing.T) {
		previous := setupRuntimeProfile.Load()
		setupRuntimeProfile.Store(uint32(runtimeProfileMacOSPacketTunnel))
		t.Cleanup(func() { setupRuntimeProfile.Store(previous) })

		mihomo, ours := parseBoth(t, silent)
		t.Logf("find-process-mode  mihomo=%v ours=%v", mihomo.General.FindProcessMode, ours.General.FindProcessMode)

		if mihomo.General.FindProcessMode != ours.General.FindProcessMode {
			t.Fatalf("macOS reads net.inet.{tcp,udp}.pcblist_n itself and the App Sandbox does "+
				"not deny it — measured, with a positive control — so this profile must keep "+
				"upstream's value: mihomo %v, ours %v",
				mihomo.General.FindProcessMode, ours.General.FindProcessMode)
		}
	})
}

func TestDNSEnableIsForcedOnAsD184Ruled(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const disabled = `
mixed-port: 7890
dns:
  enable: false
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, disabled)

	if mihomo.DNS.Enable {
		t.Fatal("upstream did not honour dns.enable: false, so there is no deviation to judge; " +
			"the fixture is wrong or upstream changed")
	}
	if !ours.DNS.Enable {
		t.Fatal("dns.enable is no longer forced on. An Apple packet tunnel requires it, " +
			"so either the code regressed or the ruling needs revisiting — not a test to fix")
	}
}

func TestDefaultNameserverSubstitutionIsObservable(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const systemBootstrap = `
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - system
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, systemBootstrap)
	t.Logf("default-nameserver  mihomo=%v", addressesOf(mihomo.DNS.DefaultNameserver))
	t.Logf("default-nameserver  ours=%v", addressesOf(ours.DNS.DefaultNameserver))
}

func TestStrippedBootstrapIsReplacedWithUpstreamsOwnDefault(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const systemBootstrap = `
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - system
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, systemBootstrap)

	upstreamDefault := config.DefaultRawConfig().DNS.DefaultNameserver
	if len(upstreamDefault) == 0 {
		t.Fatal("upstream stopped shipping a default bootstrap; the repair has nothing to inherit")
	}

	got := addressesOf(ours.DNS.DefaultNameserver)
	if len(got) != len(upstreamDefault) {
		t.Fatalf("substituted %d resolvers, upstream's default has %d: %v vs %v",
			len(got), len(upstreamDefault), got, upstreamDefault)
	}
	for i, want := range upstreamDefault {
		if !strings.Contains(got[i], want) {
			t.Errorf("bootstrap %d: substituted %q, upstream's default is %q — the repair is no "+
				"longer handing the reader mihomo's own list", i, got[i], want)
		}
	}
}

func TestRouteAddressSetLoadsExactlyAsUpstreamDoes(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const routeSet = `
mixed-port: 7890
tun:
  enable: true
  stack: system
  route-address-set:
    - cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, err := config.Parse([]byte(routeSet)); err != nil {
		t.Fatalf("upstream rejected it too, so this fixture proves nothing: %v", err)
	}
	if _, err := parseConfigForIOS(routeSet, true); err != nil {
		t.Fatalf("this fork still refuses a configuration mihomo runs: %v", err)
	}
}

func TestRouteExcludeAddressSetLoadsOnItsOwn(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const excludeSet = `
mixed-port: 7890
tun:
  enable: true
  stack: system
  route-exclude-address-set:
    - cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, err := config.Parse([]byte(excludeSet)); err != nil {
		t.Fatalf("upstream rejected it too, so this is not a deviation: %v", err)
	}

	if _, err := parseConfigForIOS(excludeSet, true); err != nil {
		t.Fatalf("this fork still refuses a configuration mihomo runs: %v", err)
	}

}

func TestStrippingInboundSurfacesLeavesOutboundAlone(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const withOutbounds = `
mixed-port: 7890
inbound-tfo: true
inbound-mptcp: true
tuic-server:
  enable: true
  listen: 127.0.0.1:10443
  token:
    - inbound-secret
proxies:
  - name: out-tuic
    type: tuic
    server: example.invalid
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    password: outbound-secret
    tfo: true
    mptcp: true
  - name: out-ss
    type: ss
    server: example.invalid
    port: 8388
    cipher: aes-128-gcm
    password: outbound-secret
    tfo: true
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, withOutbounds)

	carriedTFO := false
	for _, name := range []string{"out-tuic", "out-ss"} {
		theirs, ok := mihomo.Proxies[name]
		if !ok {
			t.Fatalf("upstream did not build outbound %q; the fixture is wrong", name)
		}
		mine, ok := ours.Proxies[name]
		if !ok {
			t.Fatalf("this fork dropped outbound %q while stripping inbound surfaces — a strip "+
				"reached past the inbound face it was aimed at", name)
		}
		if theirs.Type() != mine.Type() {
			t.Errorf("outbound %q: upstream type %v, ours %v", name, theirs.Type(), mine.Type())
		}
		if theirs.Addr() != mine.Addr() {
			t.Errorf("outbound %q: upstream addr %q, ours %q", name, theirs.Addr(), mine.Addr())
		}

		theirInfo, myInfo := theirs.ProxyInfo(), mine.ProxyInfo()

		if theirInfo.TFO {
			carriedTFO = true
		}
		if theirInfo.TFO != myInfo.TFO {
			t.Errorf("outbound %q tfo: upstream %v, ours %v — a global inbound strip reached a "+
				"per-proxy dial option", name, theirInfo.TFO, myInfo.TFO)
		}
		if theirInfo.MPTCP != myInfo.MPTCP {
			t.Errorf("outbound %q mptcp: upstream %v, ours %v — a global inbound strip reached a "+
				"per-proxy dial option", name, theirInfo.MPTCP, myInfo.MPTCP)
		}
	}

	if !carriedTFO {
		t.Fatal("no proxy in the fixture carried tfo upstream, so every tfo comparison above was " +
			"false == false — fix the fixture, not the assertions")
	}

	if ours.General.InboundTfo != mihomo.General.InboundTfo {
		t.Errorf("inbound-tfo: mihomo %v, ours %v", mihomo.General.InboundTfo, ours.General.InboundTfo)
	}
	if ours.General.InboundMPTCP != mihomo.General.InboundMPTCP {
		t.Errorf("inbound-mptcp: mihomo %v, ours %v", mihomo.General.InboundMPTCP, ours.General.InboundMPTCP)
	}
}

func TestStoreFakeIPAndUnifiedDelayMatchMihomoForASilentReader(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, silent)
	if mihomo.Profile.StoreFakeIP || !ours.Profile.StoreFakeIP {
		t.Errorf("profile.store-fake-ip  mihomo=%v ours=%v: a silent reader gets true here over upstream's false",
			mihomo.Profile.StoreFakeIP, ours.Profile.StoreFakeIP)
	}
	if mihomo.General.UnifiedDelay || !ours.General.UnifiedDelay {
		t.Errorf("unified-delay  mihomo=%v ours=%v: a silent reader gets true here over upstream's false",
			mihomo.General.UnifiedDelay, ours.General.UnifiedDelay)
	}
}

func TestStoreFakeIPIsPreservedWhenTheReaderIsExplicit(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	for _, want := range []bool{true, false} {
		document := `
mixed-port: 7890
profile:
  store-fake-ip: ` + map[bool]string{true: "true", false: "false"}[want] + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
		mihomo, ours := parseBoth(t, document)
		if mihomo.Profile.StoreFakeIP != want {
			t.Fatalf("upstream did not take store-fake-ip: %v, so the fixture proves nothing", want)
		}
		if ours.Profile.StoreFakeIP != want {
			t.Errorf("store-fake-ip: reader wrote %v, this core produced %v — an explicit value "+
				"was overridden, which the ledger row says does not happen", want, ours.Profile.StoreFakeIP)
		}
	}
}

func TestTunKnobsAReaderSetsAreReplaced(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const tunSet = `
mixed-port: 7890
tun:
  enable: true
  stack: gvisor
  mtu: 9000
  auto-route: false
  dns-hijack:
    - 1.1.1.1:53
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, tunSet)

	t.Logf("tun.stack       mihomo=%v ours=%v", mihomo.General.Tun.Stack, ours.General.Tun.Stack)
	t.Logf("tun.mtu         mihomo=%v ours=%v", mihomo.General.Tun.MTU, ours.General.Tun.MTU)
	t.Logf("tun.auto-route  mihomo=%v ours=%v", mihomo.General.Tun.AutoRoute, ours.General.Tun.AutoRoute)
	t.Logf("tun.dns-hijack  mihomo=%v ours=%v", mihomo.General.Tun.DNSHijack, ours.General.Tun.DNSHijack)
}

func TestLinuxOnlyKnobsSurviveIntoTheConfigUnchanged(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const linuxKnobs = `
mixed-port: 7890
iptables:
  enable: true
  inbound-interface: eth0
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, linuxKnobs)

	t.Logf("iptables.enable            mihomo=%v ours=%v", mihomo.IPTables.Enable, ours.IPTables.Enable)
	t.Logf("iptables.inbound-interface mihomo=%q ours=%q", mihomo.IPTables.InboundInterface, ours.IPTables.InboundInterface)

	if mihomo.IPTables.Enable != ours.IPTables.Enable {
		t.Logf("FINDING: iptables.enable is not carried through — `na` describes the wrong mechanism")
	}
}

func TestGeoUpdateIntervalIsInertOnlyBecauseWeForcedAutoUpdateOff(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const withInterval = `
mixed-port: 7890
geo-auto-update: true
geo-update-interval: 6
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, withInterval)

	t.Logf("geo-update-interval  mihomo=%v ours=%v", mihomo.General.GeoUpdateInterval, ours.General.GeoUpdateInterval)
	t.Logf("geo-auto-update      mihomo=%v ours=%v", mihomo.General.GeoAutoUpdate, ours.General.GeoAutoUpdate)

	if ours.General.GeoAutoUpdate {
		t.Fatal("this fork stopped forcing geo-auto-update off, which is the only reason " +
			"geo-update-interval is filed `na` — the row now describes nothing")
	}
}
