package clash

import (
	"errors"
	"fmt"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/config"
	LC "github.com/ProjectClash/Clash/listener/config"
	"net/netip"
	"testing"
)

func TestIPStackSnapshotValidation(t *testing.T) {
	for _, q := range []string{"ipv4-only", "dual-stack", "prefer-ipv4", "prefer-ipv6", "ipv6-only"} {
		for _, tun := range []string{"disabled", "automatic", "enabled"} {
			if _, err := parseIPStackSettings(q, tun); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, v := range [][2]string{{"", "automatic"}, {"dual-stack", ""}, {"dual", "automatic"}, {"dual-stack", "auto"}} {
		if _, err := parseIPStackSettings(v[0], v[1]); err == nil {
			t.Fatalf("accepted %v", v)
		}
	}
	if _, err := parseIPStackSettings("", ""); err != nil {
		t.Fatal(err)
	}
}

func TestIPStackRuntimeOverridesKeepCaptureIndependent(t *testing.T) {
	for _, q := range []string{"ipv4-only", "dual-stack", "prefer-ipv4", "prefer-ipv6", "ipv6-only"} {
		for _, tun := range []string{"disabled", "automatic", "enabled"} {
			for _, profileDNSIPv6 := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/dns.ipv6=%v", q, tun, profileDNSIPv6), func(t *testing.T) {
					s, _ := parseIPStackSettings(q, tun)
					raw := config.DefaultRawConfig()
					raw.IPv6 = false
					raw.DNS.IPv6 = profileDNSIPv6
					raw.Tun.Inet6Address = nil
					applyIPStackSettings(raw, s)
					if raw.IPv6 != (q != "ipv4-only") {
						t.Fatal("the core's own IPv6 follows the query mode")
					}
					wantDNS := profileDNSIPv6
					switch q {
					case "ipv4-only":
						wantDNS = false
					case "prefer-ipv6", "ipv6-only":
						wantDNS = true
					}
					if raw.DNS.IPv6 != wantDNS {
						t.Fatalf("dns.ipv6 (what apps are told) = %v, want %v", raw.DNS.IPv6, wantDNS)
					}
					if (len(raw.Tun.Inet6Address) > 0) != (tun != "disabled") {
						t.Fatal("capture must not follow DNS family or cold physical path")
					}
					if raw.PreserveTunIPv6 != (tun != "disabled") {
						t.Fatal("missing explicit capability snapshot")
					}
				})
			}
		}
	}
}
func TestIPStackTunModeIsFrozen(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	s, _ := parseIPStackSettings("dual-stack", "automatic")
	setIPStackSettings(s)
	options := newTunOptions(&LC.Tun{})
	s.tunIPv6Mode = "enabled"
	setIPStackSettings(s)
	if options.GetIPv6Mode() != "automatic" {
		t.Fatal("TunOptions re-read mutable startup state")
	}
}
func TestIPStackLegacyDoesNotOverrideConfig(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.IPv6 = false
	raw.DNS.IPv6 = false
	raw.Tun.Inet6Address = nil
	applyIPStackSettings(raw, ipStackSettings{})
	if raw.IPv6 || raw.DNS.IPv6 || len(raw.Tun.Inet6Address) != 0 || raw.PreserveTunIPv6 {
		t.Fatal("legacy changed")
	}
}

func TestIPStackSetupRejectsLiveChangesAndInvalidPairs(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	oldCount := activeCoreCount.Load()
	defer activeCoreCount.Store(oldCount)
	activeCoreCount.Store(0)
	options := testOptions(t)
	options.IPQueryMode = "dual-stack"
	options.TunIPv6Mode = "automatic"
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	frozen := currentIPStackSettings()
	activeCoreCount.Store(1)
	options.IPQueryMode = "ipv4-only"
	if err := Setup(options); err == nil {
		t.Fatal("live policy mutation accepted")
	}
	if currentIPStackSettings() != frozen {
		t.Fatal("rejected setup mutated policy")
	}
	activeCoreCount.Store(0)
	options.IPQueryMode = "dual-stack"
	options.TunIPv6Mode = "auto"
	if err := Setup(options); err == nil {
		t.Fatal("invalid alias accepted")
	}
	if currentIPStackSettings() != frozen {
		t.Fatal("invalid setup mutated policy")
	}
}
func TestIPStackIntentFingerprintSeparatesAllSnapshots(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	seen := map[string]bool{}
	for _, q := range []string{"ipv4-only", "dual-stack", "prefer-ipv4", "prefer-ipv6", "ipv6-only"} {
		for _, tun := range []string{"disabled", "automatic", "enabled"} {
			snapshot, _ := parseIPStackSettings(q, tun)
			setIPStackSettings(snapshot)
			box, err := PlatformConfigIntentJSON("ipv6: false\ndns:\n  ipv6: false\n")
			if err != nil {
				t.Fatal(err)
			}
			if seen[box.Value] {
				t.Fatalf("fingerprint did not separate %s/%s", q, tun)
			}
			seen[box.Value] = true
		}
	}
}

func TestIPStackIntentUsesOneSnapshotDuringConcurrentSetupChanges(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	a, _ := parseIPStackSettings("dual-stack", "automatic")
	b, _ := parseIPStackSettings("ipv4-only", "disabled")
	source := "ipv6: false\n"
	setIPStackSettings(a)
	ia, err := PlatformConfigIntentJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	setIPStackSettings(b)
	ib, err := PlatformConfigIntentJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				setIPStackSettings(a)
				setIPStackSettings(b)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 1000; i++ {
		got, err := PlatformConfigIntentJSON(source)
		if err != nil {
			t.Fatal(err)
		}
		if got.Value != ia.Value && got.Value != ib.Value {
			t.Fatal("intent combines fields from two startup snapshots")
		}
	}
}

func TestIPStackParsedTunOfferKeepsAddressesAndRoutesAcrossPathCapabilities(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	old4, old6 := physicalPathSupportsIPv4.Load(), physicalPathSupportsIPv6.Load()
	defer setPhysicalNetworkCapabilities(old4, old6)
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	content := `ipv6: false
tun:
  enable: true
  inet6-address: ["fdfe:dcba:9876::1/126"]
  route-address: ["2001:db8::/32"]
  route-exclude-address: ["2001:db8:1::/48"]
rules: ["MATCH,DIRECT"]
`
	for _, mode := range []string{"automatic", "enabled", "disabled"} {
		snapshot, _ := parseIPStackSettings("ipv4-only", mode)
		setIPStackSettings(snapshot)
		setPhysicalNetworkCapabilities(true, false)
		cfg, err := parseConfigForIOS(content, true)
		if err != nil {
			t.Fatal(err)
		}
		offered := newTunOptions(&cfg.General.Tun)
		if offered.GetIPv6Mode() != mode {
			t.Fatal("offer mode mismatch")
		}
		if (offered.GetInet6Address().Len() > 0) != (mode != "disabled") {
			t.Fatalf("parsed offer lost capture capability for %s", mode)
		}
		if mode != "disabled" {
			if offered.GetInet6RouteAddress().Len() != 1 || offered.GetInet6RouteExcludeAddress().Len() != 1 {
				t.Fatal("parsed offer lost full v6 routes")
			}
			setPhysicalNetworkCapabilities(false, true)
			if offered.GetInet6Address().Len() != 1 || offered.GetInet6RouteAddress().Len() != 1 {
				t.Fatal("offer mutated with physical path")
			}
		}
	}
}

func TestIPStackPhysicalIPv6AvailabilityDoesNotDisableNAT64OrLocalIPv6(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	setupNAT64PolicyTest(t)
	s, _ := parseIPStackSettings("dual-stack", "automatic")
	setIPStackSettings(s)
	setPhysicalNetworkCapabilities(true, false)
	if _, err := transformPhysicalAddressForApple("udp", netip.MustParseAddr("2001:db8::1")); !errors.Is(err, dialer.ErrPhysicalIPv6Unavailable) {
		t.Fatalf("unavailable public IPv6 peer accepted: %v", err)
	}
	for _, addr := range []string{"::1", "fe80::1", "fd00::1"} {
		if _, err := transformPhysicalAddressForApple("udp", netip.MustParseAddr(addr)); err != nil {
			t.Fatalf("local IPv6 incorrectly ruled out: %s %v", addr, err)
		}
	}
	setPhysicalNetworkCapabilities(false, true)
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) { return netip.MustParseAddr("64:ff9b::c000:201"), nil }
	got, err := transformPhysicalAddressForApple("udp", netip.MustParseAddr("192.0.2.1"))
	if err != nil || !got.Is6() {
		t.Fatalf("NAT64 broken: %v %v", got, err)
	}
}

func TestIPStackFollowConfigurationLeavesTheProfileAlone(t *testing.T) {
	both, err := parseIPStackSettings("config", "config")
	if err != nil {
		t.Fatal(err)
	}
	if both.queryMode != resolver.IPQueryLegacy || both.tunIPv6Mode != "config" {
		t.Fatalf("config/config parses to the legacy query policy and a named tun mode, got %+v", both)
	}
	raw := config.DefaultRawConfig()
	raw.IPv6 = false
	raw.DNS.IPv6 = false
	raw.Tun.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}
	applyIPStackSettings(raw, both)
	if raw.IPv6 || raw.DNS.IPv6 || len(raw.Tun.Inet6Address) != 1 || raw.PreserveTunIPv6 {
		t.Fatal("config/config changed the profile")
	}

	queryOnly, err := parseIPStackSettings("config", "disabled")
	if err != nil {
		t.Fatal(err)
	}
	raw = config.DefaultRawConfig()
	raw.IPv6 = true
	raw.DNS.IPv6 = true
	raw.Tun.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}
	applyIPStackSettings(raw, queryOnly)
	if !raw.IPv6 || !raw.DNS.IPv6 || len(raw.Tun.Inet6Address) != 0 || raw.PreserveTunIPv6 {
		t.Fatal("config/disabled: the query half must stay the file's, the tun half must switch off")
	}

	tunOnly, err := parseIPStackSettings("ipv4-only", "config")
	if err != nil {
		t.Fatal(err)
	}
	raw = config.DefaultRawConfig()
	raw.IPv6 = true
	raw.Tun.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}
	applyIPStackSettings(raw, tunOnly)
	if raw.IPv6 || raw.DNS.IPv6 || len(raw.Tun.Inet6Address) != 1 || raw.PreserveTunIPv6 {
		t.Fatal("ipv4-only/config: the query half applies, the tun half is left to the file")
	}

	if _, err := parseIPStackSettings("config", ""); err == nil {
		t.Fatal("config with an empty tun mode is a half pair")
	}
}

func TestIPStackFollowConfigurationIsOfferedByName(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := parseIPStackSettings("config", "config")
	if err != nil {
		t.Fatal(err)
	}
	setIPStackSettings(snapshot)
	cfg, err := parseConfigForIOS("tun:\n  enable: true\nrules: [\"MATCH,DIRECT\"]\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := newTunOptions(&cfg.General.Tun).GetIPv6Mode(); got != "config" {
		t.Fatalf("offer mode %q", got)
	}
}
