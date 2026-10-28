package clash

import (
	"encoding/json"
	"testing"

	"github.com/ProjectClash/Clash/dns"
)

const dnsCacheSilent = `
mixed-port: 7890
dns:
  enable: true
  nameserver: [1.1.1.1]
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`

func TestTheBoundedDNSCacheIsTheIOSAndTVOSTunnels(t *testing.T) {
	for _, c := range []struct {
		profile runtimeProfile
		underNE bool
		want    bool
	}{
		{runtimeProfileIOSPacketTunnel, true, true},
		{runtimeProfileTVOSPacketTunnel, true, true},
		{runtimeProfileIOSPacketTunnel, false, false},
		{runtimeProfileTVOSPacketTunnel, false, false},
		{runtimeProfileMacOSPacketTunnel, true, false},
		{runtimeProfileMacOSPacketTunnel, false, false},
		{runtimeProfileMacOSApplication, false, false},
	} {
		if got := runtimePolicyFor(c.profile, c.underNE).boundedDNSCache; got != c.want {
			t.Errorf("%v under NE %v: boundedDNSCache %v, want %v", c.profile, c.underNE, got, c.want)
		}
	}
}

func TestTheServiceSetsTheResolverCacheDefaultBeforeAnyParse(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	t.Cleanup(func() { dns.ClashSetDefaultCacheMaxSize(0) })
	setDNSCacheDefaultFor(runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if got := dns.ClashDefaultCacheMaxSize(); got != appleBoundedDNSCacheMaxSize {
		t.Fatalf("iOS tunnel: a cache given no size holds %d, want %d", got, appleBoundedDNSCacheMaxSize)
	}
	for _, other := range []appleRuntimePolicy{
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, false),
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true),
	} {
		setDNSCacheDefaultFor(other)
		if got := dns.ClashDefaultCacheMaxSize(); got != 4096 {
			t.Fatalf("%v: a cache given no size holds %d, want upstream's 4096", other.profile, got)
		}
	}
}

func TestFinalizeSaysTheSizeTheResolversHold(t *testing.T) {
	for _, c := range []struct {
		doc     string
		policy  appleRuntimePolicy
		written int
		want    int
	}{
		{dnsCacheSilent, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), 0, appleBoundedDNSCacheMaxSize},
		{dnsCacheSilent, runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), 0, 0},
	} {
		cfg, err := parseConfigForIOS(c.doc, true)
		if err != nil {
			t.Fatal(err)
		}
		finalizeConfigForApple(cfg, c.policy)
		if cfg.DNS.CacheMaxSize != c.want {
			t.Fatalf("%v: effective cache-max-size %d, want %d", c.policy.profile, cfg.DNS.CacheMaxSize, c.want)
		}
	}
	cfg, err := parseConfigForIOS("dns:\n  enable: true\n  nameserver: [1.1.1.1]\n  cache-max-size: 300\nrules:\n  - MATCH,DIRECT\n", true)
	if err != nil {
		t.Fatal(err)
	}
	finalizeConfigForApple(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if cfg.DNS.CacheMaxSize != 300 {
		t.Fatalf("a written 300 became %d", cfg.DNS.CacheMaxSize)
	}
}

func dnsCacheRowFor(t *testing.T, yaml, profile string) map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(yaml, profile)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON: %v", err)
	}
	var report struct {
		Deviations []map[string]any `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatal(err)
	}
	for _, d := range report.Deviations {
		if d["field"] == "dns.cache-max-size" {
			return d
		}
	}
	return nil
}

func TestTheDNSCacheSizeIsReportedOnlyWhereAndWhenItChanges(t *testing.T) {
	sized := func(size string) string {
		return "dns:\n  enable: true\n  nameserver: [1.1.1.1]\n  cache-max-size: " + size + "\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	}
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		if row := dnsCacheRowFor(t, dnsCacheSilent, profile); row == nil {
			t.Fatalf("%s: not written and not reported", profile)
		} else if given, _ := row["given"].(string); given != "not set (core default: 4096)" {
			t.Fatalf("%s: given = %q; for an unwritten field it names the upstream default", profile, given)
		}
		if row := dnsCacheRowFor(t, sized("0"), profile); row == nil {
			t.Fatalf("%s: 0 -- upstream's word for the default -- not reported", profile)
		} else if row["given"] != "0 (core default: 4096)" || row["upstreamDefault"] != "4096" || row["written"] != false {
			t.Fatalf("%s: a written 0 reads %v / %v / written=%v, not as the default", profile, row["given"], row["upstreamDefault"], row["written"])
		}
		for _, kept := range []string{"4096", "1024", "512"} {
			if row := dnsCacheRowFor(t, sized(kept), profile); row != nil {
				t.Fatalf("%s: %s written, yet reported: %v", profile, kept, row)
			}
		}
	}
	for _, profile := range []string{RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		if row := dnsCacheRowFor(t, dnsCacheSilent, profile); row != nil {
			t.Fatalf("%s keeps upstream's cache, yet reported: %v", profile, row)
		}
	}
}
