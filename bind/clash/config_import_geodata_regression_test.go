package clash

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/component/geodata/router"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/common"
	"google.golang.org/protobuf/proto"
)

func writeGeodataAtomically(t *testing.T, path string, message proto.Message) {
	t.Helper()
	payload, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".next", payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
}

func TestDeferredCompileDoesNotReplaceBytesUnderAParsedProvider(t *testing.T) {
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileMacOSPacketTunnel} {
		t.Run(profile, func(t *testing.T) {
			home := setupConfigPipelineTest(t)
			C.SetHomeDir(home)
			resetGeodataFlagsForYardstick(t)
			if err := Setup(&SetupOptions{BasePath: filepath.Dir(home), WorkingPath: home, TempPath: filepath.Join(filepath.Dir(home), "temp"), RuntimeProfile: profile}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
			source := filepath.Join(home, "audit-rules.txt")
			if err := os.WriteFile(source, []byte("DOMAIN,old.example.com\nDOMAIN,new.example.com\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			document := "mode: rule\nrule-providers:\n  audit: {type: file, behavior: classical, format: text, path: " + source + "}\nrules:\n - RULE-SET,audit,DIRECT\n - MATCH,REJECT\n"
			finalized, err := FinalizeForIOS(document, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := StageProvidersForPublish(finalized.Value, profile, false); err != nil {
				t.Fatal(err)
			}
			cfg, runtime, err := parseConfigForIOSRuntime(finalized.Value, true, "audit-deferred")
			if err != nil {
				t.Fatal(err)
			}
			if runtime != nil {
				defer runtime.close()
			}
			defer closeCatalogObjects(cfg.Proxies, cfg.Providers)
			if err := StageProvidersForPublish(finalized.Value, profile, true); err != nil {
				t.Fatal(err)
			}
			provider := cfg.RuleProviders["audit"]
			initialErr := provider.Initial()
			if closer, ok := provider.(interface{ Close() error }); ok {
				defer closer.Close()
			}
			if provider.Count() != 2 {
				t.Fatalf("the deferred compile changed the bytes under the parsed provider: count=%d, Initial error %v", provider.Count(), initialErr)
			}
			next, nextRuntime, err := parseConfigForIOSRuntime(finalized.Value, true, "audit-next")
			if err != nil {
				t.Fatal(err)
			}
			if nextRuntime != nil {
				defer nextRuntime.close()
			}
			defer closeCatalogObjects(next.Proxies, next.Providers)
			nextProvider := next.RuleProviders["audit"]
			if err := nextProvider.Initial(); err != nil || nextProvider.Count() != 2 {
				t.Fatalf("next start: count=%d err=%v", nextProvider.Count(), err)
			}
			if closer, ok := nextProvider.(interface{ Close() error }); ok {
				defer closer.Close()
			}
			if got, _ := nextProvider.(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON(); !strings.Contains(string(got), `"behavior":"Domain"`) {
				t.Fatalf("next start did not read the compiled artifact: %s", got)
			}
		})
	}
}

func TestGeodataRecompileFailureRetiresTheStaleArtifact(t *testing.T) {
	previousMode := geodata.GeodataMode()
	t.Cleanup(func() { geodata.SetGeodataMode(previousMode) })
	home := setupConfigPipelineTest(t)
	C.SetHomeDir(home)
	previousLoader := geodata.LoaderName()
	geodata.SetLoader("standard")
	t.Cleanup(func() { geodata.SetLoader(previousLoader) })
	resetGeodataFlagsForYardstick(t)
	sitePath := filepath.Join(home, "GeoSite.dat")
	ipPath := filepath.Join(home, "GeoIP.dat")
	writeGeodataAtomically(t, sitePath, &router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "AUDIT", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "old.example.com"}}}}})
	writeGeodataAtomically(t, ipPath, &router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "AUDIT", Cidr: []*router.CIDR{{Ip: []byte{203, 0, 113, 0}, Prefix: 24}}}}})
	document := "geodata-mode: true\nrules:\n - GEOSITE,audit,DIRECT\n - GEOIP,audit,DIRECT\n - MATCH,REJECT\n"
	if _, err := PrepareGeoSiteCache(document); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareGeoIPCache(document, true); err != nil {
		t.Fatal(err)
	}
	writeGeodataAtomically(t, sitePath, &router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "OTHER", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "new.example.com"}}}}})
	writeGeodataAtomically(t, ipPath, &router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "OTHER", Cidr: []*router.CIDR{{Ip: []byte{198, 51, 100, 0}, Prefix: 24}}}}})
	_, _ = PrepareGeoSiteCache(document)
	_, _ = PrepareGeoIPCache(document, true)
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	geodata.SetCompiledGeoSiteOnly(true)
	geodata.SetCompiledGeoIPOnly(true)
	geodata.SetGeodataMode(true)
	if site, err := common.NewGEOSITE("audit", "DIRECT"); err == nil && site.MatchDomain("old.example.com") {
		t.Error("GEOSITE,audit still matches a domain the new GeoSite.dat no longer holds")
	}
	if ip, err := common.NewGEOIP("audit", "DIRECT", false, true); err == nil && ip.MatchIp(netip.MustParseAddr("203.0.113.1")) {
		t.Error("GEOIP,audit still matches a network the new GeoIP.dat no longer holds")
	}
}

func TestEncodedAuthorityKeepsAnAtInItsTitleOrQuery(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for name, test := range map[string]struct{ link, password string }{
		"title":              {"https://" + encode("u:pw@h.example.com:443/#team@example.com"), "pw"},
		"query":              {"https://" + encode("u:pw@h.example.com:443/?name=team@example.com"), "pw"},
		"password with @":    {"ss://" + encode("aes-128-gcm:pw@literal@h.example.com:8388"), "pw@literal"},
		"password with ?#/%": {"ss://" + encode("aes-128-gcm:pa#?/%ss@h.example.com:80"), "pa#?/%ss"},
	} {
		for _, context := range []string{"singleNode", "subscriptionBody"} {
			t.Run(name+"/"+context, func(t *testing.T) {
				report := inspectProxyPayloadReport(t, test.link, context)
				if len(report.Proxies) != 1 {
					t.Fatalf("skipped %v", report.Skipped)
				}
				if got := shadowrocketField(report.Proxies[0], "password"); got != test.password {
					t.Fatalf("password = %q, want %q", got, test.password)
				}
				if _, err := adapter.ParseProxy(report.Proxies[0]); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestWSSKeepsTheNamedServerName(t *testing.T) {
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte("auto:"+srUUID+"@vm.example.com:443")) + "?obfs=wss&obfsParam=cdn.example.com&path=/ws&peer=certificate.example.com"
	for _, context := range []string{"singleNode", "subscriptionBody"} {
		report := inspectProxyPayloadReport(t, link, context)
		if len(report.Proxies) != 1 {
			t.Fatalf("%s: skipped %v", context, report.Skipped)
		}
		proxy := report.Proxies[0]
		if shadowrocketField(proxy, "servername") != "certificate.example.com" || shadowrocketField(proxy, "tls") != "true" {
			t.Fatalf("%s: %v", context, proxy)
		}
	}
}

func TestEncodedAuthorityAtSelectionReview(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	report := inspectProxyPayloadReport(t, "ss://"+encode("aes-128-gcm:psk@real.example.com:443/#ops@backup.example.com:8443"), "singleNode")
	if len(report.Proxies) != 1 || shadowrocketField(report.Proxies[0], "server") != "real.example.com" || shadowrocketField(report.Proxies[0], "password") != "psk" {
		t.Fatalf("title endpoint taken for the server: %+v", report)
	}
	for _, title := range []string{"HK@Speed:10G", "a@b:c"} {
		report := inspectProxyPayloadReport(t, "https://"+encode("u:pw@h.example.com:443/#"+title), "singleNode")
		if len(report.Proxies) != 1 || shadowrocketField(report.Proxies[0], "server") != "h.example.com" {
			t.Fatalf("%s: %+v", title, report)
		}
	}
	if normalized, ok := normalizeEncodedProxyAuthority("socks://" + encode("method:pass@hostnoport")); ok {
		t.Fatalf("an authority with no endpoint was accepted: %s", normalized)
	}
	start := time.Now()
	normalizeEncodedProxyAuthority("socks://" + encode(strings.Repeat("@", 200_000)))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("200k `@` took %v", elapsed)
	}
}

func TestEncodedAuthorityReview2(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, link := range []string{
		"http://" + encode("u:pw@h.example.com:1000-2000"),
		"socks://" + encode("u:pw@h.example.com:1000,2000"),
		"socks://" + encode("h.example.com:443#a@b"),
	} {
		report := inspectProxyPayloadReport(t, link, "singleNode")
		if len(report.Proxies) != 1 || shadowrocketField(report.Proxies[0], "server") != "h.example.com" {
			t.Errorf("%s: %+v", link, report)
		}
	}
}

func TestEncodedAuthorityReview3(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, decoded := range []string{"user:1/abc@hostnoport", "user:1234?q@2001:db8::1:1080"} {
		if normalized, ok := normalizeEncodedProxyAuthority("socks://" + encode(decoded)); ok {
			t.Errorf("%s was read as %s", decoded, normalized)
		}
	}
}

func TestAuditDefectsIOSMatrixStrings(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	report := inspectProxyPayloadReport(t, "https://"+encode(srUUID+":"+srUUID+"@hs.example.com:443/#HK@01"), "singleNode")
	if len(report.Proxies) != 1 || shadowrocketField(report.Proxies[0], "server") != "hs.example.com" || shadowrocketField(report.Proxies[0], "name") != "HK@01" {
		t.Fatalf("https title with @: %+v", report)
	}
	report = inspectProxyPayloadReport(t, "vmess://"+encode("auto:"+srUUID+"@vm.example.com:443")+"?obfs=wss&obfsParam=cdn&path=/ws&peer=sni.example.com", "singleNode")
	if len(report.Proxies) != 1 || shadowrocketField(report.Proxies[0], "servername") != "sni.example.com" {
		t.Fatalf("vmess wss servername: %+v", report)
	}
}
