package clash

import (
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/component/netidentity"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/dns"
)

type clearCountingResolver struct {
	resolver.Resolver
	clears atomic.Int32
}

func (r *clearCountingResolver) ClearCache() { r.clears.Add(1) }

func TestSetNetworkIdentityReadsTheNetworkAndDropsTheCacheOnANewWiFi(t *testing.T) {
	t.Cleanup(netidentity.Reset)
	previous := resolver.DefaultResolver
	counter := &clearCountingResolver{}
	resolver.DefaultResolver = counter
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	ns := dns.NameServer{Net: "udp", Addr: "127.0.0.1:53"}
	dns.NewResolver(dns.Config{Main: []dns.NameServer{ns}, SSIDPolicy: []dns.SSIDPolicy{{SSID: "Home", NameServers: []dns.NameServer{ns}}}})
	t.Cleanup(func() { dns.NewResolver(dns.Config{Main: []dns.NameServer{ns}}) })

	SetNetworkIdentity("wifi", "192.168.1.1, not-an-address, ::ffff:10.0.0.1", " Home ", "AA:BB:CC:00:11:22", "CTRadioAccessTechnologyLTE")
	got := netidentity.Current()
	if got.Kind != netidentity.KindWiFi || got.SSID != "Home" || got.BSSID != "aa:bb:cc:00:11:22" ||
		!reflect.DeepEqual(got.Routers, []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.0.0.1")}) {
		t.Fatalf("the identity read %+v", got)
	}
	if n := counter.clears.Load(); n != 1 {
		t.Fatalf("a new Wi-Fi network cleared the cache %d times before returning, want 1", n)
	}
	SetNetworkIdentity("wifi", "192.168.1.1", "Home", "AA:BB:CC:00:11:22", "")
	SetNetworkIdentity("wifi", "192.168.1.254", "Home", "aa:bb:cc:00:11:23", "")
	if n := counter.clears.Load(); n != 1 {
		t.Fatalf("the same Wi-Fi name cleared the cache again (%d)", n)
	}
	SetNetworkIdentity("cellular", "", "", "", "LTE")
	if n := counter.clears.Load(); n != 2 {
		t.Fatalf("leaving the Wi-Fi network cleared the cache %d times in all, want 2", n)
	}
}

type recordingRuleNotificationHandler struct{ texts []string }

func (h *recordingRuleNotificationHandler) RuleMatched(text, rule string) {
	h.texts = append(h.texts, text, rule)
}

func TestSetRuleNotificationHandlerDecoratesTheHandler(t *testing.T) {
	handler := &recordingRuleNotificationHandler{}
	sink := ruleNotificationSink(handler)
	sink("ok\xff", "DOMAIN,a.example")
	if len(handler.texts) != 2 || handler.texts[0] != bridgeSafeString("ok\xff") || handler.texts[0] == "ok\xff" {
		t.Fatalf("the handler got %q, want the text made bridge-safe", handler.texts)
	}
	if ruleNotificationSink(nil) != nil {
		t.Fatal("no handler is a sink")
	}
}
