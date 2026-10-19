package netidentity

import (
	"net/netip"
	"testing"
)

func TestSetNormalizesAndReportsAChange(t *testing.T) {
	t.Cleanup(Reset)
	if got := Current(); got.Kind != "" || got.SSID != "" {
		t.Fatalf("before any identity: %+v", got)
	}
	id := Identity{Kind: "wifi", SSID: " Home ", BSSID: "AA:BB:CC:00:11:22", Routers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}
	if !Set(id) {
		t.Fatal("the first identity was not a change")
	}
	got := Current()
	if got.Kind != KindWiFi || got.SSID != "Home" || got.BSSID != "aa:bb:cc:00:11:22" {
		t.Fatalf("normalized to %+v", got)
	}
	if Set(id) {
		t.Fatal("the same identity again was a change")
	}
	if !Set(Identity{Kind: "CELLULAR", Radio: "CTRadioAccessTechnologyLTE"}) || Current().Radio != "LTE" {
		t.Fatalf("radio normalized to %q", Current().Radio)
	}
}
