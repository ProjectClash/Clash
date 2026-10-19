package common

import (
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/component/netidentity"
	C "github.com/ProjectClash/Clash/constant"
)

var (
	homeWiFi = netidentity.Identity{
		Kind: netidentity.KindWiFi, SSID: "Office-3F", BSSID: "aa:bb:cc:00:11:22",
		Routers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
	}
	lte = netidentity.Identity{
		Kind: netidentity.KindCellular, Radio: "LTE",
		Routers: []netip.Addr{netip.MustParseAddr("10.64.0.1")},
	}
	ethernet = netidentity.Identity{Kind: netidentity.KindWired, Routers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}
)

func TestSubnetReadsSurgesExpressions(t *testing.T) {
	t.Cleanup(netidentity.Reset)
	for expression, want := range map[string][3]bool{
		"TYPE:WIFI":          {true, false, false},
		"type:cellular":      {false, true, false},
		"TYPE:WIRED":         {false, false, true},
		"ROUTER:192.168.1.1": {true, false, true},
		"ROUTER:10.64.0.1":   {false, true, false},
		"SSID:Office-*":      {true, false, false},
		"SSID:office-*":      {false, false, false},
		"SSID:Office-?F":     {true, false, false},
		"BSSID:AA:BB:CC:*":   {true, false, false},
		"MCCMNC:310260":      {false, false, false},
		"Office-3F":          {true, false, false},
		"Office*":            {true, false, false},
		"AA:BB:CC:00:11:22":  {true, false, false},
		"192.168.1.1":        {true, false, true},
		"Elsewhere":          {false, false, false},
	} {
		rule, err := NewSubnet(expression, "P")
		if err != nil {
			t.Errorf("SUBNET,%s refused: %v", expression, err)
			continue
		}
		for i, id := range []netidentity.Identity{homeWiFi, lte, ethernet} {
			netidentity.Set(id)
			if got, adapter := rule.Match(&C.Metadata{}, C.RuleMatchHelper{}); got != want[i] || adapter != "P" {
				t.Errorf("SUBNET,%s on %s: %v, want %v", expression, id.Kind, got, want[i])
			}
		}
	}
	netidentity.Reset()
	rule, _ := NewSubnet("TYPE:WIFI", "P")
	if got, _ := rule.Match(&C.Metadata{}, C.RuleMatchHelper{}); got {
		t.Error("SUBNET matched before the platform handed over any network")
	}
}

func TestSubnetRefusesWhatItCannotRead(t *testing.T) {
	for _, expression := range []string{"TYPE:BLUETOOTH", "ROUTER:not-an-ip", "MCCMNC:31x", "SSID:", ""} {
		if _, err := NewSubnet(expression, "P"); err == nil {
			t.Errorf("SUBNET,%s was accepted", expression)
		}
	}
}

func TestCellularRadioMatchesOffWiFiOnly(t *testing.T) {
	t.Cleanup(netidentity.Reset)
	rule, err := NewCellularRadio("lte", "P")
	if err != nil || rule.Payload() != "LTE" || rule.RuleType() != C.CellularRadio {
		t.Fatalf("CELLULAR-RADIO,lte: %v %v", rule, err)
	}
	for id, want := range map[*netidentity.Identity]bool{&lte: true, &homeWiFi: false} {
		netidentity.Set(*id)
		if got, _ := rule.Match(&C.Metadata{}, C.RuleMatchHelper{}); got != want {
			t.Errorf("on %s: %v, want %v", id.Kind, got, want)
		}
	}
	netidentity.Set(netidentity.Identity{Kind: netidentity.KindCellular, Radio: "CTRadioAccessTechnologyNR"})
	if got, _ := rule.Match(&C.Metadata{}, C.RuleMatchHelper{}); got {
		t.Error("CELLULAR-RADIO,LTE matched on NR")
	}
	if _, err := NewCellularRadio("6G", "P"); err == nil {
		t.Error("CELLULAR-RADIO,6G was accepted")
	}
}
