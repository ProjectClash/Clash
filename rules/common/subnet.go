package common

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ProjectClash/Clash/component/netidentity"
	"github.com/ProjectClash/Clash/component/wildcard"
	C "github.com/ProjectClash/Clash/constant"
)

type Subnet struct {
	Base
	kind    string
	value   string
	router  netip.Addr
	adapter string
	payload string
}

func NewSubnet(payload, adapter string) (*Subnet, error) {
	expression := strings.TrimSpace(payload)
	rule := &Subnet{adapter: adapter, payload: expression}
	kind, value, prefixed := strings.Cut(expression, ":")
	if prefixed {
		switch upper := strings.ToUpper(strings.TrimSpace(kind)); upper {
		case "TYPE", "ROUTER", "SSID", "BSSID", "MCCMNC":
			rule.kind = upper
			value = strings.TrimSpace(value)
		default:
			prefixed = false
		}
	}
	if !prefixed {
		value = expression
	}
	if value == "" {
		return nil, fmt.Errorf("SUBNET needs a value after %q", kind)
	}
	switch rule.kind {
	case "TYPE":
		value = strings.ToUpper(value)
		if value != netidentity.KindWiFi && value != netidentity.KindWired && value != netidentity.KindCellular {
			return nil, fmt.Errorf("unsupported SUBNET type %q, only WIFI/WIRED/CELLULAR", value)
		}
	case "ROUTER":
		router, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("SUBNET ROUTER is not an IP address: %w", err)
		}
		rule.router = router.Unmap()
	case "BSSID":
		value = strings.ToLower(value)
	case "MCCMNC":
		for _, r := range value {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("SUBNET MCCMNC is digits only: %q", value)
			}
		}
	case "":
		if router, err := netip.ParseAddr(value); err == nil {
			rule.router = router.Unmap()
		}
	}
	rule.value = value
	return rule, nil
}

func (s *Subnet) RuleType() C.RuleType { return C.Subnet }

func (s *Subnet) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	return s.matches(netidentity.Current()), s.adapter
}

func (s *Subnet) matches(id netidentity.Identity) bool {
	switch s.kind {
	case "TYPE":
		return id.Kind == s.value
	case "ROUTER":
		return hasRouter(id, s.router)
	case "SSID":
		return id.SSID != "" && wildcard.Match(s.value, id.SSID)
	case "BSSID":
		return id.BSSID != "" && wildcard.Match(s.value, id.BSSID)
	case "MCCMNC":
		return id.Kind != netidentity.KindWiFi && id.MCCMNC != "" && id.MCCMNC == s.value
	}
	if strings.ContainsAny(s.value, "*?") {
		return id.SSID != "" && wildcard.Match(s.value, id.SSID)
	}
	return (id.SSID != "" && id.SSID == s.value) ||
		(id.BSSID != "" && strings.EqualFold(id.BSSID, s.value)) ||
		(s.router.IsValid() && hasRouter(id, s.router))
}

func hasRouter(id netidentity.Identity, router netip.Addr) bool {
	for _, r := range id.Routers {
		if r.Unmap() == router {
			return true
		}
	}
	return false
}

func (s *Subnet) Adapter() string { return s.adapter }

func (s *Subnet) Payload() string { return s.payload }

type CellularRadio struct {
	Base
	radio   string
	adapter string
}

var cellularRadios = [...]string{
	"GPRS", "Edge", "WCDMA", "HSDPA", "HSUPA", "CDMA1x", "CDMAEVDORev0", "CDMAEVDORevA",
	"CDMAEVDORevB", "eHRPD", "HRPD", "LTE", "NRNSA", "NR",
}

func NewCellularRadio(payload, adapter string) (*CellularRadio, error) {
	value := strings.TrimSpace(payload)
	for _, radio := range cellularRadios {
		if strings.EqualFold(radio, value) {
			return &CellularRadio{radio: radio, adapter: adapter}, nil
		}
	}
	return nil, fmt.Errorf("unsupported cellular radio %q, only %s", value, strings.Join(cellularRadios[:], "/"))
}

func (c *CellularRadio) RuleType() C.RuleType { return C.CellularRadio }

func (c *CellularRadio) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	id := netidentity.Current()
	return id.Kind == netidentity.KindCellular && strings.EqualFold(id.Radio, c.radio), c.adapter
}

func (c *CellularRadio) Adapter() string { return c.adapter }

func (c *CellularRadio) Payload() string { return c.radio }

var (
	_ C.Rule = (*Subnet)(nil)
	_ C.Rule = (*CellularRadio)(nil)
)
