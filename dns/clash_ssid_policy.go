package dns

import (
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/netidentity"
)

type SSIDPolicy struct {
	SSID        string
	NameServers []NameServer
}

type ssidPolicy struct {
	ssid    string
	clients []dnsClient
}

func (p ssidPolicy) Match(string) []dnsClient {
	if netidentity.Current().SSID == p.ssid {
		return p.clients
	}
	return nil
}

func (p ssidPolicy) Clients() []dnsClient { return p.clients }

var ssidPoliciesInForce atomic.Bool

func SSIDPoliciesInForce() bool { return ssidPoliciesInForce.Load() }
